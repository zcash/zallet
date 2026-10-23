use std::ffi::c_int;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use abscissa_core::Runnable;
use rusqlite::{
    Connection, OpenFlags,
    backup::{Backup, StepResult},
    ffi,
};

use crate::{
    cli::BackupCmd,
    commands::AsyncRunnable,
    error::{Error, ErrorKind},
    fl,
    fs::{Publish, PublishError, publish_private_file, temp_path},
    prelude::*,
};

/// How many database pages are copied per backup step.
///
/// The step size trades two costs against each other. Each step holds the source
/// database's read lock while it copies, so a running wallet's writes stall for
/// one step's worth of I/O: 4096 pages is 16 MiB at SQLite's default 4 KiB page
/// size, roughly 60 ms on a SATA SSD and under a second even on a spinning disk.
/// Between steps the wallet is free to write, and a write made there restarts
/// the copy from the beginning on the next step, so smaller steps stall the
/// wallet less but open more restart windows, and a busy wallet may never
/// complete a pass. The hard ceiling is the running wallet itself: its own
/// connections give up on a lock after the 5-second busy timeout `rusqlite`
/// installs, so a step must stall writers for comfortably less than that or the
/// backup would surface spurious busy errors inside the wallet. 16 MiB keeps the
/// per-step stall well under a second while copying a typical (tens to hundreds
/// of MiB) wallet database in few enough steps that it has a real chance of
/// finishing between bursts of writes. The final step also commits the
/// destination inside the same stall; the destination connection runs with
/// `synchronous=OFF` so that commit does not add an fsync of the whole backup
/// file to it.
const PAGES_PER_STEP: c_int = 4096;

/// How long to wait after a busy/locked step before retrying.
///
/// This is the pause SQLite's own documentation uses between steps when backing
/// up a running database ("Example 2" of <https://www.sqlite.org/backup.html>):
/// long enough for a writer holding the lock to finish committing, short enough
/// that the backup does not sit idle once the lock clears.
const BUSY_RETRY_PAUSE: Duration = Duration::from_millis(250);

/// How long the source database may stay continuously busy before the backup
/// fails loudly.
///
/// A healthy wallet's write transactions commit in well under a second, and the
/// 5-second busy timeout `rusqlite` installs on every other Zallet connection is
/// already treated as "something is wrong" elsewhere in the codebase. A streak
/// six times that long means something is sitting on the database (an abandoned
/// transaction, or a stray process on a shared datadir) and will not clear by
/// waiting. Failing loudly rather than spinning forever is the operator signal
/// #195 asks for: a backup that is not completing must say so.
const MAX_BUSY_WAIT: Duration = Duration::from_secs(30);

/// How long the whole backup may run before it fails loudly.
///
/// Every wallet write made between steps restarts the copy, so under sustained
/// write load (such as initial sync) each step can keep succeeding while the
/// backup makes no net progress: the "`SQLITE_OK` forever, never `SQLITE_DONE`"
/// case called out on #195. This deadline bounds that case, sized from the
/// honest work bound: one uncontended pass over even a very large (2 GiB) wallet
/// database on slow (~50 MB/s effective) storage takes under two minutes, so
/// allowing five times that means the deadline only fires when restarts, not
/// database size, are consuming the time; ten minutes is also short enough
/// that an operator watching the command learns promptly that it is not going
/// to finish.
const MAX_BACKUP_DURATION: Duration = Duration::from_secs(10 * 60);

/// Pacing and failure bounds for the copy loop.
///
/// Injected into [`copy_database`] so that tests can exercise the failure paths
/// without waiting out the production limits.
struct CopyLimits {
    pages_per_step: c_int,
    busy_retry_pause: Duration,
    max_busy_wait: Duration,
    max_backup_duration: Duration,
}

impl Default for CopyLimits {
    fn default() -> Self {
        Self {
            pages_per_step: PAGES_PER_STEP,
            busy_retry_pause: BUSY_RETRY_PAUSE,
            max_busy_wait: MAX_BUSY_WAIT,
            max_backup_duration: MAX_BACKUP_DURATION,
        }
    }
}

impl AsyncRunnable for BackupCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();

        // Deliberately no datadir lock: the Online Backup API yields a
        // transaction-consistent snapshot even while a running `zallet start` is
        // writing (SQLite restarts the copy if the source changes mid-backup), so
        // this command works against a live wallet and a stopped one alike. The
        // source is opened read-only below, so the command also cannot disturb
        // whichever process does hold the datadir.
        let source = config.wallet_db_path();

        // A zero-length file is not yet a SQLite database (SQLite initializes it on
        // first write), so treat it like a missing one, mirroring `Database::open`.
        match fs::metadata(&source) {
            Ok(meta) if meta.len() > 0 => {}
            Ok(_) | Err(_) => {
                return Err(ErrorKind::Generic
                    .context(fl!(
                        "err-backup-no-wallet",
                        path = source.display().to_string(),
                    ))
                    .into());
            }
        }

        let destination = resolve_destination(&self.destination, time::OffsetDateTime::now_utc())?;

        let pages = {
            let destination = destination.clone();
            tokio::task::spawn_blocking(move || {
                copy_database(&source, &destination, &CopyLimits::default())
            })
            .await
            .map_err(|e| ErrorKind::Generic.context(e))??
        };

        println!(
            "{}",
            fl!(
                "cmd-backup-complete",
                path = destination.display().to_string(),
                pages = pages.to_string(),
            )
        );

        // The wallet database holds key material in encrypted form only; a restore
        // additionally needs the (static) age encryption identity, which this
        // command deliberately does not copy into the same location as the backup,
        // since co-locating them would make the backup self-decrypting.
        #[cfg(zallet_build = "wallet")]
        println!(
            "{}",
            fl!(
                "cmd-backup-identity-reminder",
                identity = config.encryption_identity().display().to_string(),
            )
        );

        Ok(())
    }
}

/// Resolves the operator-supplied destination to the backup file's final path.
///
/// An existing directory gets a timestamped file name inside it, so repeated backups
/// into the same directory rotate naturally instead of colliding. Any other path is
/// used as given. An existing file is refused rather than overwritten: the file
/// being replaced is the operator's previous good backup.
fn resolve_destination(destination: &Path, now: time::OffsetDateTime) -> Result<PathBuf, Error> {
    let generated = destination.is_dir();
    let destination = if generated {
        let timestamp = format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
        );
        destination.join(format!("zallet-wallet-backup-{timestamp}.db"))
    } else {
        destination.to_path_buf()
    };

    if destination.exists() {
        // A generated name collides only with a backup from the same second,
        // and changes by itself on retry.
        let message = if generated {
            fl!(
                "err-backup-timestamp-collision",
                path = destination.display().to_string(),
            )
        } else {
            fl!(
                "err-backup-destination-exists",
                path = destination.display().to_string(),
            )
        };
        return Err(ErrorKind::Generic.context(message).into());
    }

    Ok(destination)
}

/// Suffix of the in-progress file the backup is written to before publication.
///
/// The name is deterministic so it doubles as mutual exclusion between
/// concurrent backups to the same destination; a stale one left by an
/// interrupted run is refused with an actionable error rather than reused.
const PARTIAL_SUFFIX: &str = ".partial";

/// Copies the wallet database to `destination` using SQLite's Online Backup API,
/// returning the number of pages copied.
///
/// The copy lands in an owner-only temporary file beside the destination and is
/// published only after it has been verified and synced to disk, so
/// `destination` either does not exist or is a complete, checked backup, never
/// a torn copy.
fn copy_database(source: &Path, destination: &Path, limits: &CopyLimits) -> Result<u64, Error> {
    publish_private_file(
        destination,
        Publish::NoClobber {
            temp_suffix: PARTIAL_SUFFIX,
        },
        |tmp| copy_into(source, tmp, limits),
    )
    .map_err(|e| match e {
        PublishError::Create(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            ErrorKind::Generic
                .context(fl!(
                    "err-backup-partial-in-the-way",
                    path = tmp_path(destination).display().to_string(),
                ))
                .into()
        }
        PublishError::Create(e) => {
            // The raw I/O error names neither the operation nor the file.
            ErrorKind::Generic
                .context(fl!(
                    "err-backup-cannot-create",
                    path = tmp_path(destination).display().to_string(),
                    error = e.to_string(),
                ))
                .into()
        }
        PublishError::Fill(e) => e,
        PublishError::DestinationExists => destination_exists_error(destination),
        PublishError::Publish(e) => ErrorKind::Generic.context(e).into(),
        PublishError::PostPublish(e) => published_backup_error(destination, e),
    })
}

/// The in-progress file the backup is written to before it is published.
fn tmp_path(destination: &Path) -> PathBuf {
    temp_path(destination, PARTIAL_SUFFIX)
}

/// Maps a SQLite error from the copy to an operator-actionable Zallet error.
///
/// A wallet that was not shut down cleanly leaves recovery state (a hot rollback
/// journal, or a WAL needing recovery) that this command's read-only connection is
/// not permitted to apply; SQLite reports that with a specific extended code, and
/// the fix (run the wallet once so it recovers the database) is not apparent
/// from SQLite's own message. Everything else passes through unchanged.
fn map_copy_error(e: rusqlite::Error) -> Error {
    match &e {
        rusqlite::Error::SqliteFailure(cause, _)
            if cause.extended_code == ffi::SQLITE_READONLY_ROLLBACK
                || cause.extended_code == ffi::SQLITE_READONLY_RECOVERY =>
        {
            ErrorKind::Generic
                .context(fl!("err-backup-needs-recovery"))
                .into()
        }
        _ => ErrorKind::Generic.context(e).into(),
    }
}

/// Runs the Online Backup API copy and verifies the result, returning pages copied.
fn copy_into(source: &Path, tmp: &Path, limits: &CopyLimits) -> Result<u64, Error> {
    let src = Connection::open_with_flags(
        source,
        // Read-only, and never create: this must observe the wallet database
        // without initializing or migrating anything, unlike `Database::open`.
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(map_copy_error)?;
    let mut dst = Connection::open(tmp).map_err(|e| ErrorKind::Generic.context(e))?;

    // The final backup step commits the destination while the source read lock
    // is still held, and under the default `synchronous=FULL` that commit
    // fsyncs the whole backup file inside the wallet's write stall. Durability
    // comes from the explicit `sync_all` before publication, so SQLite-level
    // syncing here is pure stall. `journal_mode=OFF` likewise avoids leaving a
    // `.partial-journal` sidecar behind when a run is interrupted.
    dst.pragma_update(None, "synchronous", "OFF")
        .map_err(|e| ErrorKind::Generic.context(e))?;
    dst.pragma_update(None, "journal_mode", "OFF")
        .map_err(|e| ErrorKind::Generic.context(e))?;

    // Busy waits are governed by this loop's own pause/retry policy, bounded by
    // `max_busy_wait`. Disable the built-in busy handler (`rusqlite` installs a
    // 5-second one on every connection) so the two policies do not stack, which
    // would otherwise make each busy step block inside SQLite before reporting.
    for conn in [&src, &dst] {
        conn.busy_timeout(Duration::ZERO)
            .map_err(|e| ErrorKind::Generic.context(e))?;
    }

    let pages = {
        let backup = Backup::new(&src, &mut dst).map_err(map_copy_error)?;

        let start = Instant::now();
        let mut busy_since: Option<Instant> = None;
        loop {
            match backup.step(limits.pages_per_step) {
                Ok(StepResult::Done) => break,
                // Progress clears any busy streak; a copy that keeps being
                // restarted by wallet writes is bounded by the overall deadline
                // below instead.
                Ok(StepResult::More) => busy_since = None,
                // `Busy` and `Locked` are transient. `StepResult` is also
                // non-exhaustive; treat anything unrecognized like a busy state
                // so it is bounded by the same limit rather than looping or
                // aborting on a library addition.
                Ok(_) => {
                    let since = *busy_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= limits.max_busy_wait {
                        return Err(ErrorKind::Generic
                            .context(fl!(
                                "err-backup-source-busy",
                                seconds = limits.max_busy_wait.as_secs().to_string(),
                            ))
                            .into());
                    }
                    thread::sleep(limits.busy_retry_pause);
                }
                Err(e) => return Err(map_copy_error(e)),
            }

            // Completion always wins: the deadline bounds non-completion, so it is
            // only checked when another step is still needed.
            if start.elapsed() >= limits.max_backup_duration {
                return Err(ErrorKind::Generic
                    .context(fl!(
                        "err-backup-not-completing",
                        seconds = limits.max_backup_duration.as_secs().to_string(),
                    ))
                    .into());
            }
        }

        let progress = backup.progress();
        u64::try_from(progress.pagecount).expect("SQLite page counts are non-negative")
    };

    // A backup that cannot pass an integrity check is not a backup. `quick_check`
    // catches malformed pages and index corruption without `integrity_check`'s
    // full-table scans.
    let ok: String = dst
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|e| ErrorKind::Generic.context(e))?;
    if ok != "ok" {
        return Err(ErrorKind::Generic
            .context(fl!("err-backup-integrity", detail = ok))
            .into());
    }

    Ok(pages)
}

fn destination_exists_error(destination: &Path) -> Error {
    ErrorKind::Generic
        .context(fl!(
            "err-backup-destination-exists",
            path = destination.display().to_string(),
        ))
        .into()
}

/// A failure after the backup is already visible at `destination` must not
/// read as "no backup was created".
fn published_backup_error(destination: &Path, e: std::io::Error) -> Error {
    ErrorKind::Generic
        .context(fl!(
            "err-backup-post-publication",
            path = destination.display().to_string(),
            error = e.to_string(),
        ))
        .into()
}

impl Runnable for BackupCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_db(path: &Path) -> Connection {
        let conn = Connection::open(path).expect("source db opens");
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, data BLOB NOT NULL);
             INSERT INTO t (data) VALUES (randomblob(4096));
             INSERT INTO t (data) VALUES (randomblob(4096));",
        )
        .expect("schema and rows apply");
        conn
    }

    #[test]
    fn backup_copies_identical_content_and_passes_quick_check() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("wallet.db");
        let dest = dir.path().join("backup.db");

        let conn = seeded_db(&source);

        let pages = copy_database(&source, &dest, &CopyLimits::default()).expect("backup succeeds");
        assert!(pages > 0, "a non-empty database copies at least one page");
        assert!(dest.exists(), "the backup file is renamed into place");
        assert!(
            !tmp_path(&dest).exists(),
            "the temporary file does not outlive the backup",
        );

        let copy = Connection::open_with_flags(&dest, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("backup opens");
        let (rows, bytes): (u64, u64) = copy
            .query_row("SELECT COUNT(*), SUM(LENGTH(data)) FROM t", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("backup is queryable");
        assert_eq!(rows, 2);
        assert_eq!(bytes, 8192);

        drop(conn);
    }

    #[test]
    fn backup_completes_while_the_source_is_being_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("wallet.db");
        let dest = dir.path().join("backup.db");

        // The writer opens its own connection, as a running wallet would.
        drop(seeded_db(&source));

        // Enough commits, spread out enough, that some land between copy steps
        // and restart the copy; finite, so the backup always eventually wins.
        const WRITER_COMMITS: u64 = 20;
        const WRITER_PAUSE: Duration = Duration::from_millis(5);
        let writer = {
            let source = source.clone();
            thread::spawn(move || {
                let conn = Connection::open(&source).expect("writer opens");
                for _ in 0..WRITER_COMMITS {
                    conn.execute("INSERT INTO t (data) VALUES (randomblob(1024))", [])
                        .expect("concurrent write applies");
                    thread::sleep(WRITER_PAUSE);
                }
            })
        };

        // Single-page steps maximize the windows in which the writer's commits
        // land, forcing the restart path; the failure bounds are left generous so
        // a slow CI machine cannot turn contention into a spurious failure.
        let limits = CopyLimits {
            pages_per_step: 1,
            busy_retry_pause: Duration::from_millis(5),
            max_busy_wait: Duration::from_secs(30),
            max_backup_duration: Duration::from_secs(60),
        };
        let pages =
            copy_database(&source, &dest, &limits).expect("backup succeeds against a live writer");
        writer.join().expect("writer thread finishes");

        assert!(pages > 0, "a non-empty database copies at least one page");
        // `copy_database` publishes only after `PRAGMA quick_check`, so success
        // means the snapshot was internally consistent despite the writer; the
        // row count must be a transaction boundary the source actually passed
        // through: the two seeded rows plus some prefix of the writer's commits.
        let copy = Connection::open_with_flags(&dest, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("backup opens");
        let rows: u64 = copy
            .query_row("SELECT COUNT(*) FROM t", [], |row| row.get(0))
            .expect("backup is queryable");
        assert!(
            (2..=2 + WRITER_COMMITS).contains(&rows),
            "snapshot must hold the seeded rows plus a prefix of the writer's commits, got {rows}",
        );
    }

    /// A fixed timestamp for tests of the generated backup file name.
    fn test_timestamp() -> time::OffsetDateTime {
        time::Date::from_calendar_date(2026, time::Month::January, 2)
            .expect("valid date")
            .with_hms(3, 4, 5)
            .expect("valid time")
            .assume_utc()
    }

    #[test]
    fn backup_fails_loudly_when_the_source_stays_locked() {
        crate::i18n::load_languages(&[]);

        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("wallet.db");
        let dest = dir.path().join("backup.db");

        let _conn = seeded_db(&source);

        // An exclusive transaction held for the whole attempt stands in for an
        // abandoned transaction or a stray process sitting on the database.
        let holder = Connection::open(&source).expect("lock holder opens");
        holder
            .execute_batch("BEGIN EXCLUSIVE")
            .expect("takes the write lock");

        // Tiny bounds so the test exercises the busy limit without waiting out
        // the production values.
        let limits = CopyLimits {
            pages_per_step: 1,
            busy_retry_pause: Duration::from_millis(5),
            max_busy_wait: Duration::from_millis(50),
            max_backup_duration: Duration::from_secs(10),
        };
        let err = copy_database(&source, &dest, &limits)
            .expect_err("a continuously locked source must fail loudly");
        assert!(
            err.to_string().contains("locked"),
            "unexpected error: {err}",
        );
        assert!(!dest.exists(), "no backup file appears on failure");
        assert!(
            !tmp_path(&dest).exists(),
            "no partial file is left behind on failure",
        );
    }

    #[test]
    fn backup_fails_loudly_when_it_cannot_finish_in_time() {
        crate::i18n::load_languages(&[]);

        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("wallet.db");
        let dest = dir.path().join("backup.db");

        let _conn = seeded_db(&source);

        // A zero deadline with single-page steps fails the copy at the first
        // incomplete step, standing in for a copy endlessly restarted by wallet
        // writes.
        let limits = CopyLimits {
            pages_per_step: 1,
            busy_retry_pause: Duration::from_millis(5),
            max_busy_wait: Duration::from_secs(10),
            max_backup_duration: Duration::ZERO,
        };
        let err = copy_database(&source, &dest, &limits)
            .expect_err("an expired deadline must fail loudly");
        assert!(
            err.to_string().contains("did not complete"),
            "unexpected error: {err}",
        );
        assert!(!dest.exists(), "no backup file appears on failure");
        assert!(
            !tmp_path(&dest).exists(),
            "no partial file is left behind on failure",
        );
    }

    #[test]
    fn recovery_pending_errors_get_an_actionable_message() {
        crate::i18n::load_languages(&[]);

        // Both extended codes SQLite uses for "this database needs recovery that
        // a read-only connection cannot perform" must map to the message telling
        // the operator to run the wallet once.
        for code in [ffi::SQLITE_READONLY_ROLLBACK, ffi::SQLITE_READONLY_RECOVERY] {
            let mapped =
                map_copy_error(rusqlite::Error::SqliteFailure(ffi::Error::new(code), None));
            assert!(
                mapped.to_string().contains("recover"),
                "extended code {code} must map to the recovery hint, got: {mapped}",
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn backup_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("wallet.db");
        let dest = dir.path().join("backup.db");

        let _conn = seeded_db(&source);
        copy_database(&source, &dest, &CopyLimits::default()).expect("backup succeeds");

        let mode = fs::metadata(&dest).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "backup must be private to the owner");
    }

    #[test]
    fn directory_destination_gets_a_timestamped_file_name() {
        let dir = tempfile::tempdir().expect("tempdir");

        let resolved = resolve_destination(dir.path(), test_timestamp()).expect("resolves");
        assert_eq!(
            resolved,
            dir.path().join("zallet-wallet-backup-20260102-030405.db"),
        );
    }

    #[test]
    fn existing_destination_file_is_refused() {
        crate::i18n::load_languages(&[]);

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("backup.db");
        fs::write(&dest, b"previous good backup").expect("existing file");

        assert!(
            resolve_destination(&dest, test_timestamp()).is_err(),
            "an existing backup must never be overwritten",
        );
        assert_eq!(
            fs::read(&dest).expect("still readable"),
            b"previous good backup",
        );
    }

    #[test]
    fn same_second_directory_backups_get_retry_advice() {
        crate::i18n::load_languages(&[]);

        let dir = tempfile::tempdir().expect("tempdir");
        let now = test_timestamp();

        let first = resolve_destination(dir.path(), now).expect("resolves");
        fs::write(&first, b"backup from the same second").expect("existing file");

        let err = resolve_destination(dir.path(), now)
            .expect_err("a same-second name collision must be refused");
        assert!(
            err.to_string().contains("Retry"),
            "a time-derived collision must advise retrying, not a different path: {err}",
        );
    }

    #[test]
    fn stale_partial_file_gets_an_actionable_error() {
        crate::i18n::load_languages(&[]);

        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("wallet.db");
        let dest = dir.path().join("backup.db");

        let _conn = seeded_db(&source);

        // Stands in for the in-progress file of a backup that was killed
        // uncleanly (or of one still running to the same destination).
        let stale = tmp_path(&dest);
        fs::write(&stale, b"interrupted backup").expect("stale partial file");

        let err = copy_database(&source, &dest, &CopyLimits::default())
            .expect_err("a leftover in-progress file must be refused");
        assert!(
            err.to_string().contains(&stale.display().to_string()),
            "the error must name the file in the way: {err}",
        );
        assert!(!dest.exists(), "no backup file appears");
        assert_eq!(
            fs::read(&stale).expect("still readable"),
            b"interrupted backup",
            "the file in the way is left for the operator to inspect",
        );
    }

    #[test]
    fn file_appearing_at_destination_during_the_copy_is_not_overwritten() {
        crate::i18n::load_languages(&[]);

        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("wallet.db");
        let dest = dir.path().join("backup.db");

        let _conn = seeded_db(&source);

        // `copy_database` never sees `resolve_destination`'s check, so a file
        // already present here models one that appeared while the copy ran.
        fs::write(&dest, b"appeared mid-copy").expect("existing file");

        let err = copy_database(&source, &dest, &CopyLimits::default())
            .expect_err("an existing destination must be refused at rename time");
        assert!(
            err.to_string().contains("refusing to overwrite"),
            "unexpected error: {err}",
        );
        assert_eq!(
            fs::read(&dest).expect("still readable"),
            b"appeared mid-copy",
            "the existing file must survive untouched",
        );
        assert!(
            !tmp_path(&dest).exists(),
            "the temporary file is cleaned up when the rename is refused",
        );
    }

    #[test]
    fn failed_backup_leaves_no_partial_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("missing.db");
        let dest = dir.path().join("backup.db");

        assert!(copy_database(&source, &dest, &CopyLimits::default()).is_err());
        assert!(!dest.exists());
        assert!(!tmp_path(&dest).exists());
    }
}
