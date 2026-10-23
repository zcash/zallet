//! Shared file-system primitives.
//!
//! `zallet-core` writes several files whose contents must never be observable by
//! other users (the RPC cookie, encryption identities, wallet database backups)
//! and must never appear truncated or torn at their final path. This module owns
//! the primitives those call sites share: creating a file that is owner-only
//! from the moment it exists, and writing content through a temporary file that
//! is then published at its destination. See zcash/zallet#910 for the inventory
//! of call sites.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rand::{Rng, rngs::OsRng};

/// Creates a new file that is readable and writable only by the user the Zallet
/// process runs as.
///
/// The restrictive access policy is applied atomically at creation time, so there is
/// no window during which the file is observable by other users with access to the
/// parent directory. On Unix the mode is then forced to exactly `0600` through the
/// handle, so the process umask can neither widen nor narrow it.
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        // `open` masks the mode with the umask; this `fchmod` is not masked, so
        // the file ends up owner read-write regardless of the environment.
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(f)
    }

    #[cfg(windows)]
    {
        create_owner_only_file_windows(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        // No supported access-control API; fall back to the permissions inherited
        // from the parent directory.
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    }
}

/// SDDL form of the access policy for [`create_private_file`]: a protected DACL
/// granting full access to the file's owner and nothing to anyone else.
///
/// - `D:` introduces the DACL.
/// - `P` marks the DACL as protected, so ACEs inherited from the parent directory
///   cannot broaden it (on creation or after a rename).
/// - `(A;;FA;;;OW)` is a single ACE allowing (`A`) full access (`FA`) to the
///   `OWNER RIGHTS` principal (`OW`), i.e. the file's owner. The file is created and
///   therefore owned by the user the Zallet process runs as, so that user retains
///   full access while no ACE grants any other user anything.
#[cfg(windows)]
pub(crate) const OWNER_ONLY_SDDL: &str = "D:P(A;;FA;;;OW)";

/// Creates a new file protected by [`OWNER_ONLY_SDDL`].
///
/// [`fs::OpenOptions`] provides no way to pass a security descriptor to `CreateFileW`,
/// and applying an ACL after creation would leave a window during which the file has
/// the (potentially permissive) ACL inherited from the parent directory, so this calls
/// `CreateFileW` directly. The `windows` crate's bindings return `Result`s and typed
/// handles, but the two Win32 calls remain `unsafe fn`s because they take raw
/// pointers; each call site carries its safety argument.
#[cfg(windows)]
#[allow(unsafe_code)]
fn create_owner_only_file_windows(path: &Path) -> io::Result<File> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    use windows::Win32::Foundation::{GENERIC_WRITE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
    };
    use windows::core::HSTRING;

    /// Owns the security descriptor allocated by
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW`, freeing it on every
    /// return path.
    struct SecurityDescriptorGuard(PSECURITY_DESCRIPTOR);

    impl Drop for SecurityDescriptorGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: the descriptor was allocated on the local heap by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, and this guard
            // is its sole owner, so it is freed exactly once.
            unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
        }
    }

    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the `HSTRING` is a NUL-terminated UTF-16 string that outlives the
    // call, and `descriptor` is a valid out-pointer.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(OWNER_ONLY_SDDL),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }?;
    let descriptor = SecurityDescriptorGuard(descriptor);

    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.0,
        bInheritHandle: false.into(),
    };

    // SAFETY: the `HSTRING` path is a NUL-terminated UTF-16 string, and
    // `security_attributes` and the descriptor it points to (kept alive by the
    // guard) outlive the call.
    let handle = unsafe {
        CreateFileW(
            &HSTRING::from(path.as_os_str()),
            GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            Some(&security_attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }?;

    // SAFETY: `CreateFileW` returned successfully, so `handle` is a fresh, valid
    // file handle owned by this call and by nothing else.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    Ok(File::from(handle))
}

/// How a private file is written and published. Each variant is a complete,
/// coherent profile; incoherent combinations of temp naming, overwrite policy,
/// and durability are not representable.
pub(crate) enum Publish {
    /// For per-process files such as the RPC cookie: the temporary is
    /// `<destination's file name><suffix>` and a stale one left by a crashed
    /// process is silently replaced, an existing destination is replaced, and
    /// nothing is synced.
    Replacing {
        /// Suffix appended to the destination's file name to form the temporary's.
        temp_suffix: &'static str,
    },
    /// For regenerable files that must never replace an existing destination:
    /// the temporary is `<destination's file name><suffix>` and an existing one
    /// is refused, so the name doubles as mutual exclusion between concurrent
    /// writers (the caller owns telling the operator about a stale one).
    /// Publication is an atomic create-new hard link; filesystems without
    /// hard-link support fall back to a checked rename, which narrows the
    /// overwrite race without closing it. The result is made durable.
    NoClobber {
        /// Suffix appended to the destination's file name to form the temporary's.
        temp_suffix: &'static str,
    },
    /// For irreplaceable content such as key material: like [`Publish::NoClobber`]
    /// but with a random temporary name, and publication fails closed rather
    /// than falling back where the filesystem cannot provide an atomic
    /// create-new hard link, so an existing destination can never be replaced,
    /// even by the narrowed race. The result is made durable.
    NoClobberStrict,
}

impl Publish {
    fn durable(&self) -> bool {
        match self {
            Publish::Replacing { .. } => false,
            Publish::NoClobber { .. } | Publish::NoClobberStrict => true,
        }
    }
}

/// Why publishing failed, by phase; each phase leaves the filesystem in the
/// documented state.
#[derive(Debug)]
pub(crate) enum PublishError<E> {
    /// The temporary file could not be created; nothing was changed. With
    /// [`Publish::NoClobber`], [`io::ErrorKind::AlreadyExists`] means another
    /// writer is active or a crashed one left its temporary behind.
    Create(io::Error),
    /// Writing the content failed; the temporary file was removed.
    Fill(E),
    /// A file exists at the destination (the no-clobber modes only); the
    /// temporary file was removed and the destination is untouched.
    DestinationExists,
    /// Syncing or publishing the temporary file failed; it was removed and the
    /// destination is untouched.
    Publish(io::Error),
    /// The published file is complete and visible at the destination, but a step
    /// after publication (retiring the temporary's name, or syncing the parent
    /// directory) failed.
    PostPublish(io::Error),
}

/// The deterministic temporary path for `destination`: its file name with
/// `suffix` appended, in the same directory.
pub(crate) fn temp_path(destination: &Path, suffix: &str) -> PathBuf {
    let mut name = destination
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(suffix);
    destination.with_file_name(name)
}

/// Removes the temporary file on drop unless disarmed, so every failure path
/// (including a panic while writing) leaves nothing behind.
struct TempGuard<'p> {
    path: &'p Path,
    armed: bool,
}

impl Drop for TempGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(self.path);
        }
    }
}

/// Writes `body` to an owner-only file published at `destination`.
///
/// The content is written and (for durable modes) synced through the handle the
/// temporary was created with, so no step reopens the file by path and nothing
/// can be swapped in between creation and the writes.
pub(crate) fn write_private_file(
    destination: &Path,
    mode: Publish,
    body: &[u8],
) -> Result<(), PublishError<io::Error>> {
    let tmp = prepare_temp_path(destination, &mode).map_err(PublishError::Create)?;
    let mut file = create_private_file(&tmp).map_err(PublishError::Create)?;
    let mut guard = TempGuard {
        path: &tmp,
        armed: true,
    };

    file.write_all(body).map_err(PublishError::Fill)?;
    if mode.durable() {
        // Publication is only meaningful if the contents reach disk first.
        file.sync_all().map_err(PublishError::Publish)?;
    }
    drop(file);

    publish_temp(&tmp, destination, &mode, &mut guard)
}

/// Writes a file via `fill`, owner-only from the moment it exists, and publishes
/// it at `destination` only once `fill` has succeeded, so the destination never
/// observes a partial file.
///
/// This variant exists for content producers that must open the file by path
/// themselves (such as SQLite); the creation handle is closed before `fill`
/// runs, because the Windows creation path opens with no sharing and would
/// otherwise lock `fill` out of its own file. Callers whose content is a byte
/// buffer should use [`write_private_file`], which keeps every write on the
/// creation handle.
pub(crate) fn publish_private_file<T, E>(
    destination: &Path,
    mode: Publish,
    fill: impl FnOnce(&Path) -> Result<T, E>,
) -> Result<T, PublishError<E>> {
    let tmp = prepare_temp_path(destination, &mode).map_err(PublishError::Create)?;
    create_private_file(&tmp)
        .map(drop)
        .map_err(PublishError::Create)?;
    let mut guard = TempGuard {
        path: &tmp,
        armed: true,
    };

    let value = fill(&tmp).map_err(PublishError::Fill)?;

    if mode.durable() {
        // Publication is only meaningful if the contents reach disk first. The
        // handle must be writable: on Windows, flushing requires write access.
        fs::OpenOptions::new()
            .write(true)
            .open(&tmp)
            .and_then(|f| f.sync_all())
            .map_err(PublishError::Publish)?;
    }

    publish_temp(&tmp, destination, &mode, &mut guard)?;
    Ok(value)
}

/// Resolves the temporary path for `mode`, clearing a stale one where the mode
/// allows it.
fn prepare_temp_path(destination: &Path, mode: &Publish) -> io::Result<PathBuf> {
    match mode {
        Publish::Replacing { temp_suffix } => {
            let path = temp_path(destination, temp_suffix);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            Ok(path)
        }
        Publish::NoClobber { temp_suffix } => Ok(temp_path(destination, temp_suffix)),
        Publish::NoClobberStrict => {
            let token: u64 = OsRng.r#gen();
            Ok(temp_path(destination, &format!(".{token:016x}.tmp")))
        }
    }
}

/// Publishes the filled temporary at `destination` per `mode`, then (for
/// durable modes, on Unix) syncs the parent directory so the publication
/// survives a crash. On other platforms the durability of the new directory
/// entry is left to the operating system.
fn publish_temp<E>(
    tmp: &Path,
    destination: &Path,
    mode: &Publish,
    guard: &mut TempGuard<'_>,
) -> Result<(), PublishError<E>> {
    match mode {
        Publish::Replacing { .. } => {
            fs::rename(tmp, destination).map_err(PublishError::Publish)?;
            guard.armed = false;
        }
        Publish::NoClobber { .. } | Publish::NoClobberStrict => {
            // A hard link publishes atomically and fails if the destination
            // exists, where `rename` would silently replace a file that
            // appeared after the caller's checks.
            match fs::hard_link(tmp, destination) {
                Ok(()) => {
                    guard.armed = false;
                    // The published file briefly has two names; retire the
                    // temporary one.
                    if let Err(e) = fs::remove_file(tmp) {
                        return Err(PublishError::PostPublish(e));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(PublishError::DestinationExists);
                }
                Err(e) if matches!(mode, Publish::NoClobberStrict) => {
                    // Fail closed: without an atomic create-new operation the
                    // never-replace promise cannot be kept, and the content is
                    // too valuable to publish through a racy fallback.
                    return Err(PublishError::Publish(e));
                }
                Err(_) => {
                    // Filesystems without hard-link support get a checked
                    // rename; a genuine failure resurfaces from the rename.
                    if destination.exists() {
                        return Err(PublishError::DestinationExists);
                    }
                    fs::rename(tmp, destination).map_err(PublishError::Publish)?;
                    guard.armed = false;
                }
            }
        }
    }

    if mode.durable() {
        #[cfg(unix)]
        if let Some(parent) = destination.parent() {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            if let Err(e) = File::open(parent).and_then(|d| d.sync_all()) {
                return Err(PublishError::PostPublish(e));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_file_is_owner_only_at_creation() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("private");
        create_private_file(&path).expect("creates");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn private_file_refuses_an_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("private");
        fs::write(&path, b"existing").expect("existing file");
        let err = create_private_file(&path).expect_err("must refuse");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn no_clobber_writes_content_and_removes_the_temporary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out");

        publish_private_file(
            &dest,
            Publish::NoClobber {
                temp_suffix: ".partial",
            },
            |tmp| fs::write(tmp, b"content"),
        )
        .expect("publishes");

        assert_eq!(fs::read(&dest).expect("readable"), b"content");
        assert_eq!(
            fs::read_dir(dir.path()).expect("dir").count(),
            1,
            "no temporary outlives publication",
        );
    }

    #[test]
    fn no_clobber_refuses_a_stale_temporary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out");
        fs::write(temp_path(&dest, ".partial"), b"stale").expect("stale temp");

        let err = write_private_file(
            &dest,
            Publish::NoClobber {
                temp_suffix: ".partial",
            },
            b"content",
        )
        .expect_err("must refuse");

        assert!(matches!(
            err,
            PublishError::Create(e) if e.kind() == io::ErrorKind::AlreadyExists,
        ));
        assert_eq!(
            fs::read(temp_path(&dest, ".partial")).expect("still readable"),
            b"stale",
            "the stale temporary is left for the operator to inspect",
        );
        assert!(!dest.exists());
    }

    #[test]
    fn replacing_replaces_a_stale_temporary_and_the_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out");
        fs::write(temp_path(&dest, ".tmp"), b"stale").expect("stale temp");
        fs::write(&dest, b"old").expect("existing destination");

        write_private_file(
            &dest,
            Publish::Replacing {
                temp_suffix: ".tmp",
            },
            b"new",
        )
        .expect("publishes");

        assert_eq!(fs::read(&dest).expect("readable"), b"new");
        assert!(!temp_path(&dest, ".tmp").exists());
    }

    #[test]
    fn strict_refuses_an_existing_destination_and_cleans_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out");
        fs::write(&dest, b"existing").expect("existing destination");

        let err = write_private_file(&dest, Publish::NoClobberStrict, b"content")
            .expect_err("must refuse");

        assert!(matches!(err, PublishError::DestinationExists));
        assert_eq!(fs::read(&dest).expect("still readable"), b"existing");
        assert_eq!(
            fs::read_dir(dir.path()).expect("dir").count(),
            1,
            "the temporary is removed on refusal",
        );
    }

    #[test]
    fn strict_publishes_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out");

        write_private_file(&dest, Publish::NoClobberStrict, b"content").expect("publishes");

        assert_eq!(fs::read(&dest).expect("readable"), b"content");
        assert_eq!(fs::read_dir(dir.path()).expect("dir").count(), 1);
    }

    #[test]
    fn fill_failure_removes_the_temporary_and_leaves_no_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out");

        let err = publish_private_file(
            &dest,
            Publish::NoClobber {
                temp_suffix: ".partial",
            },
            |_tmp| Err::<(), _>("fill failed"),
        )
        .expect_err("fill failure propagates");

        assert!(matches!(err, PublishError::Fill("fill failed")));
        assert!(!dest.exists());
        assert_eq!(
            fs::read_dir(dir.path()).expect("dir").count(),
            0,
            "nothing is left behind",
        );
    }

    #[test]
    fn a_panic_while_filling_removes_the_temporary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("out");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            publish_private_file(
                &dest,
                Publish::NoClobber {
                    temp_suffix: ".partial",
                },
                |_tmp| -> Result<(), io::Error> { panic!("fill panicked") },
            )
        }));

        assert!(result.is_err(), "the panic propagates");
        assert!(!dest.exists());
        assert_eq!(
            fs::read_dir(dir.path()).expect("dir").count(),
            0,
            "the temporary does not survive an unwind",
        );
    }
}
