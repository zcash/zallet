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

use rand::{RngExt, rand_core::UnwrapErr, rngs::SysRng};

/// Creates a new file that is readable and writable only by the user the Zallet
/// process runs as.
///
/// The restrictive access policy is applied atomically at creation time, so there is
/// no window during which the file is observable by other users with access to the
/// parent directory. On Unix the mode ends up exactly `0600`: the umask can only
/// narrow the requested mode, and the rare pathological umask that strips owner
/// bits is repaired through the handle. A failure after creation removes the
/// file, so no path is ever left occupied by a half-initialized temporary.
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        // `open` masks the mode with the umask, which can only remove bits, so
        // the `fchmod` repair (not itself masked) is needed only under a umask
        // that strips owner bits. Filesystems that refuse `fchmod` therefore
        // work under every sane umask.
        let repaired = f.metadata().and_then(|m| {
            if m.permissions().mode() & 0o777 == 0o600 {
                Ok(())
            } else {
                f.set_permissions(fs::Permissions::from_mode(0o600))
            }
        });
        if let Err(e) = repaired {
            drop(f);
            // Created with `create_new` above, so the name is ours to remove.
            let _ = fs::remove_file(path);
            return Err(e);
        }
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
    }
    .map_err(win32_io_error)?;
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
    }
    .map_err(win32_io_error)?;

    // SAFETY: `CreateFileW` returned successfully, so `handle` is a fresh, valid
    // file handle owned by this call and by nothing else.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle.0) };
    Ok(File::from(handle))
}

/// Converts a `windows` crate error into an [`io::Error`] that preserves the
/// Win32 error code, so callers can match on [`io::ErrorKind`] (for example
/// `ERROR_FILE_EXISTS` categorizing as `AlreadyExists`).
///
/// The `windows` crate surfaces Win32 failures as HRESULTs, whose direct
/// [`io::Error`] conversion has an uncategorized kind; the original code is in
/// the low 16 bits.
#[cfg(windows)]
fn win32_io_error(e: windows::core::Error) -> io::Error {
    /// The high 16 bits of every Win32-facility failure HRESULT: severity set,
    /// facility `FACILITY_WIN32` (7).
    const WIN32_FACILITY_PREFIX: u32 = 0x8007;

    let hresult = e.code().0 as u32;
    if (hresult >> 16) == WIN32_FACILITY_PREFIX {
        io::Error::from_raw_os_error((hresult & 0xFFFF) as i32)
    } else {
        io::Error::other(e)
    }
}

/// Renames `from` to `to`, refusing to replace an existing destination.
///
/// `std::fs::rename` on Windows passes `MOVEFILE_REPLACE_EXISTING`; this calls
/// `MoveFileExW` without it, which is an atomic no-replace rename on every
/// Windows filesystem, including those without hard-link support. The
/// write-through flag makes the rename durable before the call returns, since
/// Windows has no parent-directory `fsync` to run afterwards.
#[cfg(windows)]
#[allow(unsafe_code)]
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    use windows::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};
    use windows::core::HSTRING;

    // SAFETY: both `HSTRING`s are NUL-terminated UTF-16 strings that outlive
    // the call.
    unsafe {
        MoveFileExW(
            &HSTRING::from(from.as_os_str()),
            &HSTRING::from(to.as_os_str()),
            MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(win32_io_error)
}

/// Renames `from` to `to`, atomically refusing to replace an existing
/// destination, where the kernel and filesystem support it.
///
/// This is the primary no-clobber publication on these platforms, the same
/// mechanism `tempfile`'s `persist_noclobber` uses: `RENAME_NOREPLACE` is
/// implemented by mainstream filesystems including Linux's vfat and exfat
/// drivers, so it needs no hard-link support. Callers fall back to the
/// hard-link path when this reports `Unsupported` or `InvalidInput` (an old
/// kernel, or a filesystem without the flag).
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    use rustix::fs::{CWD, RenameFlags, renameat_with};
    renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(io::Error::from)
}

/// How a private file is written and published. Each variant is a complete,
/// coherent profile; incoherent combinations of temp naming, overwrite policy,
/// and durability are not representable.
pub(crate) enum Publish {
    /// For per-process files such as the RPC cookie: the temporary is
    /// `<destination's file name><suffix>` and a stale one left by a crashed
    /// process is silently replaced, an existing destination is replaced, and
    /// nothing is synced. Writers in this mode must already be serialized by
    /// something else (the cookie writer runs under the datadir lock); two
    /// concurrent writers could delete each other's temporary and publish a
    /// torn file.
    Replacing {
        /// Suffix appended to the destination's file name to form the temporary's.
        temp_suffix: &'static str,
    },
    /// For regenerable files that must never replace an existing destination:
    /// the temporary is `<destination's file name><suffix>` and an existing one
    /// is refused, so the name doubles as mutual exclusion between concurrent
    /// writers (the caller owns telling the operator about a stale one).
    /// Publication is an atomic no-replace rename (`MoveFileExW` on Windows,
    /// `RENAME_NOREPLACE` on Linux, Android, and Apple platforms), falling back
    /// where the kernel or filesystem lacks it to a create-new hard link, and
    /// then to a checked rename, which narrows the overwrite race without
    /// closing it. The result is made durable.
    NoClobber {
        /// Suffix appended to the destination's file name to form the temporary's.
        temp_suffix: &'static str,
    },
    /// For irreplaceable content such as key material: like [`Publish::NoClobber`]
    /// but with a random temporary name, and no racy final fallback: where
    /// neither an atomic no-replace rename nor a create-new hard link is
    /// available, publication fails closed rather than racing. The result is
    /// made durable.
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
    /// The temporary file at `temp` could not be created; nothing was changed.
    /// With [`Publish::NoClobber`], [`io::ErrorKind::AlreadyExists`] means
    /// another writer is active or a crashed one left its temporary behind.
    Create {
        /// The temporary path that could not be created.
        temp: PathBuf,
        /// The underlying failure.
        source: io::Error,
    },
    /// Writing the content failed; the temporary file was removed.
    Fill(E),
    /// A file exists at the destination (the no-clobber modes only); the
    /// temporary file was removed and the destination is untouched.
    DestinationExists,
    /// Syncing or publishing the temporary file failed; it was removed and the
    /// destination is untouched.
    Publish(io::Error),
    /// The published file is complete and visible at the destination, but a
    /// step after publication failed: syncing the parent directory
    /// (`leftover_temp` is `None`), or retiring the temporary's second name
    /// after a hard-link publication (`leftover_temp` names the file left
    /// behind, whose content equals the published one). Both steps exist only
    /// off Windows, whose publish path is a single write-through rename;
    /// callers still match this variant so their handling stays
    /// platform-independent.
    #[cfg_attr(
        windows,
        expect(dead_code, reason = "no post-publication step on Windows")
    )]
    PostPublish {
        /// The temporary that could not be retired, if it still exists.
        leftover_temp: Option<PathBuf>,
        /// The underlying failure.
        source: io::Error,
    },
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
    let tmp = prepare_temp_path(destination, &mode).map_err(into_create_error)?;
    // Declared before `file` so an unwind or early return drops the handle
    // first: Windows cannot delete a file whose no-share handle is still open.
    let mut guard = TempGuard {
        path: &tmp,
        armed: false,
    };
    let mut file = create_private_file(&tmp).map_err(|source| PublishError::Create {
        temp: tmp.clone(),
        source,
    })?;
    guard.armed = true;

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
/// otherwise lock `fill` out of its own file. For the same reason, `fill` must
/// close every handle it opened on the path before returning: the sync and
/// publication steps fail on Windows while a handle is open. Callers whose
/// content is a byte buffer should use [`write_private_file`], which keeps
/// every write on the creation handle.
pub(crate) fn publish_private_file<T, E>(
    destination: &Path,
    mode: Publish,
    fill: impl FnOnce(&Path) -> Result<T, E>,
) -> Result<T, PublishError<E>> {
    let tmp = prepare_temp_path(destination, &mode).map_err(into_create_error)?;
    let mut guard = TempGuard {
        path: &tmp,
        armed: false,
    };
    create_private_file(&tmp)
        .map(drop)
        .map_err(|source| PublishError::Create {
            temp: tmp.clone(),
            source,
        })?;
    guard.armed = true;

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
/// allows it. Errors carry the path they are about so the caller can report it.
fn prepare_temp_path(destination: &Path, mode: &Publish) -> Result<PathBuf, (PathBuf, io::Error)> {
    // A destination without a file name (such as `sub/..`) would silently
    // derive a temporary named just `<suffix>` in the parent directory.
    if destination.file_name().is_none() {
        return Err((
            destination.to_path_buf(),
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "publish destination has no file name",
            ),
        ));
    }

    match mode {
        Publish::Replacing { temp_suffix } => {
            let path = temp_path(destination, temp_suffix);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err((path, e)),
            }
            Ok(path)
        }
        Publish::NoClobber { temp_suffix } => Ok(temp_path(destination, temp_suffix)),
        Publish::NoClobberStrict => {
            let token: u64 = UnwrapErr(SysRng).random();
            Ok(temp_path(destination, &format!(".{token:016x}.tmp")))
        }
    }
}

/// Adapts [`prepare_temp_path`]'s error into the public error type.
fn into_create_error<E>((temp, source): (PathBuf, io::Error)) -> PublishError<E> {
    PublishError::Create { temp, source }
}

/// Publishes the filled temporary at `destination` per `mode`, then (for
/// durable modes, on Unix) syncs the parent directory so the publication
/// survives a crash. On Windows the durable modes publish with a write-through
/// rename instead; on any other platform the durability of the new directory
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
            #[cfg(windows)]
            {
                // One atomic no-replace rename covers every Windows filesystem,
                // so neither mode needs a hard link or a fallback there.
                match rename_no_replace(tmp, destination) {
                    Ok(()) => guard.armed = false,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(PublishError::DestinationExists);
                    }
                    Err(e) => return Err(PublishError::Publish(e)),
                }
            }

            #[cfg(not(windows))]
            {
                if let NoReplaceRename::Unavailable =
                    try_rename_no_replace(tmp, destination, guard)?
                {
                    publish_via_hard_link(tmp, destination, mode, guard)?;
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
                return Err(PublishError::PostPublish {
                    leftover_temp: None,
                    source: e,
                });
            }
        }
    }

    Ok(())
}

/// Outcome of the primary Unix publication attempt.
#[cfg(not(windows))]
enum NoReplaceRename {
    /// The temporary was published atomically; nothing remains to retire.
    Published,
    /// The platform, kernel, or filesystem lacks the operation; the hard-link
    /// path should run instead.
    Unavailable,
}

/// Attempts the primary Unix publication, an atomic `RENAME_NOREPLACE` rename,
/// mirroring `tempfile`'s `persist_noclobber` fallback order.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn try_rename_no_replace<E>(
    tmp: &Path,
    destination: &Path,
    guard: &mut TempGuard<'_>,
) -> Result<NoReplaceRename, PublishError<E>> {
    match rename_no_replace(tmp, destination) {
        Ok(()) => {
            guard.armed = false;
            Ok(NoReplaceRename::Published)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(PublishError::DestinationExists),
        // An old kernel (ENOSYS) or a filesystem without the flag (EINVAL).
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::Unsupported | io::ErrorKind::InvalidInput
            ) =>
        {
            Ok(NoReplaceRename::Unavailable)
        }
        Err(e) => Err(PublishError::Publish(e)),
    }
}

/// Unix platforms without `RENAME_NOREPLACE` go straight to the hard-link path.
#[cfg(all(
    not(windows),
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn try_rename_no_replace<E>(
    _tmp: &Path,
    _destination: &Path,
    _guard: &mut TempGuard<'_>,
) -> Result<NoReplaceRename, PublishError<E>> {
    Ok(NoReplaceRename::Unavailable)
}

/// Publishes via an atomic create-new hard link, which fails if the destination
/// exists, where `rename` would silently replace a file that appeared after the
/// caller's checks.
#[cfg(not(windows))]
fn publish_via_hard_link<E>(
    tmp: &Path,
    destination: &Path,
    mode: &Publish,
    guard: &mut TempGuard<'_>,
) -> Result<(), PublishError<E>> {
    match fs::hard_link(tmp, destination) {
        Ok(()) => {
            guard.armed = false;
            // The published file briefly has two names; retire the temporary
            // one.
            if let Err(e) = fs::remove_file(tmp) {
                return Err(PublishError::PostPublish {
                    leftover_temp: Some(tmp.to_path_buf()),
                    source: e,
                });
            }
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(PublishError::DestinationExists);
        }
        Err(e) if matches!(mode, Publish::NoClobberStrict) => {
            // Fail closed: without an atomic no-replace operation the
            // never-replace promise cannot be kept, and the content is too
            // valuable for a racy fallback.
            return Err(PublishError::Publish(e));
        }
        Err(_) => {
            // Filesystems with neither rename-no-replace nor hard links get a
            // checked rename; a genuine failure resurfaces from the rename.
            match fs::symlink_metadata(destination) {
                Ok(_) => return Err(PublishError::DestinationExists),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(PublishError::Publish(e)),
            }
            fs::rename(tmp, destination).map_err(PublishError::Publish)?;
            guard.armed = false;
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
            PublishError::Create { ref temp, ref source }
                if source.kind() == io::ErrorKind::AlreadyExists
                    && *temp == temp_path(&dest, ".partial"),
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
    fn a_destination_appearing_while_filling_is_not_replaced() {
        for strict in [false, true] {
            let dir = tempfile::tempdir().expect("tempdir");
            let dest = dir.path().join("out");
            let racer = dest.clone();
            let mode = if strict {
                Publish::NoClobberStrict
            } else {
                Publish::NoClobber {
                    temp_suffix: ".partial",
                }
            };

            let err = publish_private_file(&dest, mode, move |tmp| {
                fs::write(tmp, b"new")?;
                // A file lands at the destination while the content is still
                // being produced, after any pre-copy checks a caller could run.
                fs::write(&racer, b"racer")
            })
            .expect_err("must refuse");

            assert!(matches!(err, PublishError::DestinationExists));
            assert_eq!(
                fs::read(&dest).expect("still readable"),
                b"racer",
                "strict={strict}: the racer file must survive untouched",
            );
            assert_eq!(
                fs::read_dir(dir.path()).expect("dir").count(),
                1,
                "strict={strict}: the temporary is removed on refusal",
            );
        }
    }

    #[test]
    fn a_destination_without_a_file_name_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("sub").join("..");

        let err = write_private_file(&dest, Publish::NoClobberStrict, b"content")
            .expect_err("must refuse");

        assert!(matches!(
            err,
            PublishError::Create { ref source, .. }
                if source.kind() == io::ErrorKind::InvalidInput,
        ));
        assert_eq!(
            fs::read_dir(dir.path()).expect("dir").count(),
            0,
            "nothing is created for an invalid destination",
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
