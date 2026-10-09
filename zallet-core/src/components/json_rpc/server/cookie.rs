use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use rand::{RngExt, rand_core::UnwrapErr, rngs::SysRng};
use tracing::{info, warn};

use super::authorization::PasswordHash;
use crate::error::{Error, ErrorKind};
use crate::fl;

/// Username for cookie-based auth, matching zcashd convention.
pub(crate) const COOKIE_USER: &str = "__cookie__";

/// Default cookie filename within the data directory.
const COOKIE_FILENAME: &str = ".cookie";

/// Guard that deletes the cookie file when dropped.
///
/// This ensures the cookie is cleaned up on normal shutdown or task cancellation.
pub(crate) struct CookieGuard {
    path: PathBuf,
}

impl Drop for CookieGuard {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_file(&self.path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                "Failed to remove cookie file {}: {}",
                self.path.display(),
                e
            );
        }
    }
}

pub(crate) fn cookie_path(datadir: &Path) -> PathBuf {
    datadir.join(COOKIE_FILENAME)
}

pub(crate) fn generate_cookie(
    datadir: &Path,
) -> Result<(String, PasswordHash, CookieGuard), Error> {
    let password: [u8; 32] = UnwrapErr(SysRng).random();
    let password = Base64::encode_string(&password);
    let cookie = format!("{COOKIE_USER}:{password}");

    let cookie_path = cookie_path(datadir);
    let tmp_path = datadir.join(format!("{COOKIE_FILENAME}.tmp"));

    // Clean up any leftover tmp file from a previous crash.
    let _ = fs::remove_file(&tmp_path);

    // Write to temp file with restricted permissions for atomic creation. The
    // restrictions are applied at creation time so there is no window during which
    // another user can open the file, and the atomic rename below preserves them.
    {
        use std::io::Write;
        let mut f = create_private_file(&tmp_path).map_err(|e| ErrorKind::Init.context(e))?;
        f.write_all(cookie.as_bytes()).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            ErrorKind::Init.context(e)
        })?;
    }

    // Atomic rename into place.
    if let Err(e) = fs::rename(&tmp_path, &cookie_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ErrorKind::Init.context(e).into());
    }

    info!(
        "{}",
        fl!(
            "rpc-cookie-generated",
            path = cookie_path.display().to_string()
        )
    );

    let password_hash = PasswordHash::from_bare(&password);
    let guard = CookieGuard { path: cookie_path };
    Ok((COOKIE_USER.to_string(), password_hash, guard))
}

/// Creates a new file that is readable and writable only by the user the Zallet
/// process runs as.
///
/// The restrictive access policy is applied atomically at creation time, so there is
/// no window during which the file is observable by other users with access to the
/// parent directory.
fn create_private_file(path: &Path) -> std::io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
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
const OWNER_ONLY_SDDL: &str = "D:P(A;;FA;;;OW)";

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
fn create_owner_only_file_windows(path: &Path) -> std::io::Result<fs::File> {
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
    Ok(fs::File::from(handle))
}

#[cfg(feature = "rpc-cli")]
pub(crate) fn read_cookie(datadir: &Path) -> Result<String, Error> {
    let path = cookie_path(datadir);
    let cookie = fs::read_to_string(&path)
        .map_err(|e| ErrorKind::Init.context(e))?
        .trim()
        .to_string();
    if !cookie.starts_with(&format!("{COOKIE_USER}:")) {
        return Err(ErrorKind::Init.context("Invalid cookie file format").into());
    }
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_creates_file() {
        let dir = TempDir::new().unwrap();
        let _guard = generate_cookie(dir.path()).unwrap();
        assert!(dir.path().join(COOKIE_FILENAME).exists());
    }

    #[test]
    fn generate_file_contents_valid() {
        let dir = TempDir::new().unwrap();
        let _guard = generate_cookie(dir.path()).unwrap();
        let contents = fs::read_to_string(dir.path().join(COOKIE_FILENAME)).unwrap();
        assert!(contents.starts_with(&format!("{COOKIE_USER}:")));
        assert!(contents.len() > format!("{COOKIE_USER}:").len());
    }

    #[test]
    fn generate_no_tmp_leftover() {
        let dir = TempDir::new().unwrap();
        let _guard = generate_cookie(dir.path()).unwrap();
        assert!(!dir.path().join(".cookie.tmp").exists());
    }

    #[test]
    fn generate_different_each_call() {
        let dir = TempDir::new().unwrap();
        let _guard1 = generate_cookie(dir.path()).unwrap();
        let contents_1 = fs::read_to_string(dir.path().join(COOKIE_FILENAME)).unwrap();
        let _guard2 = generate_cookie(dir.path()).unwrap();
        let contents_2 = fs::read_to_string(dir.path().join(COOKIE_FILENAME)).unwrap();
        assert_ne!(contents_1, contents_2);
    }

    #[cfg(feature = "rpc-cli")]
    #[test]
    fn read_round_trip() {
        let dir = TempDir::new().unwrap();
        let _guard = generate_cookie(dir.path()).unwrap();
        let contents = fs::read_to_string(dir.path().join(COOKIE_FILENAME)).unwrap();
        let read_val = read_cookie(dir.path()).unwrap();
        assert_eq!(contents, read_val);
    }

    #[cfg(feature = "rpc-cli")]
    #[test]
    fn read_invalid_format_errors() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(COOKIE_FILENAME), "invalid_cookie").unwrap();
        assert!(read_cookie(dir.path()).is_err());
    }

    #[cfg(feature = "rpc-cli")]
    #[test]
    fn read_missing_file_errors() {
        let dir = TempDir::new().unwrap();
        assert!(read_cookie(dir.path()).is_err());
    }

    #[test]
    fn guard_deletes_on_drop() {
        let dir = TempDir::new().unwrap();
        {
            let _guard = generate_cookie(dir.path()).unwrap();
            assert!(dir.path().join(COOKIE_FILENAME).exists());
        }
        // Guard dropped here — file should be gone.
        assert!(!dir.path().join(COOKIE_FILENAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let _guard = generate_cookie(dir.path()).unwrap();
        let perms = fs::metadata(dir.path().join(COOKIE_FILENAME))
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    /// Checks that the cookie installed at its final path carries the owner-only
    /// DACL applied at creation time, i.e. that the policy survives the atomic
    /// rename and is not replaced by ACEs inherited from the parent directory.
    #[cfg(windows)]
    #[allow(unsafe_code)]
    #[test]
    fn windows_file_acl() {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::{
            DACL_SECURITY_INFORMATION, GetFileSecurityW, PSECURITY_DESCRIPTOR,
        };
        use windows::core::{HSTRING, PWSTR};

        let dir = TempDir::new().unwrap();
        let _guard = generate_cookie(dir.path()).unwrap();

        let path = HSTRING::from(dir.path().join(COOKIE_FILENAME).as_os_str());

        // First call reports the required buffer size (returning failure by
        // design, hence the discarded result); the second fetches the security
        // descriptor.
        let mut needed = 0u32;
        // SAFETY: the `HSTRING` is a NUL-terminated UTF-16 string, and passing no
        // buffer is valid for querying the required size.
        let _ =
            unsafe { GetFileSecurityW(&path, DACL_SECURITY_INFORMATION.0, None, 0, &mut needed) };
        let mut sd = vec![0u8; needed as usize];
        // SAFETY: `sd` is a writable buffer of the size the previous call requested.
        let ok = unsafe {
            GetFileSecurityW(
                &path,
                DACL_SECURITY_INFORMATION.0,
                Some(PSECURITY_DESCRIPTOR(sd.as_mut_ptr().cast())),
                needed,
                &mut needed,
            )
        };
        assert!(ok.as_bool(), "{}", std::io::Error::last_os_error());

        let mut sddl_ptr = PWSTR::null();
        // SAFETY: `sd` holds the valid security descriptor fetched above, and
        // `sddl_ptr` is a valid out-pointer.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                PSECURITY_DESCRIPTOR(sd.as_mut_ptr().cast()),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl_ptr,
                None,
            )
        }
        .unwrap();

        // SAFETY: `sddl_ptr` is the NUL-terminated UTF-16 string the conversion
        // above allocated on the local heap; it is read once and freed once.
        let sddl = unsafe {
            let sddl = sddl_ptr.to_string().unwrap();
            LocalFree(Some(HLOCAL(sddl_ptr.as_ptr().cast())));
            sddl
        };

        assert_eq!(sddl, OWNER_ONLY_SDDL);
    }
}
