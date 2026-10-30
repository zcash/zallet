use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use rand::{RngExt, rand_core::UnwrapErr, rngs::SysRng};
use tracing::{info, warn};

use super::authorization::PasswordHash;
use crate::error::{Error, ErrorKind};
use crate::fl;
use crate::fs::{Publish, PublishError, write_private_file};

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

    // The restrictive permissions are applied at creation time so there is no
    // window during which another user can open the file, and the publication
    // rename preserves them. The cookie is per-process, so an existing cookie
    // (or a temporary left by a crashed process) is replaced.
    write_private_file(
        &cookie_path,
        Publish::Replacing {
            temp_suffix: ".tmp",
        },
        cookie.as_bytes(),
    )
    .map_err(|e| match e {
        PublishError::Create { source, .. } | PublishError::PostPublish { source, .. } => {
            ErrorKind::Init.context(source)
        }
        PublishError::Fill(e) | PublishError::Publish(e) => ErrorKind::Init.context(e),
        // Replacing mode never refuses an existing destination; map it like any
        // other publication failure rather than asserting on it.
        PublishError::DestinationExists => {
            ErrorKind::Init.context(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
        }
    })?;

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
        use crate::fs::OWNER_ONLY_SDDL;
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
