use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use rand::{Rng, rngs::OsRng};
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
    let password: [u8; 32] = OsRng.r#gen();
    let password = Base64::encode_string(&password);
    let cookie = format!("{COOKIE_USER}:{password}");

    let cookie_path = cookie_path(datadir);
    let tmp_path = datadir.join(format!("{COOKIE_FILENAME}.tmp"));

    // Clean up any leftover tmp file from a previous crash.
    let _ = fs::remove_file(&tmp_path);

    // Write to temp file with restricted permissions for atomic creation.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| ErrorKind::Init.context(e))?;
        f.write_all(cookie.as_bytes()).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            ErrorKind::Init.context(e)
        })?;
    }

    #[cfg(not(unix))]
    fs::write(&tmp_path, cookie.as_bytes()).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        ErrorKind::Init.context(e)
    })?;

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
}
