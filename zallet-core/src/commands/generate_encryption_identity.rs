//! `generate-encryption-identity` subcommand

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fmt::Write as _, io::Write as _, path::Path};

use abscissa_core::Runnable;
use age::secrecy::{
    ExposeSecret, SecretString,
    zeroize::{Zeroize, Zeroizing},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{self, AsyncWriteExt};

use crate::{
    cli::GenerateEncryptionIdentityCmd,
    commands::AsyncRunnable,
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

/// Environment variable from which the passphrase is read in non-interactive contexts.
const PASSPHRASE_ENV: &str = "ZALLET_IDENTITY_PASSPHRASE";

impl AsyncRunnable for GenerateEncryptionIdentityCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();

        // Generate a fresh native X25519 identity (equivalent to `rage-keygen`).
        let identity = age::x25519::Identity::generate();
        let pubkey = identity.to_public();

        // Build the file body, either as a plain identity or passphrase-encrypted
        // (equivalent to `rage -p`).
        let passphrase = if self.passphrase {
            Some(read_passphrase()?)
        } else {
            None
        };
        let body = encode_identity(&identity, passphrase)?;

        // Resolve the output target.
        let output_path = match self.output.as_deref() {
            None => Some(config.encryption_identity()),
            Some("-") => None,
            Some(path) => Some(path.into()),
        };

        if let Some(path) = output_path {
            // Ensure the parent directory exists; `generate-encryption-identity`
            // is typically the first command run against a fresh data directory.
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    ErrorKind::Init.context(fl!(
                        "cmd-generate-encryption-identity-write-failed",
                        path = path.display().to_string(),
                        error = e.to_string(),
                    ))
                })?;
            }

            write_identity_file(&path, body.as_slice())?;
            eprintln!(
                "{}",
                fl!(
                    "cmd-generate-encryption-identity-written",
                    path = path.display().to_string()
                )
            );
            // Print the public key (recipient) to stderr, like `rage-keygen` does
            // when writing to a file. Suppressed for stdout output (below) so
            // scripted / non-interactive consumers get output identical to
            // `rage-keygen`.
            eprintln!(
                "{}",
                fl!(
                    "cmd-generate-encryption-identity-public-key",
                    pubkey = pubkey.to_string()
                )
            );
        } else {
            let mut stdout = io::stdout();
            stdout
                .write_all(body.as_slice())
                .await
                .map_err(|e| ErrorKind::Generic.context(e))?;
            stdout
                .flush()
                .await
                .map_err(|e| ErrorKind::Generic.context(e))?;
        }

        Ok(())
    }
}

/// Writes the identity file without overwriting any existing identity.
///
/// The body is key material, so it is staged in a temporary file alongside the
/// destination, fully written and `fsync`ed, then atomically renamed into place.
/// This ensures the destination only ever observes a complete, durable file: an
/// interruption mid-write leaves the temporary file (which is cleaned up) rather
/// than a truncated identity at `path`.
///
/// An existing identity is never overwritten. `persist_noclobber` refuses to
/// replace an existing file, since clobbering would risk irrecoverable loss of
/// an in-use wallet's key material; the file must be removed deliberately to
/// regenerate.
fn write_identity_file(path: &Path, body: &[u8]) -> Result<(), Error> {
    // The temporary file must live in the destination's parent directory so that
    // the final `persist_noclobber` is an atomic same-filesystem rename.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut f = tempfile::NamedTempFile::new_in(parent).map_err(|e| write_failed(path, e))?;
    // Create the identity readable only by the owner (mode 0600 on Unix).
    // `set_permissions` is an `fchmod`, so this holds regardless of the process
    // umask, and the mode is preserved across the rename below.
    #[cfg(unix)]
    f.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| write_failed(path, e))?;

    f.write_all(body).map_err(|e| write_failed(path, e))?;
    f.flush().map_err(|e| write_failed(path, e))?;
    f.as_file().sync_all().map_err(|e| write_failed(path, e))?;
    f.persist_noclobber(path).map_err(|e| {
        // `persist_noclobber` fails with `AlreadyExists` when an identity is
        // already present; surface a dedicated, actionable message rather than
        // the generic write failure, since overwriting would risk key loss.
        if e.error.kind() == io::ErrorKind::AlreadyExists {
            ErrorKind::Init
                .context(fl!(
                    "cmd-generate-encryption-identity-exists",
                    path = path.display().to_string(),
                ))
                .into()
        } else {
            write_failed(path, e.error)
        }
    })?;

    Ok(())
}

fn write_failed(path: &Path, error: impl ToString) -> Error {
    ErrorKind::Init
        .context(fl!(
            "cmd-generate-encryption-identity-write-failed",
            path = path.display().to_string(),
            error = error.to_string(),
        ))
        .into()
}

/// Encodes an age identity into the bytes to write to the identity file.
///
/// The identity is rendered in `rage-keygen`'s format: a `created` timestamp and
/// the public key as comments, followed by the secret key line. When
/// `passphrase` is `Some`, that rendering is passphrase-encrypted and
/// ASCII-armored (equivalent to `rage -p <(rage-keygen)`); otherwise it is
/// written as a plain identity file (equivalent to `rage-keygen`).
fn encode_identity(
    identity: &age::x25519::Identity,
    passphrase: Option<SecretString>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut rendered = String::new();
    let now = OffsetDateTime::now_utc();
    if let Ok(created) = now.replace_nanosecond(0).unwrap_or(now).format(&Rfc3339) {
        let _ = writeln!(rendered, "# created: {created}");
    }
    let _ = writeln!(rendered, "# public key: {}", identity.to_public());
    let _ = writeln!(rendered, "{}", identity.to_string().expose_secret());

    let result = match passphrase {
        Some(passphrase) => encrypt_identity(&rendered, passphrase),
        None => Ok(Zeroizing::new(rendered.as_bytes().to_vec())),
    };

    // `rendered` holds the secret key in the clear; zero it before returning,
    // regardless of whether encryption succeeded.
    rendered.zeroize();
    result
}

/// Passphrase-encrypts and ASCII-armors the rendered identity file.
fn encrypt_identity(rendered: &str, passphrase: SecretString) -> Result<Zeroizing<Vec<u8>>, Error> {
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);

    let mut out = vec![];
    let armored = age::armor::ArmoredWriter::wrap_output(&mut out, age::armor::Format::AsciiArmor)
        .map_err(|e| ErrorKind::Generic.context(e))?;
    let mut writer = encryptor
        .wrap_output(armored)
        .map_err(|e| ErrorKind::Generic.context(e))?;
    writer
        .write_all(rendered.as_bytes())
        .map_err(|e| ErrorKind::Generic.context(e))?;
    writer
        .finish()
        .and_then(|armored| armored.finish())
        .map_err(|e| ErrorKind::Generic.context(e))?;
    Ok(Zeroizing::new(out))
}

/// Obtains the passphrase used to encrypt the identity.
///
/// In non-interactive contexts the passphrase is read from the
/// [`PASSPHRASE_ENV`] environment variable; otherwise the user is prompted for
/// it (with confirmation).
fn read_passphrase() -> Result<SecretString, Error> {
    if let Ok(passphrase) = std::env::var(PASSPHRASE_ENV) {
        return Ok(SecretString::from(passphrase));
    }

    // Take ownership of each prompt's buffer in a `SecretString` immediately, so
    // both passphrase copies are zeroized on drop (including on the mismatch
    // path) rather than lingering in plain `String`s.
    let passphrase = SecretString::from(
        rpassword::prompt_password(fl!("cmd-generate-encryption-identity-passphrase-prompt"))
            .map_err(|e| ErrorKind::Generic.context(e))?,
    );
    let confirm = SecretString::from(
        rpassword::prompt_password(fl!("cmd-generate-encryption-identity-passphrase-confirm"))
            .map_err(|e| ErrorKind::Generic.context(e))?,
    );

    if passphrase.expose_secret() != confirm.expose_secret() {
        return Err(ErrorKind::Generic
            .context(fl!("cmd-generate-encryption-identity-passphrase-mismatch"))
            .into());
    }

    Ok(passphrase)
}

impl Runnable for GenerateEncryptionIdentityCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Read};

    use age::secrecy::SecretString;

    use super::{encode_identity, write_identity_file};

    /// Decrypts a passphrase-encrypted, armored identity body, returning the
    /// recovered plaintext.
    fn decrypt(body: &[u8], passphrase: SecretString) -> Result<String, age::DecryptError> {
        let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(body))?;
        let identity = age::scrypt::Identity::new(passphrase);
        let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
        let mut plaintext = String::new();
        reader.read_to_string(&mut plaintext).expect("valid UTF-8");
        Ok(plaintext)
    }

    #[test]
    fn plain_identity_round_trips() {
        let identity = age::x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();

        let body = encode_identity(&identity, None).expect("encoding succeeds");
        let body = String::from_utf8(body.to_vec()).expect("plain identity is UTF-8");

        // The body is in `rage-keygen` format: comment header plus secret line.
        assert!(body.contains("# public key: "));
        let secret_line = body
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
            .expect("has a secret key line");

        // The secret line is parseable back into the same identity.
        let recovered: age::x25519::Identity = secret_line.parse().expect("parses as identity");
        assert_eq!(recovered.to_public().to_string(), pubkey);
    }

    #[test]
    fn passphrase_identity_is_decryptable() {
        let identity = age::x25519::Identity::generate();
        let pubkey = identity.to_public().to_string();
        let passphrase = SecretString::from("correct horse battery staple".to_owned());

        let body = encode_identity(&identity, Some(passphrase.clone())).expect("encoding succeeds");

        assert!(body.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));

        // Decrypting with the passphrase recovers the original secret key.
        let recovered = decrypt(&body, passphrase).expect("decryption succeeds");
        let secret_line = recovered
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
            .expect("has a secret key line");
        let recovered: age::x25519::Identity = secret_line.parse().expect("parses as identity");
        assert_eq!(recovered.to_public().to_string(), pubkey);
    }

    #[test]
    fn passphrase_identity_rejects_wrong_passphrase() {
        let identity = age::x25519::Identity::generate();
        let passphrase = SecretString::from("the right passphrase".to_owned());

        let body = encode_identity(&identity, Some(passphrase)).expect("encoding succeeds");

        let result = decrypt(&body, SecretString::from("the wrong passphrase".to_owned()));
        assert!(matches!(result, Err(age::DecryptError::DecryptionFailed)));
    }

    #[test]
    fn write_identity_file_creates_private_file() {
        let dir = tempfile::tempdir().expect("creates tempdir");
        let path = dir.path().join("identity.txt");

        write_identity_file(&path, b"identity body").expect("writes identity file");

        assert_eq!(
            fs::read(&path).expect("reads identity file"),
            b"identity body"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&path)
                .expect("reads identity file metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn write_identity_file_does_not_overwrite_existing_file() {
        let dir = tempfile::tempdir().expect("creates tempdir");
        let path = dir.path().join("identity.txt");
        fs::write(&path, b"existing identity").expect("writes existing identity");

        let result = write_identity_file(&path, b"new identity");

        assert!(result.is_err());
        assert_eq!(
            fs::read(&path).expect("reads existing identity"),
            b"existing identity"
        );
        assert_eq!(
            fs::read_dir(dir.path()).expect("reads tempdir").count(),
            1,
            "failed persist should clean up its temporary file"
        );
    }
}
