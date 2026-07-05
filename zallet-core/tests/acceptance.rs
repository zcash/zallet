//! Acceptance test: runs the application as a subprocess and asserts its
//! output for given argument combinations matches what is expected.
//!
//! For more information, see:
//! <https://docs.rs/abscissa_core/latest/abscissa_core/testing/index.html>

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    unused_lifetimes,
    unused_qualifications
)]

use abscissa_core::testing::prelude::*;
use once_cell::sync::Lazy;
use tempfile::tempdir;

#[cfg(zallet_build = "wallet")]
use {
    abscissa_core::fs::File,
    age::secrecy::ExposeSecret,
    std::io::{BufRead, Write},
};

/// Executes your application binary via `cargo run`.
///
/// Storing this value as a [`Lazy`] static ensures that all instances of
/// the runner acquire a mutex when executing commands and inspecting
/// exit statuses, serializing what would otherwise be multithreaded
/// invocations as `cargo test` executes tests in parallel by default.
pub static RUNNER: Lazy<CmdRunner> = Lazy::new(CmdRunner::default);

/// Use `ZalletConfig::default()` value if no config or args
#[test]
fn start_no_args() {
    let datadir = tempdir().unwrap();
    let mut runner = RUNNER.clone();
    let cmd = runner
        .arg("--datadir")
        .arg(datadir.path())
        .arg("start")
        .run();
    cmd.wait().unwrap().expect_code(1);
}

/// Example of a test which matches a regular expression
#[test]
fn version_no_args() {
    let mut runner = RUNNER.clone();
    let mut cmd = runner.arg("--version").capture_stdout().run();
    cmd.stdout().expect_regex(r"\A\w+ [\d\.\-a-z]+\z");
}

#[cfg(zallet_build = "wallet")]
#[test]
fn setup_new_wallet() {
    let datadir = tempdir().unwrap();
    let config_file = datadir.path().join("zallet.toml");
    let identity_file = datadir.path().join("encryption-identity.txt");

    {
        let mut f = File::create(&config_file).unwrap();
        writeln!(f, "[builder]").unwrap();
        writeln!(f, "[builder.limits]").unwrap();
        writeln!(f, "[consensus]").unwrap();
        writeln!(f, "network = \"test\"").unwrap();
        writeln!(f, "[database]").unwrap();
        writeln!(f, "[external]").unwrap();
        writeln!(f, "[features]").unwrap();
        writeln!(f, "as_of_version = \"{}\"", env!("CARGO_PKG_VERSION")).unwrap();
        writeln!(f, "[features.deprecated]").unwrap();
        writeln!(f, "[features.experimental]").unwrap();
        writeln!(f, "[indexer]").unwrap();
        writeln!(f, "validator_address = \"127.0.0.1:65536\"").unwrap();
        writeln!(f, "[keystore]").unwrap();
        writeln!(f, "[note_management]").unwrap();
        writeln!(f, "[rpc]").unwrap();
        writeln!(f, "bind = []").unwrap();
    }

    {
        let mut f = File::create(identity_file).unwrap();
        writeln!(
            f,
            "{}",
            age::x25519::Identity::generate()
                .to_string()
                .expose_secret()
        )
        .unwrap();
    }

    {
        let mut runner = RUNNER.clone();
        let mut cmd = runner
            .arg("--datadir")
            .arg(datadir.path())
            .arg("init-wallet-encryption")
            .capture_stderr()
            .run();
        let stderr = cmd.stderr();
        wait_until_running(stderr);
        // Every command first logs the configuration file it is loading.
        stderr.expect_regex(".*Loading configuration.*");
        stderr.expect_regex(".*Creating empty database.*");
        cmd.wait().unwrap().expect_code(0);
    }

    {
        let mut runner = RUNNER.clone();
        let mut cmd = runner
            .arg("--datadir")
            .arg(datadir.path())
            .arg("generate-mnemonic")
            .capture_stderr()
            .run();
        let stderr = cmd.stderr();
        wait_until_running(stderr);
        // Every command first logs the configuration file it is loading.
        stderr.expect_regex(".*Loading configuration.*");
        stderr.expect_regex(".*Applying latest database migrations.*");
        cmd.wait().unwrap().expect_code(0);
    }

    {
        let mut runner = RUNNER.clone();
        let cmd = runner
            .arg("--datadir")
            .arg(datadir.path())
            .arg("start")
            .run();
        // We added invalid data to the config in order to ensure that `start` fails.
        cmd.wait().unwrap().expect_code(1);
    }
}

/// The identity produced by `generate-encryption-identity` drives the full setup flow:
/// `init-wallet-encryption` consumes it, and a mnemonic can then be generated.
#[cfg(zallet_build = "wallet")]
#[test]
fn generate_encryption_identity_drives_setup() {
    let datadir = tempdir().unwrap();
    let config_file = datadir.path().join("zallet.toml");

    {
        let mut f = File::create(&config_file).unwrap();
        writeln!(f, "[builder]").unwrap();
        writeln!(f, "[builder.limits]").unwrap();
        writeln!(f, "[consensus]").unwrap();
        writeln!(f, "network = \"test\"").unwrap();
        writeln!(f, "[database]").unwrap();
        writeln!(f, "[external]").unwrap();
        writeln!(f, "[features]").unwrap();
        writeln!(f, "as_of_version = \"{}\"", env!("CARGO_PKG_VERSION")).unwrap();
        writeln!(f, "[features.deprecated]").unwrap();
        writeln!(f, "[features.experimental]").unwrap();
        writeln!(f, "[indexer]").unwrap();
        writeln!(f, "validator_address = \"127.0.0.1:65536\"").unwrap();
        writeln!(f, "[keystore]").unwrap();
        writeln!(f, "[note_management]").unwrap();
        writeln!(f, "[rpc]").unwrap();
        writeln!(f, "bind = []").unwrap();
    }

    // Generate the encryption identity with the new subcommand.
    {
        let mut runner = RUNNER.clone();
        let mut cmd = runner
            .arg("--datadir")
            .arg(datadir.path())
            .arg("generate-encryption-identity")
            .capture_stderr()
            .run();
        // The recipient is printed to stderr; drain past cargo's build output
        // (the runner invokes the binary via `cargo run`) to find it.
        let stderr = cmd.stderr();
        let mut found = false;
        let mut line = String::new();
        while stderr.read_line(&mut line).unwrap() != 0 {
            if line.contains("Public key: age1") {
                found = true;
                break;
            }
            line.clear();
        }
        assert!(
            found,
            "generate-encryption-identity did not print the public key"
        );
        cmd.wait().unwrap().expect_code(0);
    }

    // The generated identity file is consumable by `init-wallet-encryption`.
    {
        let mut runner = RUNNER.clone();
        let mut cmd = runner
            .arg("--datadir")
            .arg(datadir.path())
            .arg("init-wallet-encryption")
            .capture_stderr()
            .run();
        let stderr = cmd.stderr();
        wait_until_running(stderr);
        // Every command first logs the configuration file it is loading.
        stderr.expect_regex(".*Loading configuration.*");
        stderr.expect_regex(".*Creating empty database.*");
        cmd.wait().unwrap().expect_code(0);
    }

    // And a mnemonic can be generated, encrypted with the derived recipient.
    {
        let mut runner = RUNNER.clone();
        let mut cmd = runner
            .arg("--datadir")
            .arg(datadir.path())
            .arg("generate-mnemonic")
            .capture_stderr()
            .run();
        let stderr = cmd.stderr();
        wait_until_running(stderr);
        // Every command first logs the configuration file it is loading.
        stderr.expect_regex(".*Loading configuration.*");
        stderr.expect_regex(".*Applying latest database migrations.*");
        cmd.wait().unwrap().expect_code(0);
    }
}

/// The identity file is key material, so it must be written readable only by the
/// owner (mode 0600) on creation.
#[cfg(all(zallet_build = "wallet", unix))]
#[test]
fn generate_encryption_identity_sets_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let datadir = tempdir().unwrap();
    let identity_file = datadir.path().join("encryption-identity.txt");

    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;

    // Fresh creation is 0600.
    {
        let mut runner = RUNNER.clone();
        let cmd = runner
            .arg("--datadir")
            .arg(datadir.path())
            .arg("generate-encryption-identity")
            .capture_stderr()
            .run();
        cmd.wait().unwrap().expect_code(0);
    }
    assert_eq!(mode(&identity_file), 0o600);
}

/// An existing identity file is never overwritten: a second run exits non-zero
/// and leaves the file untouched (clobbering would risk irrecoverable key loss).
#[cfg(zallet_build = "wallet")]
#[test]
fn generate_encryption_identity_refuses_to_clobber() {
    let datadir = tempdir().unwrap();
    let identity_file = datadir.path().join("encryption-identity.txt");

    {
        let mut runner = RUNNER.clone();
        let cmd = runner
            .arg("--datadir")
            .arg(datadir.path())
            .arg("generate-encryption-identity")
            .capture_stderr()
            .run();
        cmd.wait().unwrap().expect_code(0);
    }
    let before = std::fs::read(&identity_file).unwrap();

    {
        let mut runner = RUNNER.clone();
        let cmd = runner
            .arg("--datadir")
            .arg(datadir.path())
            .arg("generate-encryption-identity")
            .capture_stderr()
            .run();
        cmd.wait().unwrap().expect_code(1);
    }
    let after = std::fs::read(&identity_file).unwrap();
    assert_eq!(
        before, after,
        "existing identity file must be left unchanged"
    );
}

/// `-o -` writes the identity to stdout and, matching `rage-keygen`, suppresses
/// the `Public key:` stderr echo that the file-writing path emits — so scripted /
/// non-interactive stdout consumers get output identical to `rage-keygen`. Spawned
/// directly so both streams can be inspected without `cargo run` build noise.
#[cfg(zallet_build = "wallet")]
#[test]
fn generate_encryption_identity_writes_to_stdout() {
    let datadir = tempdir().unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zallet"))
        .arg("--datadir")
        .arg(datadir.path())
        .arg("generate-encryption-identity")
        .arg("-o")
        .arg("-")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The identity body is written to stdout in `rage-keygen` format.
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.lines().any(|l| l.starts_with("AGE-SECRET-KEY-1")),
        "generate-encryption-identity -o - did not write the secret key to stdout"
    );

    // The `Public key:` echo is suppressed for stdout output: no stderr line
    // begins with `Public key:`. (This is distinct from the `# public key:`
    // comment, which is part of the body on stdout.)
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.lines().any(|l| l.starts_with("Public key:")),
        "generate-encryption-identity -o - must not echo the public key to stderr; got: {stderr}"
    );
}

/// A missing parent directory for the output path is created.
#[cfg(zallet_build = "wallet")]
#[test]
fn generate_encryption_identity_creates_missing_parent_dir() {
    let datadir = tempdir().unwrap();
    let nested = datadir
        .path()
        .join("sub")
        .join("dir")
        .join("encryption-identity.txt");

    let mut runner = RUNNER.clone();
    let cmd = runner
        .arg("--datadir")
        .arg(datadir.path())
        .arg("generate-encryption-identity")
        .arg("-o")
        .arg(&nested)
        .capture_stderr()
        .run();
    cmd.wait().unwrap().expect_code(0);
    assert!(
        nested.exists(),
        "nested output path should have been created"
    );
}

/// With `-p` and `ZALLET_IDENTITY_PASSPHRASE` set, the identity file is written
/// passphrase-encrypted (ASCII-armored) and the command succeeds. Spawned
/// directly so the child gets the env var without `std::env::set_var` (which is
/// `unsafe` under edition 2024, and this file is `#![forbid(unsafe_code)]`).
#[cfg(zallet_build = "wallet")]
#[test]
fn generate_encryption_identity_passphrase_writes_armored_file() {
    let datadir = tempdir().unwrap();
    let identity_file = datadir.path().join("encryption-identity.txt");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zallet"))
        .arg("--datadir")
        .arg(datadir.path())
        .arg("generate-encryption-identity")
        .arg("-p")
        .env("ZALLET_IDENTITY_PASSPHRASE", "test-passphrase")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let body = std::fs::read(&identity_file).unwrap();
    assert!(body.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
}

#[cfg(zallet_build = "wallet")]
fn wait_until_running(stderr: &mut Stderr) {
    let mut buf = String::new();
    while !buf.contains("Running") {
        stderr.read_line(&mut buf).unwrap();
    }
}
