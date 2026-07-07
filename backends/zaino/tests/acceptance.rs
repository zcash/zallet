//! Acceptance smoke tests for the `zallet-zaino` backend binary: runs the
//! application as a subprocess and asserts basic CLI behaviour, mirroring the
//! richer suite in `backends/zebra/tests/acceptance.rs` (the CLI surface is
//! shared `zallet-core` code, so it is exercised in depth once, there).

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

/// Executes the application binary via `cargo run`.
///
/// Storing this value as a [`Lazy`] static ensures that all instances of
/// the runner acquire a mutex when executing commands and inspecting
/// exit statuses, serializing what would otherwise be multithreaded
/// invocations as `cargo test` executes tests in parallel by default.
pub static RUNNER: Lazy<CmdRunner> = Lazy::new(CmdRunner::default);

/// The version string is printed with the shared `zallet` CLI name.
#[test]
fn version_no_args() {
    let mut runner = RUNNER.clone();
    let mut cmd = runner.arg("--version").capture_stdout().run();
    cmd.stdout().expect_regex(r"\A\w+ [\d\.\-a-z]+\z");
}

/// `start` without a chain to connect to exits with an error, not a panic.
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
