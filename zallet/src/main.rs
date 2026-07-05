//! The Zallet launcher.
//!
//! Zallet's chain backends are separate binaries (`zallet-zebra`,
//! `zallet-zaino`), each built in its own cargo workspace so their `zebra-state`
//! dependency versions can move independently (see zcash/zallet#540). This binary is
//! the user-facing `zallet` command: it reads the config file's top-level `backend`
//! key and hands the entire invocation over to the corresponding backend binary.
//!
//! The launcher is deliberately dependency-light and performs only best-effort
//! argument scanning: it understands exactly the config-locating global flags
//! (`--datadir`/`-d`, `--config`/`-c`) that `zallet-core`'s CLI defines. If the
//! backend cannot be determined (no config file, unreadable file), it dispatches to
//! the default backend; the backend binaries themselves authoritatively validate the
//! config's `backend` key against the backend they provide, so a scanning gap can
//! never run a wallet against the wrong backend.

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The default Zallet config file name.
///
/// Deliberately duplicated from `zallet_core::commands::CONFIG_FILE` (the source of
/// truth); the launcher must not depend on the wallet library.
const CONFIG_FILE: &str = "zallet.toml";

/// The backend the launcher dispatches to when no config file exists or the config
/// does not set the `backend` key.
///
/// The default backend is a deployment decision, so it lives here in the launcher,
/// not in the wallet library.
const DEFAULT_BACKEND: &str = "zebra";

/// Parses a config file's `backend` value.
///
/// Backend names are an open namespace: any well-formed name is accepted, and the
/// name `foo` dispatches to the `zallet-foo` sibling binary. The validity rules are
/// deliberately duplicated from `zallet_core::config::BackendName` (the source of
/// truth); the launcher must not depend on the wallet library. The charset
/// restriction also keeps a name safe to embed in a binary filename — in
/// particular, free of path separators.
fn parse_backend_name(value: &str) -> Result<String, String> {
    if !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        Ok(value.into())
    } else {
        Err(format!(
            "invalid backend name '{value}' in config file: backend names are nonempty, lowercase alphanumeric plus hyphens",
        ))
    }
}

/// The name of the binary providing the named backend.
fn backend_binary_name(backend: &str) -> String {
    format!("zallet-{backend}")
}

/// The config-locating global options scanned out of the command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct ConfigLocator {
    /// The value of `--datadir`/`-d`, if present.
    datadir: Option<PathBuf>,
    /// The value of `--config`/`-c`, if present.
    config: Option<PathBuf>,
}

/// Scans the command line (without the program name) for the config-locating global
/// options defined by the Zallet CLI.
///
/// This mirrors how clap in `zallet-core` accepts these options: `--flag value`,
/// `--flag=value`, `-f value`, `-f=value`, and the attached short form `-fvalue`.
/// Options after a `--` terminator are not scanned. Flag clusters that combine other
/// short options (e.g. `-vd path`) are not understood; in that case the launcher
/// falls back to the default backend and the backend binary's own config validation
/// has the final say.
fn scan_locator_args(args: &[OsString]) -> ConfigLocator {
    fn take(
        args: &[OsString],
        i: usize,
        long: &str,
        short: char,
    ) -> (Option<PathBuf>, /* consumed extra arg */ bool) {
        let Some(arg) = args[i].to_str() else {
            return (None, false);
        };

        let long_flag = format!("--{long}");
        let short_flag = format!("-{short}");

        if arg == long_flag || arg == short_flag {
            // `--flag value` / `-f value`
            (args.get(i + 1).map(PathBuf::from), true)
        } else if let Some(v) = arg.strip_prefix(&format!("{long_flag}=")) {
            // `--flag=value`
            (Some(PathBuf::from(v)), false)
        } else if let Some(v) = arg.strip_prefix(&format!("{short_flag}=")) {
            // `-f=value`
            (Some(PathBuf::from(v)), false)
        } else if let Some(v) = arg.strip_prefix(&short_flag) {
            // `-fvalue` (attached short form; `arg != short_flag` was handled above,
            // so `v` is non-empty)
            (Some(PathBuf::from(v)), false)
        } else {
            (None, false)
        }
    }

    let mut locator = ConfigLocator::default();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--" {
            break;
        }
        let (datadir, skip) = take(args, i, "datadir", 'd');
        if let Some(v) = datadir {
            locator.datadir = Some(v);
            i += 1 + usize::from(skip);
            continue;
        }
        let (config, skip) = take(args, i, "config", 'c');
        if let Some(v) = config {
            locator.config = Some(v);
            i += 1 + usize::from(skip);
            continue;
        }
        i += 1;
    }
    locator
}

/// Resolves the config file path for the scanned locator options.
///
/// Mirrors `zallet-core`'s resolution: the datadir defaults to `$HOME/.zallet`
/// (Zallet deliberately eschews the XDG base directories; see
/// `EntryPoint::datadir` in `zallet-core` for the reasoning), and a relative
/// `--config` is resolved relative to the datadir.
fn resolve_config_path(locator: &ConfigLocator, home_dir: Option<&Path>) -> Option<PathBuf> {
    let datadir = locator
        .datadir
        .clone()
        .or_else(|| home_dir.map(|home| home.join(".zallet")))?;

    let config = locator
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(CONFIG_FILE));

    Some(if config.is_absolute() {
        config
    } else {
        datadir.join(config)
    })
}

/// Reads the `backend` key out of config file contents.
///
/// Returns the default backend if the key is absent. A file that fails to parse
/// is an error: silently dispatching a malformed config to the default backend
/// could mask the `backend` selection the file was trying to make.
fn backend_from_config(contents: &str) -> Result<String, String> {
    let table = contents
        .parse::<toml::Table>()
        .map_err(|e| format!("failed to parse config file: {e}"))?;
    match table.get("backend") {
        None => Ok(DEFAULT_BACKEND.into()),
        Some(toml::Value::String(s)) => parse_backend_name(s),
        Some(other) => Err(format!(
            "invalid `backend` value {other} in config file (expected a string naming a backend, e.g. \"zebra\")",
        )),
    }
}

/// Determines which backend to dispatch to for the given command line.
fn select_backend(args: &[OsString], home_dir: Option<&Path>) -> Result<String, String> {
    let locator = scan_locator_args(args);
    match resolve_config_path(&locator, home_dir) {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(contents) => {
                backend_from_config(&contents).map_err(|e| format!("{}: {e}", path.display()))
            }
            // No config file (or unreadable): dispatch to the default backend, which
            // reproduces the canonical error for an explicit `--config` that does not
            // exist, and supports configless commands like `example-config`.
            Err(_) => Ok(DEFAULT_BACKEND.into()),
        },
        None => Ok(DEFAULT_BACKEND.into()),
    }
}

/// Locates the backend binary: next to this launcher first, then via `$PATH`.
fn locate_backend_binary(backend: &str) -> OsString {
    let name = format!(
        "{}{}",
        backend_binary_name(backend),
        env::consts::EXE_SUFFIX
    );
    if let Ok(exe) = env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join(&name);
        if sibling.exists() {
            return sibling.into();
        }
    }
    name.into()
}

/// Hands the invocation over to the backend binary.
///
/// On Unix this replaces the launcher process entirely, so signals, exit codes, and
/// stdio behave exactly as if the backend binary had been invoked directly.
#[cfg(unix)]
fn dispatch(binary: &OsStr, args: &[OsString]) -> Result<ExitCode, String> {
    use std::os::unix::process::CommandExt;

    // `exec` only returns on error.
    let err = Command::new(binary).args(args).exec();
    Err(report_spawn_error(binary, err))
}

/// Hands the invocation over to the backend binary.
///
/// Windows has no `exec`; run the backend as a child and forward its exit code.
#[cfg(not(unix))]
fn dispatch(binary: &OsStr, args: &[OsString]) -> Result<ExitCode, String> {
    let status = Command::new(binary)
        .args(args)
        .status()
        .map_err(|e| report_spawn_error(binary, e))?;
    Ok(match status.code() {
        Some(code) => ExitCode::from(code.clamp(0, u8::MAX.into()) as u8),
        None => ExitCode::FAILURE,
    })
}

/// Renders a helpful error for a backend binary that could not be run.
fn report_spawn_error(binary: &OsStr, err: std::io::Error) -> String {
    let mut msg = format!(
        "failed to run the backend binary `{}`: {err}\n\
         The launcher looks for backend binaries next to itself and then on the PATH.\n\
         Is the corresponding backend package installed?",
        Path::new(binary).display(),
    );
    // Backend names are discovered, not compiled in: list the `zallet-*` binaries
    // that are actually installed next to the launcher.
    if let Some(available) = discover_sibling_backends() {
        msg.push_str(&format!(
            "\nBackend binaries found next to the launcher: {available}"
        ));
    }
    msg
}

/// Lists the `zallet-*` binaries installed next to the launcher, if any.
fn discover_sibling_backends() -> Option<String> {
    let exe = env::current_exe().ok()?;
    let entries = std::fs::read_dir(exe.parent()?).ok()?;
    let mut found: Vec<String> = entries
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            name.strip_prefix("zallet-")
                .map(|rest| rest.strip_suffix(env::consts::EXE_SUFFIX).unwrap_or(rest))
                .filter(|rest| !rest.is_empty())
                .map(String::from)
        })
        .collect();
    found.sort();
    (!found.is_empty()).then(|| found.join(", "))
}

fn main() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();

    let backend = match select_backend(&args, home::home_dir().as_deref()) {
        Ok(backend) => backend,
        Err(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::FAILURE;
        }
    };

    match dispatch(&locate_backend_binary(&backend), &args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use super::{
        ConfigLocator, DEFAULT_BACKEND, backend_binary_name, backend_from_config,
        resolve_config_path, scan_locator_args, select_backend,
    };

    fn args(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn locator_scanning_matches_clap_forms() {
        for case in [
            &["--datadir", "/dd", "--config", "conf.toml"][..],
            &["--datadir=/dd", "--config=conf.toml"],
            &["-d", "/dd", "-c", "conf.toml"],
            &["-d=/dd", "-c=conf.toml"],
            &["-d/dd", "-cconf.toml"],
            &["start", "--datadir", "/dd", "-c", "conf.toml"],
        ] {
            assert_eq!(
                scan_locator_args(&args(case)),
                ConfigLocator {
                    datadir: Some(PathBuf::from("/dd")),
                    config: Some(PathBuf::from("conf.toml")),
                },
                "case: {case:?}",
            );
        }
    }

    #[test]
    fn locator_scanning_stops_at_double_dash() {
        assert_eq!(
            scan_locator_args(&args(&["start", "--", "--datadir", "/dd"])),
            ConfigLocator::default(),
        );
    }

    #[test]
    fn config_path_resolution() {
        // Explicit datadir, default config name.
        assert_eq!(
            resolve_config_path(
                &ConfigLocator {
                    datadir: Some("/dd".into()),
                    config: None,
                },
                Some(Path::new("/home/u")),
            ),
            Some(PathBuf::from("/dd/zallet.toml")),
        );
        // Default datadir under the home directory.
        assert_eq!(
            resolve_config_path(&ConfigLocator::default(), Some(Path::new("/home/u"))),
            Some(PathBuf::from("/home/u/.zallet/zallet.toml")),
        );
        // Relative --config resolves under the datadir; absolute wins outright.
        assert_eq!(
            resolve_config_path(
                &ConfigLocator {
                    datadir: Some("/dd".into()),
                    config: Some("sub/c.toml".into()),
                },
                None,
            ),
            Some(PathBuf::from("/dd/sub/c.toml")),
        );
        assert_eq!(
            resolve_config_path(
                &ConfigLocator {
                    datadir: Some("/dd".into()),
                    config: Some("/abs/c.toml".into()),
                },
                None,
            ),
            Some(PathBuf::from("/abs/c.toml")),
        );
    }

    #[test]
    fn backend_peeking() {
        assert_eq!(backend_from_config(""), Ok(DEFAULT_BACKEND.into()));
        assert_eq!(
            backend_from_config("backend = \"zebra\"\n[rpc]\n"),
            Ok("zebra".into()),
        );
        assert_eq!(
            backend_from_config("backend = \"zaino\"\n"),
            Ok("zaino".into()),
        );
        // Backend names are an open namespace: whether a backend by this name is
        // installed is discovered at dispatch time.
        assert_eq!(
            backend_from_config("backend = \"bitcoind\""),
            Ok("bitcoind".into()),
        );
        // Malformed names are an error the launcher owns (no binary to defer to);
        // the charset rule keeps names safe to embed in a binary filename.
        for bad in [
            "backend = \"Zebra-State\"",
            "backend = \"../evil\"",
            "backend = \"\"",
            "backend = 7",
        ] {
            assert!(
                backend_from_config(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
        // Unparseable files are the launcher's error: a malformed config must not
        // silently dispatch to the default backend.
        assert!(
            backend_from_config("this is { not toml")
                .is_err_and(|e| e.contains("failed to parse config file")),
        );
    }

    #[test]
    fn missing_config_file_selects_default_backend() {
        assert_eq!(
            select_backend(
                &args(&["--datadir", "/nonexistent-dir-for-zallet-tests"]),
                None,
            ),
            Ok(DEFAULT_BACKEND.into()),
        );
    }

    #[test]
    fn backend_binary_names_follow_the_convention() {
        assert_eq!(backend_binary_name("zebra"), "zallet-zebra");
        assert_eq!(backend_binary_name("zaino"), "zallet-zaino");
        assert_eq!(backend_binary_name("frobnicator"), "zallet-frobnicator");
    }
}
