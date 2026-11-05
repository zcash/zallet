//! `rpc` subcommand

use std::fmt;
use std::time::Duration;

use abscissa_core::Runnable;
use age::secrecy::zeroize::Zeroizing;
use base64ct::{Base64, Encoding};
use hyper::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use jsonrpsee::core::{client::ClientT, params::ArrayParams};
use jsonrpsee_http_client::HttpClientBuilder;
use secrecy::{ExposeSecret, SecretString};
use tracing::warn;

use crate::{
    cli::RpcCliCmd, commands::AsyncRunnable, components::json_rpc::server::cookie, error::Error,
    fl, prelude::*,
};

const DEFAULT_HTTP_CLIENT_TIMEOUT: u64 = 900;

macro_rules! wfl {
    ($f:ident, $message_id:literal) => {
        write!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        write!($f, "{}", $crate::fl!($message_id, $($args), *))
    };
}

#[allow(unused_macros)]
macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        writeln!($f, "{}", $crate::fl!($message_id, $($args), *))
    };
}

impl AsyncRunnable for RpcCliCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();

        // `help` is generated from static method metadata, so answer it locally
        // instead of requiring a wallet with a running JSON-RPC server.
        #[cfg(zallet_build = "wallet")]
        if self.command == "help" {
            let command = match self.params.as_slice() {
                [] => None,
                [command] => Some(
                    serde_json::from_str::<String>(command).unwrap_or_else(|_| command.clone()),
                ),
                [_, param, ..] => {
                    return Err(RpcCliError::InvalidParameter(param.clone()).into());
                }
            };
            print!(
                "{}",
                crate::components::json_rpc::methods::help::text(
                    config.consensus.network,
                    command.as_deref(),
                )
            );
            return Ok(());
        }

        let timeout = Duration::from_secs(match self.timeout {
            Some(0) => u64::MAX,
            Some(timeout) => timeout,
            None => DEFAULT_HTTP_CLIENT_TIMEOUT,
        });

        // Find credentials: prefer configured password, fall back to cookie file.
        let credentials = config
            .rpc
            .auth
            .iter()
            .find_map(|auth| {
                auth.password
                    .as_ref()
                    .map(|pw| SecretString::new(format!("{}:{}", auth.user, pw.expose_secret())))
            })
            .or_else(|| {
                // Fall back to cookie-based auth.
                cookie::read_cookie(config.datadir())
                    .map_err(|err| {
                        warn!("{}", fl!("rpc-cookie-read-failed", error = err.to_string()));
                    })
                    .ok()
                    .map(SecretString::new)
            });

        // Build auth header if credentials are available.
        let mut headers = HeaderMap::new();
        if let Some(creds) = &credentials {
            let encoded = Base64::encode_string(creds.expose_secret().as_bytes());
            let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
                .map_err(|_| RpcCliError::FailedToConnect)?;
            value.set_sensitive(true);
            headers.insert(AUTHORIZATION, value);
        }

        // Connect to the Zallet wallet.
        let client = match config.rpc.bind.as_slice() {
            &[] => Err(RpcCliError::WalletHasNoRpcServer),
            &[bind] => HttpClientBuilder::default()
                .request_timeout(timeout)
                .set_headers(headers.clone())
                .build(format!("http://{bind}"))
                .map_err(|_| RpcCliError::FailedToConnect),
            addrs => addrs
                .iter()
                .find_map(|bind| {
                    HttpClientBuilder::default()
                        .request_timeout(timeout)
                        .set_headers(headers.clone())
                        .build(format!("http://{bind}"))
                        .ok()
                })
                .ok_or(RpcCliError::FailedToConnect),
        }?;

        // Construct the request.
        let mut params = ArrayParams::new();
        for param in &self.params {
            let value = match param.strip_prefix('@') {
                Some(source) => serde_json::Value::String(read_indirect_param(source)?),
                None => serde_json::from_str(param)
                    .map_err(|_| RpcCliError::InvalidParameter(param.clone()))?,
            };
            params
                .insert(value)
                .map_err(|_| RpcCliError::InvalidParameter(param.clone()))?;
        }

        // Make the request.
        let response: serde_json::Value = client
            .request(&self.command, params)
            .await
            .map_err(|e| RpcCliError::RequestFailed(e.to_string()))?;

        // Print the response.
        match response {
            serde_json::Value::String(s) => print!("{s}"),
            _ => serde_json::to_writer_pretty(std::io::stdout(), &response)
                .expect("response should be valid"),
        }

        Ok(())
    }
}

/// Reads the value of an `@PATH` parameter: the first line of `PATH`, without its line
/// terminator.
///
/// `-` means standard input, prompting without echo when it is a terminal. This exists so
/// that secret parameters (a `z_importkey` spending key, a `walletpassphrase` passphrase)
/// never have to appear in the process argument vector, where other local users can read
/// them from process listings and where the shell records them in its history.
fn read_indirect_param(source: &str) -> Result<String, RpcCliError> {
    use std::io::{BufRead, IsTerminal};

    let read_failed = |e: std::io::Error| RpcCliError::ParamReadFailed {
        source: source.to_string(),
        error: e.to_string(),
    };

    if source == "-" && std::io::stdin().is_terminal() {
        return rpassword::prompt_password(fl!("rpc-cli-param-prompt")).map_err(read_failed);
    }

    // The buffer holds the parameter in the clear, so zeroize it on drop.
    let mut buf = Zeroizing::new(Vec::new());
    if source == "-" {
        std::io::stdin()
            .lock()
            .read_until(b'\n', &mut buf)
            .map_err(read_failed)?;
    } else {
        let file = std::fs::File::open(source).map_err(read_failed)?;
        std::io::BufReader::new(file)
            .read_until(b'\n', &mut buf)
            .map_err(read_failed)?;
    }

    while matches!(buf.last(), Some(b'\n' | b'\r')) {
        buf.pop();
    }

    std::str::from_utf8(&buf)
        .map(|s| s.to_owned())
        .map_err(|e| RpcCliError::ParamReadFailed {
            source: source.to_string(),
            error: e.to_string(),
        })
}

impl Runnable for RpcCliCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}

/// Errors that can occur while running the `zallet rpc` client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcCliError {
    /// The wallet's JSON-RPC server could not be reached.
    FailedToConnect,
    /// A request parameter was not valid JSON.
    InvalidParameter(String),
    /// An `@PATH` request parameter could not be read.
    ParamReadFailed {
        /// The `PATH` the parameter was to be read from.
        source: String,
        /// Why reading it failed.
        error: String,
    },
    /// The JSON-RPC request failed.
    RequestFailed(String),
    /// The wallet is not running a JSON-RPC server.
    WalletHasNoRpcServer,
}

impl fmt::Display for RpcCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedToConnect => wfl!(f, "err-rpc-cli-conn-failed"),
            Self::InvalidParameter(param) => {
                wfl!(f, "err-rpc-cli-invalid-param", parameter = param)
            }
            Self::ParamReadFailed { source, error } => {
                wfl!(
                    f,
                    "err-rpc-cli-param-read-failed",
                    path = source,
                    error = error
                )
            }
            Self::RequestFailed(e) => {
                wfl!(f, "err-rpc-cli-request-failed", error = e)
            }
            Self::WalletHasNoRpcServer => wfl!(f, "err-rpc-cli-no-server"),
        }
    }
}

impl std::error::Error for RpcCliError {}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::read_indirect_param;

    /// Writes `contents` to a temporary file and returns its path.
    fn temp_file(contents: &[u8]) -> tempfile::TempPath {
        let mut f = tempfile::NamedTempFile::new().expect("creates temp file");
        f.write_all(contents).expect("writes temp file");
        f.into_temp_path()
    }

    /// Only the first line is taken, and the line terminator is not part of the value:
    /// a here-doc or `echo` adds a trailing newline that is not part of the secret.
    #[test]
    fn reads_first_line_without_terminator() {
        for (contents, expected) in [
            (&b"secret-key"[..], "secret-key"),
            (&b"secret-key\n"[..], "secret-key"),
            (&b"secret-key\r\n"[..], "secret-key"),
            (&b"secret-key\nnot this\n"[..], "secret-key"),
            (&b""[..], ""),
        ] {
            let path = temp_file(contents);
            assert_eq!(
                read_indirect_param(path.to_str().expect("valid path")).expect("reads param"),
                expected,
                "contents {contents:?}",
            );
        }
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(read_indirect_param("/nonexistent/zallet-rpc-param").is_err());
    }
}
