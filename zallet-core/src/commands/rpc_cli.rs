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
use serde_json::Value;
use tracing::warn;

use crate::{
    cli::RpcCliCmd,
    commands::AsyncRunnable,
    components::json_rpc::{methods::rpc_cli, server::cookie},
    error::Error,
    fl,
    prelude::*,
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
        let converted_params = convert_params(&self.command, &self.params)?;
        let config = APP.config();

        // `help` is generated from static method metadata, so answer it locally
        // instead of requiring a wallet with a running JSON-RPC server.
        #[cfg(zallet_build = "wallet")]
        if self.command == "help" {
            print!(
                "{}",
                crate::components::json_rpc::methods::help::text(
                    config.consensus.network,
                    help_command(&converted_params),
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
        for value in converted_params {
            params
                .insert(value)
                .expect("serde_json::Value always serializes");
        }

        // Make the request.
        let response: Value = client
            .request(&self.command, params)
            .await
            .map_err(|e| RpcCliError::RequestFailed(e.to_string()))?;

        // Print the response.
        match response {
            Value::String(s) => print!("{s}"),
            _ => serde_json::to_writer_pretty(std::io::stdout(), &response)
                .expect("response should be valid"),
        }

        Ok(())
    }
}

fn convert_direct_param(
    raw: &str,
    position: usize,
    parameter: Option<&rpc_cli::Parameter>,
) -> Result<Value, RpcCliError> {
    match parameter.map_or(rpc_cli::Conversion::Json, |parameter| {
        parameter.conversion()
    }) {
        rpc_cli::Conversion::String => Ok(Value::String(
            serde_json::from_str::<String>(raw).unwrap_or_else(|_| raw.to_owned()),
        )),
        rpc_cli::Conversion::NullableString if raw == "null" => Ok(Value::Null),
        rpc_cli::Conversion::NullableString => Ok(Value::String(
            serde_json::from_str::<String>(raw).unwrap_or_else(|_| raw.to_owned()),
        )),
        rpc_cli::Conversion::Json => {
            serde_json::from_str(raw).map_err(|_| RpcCliError::InvalidJsonParameter {
                position,
                name: parameter.map(rpc_cli::Parameter::name),
            })
        }
    }
}

fn convert_params(command: &str, raw_params: &[String]) -> Result<Vec<Value>, RpcCliError> {
    let method = rpc_cli::get(command);
    if let Some(method) = method {
        let minimum = method.minimum_params();
        let maximum = method.maximum_params();
        let provided = raw_params.len();
        if !(minimum..=maximum).contains(&provided) {
            return Err(RpcCliError::WrongParameterCount {
                command: command.to_owned(),
                minimum,
                maximum,
                provided,
            });
        }
    }

    raw_params
        .iter()
        .enumerate()
        .map(|(index, raw)| match raw.strip_prefix('@') {
            Some(source) => read_indirect_param(source).map(Value::String),
            None => convert_direct_param(
                raw,
                index + 1,
                method.and_then(|method| method.params().get(index)),
            ),
        })
        .collect()
}

#[cfg(zallet_build = "wallet")]
fn help_command(params: &[Value]) -> Option<&str> {
    match params {
        [] | [Value::Null] => None,
        [Value::String(command)] => Some(command),
        _ => unreachable!("generated help metadata only yields a nullable string"),
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
    InvalidJsonParameter {
        /// The one-based position of the invalid parameter.
        position: usize,
        /// The generated parameter name, when the method is known to this binary.
        name: Option<&'static str>,
    },
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
    /// A known RPC method received the wrong number of parameters.
    WrongParameterCount {
        /// The RPC method name.
        command: String,
        /// The minimum accepted number of positional parameters.
        minimum: usize,
        /// The maximum accepted number of positional parameters.
        maximum: usize,
        /// The number of positional parameters provided.
        provided: usize,
    },
}

impl fmt::Display for RpcCliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedToConnect => wfl!(f, "err-rpc-cli-conn-failed"),
            Self::InvalidJsonParameter {
                position,
                name: Some(name),
            } => {
                wfl!(
                    f,
                    "err-rpc-cli-invalid-named-param",
                    position = position.to_string(),
                    name = (*name).to_owned()
                )
            }
            Self::InvalidJsonParameter {
                position,
                name: None,
            } => {
                wfl!(
                    f,
                    "err-rpc-cli-invalid-param",
                    position = position.to_string()
                )
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
            Self::WrongParameterCount {
                command,
                minimum,
                maximum,
                provided,
            } => {
                wfl!(
                    f,
                    "err-rpc-cli-wrong-param-count",
                    method = command.as_str().to_owned(),
                    minimum = minimum.to_string(),
                    maximum = maximum.to_string(),
                    provided = provided.to_string()
                )
            }
        }
    }
}

impl std::error::Error for RpcCliError {}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use serde_json::{Value, json};

    #[cfg(zallet_build = "wallet")]
    use super::help_command;
    use super::{RpcCliError, convert_params, read_indirect_param};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// The language loader is process-global. A parallel test can reload its Fluent
    /// bundles between `load_languages` disabling isolation and this test formatting a
    /// message, transiently restoring the default directionality markers. Remove only
    /// those presentation markers so the message text remains an exact assertion.
    fn without_fluent_isolation_marks(message: &str) -> String {
        message.replace(['\u{2068}', '\u{2069}'], "")
    }

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
    fn known_strings_accept_bare_and_json_quoted_values() {
        for raw in ["alice", r#""alice""#] {
            assert_eq!(
                convert_params("z_getaccount", &args(&[raw])).expect("valid parameter"),
                vec![json!("alice")],
            );
        }

        assert_eq!(
            convert_params("z_getaccount", &args(&["null"])).expect("valid string"),
            vec![json!("null")],
        );
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn nullable_strings_distinguish_null_from_the_string_null() {
        assert_eq!(
            convert_params("help", &args(&["null"])).expect("valid null"),
            vec![Value::Null],
        );
        assert_eq!(
            convert_params("help", &args(&[r#""null""#])).expect("valid string"),
            vec![json!("null")],
        );
    }

    #[test]
    fn known_json_parameters_remain_strict_json() {
        for raw in ["null", "true", "42", "[]", "{}", r#""alice""#] {
            assert_eq!(
                convert_params("z_getaddressforaccount", &args(&[raw]))
                    .expect("valid JSON parameter"),
                vec![serde_json::from_str::<Value>(raw).expect("test JSON")],
            );
        }
    }

    #[test]
    fn invalid_json_names_the_position_without_echoing_contents() {
        crate::i18n::load_languages(&[]);

        let sensitive = "not-json-sensitive-address";
        let error = convert_params("z_getaddressforaccount", &args(&[sensitive]))
            .expect_err("JSON parameter must stay strict");

        assert_eq!(
            error,
            RpcCliError::InvalidJsonParameter {
                position: 1,
                name: Some("account"),
            },
        );
        let message = error.to_string();
        assert_eq!(
            without_fluent_isolation_marks(&message),
            "Parameter 1 (account) must be valid JSON.",
        );
        assert!(!message.contains(sensitive));
    }

    #[test]
    fn validates_known_method_arity() {
        crate::i18n::load_languages(&[]);

        let too_few = convert_params("z_getaccount", &[]).expect_err("one required parameter");
        assert_eq!(
            too_few,
            RpcCliError::WrongParameterCount {
                command: "z_getaccount".to_owned(),
                minimum: 1,
                maximum: 1,
                provided: 0,
            },
        );
        let message = too_few.to_string();
        assert_eq!(
            without_fluent_isolation_marks(&message),
            "Wrong number of parameters for 'z_getaccount': expected 1 to 1, received 0.",
        );
        assert_eq!(
            convert_params("z_getaccount", &args(&[r#""a""#, r#""b""#]))
                .expect_err("one maximum parameter"),
            RpcCliError::WrongParameterCount {
                command: "z_getaccount".to_owned(),
                minimum: 1,
                maximum: 1,
                provided: 2,
            },
        );
    }

    #[test]
    fn required_vec_parameter_is_not_optional() {
        assert!(matches!(
            convert_params("pczt_combine", &[]),
            Err(RpcCliError::WrongParameterCount { minimum: 1, .. })
        ));
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn supports_optional_parameters_and_vecs() {
        assert_eq!(convert_params("help", &[]), Ok(vec![]));
        assert_eq!(convert_params("z_getoperationstatus", &[]), Ok(vec![]));
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn later_required_parameter_sets_the_minimum_position() {
        let raw = args(&[
            r#""account-id""#,
            r#""orchard""#,
            "[]",
            "null",
            "AllowRevealedAmounts",
        ]);
        assert_eq!(
            convert_params("z_sendfromaccount", &raw).expect("explicit null placeholder"),
            vec![
                json!("account-id"),
                json!("orchard"),
                json!([]),
                Value::Null,
                json!("AllowRevealedAmounts"),
            ],
        );
        assert!(matches!(
            convert_params("z_sendfromaccount", &raw[..4]),
            Err(RpcCliError::WrongParameterCount {
                minimum: 5,
                maximum: 5,
                provided: 4,
                ..
            })
        ));
    }

    #[test]
    fn unknown_methods_keep_json_only_parsing_without_an_arity_limit() {
        crate::i18n::load_languages(&[]);

        assert_eq!(
            convert_params("remote_only", &args(&["1", "true", "null", "[]", "{}"])),
            Ok(vec![
                json!(1),
                json!(true),
                Value::Null,
                json!([]),
                json!({}),
            ]),
        );

        let sensitive = "bare-string";
        let error = convert_params("remote_only", &args(&[sensitive]))
            .expect_err("unknown methods remain JSON-only");
        assert_eq!(
            error,
            RpcCliError::InvalidJsonParameter {
                position: 1,
                name: None,
            },
        );
        let message = error.to_string();
        assert_eq!(
            without_fluent_isolation_marks(&message),
            "Parameter 1 must be valid JSON.",
        );
        assert!(!message.contains(sensitive));
    }

    #[test]
    fn indirect_parameters_are_strings_for_every_conversion() {
        let path = temp_file(b"indirect-value\n");
        let indirect = format!("@{}", path.display());

        for command in ["z_getaccount", "z_getaddressforaccount"] {
            assert_eq!(
                convert_params(command, std::slice::from_ref(&indirect))
                    .expect("reads indirect parameter"),
                vec![json!("indirect-value")],
            );
        }

        #[cfg(zallet_build = "wallet")]
        assert_eq!(
            convert_params("help", std::slice::from_ref(&indirect))
                .expect("reads nullable indirect parameter"),
            vec![json!("indirect-value")],
        );
    }

    #[test]
    fn arity_is_validated_before_indirect_io() {
        let raw = args(&["@C:/definitely/not/a/zallet/parameter", r#""extra""#]);
        assert!(matches!(
            convert_params("z_getaccount", &raw),
            Err(RpcCliError::WrongParameterCount {
                minimum: 1,
                maximum: 1,
                provided: 2,
                ..
            })
        ));
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn local_help_consumes_the_common_conversion() {
        for raw in ["z_getaccount", r#""z_getaccount""#] {
            let params = convert_params("help", &args(&[raw])).expect("valid help parameter");
            assert_eq!(help_command(&params), Some("z_getaccount"));
        }

        assert_eq!(help_command(&[]), None);
        let null = convert_params("help", &args(&["null"])).expect("valid null");
        assert_eq!(help_command(&null), None);
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(matches!(
            read_indirect_param("/nonexistent/zallet-rpc-param"),
            Err(RpcCliError::ParamReadFailed { .. })
        ));
    }
}
