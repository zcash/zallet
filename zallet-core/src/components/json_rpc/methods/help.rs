use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_protocol::consensus::NetworkType;

use super::{REGTEST_ONLY_METHODS, openrpc::METHODS};

/// Response to a `help` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The help response.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(String);

pub(super) const PARAM_COMMAND_DESC: &str = "The command to get help on.";

pub(crate) fn call(network: NetworkType, command: Option<&str>) -> Response {
    Ok(ResultType(text(network, command)))
}

pub(crate) fn text(network: NetworkType, command: Option<&str>) -> String {
    // Regtest-only commands return a "method not found" error on other networks, so
    // hide them from help there as well.
    let available =
        |command: &str| network == NetworkType::Regtest || !REGTEST_ONLY_METHODS.contains(&command);

    if let Some(command) = command {
        match METHODS.get(command).filter(|_| available(command)) {
            None => format!("help: unknown command: {command}\n"),
            Some(method) => format!("{command}\n\n{}", method.description),
        }
    } else {
        let mut commands = METHODS
            .entries()
            .filter(|(command, _)| available(command))
            .collect::<Vec<_>>();
        commands.sort_by_cached_key(|(command, _)| command.to_string());

        let mut ret = String::new();
        for (command, _) in commands {
            ret.push_str(command);
            ret.push('\n');
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::NetworkType;

    use super::{REGTEST_ONLY_METHODS, text};

    #[test]
    fn regtest_only_methods_are_hidden_on_other_networks() {
        for method in REGTEST_ONLY_METHODS {
            for network in [NetworkType::Main, NetworkType::Test] {
                assert!(!text(network, None).lines().any(|line| line == *method));
                assert_eq!(
                    text(network, Some(method)),
                    format!("help: unknown command: {method}\n"),
                );
            }

            assert!(
                text(NetworkType::Regtest, None)
                    .lines()
                    .any(|line| line == *method)
            );
            assert!(!text(NetworkType::Regtest, Some(method)).starts_with("help:"));
        }
    }
}
