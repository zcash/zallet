use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use super::openrpc::METHODS;

/// Response to a `help` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The help response.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(String);

pub(super) const PARAM_COMMAND_DESC: &str = "The command to get help on.";

pub(crate) fn call(command: Option<&str>) -> Response {
    Ok(ResultType(if let Some(command) = command {
        match METHODS.get(command) {
            None => format!("help: unknown command: {command}\n"),
            Some(method) => format!("{command}\n\n{}", method.description),
        }
    } else {
        let mut commands = METHODS.entries().collect::<Vec<_>>();
        commands.sort_by_cached_key(|(command, _)| command.to_string());

        let mut ret = String::new();
        for (command, _) in commands {
            ret.push_str(command);
            ret.push('\n');
        }
        ret
    }))
}
