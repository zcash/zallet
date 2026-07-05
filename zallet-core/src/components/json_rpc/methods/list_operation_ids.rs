use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use crate::components::json_rpc::asyncop::{AsyncOperation, OperationId, OperationState};

/// Response to a `z_listoperationids` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// A list of operation IDs.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(Vec<OperationId>);

pub(super) const PARAM_STATUS_DESC: &str =
    "Filter result by the operation's state e.g. \"success\".";

pub(crate) async fn call(async_ops: &[AsyncOperation], status: Option<&str>) -> Response {
    // - The outer `Option` indicates whether or not we are filtering.
    // - The inner `Option` indicates whether or not we recognise the requested state
    //   (`zcashd` treats unrecognised state strings as non-matching).
    let state = status.map(OperationState::parse);

    let mut operation_ids = vec![];

    for op in async_ops {
        match state {
            None => operation_ids.push(op.operation_id().clone()),
            Some(f) => {
                let op_state = op.state().await;
                if f == Some(op_state) {
                    operation_ids.push(op.operation_id().clone());
                }
            }
        }
    }

    Ok(ResultType(operation_ids))
}
