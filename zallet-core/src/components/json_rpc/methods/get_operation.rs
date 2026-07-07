use std::collections::HashSet;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use crate::components::json_rpc::asyncop::{
    AsyncOperation, OperationId, OperationState, OperationStatus,
};

/// Response to a `z_getoperationstatus` or `z_getoperationresult` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The relevant operations.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(Vec<OperationStatus>);

pub(super) const PARAM_OPERATIONID_DESC: &str = "A list of operation ids we are interested in.";
pub(super) const PARAM_OPERATIONID_REQUIRED: bool = false;

pub(crate) async fn status(
    async_ops: &[AsyncOperation],
    operationid: Vec<OperationId>,
) -> Response {
    let filter = operationid.into_iter().collect::<HashSet<_>>();

    let mut ret = vec![];

    for op in filtered(async_ops, filter) {
        ret.push(op.to_status().await);
    }

    Ok(ResultType(ret))
}

pub(crate) async fn result(
    async_ops: &mut Vec<AsyncOperation>,
    operationid: Vec<OperationId>,
) -> Response {
    let filter = operationid.into_iter().collect::<HashSet<_>>();

    let mut ret = vec![];
    let mut remove = HashSet::new();

    for op in filtered(async_ops, filter) {
        if matches!(
            op.state().await,
            OperationState::Success | OperationState::Failed | OperationState::Cancelled
        ) {
            ret.push(op.to_status().await);
            remove.insert(op.operation_id().clone());
        }
    }

    async_ops.retain(|op| !remove.contains(op.operation_id()));

    Ok(ResultType(ret))
}

fn filtered(
    async_ops: &[AsyncOperation],
    filter: HashSet<OperationId>,
) -> impl Iterator<Item = &AsyncOperation> {
    async_ops
        .iter()
        .filter(move |op| filter.is_empty() || filter.contains(op.operation_id()))
}
