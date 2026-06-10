use std::collections::HashSet;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use crate::components::json_rpc::asyncop::{AsyncOperation, OperationId, OperationStatus};

/// Response to a `z_getoperationstatus` or `z_getoperationresult` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The relevant operations.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(Vec<OperationStatus>);

pub(super) const PARAM_OPERATIONID_DESC: &str = "A list of operation ids we are interested in.";
pub(super) const PARAM_OPERATIONID_REQUIRED: bool = false;

/// Removes finished operations from the queue.
pub(super) async fn prune_finished(async_ops: &mut Vec<AsyncOperation>) {
    let mut pending = Vec::with_capacity(async_ops.len());
    for op in async_ops.drain(..) {
        if op.state().await.is_finished() {
            continue;
        }
        pending.push(op);
    }
    *async_ops = pending;
}

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
        if op.state().await.is_finished() {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use tokio::time::sleep;

    use super::*;
    use crate::components::json_rpc::asyncop::{ContextInfo, MAX_ASYNC_OPERATIONS};

    async fn wait_until_finished(op: &AsyncOperation) {
        while !op.state().await.is_finished() {
            sleep(Duration::from_millis(1)).await;
        }
    }

    #[tokio::test]
    async fn prune_finished_removes_completed_operations() {
        let finished = AsyncOperation::new(Some(ContextInfo::new("test", json!({}))), async {
            Ok::<(), _>(())
        })
        .await;
        wait_until_finished(&finished).await;

        let pending = AsyncOperation::new(Some(ContextInfo::new("test", json!({}))), async {
            sleep(Duration::from_secs(60)).await;
            Ok::<(), _>(())
        })
        .await;
        let pending_id = pending.operation_id().clone();

        let mut ops = vec![finished, pending];
        prune_finished(&mut ops).await;

        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].operation_id(), &pending_id);
    }

    #[test]
    fn max_async_operations_matches_bitcoin_rpc_workqueue() {
        assert_eq!(MAX_ASYNC_OPERATIONS, 64);
    }
}
