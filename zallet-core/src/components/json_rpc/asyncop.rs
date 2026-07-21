use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use documented::Documented;
use futures::FutureExt;
use jsonrpsee::{
    core::{JsonValue, RpcResult},
    types::ErrorObjectOwned,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::server::LegacyCode;

/// An async operation ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, Documented, JsonSchema)]
#[serde(try_from = "String")]
pub(crate) struct OperationId(String);

impl OperationId {
    fn new() -> Self {
        Self(format!("opid-{}", Uuid::new_v4()))
    }
}

impl TryFrom<String> for OperationId {
    type Error = ErrorObjectOwned;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let uuid = value
            .strip_prefix("opid-")
            .ok_or_else(|| LegacyCode::InvalidParameter.with_static("Invalid operation ID"))?;
        Uuid::try_parse(uuid)
            .map_err(|_| LegacyCode::InvalidParameter.with_static("Invalid operation ID"))?;
        Ok(Self(value))
    }
}

pub(super) struct ContextInfo {
    method: &'static str,
    params: JsonValue,
}

impl ContextInfo {
    pub(super) fn new(method: &'static str, params: JsonValue) -> Self {
        Self { method, params }
    }
}

/// The possible states that an async operation can be in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(into = "&'static str")]
pub(super) enum OperationState {
    Ready,
    Executing,
    Cancelled,
    Failed,
    Success,
}

impl OperationState {
    pub(super) fn parse(s: &str) -> Option<Self> {
        match s {
            "queued" => Some(Self::Ready),
            "executing" => Some(Self::Executing),
            "cancelled" => Some(Self::Cancelled),
            "failed" => Some(Self::Failed),
            "success" => Some(Self::Success),
            _ => None,
        }
    }
}

impl From<OperationState> for &'static str {
    fn from(value: OperationState) -> Self {
        match value {
            OperationState::Ready => "queued",
            OperationState::Executing => "executing",
            OperationState::Cancelled => "cancelled",
            OperationState::Failed => "failed",
            OperationState::Success => "success",
        }
    }
}

/// Data associated with an async operation.
pub(super) struct OperationData {
    state: OperationState,
    start_time: Option<SystemTime>,
    end_time: Option<SystemTime>,
    result: Option<RpcResult<Value>>,
}

/// An async operation launched by an RPC call.
pub(super) struct AsyncOperation {
    operation_id: OperationId,
    context: Option<ContextInfo>,
    creation_time: SystemTime,
    data: Arc<RwLock<OperationData>>,
}

impl AsyncOperation {
    /// Launches a new async operation.
    pub(super) async fn new<T: Serialize + Send + 'static>(
        context: Option<ContextInfo>,
        f: impl Future<Output = RpcResult<T>> + Send + 'static,
    ) -> Self {
        let creation_time = SystemTime::now();

        let data = Arc::new(RwLock::new(OperationData {
            state: OperationState::Ready,
            start_time: None,
            end_time: None,
            result: None,
        }));

        let handle = data.clone();

        crate::spawn!(
            context
                .as_ref()
                .map(|context| context.method)
                .unwrap_or("AsyncOp"),
            async move {
                // Record that the task has started.
                {
                    let mut data = handle.write().await;
                    if matches!(data.state, OperationState::Cancelled) {
                        return;
                    }
                    data.state = OperationState::Executing;
                    data.start_time = Some(SystemTime::now());
                }

                // Run the async task, mapping the concrete result into a generic JSON
                // blob. A panic is recorded as a failure of the operation, so it does
                // not remain in the `Executing` state forever.
                let res = AssertUnwindSafe(async {
                    f.await.and_then(|ret| {
                        serde_json::to_value(ret).map_err(|e| {
                            LegacyCode::Misc
                                .with_message(format!("Failed to serialize operation result: {e}"))
                        })
                    })
                })
                .catch_unwind()
                .await
                .unwrap_or_else(|panic| {
                    let msg = panic
                        .downcast_ref::<&str>()
                        .copied()
                        .map(String::from)
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".into());
                    Err(LegacyCode::Misc.with_message(format!("Async operation panicked: {msg}")))
                });
                let end_time = SystemTime::now();

                // Record the result.
                let mut data = handle.write().await;
                data.state = if res.is_ok() {
                    OperationState::Success
                } else {
                    OperationState::Failed
                };
                data.end_time = Some(end_time);
                data.result = Some(res);
            }
        );

        Self {
            operation_id: OperationId::new(),
            context,
            creation_time,
            data,
        }
    }

    /// Returns the ID of this operation.
    pub(super) fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the current state of this operation.
    pub(super) async fn state(&self) -> OperationState {
        self.data.read().await.state
    }

    /// Builds the current status of this operation.
    pub(super) async fn to_status(&self) -> OperationStatus {
        let data = self.data.read().await;

        let (method, params) = self
            .context
            .as_ref()
            .map(|context| (context.method, context.params.clone()))
            .unzip();

        let creation_time = self
            .creation_time
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let (error, result, execution_secs) = match &data.result {
            None => (None, None, None),
            Some(Err(e)) => (
                Some(OperationError {
                    code: e.code(),
                    message: e.message().to_string(),
                    data: e.data().map(|data| data.get().to_string()),
                }),
                None,
                None,
            ),
            Some(Ok(v)) => (
                None,
                Some(v.clone()),
                data.end_time.zip(data.start_time).map(|(end, start)| {
                    end.duration_since(start)
                        .ok()
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                }),
            ),
        };

        OperationStatus {
            id: self.operation_id.clone(),
            method,
            params,
            status: data.state,
            creation_time,
            error,
            result,
            execution_secs,
        }
    }
}

/// The status of an async operation.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct OperationStatus {
    id: OperationId,

    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'static str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<JsonValue>,

    status: OperationState,

    // The creation time, in seconds since the Unix epoch.
    creation_time: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<OperationError>,

    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,

    /// Execution time for successful operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_secs: Option<u64>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct OperationError {
    /// Code
    code: i32,

    /// Message
    message: String,

    /// Optional data
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn wait_for_terminal(op: &AsyncOperation) {
        for _ in 0..100 {
            if !matches!(
                op.state().await,
                OperationState::Ready | OperationState::Executing
            ) {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("operation did not reach a terminal state");
    }

    #[tokio::test]
    async fn task_panic_marks_operation_failed() {
        let op = AsyncOperation::new(None, async {
            panic!("something went wrong");
            #[allow(unreachable_code)]
            Ok(0_u32)
        })
        .await;

        wait_for_terminal(&op).await;
        assert_eq!(op.state().await, OperationState::Failed);

        let status = op.to_status().await;
        let error = status.error.expect("panic should be recorded as an error");
        assert_eq!(error.code, LegacyCode::Misc as i32);
        assert_eq!(
            error.message,
            "Async operation panicked: something went wrong",
        );
    }

    #[tokio::test]
    async fn unserializable_result_marks_operation_failed() {
        let op = AsyncOperation::new(None, async {
            Ok(std::collections::HashMap::from([(vec![0_u8], 0_u32)]))
        })
        .await;

        wait_for_terminal(&op).await;
        assert_eq!(op.state().await, OperationState::Failed);

        let status = op.to_status().await;
        let error = status
            .error
            .expect("serialization failure should be recorded as an error");
        assert_eq!(error.code, LegacyCode::Misc as i32);
        assert!(error.message.starts_with("Failed to serialize"));
    }

    #[tokio::test]
    async fn successful_task_records_result() {
        let op = AsyncOperation::new(None, async { Ok(42_u32) }).await;

        wait_for_terminal(&op).await;
        assert_eq!(op.state().await, OperationState::Success);

        let status = op.to_status().await;
        assert!(status.error.is_none());
        assert_eq!(status.result, Some(Value::from(42_u32)));
    }
}
