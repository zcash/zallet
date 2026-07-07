//! Compatibility fixes for JSON-RPC remote procedure calls.
//!
//! These fixes are applied at the JSON-RPC call level,
//! after the RPC request is parsed and split into calls.

use futures::future::BoxFuture;
use jsonrpsee::{
    MethodResponse,
    server::middleware::rpc::{RpcService, RpcServiceT, layer::ResponseFuture},
    tracing::debug,
    types::{ErrorCode, ErrorObject, Response, ResponsePayload},
};

use crate::components::json_rpc::server::error::LegacyCode;

/// JSON-RPC [`FixRpcResponseMiddleware`] with compatibility workarounds.
///
/// This middleware makes the following changes to JSON-RPC calls:
///
/// ## Make RPC framework response codes match `zcashd`
///
/// [`jsonrpsee::types`] returns specific error codes while parsing requests:
/// <https://docs.rs/jsonrpsee-types/latest/jsonrpsee_types/error/enum.ErrorCode.html>
///
/// But these codes are different from `zcashd`, and some RPC clients rely on the exact
/// code.
pub struct FixRpcResponseMiddleware {
    service: RpcService,
}

impl FixRpcResponseMiddleware {
    /// Create a new `FixRpcResponseMiddleware` with the given `service`.
    pub fn new(service: RpcService) -> Self {
        Self { service }
    }
}

impl<'a> RpcServiceT<'a> for FixRpcResponseMiddleware {
    type Future = ResponseFuture<BoxFuture<'a, MethodResponse>>;

    fn call(&self, request: jsonrpsee::types::Request<'a>) -> Self::Future {
        let service = self.service.clone();
        ResponseFuture::future(Box::pin(async move {
            let response = service.call(request).await;
            if response.is_error() {
                let result: Response<'_, &serde_json::value::RawValue> =
                    serde_json::from_str(response.as_result())
                        .expect("response string should be valid json");

                let replace_code = |old, new: ErrorObject<'_>| {
                    debug!("Replacing RPC error: {old} with {new}");
                    MethodResponse::error(result.id, new)
                };

                let err = match result.payload {
                    ResponsePayload::Error(err) => err,
                    ResponsePayload::Success(_) => unreachable!(),
                };

                match (
                    err.code().into(),
                    err.data().map(|d| d.get().trim_matches('"')),
                ) {
                    // `jsonrpsee` parses the method into a `&str` using serde, so at this
                    // layer we get any JSON type that serde can massage into a string,
                    // while any other JSON type is rejected before this `RpcService` is
                    // called. This is a bug in `jsonrpsee`, and there's nothing we can do
                    // here to detect it.
                    // - https://github.com/zcash/zcash/blob/16ac743764a513e41dafb2cd79c2417c5bb41e81/src/rpc/server.cpp#L407-L434
                    (ErrorCode::MethodNotFound, _) => response,
                    // - This was unused prior to zcashd 5.6.0; Bitcoin Core used its own
                    //   error code for generic invalid parameter errors.
                    // - From 5.6.0, this was used only for help text when an invalid
                    //   number of parameters was returned.
                    (ErrorCode::InvalidParams, Some("No more params")) => response,
                    (ErrorCode::InvalidParams, data) => replace_code(
                        err.code(),
                        LegacyCode::InvalidParameter.with_message(data.unwrap_or(err.message())),
                    ),
                    _ => response,
                }
            } else {
                response
            }
        }))
    }
}
