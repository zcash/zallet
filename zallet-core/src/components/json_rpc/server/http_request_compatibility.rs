//! Compatibility fixes for JSON-RPC HTTP requests.
//!
//! These fixes are applied at the HTTP level, before the RPC request is parsed.

use std::future::Future;
use std::pin::Pin;

use futures::FutureExt;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::{StatusCode, header};
use jsonrpsee::{
    core::{BoxError, TEN_MB_SIZE_BYTES},
    server::{HttpBody, HttpRequest, HttpResponse},
    types::{ErrorCode, ErrorObject},
};
use serde::{Deserialize, Serialize};
use tower::Service;

/// HTTP [`HttpRequestMiddleware`] with compatibility workarounds.
///
/// This middleware makes the following changes to HTTP requests:
///
/// ### Map between the client's JSON-RPC version and JSON-RPC 2.0.
///
/// [`jsonrpsee`] only supports JSON-RPC 2.0, while the existing Zcash ecosystem is used
/// to communicating with `zcashd`'s "Bitcoin JSON-RPC" (a mix of 1.0, 1.1, and 2.0).
///
/// ### Add missing `content-type` HTTP header
///
/// Some RPC clients don't include a `content-type` HTTP header. But unlike web browsers,
/// [`jsonrpsee`] does not do content sniffing.
///
/// If there is no `content-type` header, we assume the content is JSON, and let the
/// parser error if we are incorrect.
///
/// ## Security
///
/// Any user-specified data in RPC requests is hex or base58check encoded. We assume the
/// client validates data encodings before sending it on to Zallet. So any fixes Zallet
/// performs won't change user-specified data.
#[derive(Clone, Debug)]
pub struct HttpRequestMiddleware<S> {
    service: S,
}

impl<S> HttpRequestMiddleware<S> {
    /// Create a new `HttpRequestMiddleware` with the given service.
    pub fn new(service: S) -> Self {
        Self { service }
    }

    /// Conditionally sets the `content-type` HTTP header to `application/json`.
    ///
    /// The header is inserted or replaced in the following cases:
    /// - no `content-type` supplied.
    /// - supplied `content-type` starts with `text/plain`, for example:
    ///   - `text/plain`
    ///   - `text/plain;`
    ///   - `text/plain; charset=utf-8`
    ///
    /// `application/json` is the only `content-type` accepted by the Zallet RPC endpoint,
    /// [as enforced by the `jsonrpsee` crate].
    ///
    /// [as enforced by the `jsonrpsee` crate]: https://github.com/paritytech/jsonrpsee/blob/656f8bb0793c8e992d20b47c3d17e7a6c396fb8b/server/src/transport/http.rs#L14-L29
    ///
    /// # Security
    ///
    /// - `content-type` headers exist so that applications know they are speaking the
    ///   correct protocol with the correct format. We can be a bit flexible, but there
    ///   are some types (such as binary) we shouldn't allow. In particular, the
    ///   `application/x-www-form-urlencoded` header should be rejected, so browser forms
    ///   can't be used to attack a local RPC port. This is handled by `jsonrpsee` as
    ///   mentioned above. See ["The Role of Routers in the CSRF Attack"].
    /// - Checking all the headers is secure, but only because `hyper` has custom code
    ///   that [just reads the first content-type header].
    ///
    /// ["The Role of Routers in the CSRF Attack"]: https://www.invicti.com/blog/web-security/importance-content-type-header-http-requests/
    /// [just reads the first content-type header]: https://github.com/hyperium/headers/blob/f01cc90cf8d601a716856bc9d29f47df92b779e4/src/common/content_type.rs#L102-L108
    pub fn insert_or_replace_content_type_header(headers: &mut header::HeaderMap) {
        if !headers.contains_key(header::CONTENT_TYPE)
            || headers
                .get(header::CONTENT_TYPE)
                .filter(|value| {
                    value
                        .to_str()
                        .ok()
                        .unwrap_or_default()
                        .starts_with("text/plain")
                })
                .is_some()
        {
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            );
        }
    }

    /// The maximum HTTP request body size this middleware will buffer.
    ///
    /// This middleware buffers the complete body before `jsonrpsee` parses the
    /// request, so `jsonrpsee`'s own limit cannot protect the buffering here; an
    /// authenticated caller could otherwise stream an arbitrarily large body into
    /// memory.
    ///
    /// This must not exceed the limit `jsonrpsee` applies to the requests it parses,
    /// or the middleware would buffer bodies the server then rejects — the memory
    /// exhaustion this exists to prevent. Rather than duplicating `jsonrpsee`'s
    /// default and hoping the two stay in step, [`super::spawn`] configures the
    /// server from this same constant, so there is one value to change.
    pub(super) const MAX_REQUEST_BODY_SIZE: u32 = TEN_MB_SIZE_BYTES;

    /// Maps whatever JSON-RPC version the client is using to JSON-RPC 2.0.
    ///
    /// Returns an error response to send back instead, if the request body could
    /// not be buffered: `413 Payload Too Large` if it exceeds
    /// [`Self::MAX_REQUEST_BODY_SIZE`], or `400 Bad Request` if reading it failed.
    // The `Err` variant is `jsonrpsee::server::HttpResponse` (an upstream type
    // we cannot shrink); allow clippy's large-error lint rather than boxing it
    // and paying a heap allocation on the error path.
    #[allow(clippy::result_large_err)]
    async fn request_to_json_rpc_2(
        request: HttpRequest<HttpBody>,
    ) -> Result<(JsonRpcVersion, HttpRequest<HttpBody>), HttpResponse> {
        let (parts, body) = request.into_parts();
        let bytes = match Limited::new(body, Self::MAX_REQUEST_BODY_SIZE as usize)
            .collect()
            .await
        {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                let status = if e.is::<LengthLimitError>() {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::BAD_REQUEST
                };
                return Err(HttpResponse::builder()
                    .status(status)
                    .body(HttpBody::empty())
                    .expect("status and empty body are always valid"));
            }
        };

        let (version, bytes) = match serde_json::from_slice::<'_, JsonRpcRequest>(bytes.as_ref()) {
            Ok(request) => {
                let version = request.version();
                if matches!(version, JsonRpcVersion::Unknown) {
                    (version, bytes)
                } else {
                    (
                        version,
                        serde_json::to_vec(&request.into_2()).expect("valid").into(),
                    )
                }
            }
            _ => (JsonRpcVersion::Unknown, bytes),
        };

        Ok((
            version,
            HttpRequest::from_parts(parts, HttpBody::from(bytes.as_ref().to_vec())),
        ))
    }

    /// Maps JSON-2.0 to whatever JSON-RPC version the client is using.
    async fn response_from_json_rpc_2(
        version: JsonRpcVersion,
        response: HttpResponse<HttpBody>,
    ) -> HttpResponse<HttpBody> {
        let (mut parts, body) = response.into_parts();
        let bytes = body
            .collect()
            .await
            .expect("Failed to collect body data")
            .to_bytes();

        let bytes =
            match serde_json::from_slice::<'_, JsonRpcResponse>(bytes.as_ref()) {
                Ok(response) => {
                    // For Bitcoin-flavoured JSON-RPC, use the expected HTTP status codes for
                    // RPC error responses.
                    // - https://github.com/zcash/zcash/blob/16ac743764a513e41dafb2cd79c2417c5bb41e81/src/httprpc.cpp#L63-L78
                    // - https://www.jsonrpc.org/historical/json-rpc-over-http.html#response-codes
                    match version {
                        JsonRpcVersion::Bitcoind | JsonRpcVersion::Lightwalletd => {
                            if let Some(e) = response.error.as_ref().and_then(|e| {
                                serde_json::from_str::<'_, ErrorObject<'_>>(e.get()).ok()
                            }) {
                                parts.status = match e.code().into() {
                                    ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
                                    ErrorCode::MethodNotFound => StatusCode::NOT_FOUND,
                                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                                };
                            }
                        }
                        _ => (),
                    }

                    serde_json::to_vec(&response.into_version(version))
                        .expect("valid")
                        .into()
                }
                _ => bytes,
            };

        HttpResponse::from_parts(parts, HttpBody::from(bytes.as_ref().to_vec()))
    }
}

/// Implements [`tower::Layer`] for [`HttpRequestMiddleware`].
#[derive(Clone)]
pub struct HttpRequestMiddlewareLayer {}

impl HttpRequestMiddlewareLayer {
    /// Creates a new `HttpRequestMiddlewareLayer`.
    pub fn new() -> Self {
        Self {}
    }
}

impl<S> tower::Layer<S> for HttpRequestMiddlewareLayer {
    type Service = HttpRequestMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        HttpRequestMiddleware::new(service)
    }
}

impl<S> Service<HttpRequest<HttpBody>> for HttpRequestMiddleware<S>
where
    S: Service<HttpRequest, Response = HttpResponse> + Clone + Send + 'static,
    S::Error: Into<BoxError> + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut request: HttpRequest<HttpBody>) -> Self::Future {
        // Fix the request headers.
        Self::insert_or_replace_content_type_header(request.headers_mut());

        let mut service = self.service.clone();

        async move {
            let (version, request) = match Self::request_to_json_rpc_2(request).await {
                Ok(mapped) => mapped,
                Err(error_response) => return Ok(error_response),
            };
            let response = service.call(request).await.map_err(Into::into)?;
            Ok(Self::response_from_json_rpc_2(version, response).await)
        }
        .boxed()
    }
}

#[derive(Clone, Copy, Debug)]
enum JsonRpcVersion {
    /// bitcoind used a mishmash of 1.0, 1.1, and 2.0 for its JSON-RPC.
    Bitcoind,
    /// lightwalletd uses the above mishmash, but also breaks spec to include a
    /// `"jsonrpc": "1.0"` key.
    Lightwalletd,
    /// The client is indicating strict 2.0 handling.
    TwoPointZero,
    /// On parse errors we don't modify anything, and let the `jsonrpsee` crate handle it.
    Unknown,
}

/// A version-agnostic JSON-RPC request.
#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    jsonrpc: Option<String>,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Box<serde_json::value::RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    fn version(&self) -> JsonRpcVersion {
        match (self.jsonrpc.as_deref(), &self.params, &self.id) {
            (
                Some("2.0"),
                _,
                None
                | Some(
                    serde_json::Value::Null
                    | serde_json::Value::String(_)
                    | serde_json::Value::Number(_),
                ),
            ) => JsonRpcVersion::TwoPointZero,
            (Some("1.0"), Some(_), Some(_)) => JsonRpcVersion::Lightwalletd,
            (None, Some(_), Some(_)) => JsonRpcVersion::Bitcoind,
            _ => JsonRpcVersion::Unknown,
        }
    }

    fn into_2(mut self) -> Self {
        self.jsonrpc = Some("2.0".into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The middleware is generic over the wrapped service, but the request mapping
    /// never touches it, so any type parameter works for exercising it.
    type Middleware = HttpRequestMiddleware<()>;

    fn request_with_body(body: Vec<u8>) -> HttpRequest<HttpBody> {
        HttpRequest::builder()
            .body(HttpBody::from(body))
            .expect("valid request")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversized_body_is_rejected_not_buffered() {
        let body = vec![b'0'; Middleware::MAX_REQUEST_BODY_SIZE as usize + 1];
        let response = Middleware::request_to_json_rpc_2(request_with_body(body))
            .await
            .expect_err("a body over the limit must be rejected");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn body_at_the_limit_is_accepted() {
        // Not valid JSON-RPC, so the mapping passes it through untouched for
        // `jsonrpsee` to reject; what matters here is that buffering succeeds.
        let body = vec![b'0'; Middleware::MAX_REQUEST_BODY_SIZE as usize];
        let (version, _request) = Middleware::request_to_json_rpc_2(request_with_body(body))
            .await
            .expect("a body at the limit must be buffered");
        assert!(matches!(version, JsonRpcVersion::Unknown));
    }

    /// A body whose stream fails for a reason other than the size limit maps to
    /// `400 Bad Request`, not the `413` reserved for oversized bodies.
    #[tokio::test(flavor = "multi_thread")]
    async fn unreadable_body_is_a_bad_request() {
        // A stream that yields an error rather than data: the read fails without ever
        // reaching the length limit.
        let failing = HttpBody::new(http_body_util::StreamBody::new(futures::stream::once(
            async {
                Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    "peer went away mid-body",
                ))
            },
        )));
        let request = HttpRequest::builder().body(failing).expect("valid request");

        let response = Middleware::request_to_json_rpc_2(request)
            .await
            .expect_err("an unreadable body must be rejected");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn small_request_is_mapped_to_json_rpc_2() {
        let body = br#"{"method":"getinfo","params":[],"id":1}"#.to_vec();
        let (version, request) = Middleware::request_to_json_rpc_2(request_with_body(body))
            .await
            .expect("a small body must be buffered");
        assert!(matches!(version, JsonRpcVersion::Bitcoind));

        let bytes = request
            .into_body()
            .collect()
            .await
            .expect("body was buffered")
            .to_bytes();
        let mapped: JsonRpcRequest = serde_json::from_slice(&bytes).expect("valid JSON");
        assert_eq!(mapped.jsonrpc.as_deref(), Some("2.0"));
    }
}

/// A version-agnostic JSON-RPC response.
#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    jsonrpc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Box<serde_json::value::RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Box<serde_json::value::RawValue>>,
    id: serde_json::Value,
}

impl JsonRpcResponse {
    fn into_version(mut self, version: JsonRpcVersion) -> Self {
        let json_null = || Some(serde_json::value::to_raw_value(&()).expect("valid"));

        match version {
            JsonRpcVersion::Bitcoind => {
                self.jsonrpc = None;
                self.result = self.result.or_else(json_null);
                self.error = self.error.or_else(json_null);
            }
            JsonRpcVersion::Lightwalletd => {
                self.jsonrpc = Some("1.0".into());
                self.result = self.result.or_else(json_null);
                self.error = self.error.or_else(json_null);
            }
            JsonRpcVersion::TwoPointZero => {
                // `jsonrpsee` should be returning valid JSON-RPC 2.0 responses. However,
                // a valid result of `null` can be parsed into `None` by this parser, so
                // we map the result explicitly to `Null` when there is no error.
                assert_eq!(self.jsonrpc.as_deref(), Some("2.0"));
                if self.error.is_none() {
                    self.result = self.result.or_else(json_null);
                } else {
                    assert!(self.result.is_none());
                }
            }
            JsonRpcVersion::Unknown => (),
        }
        self
    }
}
