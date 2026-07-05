//! Compatibility fixes for JSON-RPC HTTP requests.
//!
//! These fixes are applied at the HTTP level, before the RPC request is parsed.

use std::future::Future;
use std::pin::Pin;

use futures::FutureExt;
use http_body_util::BodyExt;
use hyper::{StatusCode, header};
use jsonrpsee::{
    core::BoxError,
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

    /// Maps whatever JSON-RPC version the client is using to JSON-RPC 2.0.
    async fn request_to_json_rpc_2(
        request: HttpRequest<HttpBody>,
    ) -> (JsonRpcVersion, HttpRequest<HttpBody>) {
        let (parts, body) = request.into_parts();
        let bytes = body
            .collect()
            .await
            .expect("Failed to collect body data")
            .to_bytes();

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

        (
            version,
            HttpRequest::from_parts(parts, HttpBody::from(bytes.as_ref().to_vec())),
        )
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
            let (version, request) = Self::request_to_json_rpc_2(request).await;
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
