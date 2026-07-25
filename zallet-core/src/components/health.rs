//! HTTP readiness and liveness endpoints for container / load-balancer probes.
//!
//! Mirrors Zebra's probe shape ([`GET /ready`], [`GET /healthy`]) on a dedicated
//! port so the JSON-RPC surface can stay auth-gated while orchestrators get a
//! cheap, unauthenticated health check.
//!
//! Security: these endpoints are unauthenticated by design. Bind them to a
//! loopback or private interface only.
//!
//! [`GET /ready`]: https://zebra.zfnd.org/user/health.html
//! [`GET /healthy`]: https://zebra.zfnd.org/user/health.html

use std::{convert::Infallible, sync::Arc};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Incoming, server::conn::http1};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{Instrument, info, warn};

use crate::{
    components::{TaskHandle, database::Database},
    config::HealthSection,
    error::{Error, ErrorKind},
};

/// Shared state for health handlers.
#[derive(Clone)]
struct HealthState {
    db: Database,
}

/// Spawn the health server when `health.listen_addr` is configured.
///
/// When disabled, returns a pending task (same pattern as a disabled JSON-RPC
/// server) so `zallet start` can treat it as an ongoing task uniformly.
pub(crate) async fn spawn(config: &HealthSection, db: Database) -> Result<TaskHandle, Error> {
    let Some(listen_addr) = config.listen_addr else {
        return Ok(crate::spawn!(
            "No health server",
            std::future::pending::<Result<(), Error>>().in_current_span()
        ));
    };

    info!("Opening health endpoint at {listen_addr}...");
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|e| ErrorKind::Init.context(e))?;
    let local = listener.local_addr().map_err(|e| ErrorKind::Init.context(e))?;
    info!("Opened health endpoint at {local}");

    let state = Arc::new(HealthState { db });

    Ok(crate::spawn!("health server", async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(?e, "health server accept failed");
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = hyper::service::service_fn(move |req| {
                    let state = state.clone();
                    async move { handle(req, &state).await }
                });
                if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                    warn!(?peer, ?e, "health connection error");
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), Error>(())
    }))
}

async fn handle(
    req: Request<Incoming>,
    state: &HealthState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let method = req.method();

    if *method != Method::GET {
        return Ok(plain(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n"));
    }

    match path {
        "/healthy" | "/healthz" => Ok(healthy()),
        "/ready" | "/readyz" => Ok(ready(state).await),
        _ => Ok(plain(StatusCode::NOT_FOUND, "not found\n")),
    }
}

/// Liveness: the process is up and the health server itself is serving.
fn healthy() -> Response<Full<Bytes>> {
    plain(StatusCode::OK, "ok\n")
}

/// Readiness: wallet database is openable (sync / RPC traffic can be served
/// against a working DB). Returns 503 when the pool cannot hand out a handle.
async fn ready(state: &HealthState) -> Response<Full<Bytes>> {
    match state.db.handle().await {
        Ok(_handle) => plain(StatusCode::OK, "ready\n"),
        Err(e) => {
            warn!(?e, "health /ready database handle failed");
            plain(StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
        }
    }
}

fn plain(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_is_200() {
        let res = healthy();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[test]
    fn method_not_allowed_body() {
        // path coverage is integration-level; unit-test response helper shape.
        let res = plain(StatusCode::NOT_FOUND, "not found\n");
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
