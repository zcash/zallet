//! JSON-RPC server that is compatible with `zcashd`.

use jsonrpsee::{
    server::{RpcServiceBuilder, Server},
    tracing::info,
};
use std::path::PathBuf;
use tokio::task::JoinHandle;

use crate::{
    components::{chain::Chain, database::Database, sync::SyncStatusReader},
    config::RpcSection,
    error::{Error, ErrorKind},
    fl,
};

use super::methods::{RpcImpl, RpcServer as _};

#[cfg(zallet_build = "wallet")]
use {
    super::methods::{WalletRpcImpl, WalletRpcServer},
    crate::components::{keystore::KeyStore, sync::WalletDecryptorHandle},
};

mod error;
pub(crate) use error::LegacyCode;

pub(crate) mod authorization;
pub(crate) mod cookie;
mod http_request_compatibility;
mod method_logger;
mod rpc_call_compatibility;

type ServerTask = JoinHandle<Result<(), Error>>;

pub(crate) async fn spawn<C: Chain>(
    config: RpcSection,
    datadir: PathBuf,
    wallet: Database,
    #[cfg(zallet_build = "wallet")] keystore: KeyStore,
    chain: C,
    #[cfg(zallet_build = "wallet")] decryptor: WalletDecryptorHandle,
    sync_status: SyncStatusReader,
) -> Result<ServerTask, Error> {
    // Caller should make sure `bind` only contains a single address (for now).
    assert_eq!(config.bind.len(), 1);
    let listen_addr = config.bind[0];

    // Warm the proving caches in the background, so the first `pczt_prove` or
    // `pczt_extract` call does not pay the multi-second key-generation cost
    // inside an RPC timeout.
    super::methods::spawn_proving_cache_warmer(chain.clone());

    // Initialize the RPC methods.
    #[cfg(zallet_build = "wallet")]
    let wallet_rpc_impl = WalletRpcImpl::new(
        wallet.clone(),
        keystore.clone(),
        chain.clone(),
        decryptor,
        sync_status.clone(),
        config.async_operation_limit(),
    );
    let rpc_impl = RpcImpl::new(
        wallet,
        #[cfg(zallet_build = "wallet")]
        keystore,
        chain,
        sync_status,
    );

    let timeout = config.timeout();

    // The cookie username is reserved. Reject the config before writing a cookie file we
    // would only have to tear down again.
    if config.auth.iter().any(|a| a.user == cookie::COOKIE_USER) {
        return Err(ErrorKind::Init
            .context(fl!(
                "err-init-rpc-auth-cookie-user-reserved",
                user = cookie::COOKIE_USER
            ))
            .into());
    }

    let (cookie_user, cookie_hash, _cookie_guard) = cookie::generate_cookie(&datadir)?;
    let cookie = Some((cookie_user, cookie_hash));

    let http_middleware = tower::ServiceBuilder::new()
        .layer(
            authorization::AuthorizationLayer::new(config.auth, cookie)
                .map_err(|()| ErrorKind::Init.context(fl!("err-init-rpc-auth-invalid")))?,
        )
        .layer(http_request_compatibility::HttpRequestMiddlewareLayer::new())
        .timeout(timeout);

    // Note: `RpcServiceBuilder::rpc_logger` must not be used here; it logs full
    // call parameters and responses, which can contain secrets.
    let rpc_middleware = RpcServiceBuilder::new()
        .layer_fn(method_logger::MethodLoggerMiddleware::new)
        .layer_fn(rpc_call_compatibility::FixRpcResponseMiddleware::new);

    let server_instance = Server::builder()
        .http_only()
        // Keep the server's parse limit equal to what the compatibility middleware
        // will buffer, so neither can drift into accepting a body the other rejects.
        .max_request_body_size(
            http_request_compatibility::HttpRequestMiddleware::<()>::MAX_REQUEST_BODY_SIZE,
        )
        .set_http_middleware(http_middleware)
        .set_rpc_middleware(rpc_middleware)
        .build(listen_addr)
        .await
        .map_err(|e| ErrorKind::Init.context(e))?;
    let addr = server_instance
        .local_addr()
        .map_err(|e| ErrorKind::Init.context(e))?;
    info!("Opened RPC endpoint at {}", addr);

    #[allow(unused_mut)]
    let mut rpc_module = rpc_impl.into_rpc();
    #[cfg(zallet_build = "wallet")]
    rpc_module
        .merge(wallet_rpc_impl.into_rpc())
        .map_err(|e| ErrorKind::Init.context(e))?;

    let server_task = crate::spawn!("JSON-RPC server", async move {
        // Hold the cookie guard until the server stops (or the task is cancelled).
        // When dropped, it deletes the cookie file.
        let _cookie_guard = _cookie_guard;
        server_instance.start(rpc_module).stopped().await;
        Ok(())
    });

    Ok(server_task)
}
