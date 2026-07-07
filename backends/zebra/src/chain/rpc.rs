//! A small direct JSON-RPC client for the validator (zebrad/zcashd), used by the
//! zebra-state backend for mempool access and transaction submission. Deliberately
//! Zaino-free: the `zaino-fetch` connector transitively pulls the full Zebra stack
//! (`zebra-state`, rocksdb), which would re-introduce the version coupling this backend
//! exists to remove.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use jsonrpsee::core::{client::ClientT, params::ArrayParams};
use jsonrpsee_http_client::{HeaderMap, HeaderValue, HttpClient, HttpClientBuilder};
use serde::Deserialize;

use zallet_core::components::chain::UpgradeStatus;
use zallet_core::error::{Error, ErrorKind};

/// The subset of `getblockchaininfo` we consume: the network-upgrade table, keyed by
/// consensus branch ID (as an eight-digit hex string).
#[derive(Deserialize)]
pub(crate) struct BlockchainInfo {
    pub(crate) upgrades: HashMap<String, NetworkUpgradeInfo>,
}

/// A single entry of the `getblockchaininfo` `upgrades` table.
#[derive(Deserialize)]
pub(crate) struct NetworkUpgradeInfo {
    /// The node’s name for the upgrade, used for diagnostics only.
    pub(crate) name: String,
    /// The activation height the node reports for the upgrade.
    #[serde(rename = "activationheight")]
    pub(crate) activation_height: u32,
    /// Whether the node treats the upgrade as active, pending, or disabled. Deserialized
    /// straight into the backend-neutral [`UpgradeStatus`].
    pub(crate) status: UpgradeStatus,
}

enum Auth {
    /// Static Basic auth credentials (pre-encoded, never change).
    Basic(String),
    /// Cookie file path — re-read on every request so a zebrad restart is handled transparently.
    Cookie(PathBuf),
}

/// A JSON-RPC client for the backing validator.
#[derive(Clone)]
pub(crate) struct ValidatorRpcClient {
    url: String,
    auth: std::sync::Arc<Auth>,
}

impl ValidatorRpcClient {
    /// Builds an authenticated client. Uses cookie auth when `cookie_path` is set,
    /// otherwise HTTP Basic auth with `user`/`password`.
    pub(crate) fn new(
        address: &str,
        user: &str,
        password: &str,
        cookie_path: Option<&Path>,
    ) -> Result<Self, Error> {
        let auth = match cookie_path {
            Some(path) => Auth::Cookie(path.to_path_buf()),
            None => Auth::Basic(STANDARD.encode(format!("{user}:{password}"))),
        };

        Ok(Self {
            url: format!("http://{address}"),
            auth: std::sync::Arc::new(auth),
        })
    }

    /// Builds a fresh `HttpClient` with current credentials.
    ///
    /// For cookie auth this re-reads the cookie file, so a zebrad restart that
    /// rotates the cookie is handled transparently on the next request.
    fn build_client(&self) -> Result<HttpClient, Error> {
        let credentials = match self.auth.as_ref() {
            Auth::Basic(encoded) => encoded.clone(),
            Auth::Cookie(path) => {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| ErrorKind::Generic.context(format!("reading RPC cookie: {e}")))?;
                let token = content
                    .trim()
                    .strip_prefix("__cookie__:")
                    .unwrap_or(content.trim());
                STANDARD.encode(format!("__cookie__:{token}"))
            }
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Basic {credentials}"))
                .map_err(|e| ErrorKind::Generic.context(format!("invalid RPC auth header: {e}")))?,
        );

        HttpClientBuilder::default()
            .set_headers(headers)
            .build(&self.url)
            .map_err(|e| {
                ErrorKind::Generic
                    .context(format!("building RPC client: {e}"))
                    .into()
            })
    }

    /// `sendrawtransaction(hex)` — returns the txid hex string.
    pub(crate) async fn send_raw_transaction(&self, tx_hex: String) -> Result<String, Error> {
        let mut params = ArrayParams::new();
        params
            .insert(tx_hex)
            .map_err(|e| ErrorKind::Generic.context(e))?;
        self.build_client()?
            .request("sendrawtransaction", params)
            .await
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }

    /// `getblockchaininfo()` — returns the network upgrades the backing node follows.
    pub(crate) async fn get_blockchain_info(&self) -> Result<BlockchainInfo, Error> {
        self.build_client()?
            .request("getblockchaininfo", ArrayParams::new())
            .await
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }

    /// `getrawmempool()` — returns the mempool txid hex strings.
    pub(crate) async fn get_raw_mempool(&self) -> Result<Vec<String>, Error> {
        self.build_client()?
            .request("getrawmempool", ArrayParams::new())
            .await
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }

    /// `getrawtransaction(txid, 0)` — returns the raw transaction hex string.
    pub(crate) async fn get_raw_transaction(&self, txid_hex: String) -> Result<String, Error> {
        let mut params = ArrayParams::new();
        params
            .insert(txid_hex)
            .map_err(|e| ErrorKind::Generic.context(e))?;
        params
            .insert(0u8)
            .map_err(|e| ErrorKind::Generic.context(e))?;
        self.build_client()?
            .request("getrawtransaction", params)
            .await
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }
}
