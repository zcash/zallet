//! JSON-RPC endpoint.
//!
//! This provides JSON-RPC methods that are (mostly) compatible with the `zcashd` wallet
//! RPCs:
//! - Some methods are exactly compatible.
//! - Some methods have the same name but slightly different semantics.
//! - Some methods from the `zcashd` wallet are unsupported.

use std::net::SocketAddr;

use abscissa_core::tracing::{info, warn};
use jsonrpsee::tracing::Instrument;

use crate::{
    config::ZalletConfig,
    error::{Error, ErrorKind},
    fl,
};

use super::{TaskHandle, chain::Chain, database::Database, sync::SyncStatusReader};

#[cfg(zallet_build = "wallet")]
use super::keystore::KeyStore;
#[cfg(zallet_build = "wallet")]
use super::sync::{WalletDecryptorHandle, WalletSyncWakeup};

#[cfg(zallet_build = "wallet")]
mod asyncop;
#[cfg(zallet_build = "wallet")]
mod fund_source;
pub(crate) mod methods;
#[cfg(zallet_build = "wallet")]
pub(crate) mod payments;
pub(crate) mod server;
pub(crate) mod utils;

/// The transport-security posture of a configured RPC bind address.
///
/// The JSON-RPC interface is served over plaintext HTTP, so HTTP Basic credentials
/// and request bodies (which can contain wallet passphrases and spending keys) are
/// not protected in transit. Serving it beyond loopback therefore requires an
/// explicit opt-in from the operator.
#[derive(Debug, PartialEq, Eq)]
enum BindPolicy {
    /// The address is a loopback address; plaintext HTTP is confined to the local
    /// host.
    Loopback,
    /// The address is reachable from the network, and the operator has explicitly
    /// accepted the risk of serving plaintext RPC on it. A prominent warning is
    /// logged at startup.
    InsecureRemote,
    /// The address is reachable from the network and the operator has not opted in;
    /// startup is refused.
    Refused,
}

impl BindPolicy {
    fn for_addr(addr: &SocketAddr, allow_insecure_remote: bool) -> Self {
        if addr.ip().is_loopback() {
            BindPolicy::Loopback
        } else if allow_insecure_remote {
            BindPolicy::InsecureRemote
        } else {
            BindPolicy::Refused
        }
    }
}

#[derive(Debug)]
pub(crate) struct JsonRpc {}

impl JsonRpc {
    pub(crate) async fn spawn<C: Chain>(
        config: &ZalletConfig,
        db: Database,
        #[cfg(zallet_build = "wallet")] keystore: KeyStore,
        chain: C,
        #[cfg(zallet_build = "wallet")] decryptor: WalletDecryptorHandle,
        #[cfg(zallet_build = "wallet")] sync_wakeup: WalletSyncWakeup,
        sync_status: SyncStatusReader,
    ) -> Result<TaskHandle, Error> {
        let rpc = config.rpc.clone();

        if !rpc.bind.is_empty() {
            if rpc.bind.len() > 1 {
                return Err(ErrorKind::Init
                    .context("Only one RPC bind address is supported (for now)")
                    .into());
            }
            match BindPolicy::for_addr(&rpc.bind[0], rpc.allow_insecure_remote_bind()) {
                BindPolicy::Loopback => (),
                BindPolicy::InsecureRemote => warn!(
                    "{}",
                    fl!(
                        "warn-init-rpc-bind-insecure-remote",
                        addr = rpc.bind[0].to_string()
                    )
                ),
                BindPolicy::Refused => {
                    return Err(ErrorKind::Init
                        .context(fl!(
                            "err-init-rpc-bind-not-loopback",
                            addr = rpc.bind[0].to_string()
                        ))
                        .into());
                }
            }
            info!("Spawning RPC server");
            info!("Trying to open RPC endpoint at {}...", rpc.bind[0]);
            server::spawn(
                rpc,
                config.datadir().to_path_buf(),
                db,
                #[cfg(zallet_build = "wallet")]
                keystore,
                chain,
                #[cfg(zallet_build = "wallet")]
                decryptor,
                #[cfg(zallet_build = "wallet")]
                sync_wakeup,
                sync_status,
            )
            .await
        } else {
            warn!("Configure `rpc.bind` to start the RPC server");
            // Emulate a normally-operating ongoing task to simplify subsequent logic.
            Ok(crate::spawn!(
                "No JSON-RPC",
                std::future::pending().in_current_span()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use proptest::prelude::*;

    use super::BindPolicy;

    proptest! {
        /// A loopback bind is always permitted, with or without the opt-in.
        #[test]
        fn loopback_is_always_permitted(port in any::<u16>(), allow in any::<bool>(), v6 in any::<bool>()) {
            let ip: IpAddr = if v6 {
                std::net::Ipv6Addr::LOCALHOST.into()
            } else {
                std::net::Ipv4Addr::LOCALHOST.into()
            };
            prop_assert_eq!(
                BindPolicy::for_addr(&SocketAddr::new(ip, port), allow),
                BindPolicy::Loopback
            );
        }

        /// Any non-loopback bind — unspecified, private, or public — is refused
        /// without the opt-in, and only warned about with it.
        #[test]
        fn non_loopback_requires_opt_in(addr in any::<SocketAddr>(), allow in any::<bool>()) {
            prop_assume!(!addr.ip().is_loopback());
            prop_assert_eq!(
                BindPolicy::for_addr(&addr, allow),
                if allow {
                    BindPolicy::InsecureRemote
                } else {
                    BindPolicy::Refused
                }
            );
        }
    }
}
