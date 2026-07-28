//! Unshippable integration backend for Zallet's Zinder wallet runtime.
//!
//! The crate implements the chain-read methods needed by the current wallet
//! runtime through Zallet's [`zallet_core::components::chain`] traits. It
//! satisfies the traits structurally, but methods assigned to later vertical
//! slices fail explicitly. It is not yet a complete chain backend.

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use zinder_client::{
    Capability, EndpointBackedIndex, IndexerError, Network, RemoteChainIndex, RemoteOpenOptions,
};

mod chain;

pub use chain::{ZinderBackend, ZinderChain, ZinderChainView};

/// Capabilities required to construct Zallet's Zinder wallet runtime.
///
/// The list deliberately excludes transparent history, mempool observation,
/// and transaction broadcast. Those operations belong to later vertical
/// slices and must not be inferred from chain-read readiness.
pub const WALLET_RUNTIME_REQUIRED_CAPABILITIES: [Capability; 9] = [
    Capability::ServerInfo,
    Capability::NetworkUpgradeActivations,
    Capability::VisibleTipBlock,
    Capability::BlockIdBySelector,
    Capability::TreeState,
    Capability::SubtreeRoots,
    Capability::SubtreeRootsIronwood,
    Capability::FullBlock,
    Capability::FullBlockRange,
];

/// Builds a lazy typed client for a Zinder wallet endpoint.
///
/// The expected network is checked by the client when it decodes endpoint
/// responses. An `https://` endpoint enables the client's system-root TLS
/// configuration; an `http://` endpoint remains plaintext.
pub fn open_zinder_index(
    endpoint: impl Into<String>,
    network: Network,
) -> Result<RemoteChainIndex, IndexerError> {
    RemoteChainIndex::connect(RemoteOpenOptions {
        endpoint: endpoint.into(),
        network,
    })
}

/// Reads endpoint metadata and returns every wallet-runtime capability missing.
///
/// Returning the complete set gives the composition root one actionable
/// preflight result instead of a sequence of one-capability-at-a-time failures.
pub async fn probe_missing_wallet_runtime_capabilities(
    index: &RemoteChainIndex,
) -> Result<Vec<Capability>, IndexerError> {
    let server_info = index.server_info().await?;
    Ok(missing_wallet_runtime_capabilities(
        &server_info.capabilities,
    ))
}

/// Returns every wallet-runtime capability absent from an advertised set.
#[must_use]
pub fn missing_wallet_runtime_capabilities(advertised: &[Capability]) -> Vec<Capability> {
    WALLET_RUNTIME_REQUIRED_CAPABILITIES
        .iter()
        .filter(|required| !advertised.contains(required))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use zinder_client::Capability;

    use super::{WALLET_RUNTIME_REQUIRED_CAPABILITIES, missing_wallet_runtime_capabilities};

    #[test]
    fn preflight_reports_every_missing_capability_in_requirement_order() {
        let advertised = [
            Capability::ServerInfo,
            Capability::VisibleTipBlock,
            Capability::TreeState,
        ];

        assert_eq!(
            missing_wallet_runtime_capabilities(&advertised),
            vec![
                Capability::NetworkUpgradeActivations,
                Capability::BlockIdBySelector,
                Capability::SubtreeRoots,
                Capability::SubtreeRootsIronwood,
                Capability::FullBlock,
                Capability::FullBlockRange,
            ],
        );
    }

    #[test]
    fn preflight_accepts_required_capabilities_with_additional_advertisements() {
        let mut advertised_capabilities = vec![
            Capability::ServerInfo,
            Capability::NetworkUpgradeActivations,
            Capability::VisibleTipBlock,
            Capability::BlockIdBySelector,
            Capability::TreeState,
            Capability::SubtreeRoots,
            Capability::SubtreeRootsIronwood,
            Capability::FullBlock,
            Capability::FullBlockRange,
        ];

        assert_eq!(
            WALLET_RUNTIME_REQUIRED_CAPABILITIES,
            advertised_capabilities.as_slice()
        );
        advertised_capabilities.push(Capability::Broadcast);
        assert!(missing_wallet_runtime_capabilities(&advertised_capabilities).is_empty());
    }
}
