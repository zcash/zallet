//! Native Zinder backend for Zallet's wallet runtime.
//!
//! The crate implements the chain-read methods needed by the current wallet
//! runtime through Zallet's [`zallet_core::components::chain`] traits.

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use zinder_client::{
    Capability, EndpointBackedIndex, IndexerError, Network, RemoteChainIndex, RemoteOpenOptions,
};

mod chain;

pub use chain::{ZinderBackend, ZinderChain, ZinderChainView};

/// Capabilities required by the Zinder backend's wallet-runtime boundary.
///
/// This is one immutable requirement set, rather than a selectable profile.
/// It includes transaction submission, canonical transaction reads, and the
/// read-side mempool follow needed after wallet sync reaches its captured tip.
pub const ZINDER_BACKEND_REQUIRED_CAPABILITIES: [Capability; 16] = [
    Capability::ServerInfo,
    Capability::NetworkUpgradeActivations,
    Capability::VisibleTipBlock,
    Capability::BlockIdBySelector,
    Capability::TreeState,
    Capability::SubtreeRoots,
    Capability::SubtreeRootsIronwood,
    Capability::FullBlock,
    Capability::FullBlockRange,
    Capability::Transaction,
    Capability::Broadcast,
    Capability::TransparentAddressUnspentOutputs,
    Capability::TransparentAddressHistory,
    Capability::ChainEvents,
    Capability::MempoolSnapshot,
    Capability::MempoolEvents,
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
    ZINDER_BACKEND_REQUIRED_CAPABILITIES
        .iter()
        .filter(|required| !advertised.contains(required))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use zinder_client::Capability;

    use super::{ZINDER_BACKEND_REQUIRED_CAPABILITIES, missing_wallet_runtime_capabilities};

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
                Capability::Transaction,
                Capability::Broadcast,
                Capability::TransparentAddressUnspentOutputs,
                Capability::TransparentAddressHistory,
                Capability::ChainEvents,
                Capability::MempoolSnapshot,
                Capability::MempoolEvents,
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
            Capability::Transaction,
            Capability::Broadcast,
            Capability::TransparentAddressUnspentOutputs,
            Capability::TransparentAddressHistory,
            Capability::ChainEvents,
            Capability::MempoolSnapshot,
            Capability::MempoolEvents,
        ];

        assert_eq!(
            ZINDER_BACKEND_REQUIRED_CAPABILITIES,
            advertised_capabilities.as_slice()
        );
        advertised_capabilities.push(Capability::ChainValuePools);
        assert!(missing_wallet_runtime_capabilities(&advertised_capabilities).is_empty());
    }

    #[test]
    fn preflight_requires_transaction_broadcast() {
        let advertised_capabilities = ZINDER_BACKEND_REQUIRED_CAPABILITIES
            .iter()
            .filter(|capability| **capability != Capability::Broadcast)
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(
            missing_wallet_runtime_capabilities(&advertised_capabilities),
            vec![Capability::Broadcast]
        );
    }
}
