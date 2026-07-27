//! Unshippable P1 integration tracer for Zallet's Zinder chain backend.
//!
//! The crate implements Zallet's complete [`zallet_core::components::chain`]
//! interface while deliberately serving only the methods needed for a bounded
//! shielded scan. Construction preflights that exact capability set. Methods
//! assigned to later vertical slices fail explicitly instead of implying that
//! the backend is ready to ship.

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use zinder_client::{
    Capability, EndpointBackedIndex, IndexerError, Network, RemoteChainIndex, RemoteOpenOptions,
    RetryPolicy,
};

mod chain;

pub use chain::{ZinderBackend, ZinderChain, ZinderChainView};

/// Capabilities required by Zallet's P1 bounded shielded scan.
///
/// The list deliberately excludes transparent history, mempool observation,
/// and transaction broadcast. Those operations belong to later vertical
/// slices and must not be inferred from P1 readiness.
pub const P1_SCAN_REQUIRED_CAPABILITIES: [Capability; 8] = [
    Capability::ServerInfo,
    Capability::NetworkUpgradeActivations,
    Capability::VisibleTipBlock,
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

/// Reads endpoint metadata and returns every capability missing from P1.
///
/// Returning the complete set gives operators one actionable preflight result
/// instead of a sequence of one-capability-at-a-time startup failures.
pub async fn probe_missing_p1_scan_capabilities(
    index: &RemoteChainIndex,
) -> Result<Vec<Capability>, IndexerError> {
    let server_info = index.server_info().await?;
    Ok(missing_p1_scan_capabilities(&server_info.capabilities))
}

/// Returns every P1 scan capability absent from an advertised capability set.
#[must_use]
pub fn missing_p1_scan_capabilities(advertised: &[Capability]) -> Vec<Capability> {
    P1_SCAN_REQUIRED_CAPABILITIES
        .iter()
        .filter(|required| !advertised.contains(required))
        .cloned()
        .collect()
}

/// Returns whether a failed pinned scan must restart from a fresh snapshot.
///
/// This is the typed recovery seam Zallet needs for a snapshot whose Zinder
/// chain-epoch pin has expired. The caller must discard all results from the
/// expired snapshot before capturing a replacement.
#[must_use]
pub fn scan_requires_fresh_snapshot(error: &IndexerError) -> bool {
    error.retry_policy() == RetryPolicy::RefreshChainEpoch
}

#[cfg(test)]
mod tests {
    use zinder_client::{Capability, IndexerError};

    use super::{
        P1_SCAN_REQUIRED_CAPABILITIES, missing_p1_scan_capabilities, scan_requires_fresh_snapshot,
    };

    #[test]
    fn preflight_reports_every_missing_capability_in_requirement_order() {
        let advertised = [
            Capability::ServerInfo,
            Capability::VisibleTipBlock,
            Capability::TreeState,
        ];

        assert_eq!(
            missing_p1_scan_capabilities(&advertised),
            vec![
                Capability::NetworkUpgradeActivations,
                Capability::SubtreeRoots,
                Capability::SubtreeRootsIronwood,
                Capability::FullBlock,
                Capability::FullBlockRange,
            ],
        );
    }

    #[test]
    fn preflight_accepts_the_exact_p1_capability_set() {
        assert!(missing_p1_scan_capabilities(&P1_SCAN_REQUIRED_CAPABILITIES).is_empty());
    }

    #[test]
    fn expired_chain_epoch_requires_a_fresh_snapshot() {
        assert!(scan_requires_fresh_snapshot(
            &IndexerError::ChainEpochPinUnavailable
        ));
    }

    #[test]
    fn unrelated_failure_does_not_require_a_fresh_snapshot() {
        assert!(!scan_requires_fresh_snapshot(&IndexerError::NotFound {
            resource: "full block",
        }));
    }
}
