//! Zinder-backed implementation of Zallet's chain boundary.

use std::{
    io::{self, Cursor},
    num::NonZeroU32,
    ops::Range,
    sync::Arc,
};

use futures::{
    StreamExt as _, TryStreamExt as _,
    stream::{self, BoxStream},
};
use incrementalmerkletree::frontier::CommitmentTree;
use orchard::tree::MerkleHashOrchard;
use serde_json::Value;
use transparent::address::TransparentAddress;
use zallet_core::{
    components::{
        TaskHandle,
        chain::{
            BlockLocator, Chain, ChainBlock, ChainError, ChainFactory, ChainTx, ChainView,
            ReportedUpgrade, UpgradeStatus,
        },
    },
    config::ZalletConfig,
    error::{Error, ErrorKind},
    network::Network,
};
use zcash_client_backend::data_api::{
    TransactionStatus,
    chain::{ChainState, CommitmentTreeRoot},
};
use zcash_primitives::{
    block::{Block, BlockHash, BlockHeader},
    merkle_tree::read_commitment_tree,
    transaction::Transaction,
};
use zcash_protocol::{
    TxId,
    consensus::{self, BlockHeight},
};
use zinder_client::{
    BlockHeight as ZinderBlockHeight, BlockHeightRange as ZinderBlockHeightRange,
    BlockId as ZinderBlockId, Capability, ChainIndex, IndexerError, Network as ZinderNetwork,
    OwnedChainSnapshot, RemoteChainIndex, RetryPolicy, ShieldedProtocol, SubtreeRootArtifact,
    SubtreeRootIndex, SubtreeRootRange, TreeStateArtifact,
};

use crate::{open_zinder_index, probe_missing_bounded_scan_capabilities};

/// Factory-shaped entry point for the P1 Zinder chain backend tracer.
///
/// The endpoint is supplied by the composition root rather than added to
/// Zallet's production configuration. This type is not registered by a Zallet
/// binary and does not make the tracer a production backend.
#[derive(Clone)]
pub struct ZinderBackend {
    endpoint: String,
}

impl ZinderBackend {
    /// Creates a P1 backend factory for one native Zinder wallet endpoint.
    #[must_use]
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }
}

impl ChainFactory for ZinderBackend {
    type Chain = ZinderChain;

    const NAME: &'static str = "zinder";

    async fn build(&self, config: &ZalletConfig) -> Result<(Self::Chain, TaskHandle), Error> {
        let chain = ZinderChain::connect(self.endpoint.clone(), config.consensus.network()).await?;

        // RemoteChainIndex owns a lazy tonic channel and needs no driver task.
        // ChainFactory nevertheless requires a lifetime task so `zallet start`
        // can monitor every backend through one uniform composition boundary.
        let task: TaskHandle = zallet_core::spawn!(
            "Zinder backend lifetime",
            std::future::pending::<Result<(), Error>>()
        );

        Ok((chain, task))
    }
}

/// A typed connection to a native Zinder wallet endpoint.
#[derive(Clone)]
pub struct ZinderChain {
    index: Arc<RemoteChainIndex>,
    params: Network,
}

impl ZinderChain {
    /// Connects to Zinder and verifies every P1 bounded-scan requirement.
    ///
    /// Construction performs a real `ServerInfo` request so an unreachable
    /// endpoint, network mismatch, or incomplete capability set fails before
    /// this function returns a chain value.
    pub async fn connect(endpoint: String, params: Network) -> Result<Self, Error> {
        let index = open_zinder_index(endpoint, zinder_network(params)).map_err(init_error)?;
        let missing = probe_missing_bounded_scan_capabilities(&index)
            .await
            .map_err(init_error)?;
        if !missing.is_empty() {
            return Err(ErrorKind::Init
                .context(bounded_scan_preflight_message(&missing))
                .into());
        }

        Ok(Self {
            index: Arc::new(index),
            params,
        })
    }

    async fn subtree_root_artifacts(
        &self,
        protocol: ShieldedProtocol,
    ) -> Result<Vec<SubtreeRootArtifact>, ChainError> {
        let snapshot = OwnedChainSnapshot::capture(Arc::clone(&self.index))
            .await
            .map_err(chain_error)?;
        let root_count = snapshot
            .chain_epoch()
            .tip_metadata
            .completed_subtree_count(protocol);
        let Some(max_entries) = NonZeroU32::new(root_count) else {
            return Ok(Vec::new());
        };

        snapshot
            .subtree_roots_in_range(SubtreeRootRange::new(
                protocol,
                SubtreeRootIndex::new(0),
                max_entries,
            ))
            .await
            .map_err(chain_error)
    }
}

impl Chain for ZinderChain {
    type View = ZinderChainView;

    fn params(&self) -> &Network {
        &self.params
    }

    async fn reported_upgrades(&self) -> Result<Vec<ReportedUpgrade>, Error> {
        let activations = self
            .index
            .network_upgrade_activations()
            .await
            .map_err(init_error)?;
        let tip = self.index.current_epoch().await.map_err(init_error)?;

        Ok(activations
            .activations()
            .iter()
            .map(|activation| {
                let status = if activation.activation_height <= tip.visible_tip_height {
                    UpgradeStatus::Active
                } else {
                    UpgradeStatus::Pending
                };
                ReportedUpgrade::new(
                    activation.branch_id.value(),
                    activation.name.clone(),
                    activation.activation_height.value(),
                    status,
                )
            })
            .collect())
    }

    async fn broadcast_transaction(&self, _tx: &Transaction) -> Result<(), ChainError> {
        Err(unsupported_by_bounded_scan_tracer("broadcast_transaction"))
    }

    async fn get_sapling_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<sapling::Node>>, ChainError> {
        self.subtree_root_artifacts(ShieldedProtocol::Sapling)
            .await?
            .into_iter()
            .map(sapling_subtree_root)
            .collect()
    }

    async fn get_orchard_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<MerkleHashOrchard>>, ChainError> {
        self.subtree_root_artifacts(ShieldedProtocol::Orchard)
            .await?
            .into_iter()
            .map(orchard_subtree_root)
            .collect()
    }

    async fn get_ironwood_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<MerkleHashOrchard>>, ChainError> {
        self.subtree_root_artifacts(ShieldedProtocol::Ironwood)
            .await?
            .into_iter()
            .map(orchard_subtree_root)
            .collect()
    }

    async fn snapshot(&self) -> Result<ZinderChainView, ChainError> {
        let snapshot = OwnedChainSnapshot::capture(Arc::clone(&self.index))
            .await
            .map_err(chain_error)?;
        let tip = chain_block(ZinderBlockId::new(
            snapshot.chain_epoch().visible_tip_height,
            snapshot.chain_epoch().visible_tip_hash,
        ));

        Ok(ZinderChainView {
            snapshot,
            tip,
            params: self.params,
        })
    }
}

/// A cloneable Zinder chain view pinned to one retained chain epoch.
///
/// An expired epoch is reported as [`ChainError::ViewExpired`] with the
/// original [`IndexerError::ChainEpochPinUnavailable`] retained as its source.
/// This adapter never silently moves a request onto a different chain epoch.
#[derive(Clone)]
pub struct ZinderChainView {
    snapshot: OwnedChainSnapshot<RemoteChainIndex>,
    tip: ChainBlock,
    params: Network,
}

impl ChainView for ZinderChainView {
    async fn tip(&self) -> Result<ChainBlock, ChainError> {
        Ok(self.tip)
    }

    async fn find_fork_point(
        &self,
        _locator: &BlockLocator,
    ) -> Result<Option<ChainBlock>, ChainError> {
        Err(unsupported_by_bounded_scan_tracer("find_fork_point"))
    }

    async fn tree_state_as_of(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ChainState>, ChainError> {
        if height > self.tip.height() {
            return Ok(None);
        }

        self.snapshot
            .tree_state_at(zinder_height(height))
            .await
            .map(|artifact| Some(chain_state(artifact)))
            .map_err(chain_error)?
            .transpose()
    }

    async fn get_block_header(
        &self,
        _height: BlockHeight,
    ) -> Result<Option<BlockHeader>, ChainError> {
        Err(unsupported_by_bounded_scan_tracer("get_block_header"))
    }

    async fn get_block(&self, height: BlockHeight) -> Result<Option<Block>, ChainError> {
        self.full_block_bytes(height)
            .await?
            .map(|bytes| decode_block(bytes, &self.params, height))
            .transpose()
    }

    fn stream_blocks_to_tip(
        &self,
        _start: BlockHeight,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        unsupported_stream_by_bounded_scan_tracer("stream_blocks_to_tip")
    }

    fn stream_blocks(
        &self,
        range: &Range<BlockHeight>,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        let Some(range) = zinder_range_from_half_open(range, self.tip.height()) else {
            return stream::empty().boxed();
        };

        self.stream_zinder_range(range)
    }

    async fn get_mempool_stream(&self) -> Result<Option<BoxStream<'_, Transaction>>, ChainError> {
        Err(unsupported_by_bounded_scan_tracer("get_mempool_stream"))
    }

    async fn get_transaction(&self, _txid: TxId) -> Result<Option<ChainTx>, ChainError> {
        Err(unsupported_by_bounded_scan_tracer("get_transaction"))
    }

    async fn get_transaction_status(&self, _txid: TxId) -> Result<TransactionStatus, ChainError> {
        Err(unsupported_by_bounded_scan_tracer("get_transaction_status"))
    }

    async fn get_address_unspent_outpoints(
        &self,
        _address: &TransparentAddress,
    ) -> Result<Vec<(TxId, u32)>, ChainError> {
        Err(unsupported_by_bounded_scan_tracer(
            "get_address_unspent_outpoints",
        ))
    }

    async fn get_address_tx_ids(
        &self,
        _address: &TransparentAddress,
        _range: Range<BlockHeight>,
    ) -> Result<Vec<TxId>, ChainError> {
        Err(unsupported_by_bounded_scan_tracer("get_address_tx_ids"))
    }
}

impl ZinderChainView {
    async fn full_block_bytes(&self, height: BlockHeight) -> Result<Option<Vec<u8>>, ChainError> {
        if height > self.tip.height() {
            return Ok(None);
        }

        match self.snapshot.full_block_at(zinder_height(height)).await {
            Ok(artifact) => Ok(Some(artifact.raw_block_bytes)),
            Err(IndexerError::NotFound { .. }) => Ok(None),
            Err(error) => Err(chain_error(error)),
        }
    }

    fn stream_zinder_range(
        &self,
        range: ZinderBlockHeightRange,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        let snapshot = self.snapshot.clone();
        let params = self.params;

        stream::once(async move { snapshot.full_blocks_in_range(range).await })
            .try_flatten()
            .map(move |result| {
                result.map_err(chain_error).and_then(|artifact| {
                    let height = BlockHeight::from_u32(artifact.height.value());
                    decode_block(artifact.raw_block_bytes, &params, height)
                })
            })
            .boxed()
    }
}

fn bounded_scan_preflight_message(missing: &[Capability]) -> String {
    let missing_names = missing
        .iter()
        .map(Capability::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let mut preflight_error =
        format!("Zinder endpoint is missing bounded-scan capabilities: {missing_names}");

    if missing.iter().any(|capability| {
        matches!(
            capability,
            Capability::FullBlock | Capability::FullBlockRange
        )
    }) {
        preflight_error.push_str(
            "; full-block reads require raw_blob_policy=all for Zinder ingest and query; \
             rebuild the canonical store under that policy and cut over with a blue-green \
             replacement because retention cannot be upgraded in place",
        );
    }

    preflight_error
}

fn zinder_network(params: Network) -> ZinderNetwork {
    match params {
        Network::Consensus(consensus::Network::MainNetwork) => ZinderNetwork::ZcashMainnet,
        Network::Consensus(consensus::Network::TestNetwork) => ZinderNetwork::ZcashTestnet,
        Network::RegTest(_) => ZinderNetwork::ZcashRegtest,
    }
}

fn zinder_height(height: BlockHeight) -> ZinderBlockHeight {
    ZinderBlockHeight::new(u32::from(height))
}

fn chain_block(block: ZinderBlockId) -> ChainBlock {
    ChainBlock::new(
        BlockHeight::from_u32(block.height.value()),
        BlockHash(block.hash.as_bytes()),
    )
}

fn zinder_range_from_half_open(
    range: &Range<BlockHeight>,
    tip: BlockHeight,
) -> Option<ZinderBlockHeightRange> {
    if range.is_empty() || range.start > tip {
        return None;
    }

    let end = (range.end - 1).min(tip);
    Some(ZinderBlockHeightRange::inclusive(
        zinder_height(range.start),
        zinder_height(end),
    ))
}

fn decode_block(
    bytes: Vec<u8>,
    params: &Network,
    requested_height: BlockHeight,
) -> Result<Block, ChainError> {
    let block = Block::read(bytes.as_slice(), params).map_err(|error| {
        invalid_data(format!(
            "invalid full block at height {requested_height}: {error}"
        ))
    })?;
    if block.claimed_height() != requested_height {
        return Err(invalid_data(format!(
            "full block claimed height {} for requested height {requested_height}",
            block.claimed_height()
        )));
    }
    Ok(block)
}

fn chain_state(artifact: TreeStateArtifact) -> Result<ChainState, ChainError> {
    let payload: Value = serde_json::from_slice(&artifact.payload_bytes).map_err(|error| {
        invalid_data(format!(
            "tree state at height {} is not JSON: {error}",
            artifact.height.value()
        ))
    })?;
    if !payload.is_object() {
        return Err(invalid_data(format!(
            "tree state at height {} must be a JSON object",
            artifact.height.value()
        )));
    }

    let sapling = match final_state_bytes(&payload, "sapling")? {
        Some(bytes) => sapling_frontier(&bytes)?,
        None => CommitmentTree::empty(),
    }
    .to_frontier();
    let orchard = orchard_tree_frontier(&payload, "orchard")?;
    let ironwood = orchard_tree_frontier(&payload, "ironwood")?;

    Ok(ChainState::new(
        BlockHeight::from_u32(artifact.height.value()),
        BlockHash(artifact.block_hash.as_bytes()),
        sapling,
        orchard,
        ironwood,
    ))
}

fn orchard_tree_frontier(
    payload: &Value,
    pool: &'static str,
) -> Result<
    incrementalmerkletree::frontier::Frontier<
        MerkleHashOrchard,
        { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
    >,
    ChainError,
> {
    match final_state_bytes(payload, pool)? {
        Some(bytes) => orchard_frontier(&bytes, pool),
        None => Ok(CommitmentTree::empty()),
    }
    .map(|tree| tree.to_frontier())
}

fn sapling_frontier(
    bytes: &[u8],
) -> Result<CommitmentTree<sapling::Node, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>, ChainError> {
    let mut reader = Cursor::new(bytes);
    let tree = read_commitment_tree::<sapling::Node, _, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>(
        &mut reader,
    )
    .map_err(|error| invalid_tree_state("sapling", error))?;
    reject_trailing_final_state_bytes("sapling", &reader)?;
    Ok(tree)
}

fn orchard_frontier(
    bytes: &[u8],
    pool: &'static str,
) -> Result<
    CommitmentTree<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
    ChainError,
> {
    let mut reader = Cursor::new(bytes);
    let tree = read_commitment_tree::<
        MerkleHashOrchard,
        _,
        { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
    >(&mut reader)
    .map_err(|error| invalid_tree_state(pool, error))?;
    reject_trailing_final_state_bytes(pool, &reader)?;
    Ok(tree)
}

fn reject_trailing_final_state_bytes(
    pool: &'static str,
    reader: &Cursor<&[u8]>,
) -> Result<(), ChainError> {
    let consumed = usize::try_from(reader.position()).map_err(|error| {
        invalid_tree_state(
            pool,
            format!("decoded position does not fit usize: {error}"),
        )
    })?;
    if consumed != reader.get_ref().len() {
        Err(invalid_tree_state(pool, "encoding contains trailing bytes"))
    } else {
        Ok(())
    }
}

fn final_state_bytes(payload: &Value, pool: &'static str) -> Result<Option<Vec<u8>>, ChainError> {
    let Some(pool_value) = payload.get(pool) else {
        return Ok(None);
    };
    let pool_fields = pool_value
        .as_object()
        .ok_or_else(|| invalid_data(format!("{pool} tree-state pool must be a JSON object")))?;
    let Some(commitments_value) = pool_fields.get("commitments") else {
        return Ok(None);
    };
    let commitments = commitments_value.as_object().ok_or_else(|| {
        invalid_data(format!(
            "{pool} tree-state commitments must be a JSON object"
        ))
    })?;
    let Some(final_state) = commitments.get("finalState") else {
        return if commitments.is_empty() {
            Ok(None)
        } else {
            Err(invalid_data(format!(
                "{pool} tree-state commitments are missing finalState"
            )))
        };
    };
    let encoded = final_state.as_str().ok_or_else(|| {
        invalid_data(format!(
            "{pool} tree-state finalState must be a hexadecimal string"
        ))
    })?;
    hex::decode(encoded)
        .map(Some)
        .map_err(|error| invalid_tree_state(pool, error))
}

fn sapling_subtree_root(
    artifact: SubtreeRootArtifact,
) -> Result<CommitmentTreeRoot<sapling::Node>, ChainError> {
    let root_bytes = artifact.root_hash.as_bytes();
    let root = Option::<sapling::Node>::from(sapling::Node::from_bytes(root_bytes))
        .ok_or_else(|| invalid_data("Sapling subtree root is not canonically encoded"))?;
    Ok(CommitmentTreeRoot::from_parts(
        BlockHeight::from_u32(artifact.completing_block_height.value()),
        root,
    ))
}

fn orchard_subtree_root(
    artifact: SubtreeRootArtifact,
) -> Result<CommitmentTreeRoot<MerkleHashOrchard>, ChainError> {
    let root_bytes = artifact.root_hash.as_bytes();
    let root = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&root_bytes))
        .ok_or_else(|| invalid_data("Orchard-shaped subtree root is not canonically encoded"))?;
    Ok(CommitmentTreeRoot::from_parts(
        BlockHeight::from_u32(artifact.completing_block_height.value()),
        root,
    ))
}

fn init_error(error: IndexerError) -> Error {
    ErrorKind::Init.context(error).into()
}

fn chain_error(error: IndexerError) -> ChainError {
    match error {
        error @ IndexerError::ChainEpochPinUnavailable => ChainError::view_expired(error),
        error @ (IndexerError::DataLoss { .. }
        | IndexerError::MalformedResponse { .. }
        | IndexerError::NetworkMismatch { .. }) => ChainError::invalid_data(error),
        error if error.retry_policy() == RetryPolicy::RetryWithBackoff => {
            ChainError::unavailable(error)
        }
        error => ChainError::backend(error),
    }
}

fn invalid_tree_state(pool: &'static str, source: impl std::fmt::Display) -> ChainError {
    invalid_data(format!("{pool} tree-state finalState is invalid: {source}"))
}

fn invalid_data(message: impl Into<String>) -> ChainError {
    ChainError::invalid_data(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

fn unsupported_by_bounded_scan_tracer(method: &'static str) -> ChainError {
    ChainError::backend(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{method} is unsupported by the bounded-scan tracer"),
    ))
}

fn unsupported_stream_by_bounded_scan_tracer(
    method: &'static str,
) -> BoxStream<'static, Result<Block, ChainError>> {
    stream::once(async move { Err(unsupported_by_bounded_scan_tracer(method)) }).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zinder_client::BlockHash as ZinderBlockHash;

    #[test]
    fn zinder_types_satisfy_chain_trait_bounds() {
        fn assert_chain<T: Chain>() {}
        fn assert_chain_view<T: ChainView>() {}

        assert_chain::<ZinderChain>();
        assert_chain_view::<ZinderChainView>();
    }

    #[test]
    fn half_open_range_is_clamped_to_the_snapshot_tip() {
        let range = BlockHeight::from_u32(10)..BlockHeight::from_u32(20);

        assert_eq!(
            zinder_range_from_half_open(&range, BlockHeight::from_u32(14)),
            Some(ZinderBlockHeightRange::inclusive(
                ZinderBlockHeight::new(10),
                ZinderBlockHeight::new(14),
            )),
        );
    }

    #[test]
    fn empty_or_above_tip_ranges_do_not_issue_a_zinder_request() {
        let empty = BlockHeight::from_u32(10)..BlockHeight::from_u32(10);
        let above_tip = BlockHeight::from_u32(15)..BlockHeight::from_u32(20);

        assert_eq!(
            zinder_range_from_half_open(&empty, BlockHeight::from_u32(14)),
            None
        );
        assert_eq!(
            zinder_range_from_half_open(&above_tip, BlockHeight::from_u32(14)),
            None
        );
    }

    #[test]
    fn missing_full_blocks_explain_retention_rebuild_and_cutover() {
        let message =
            bounded_scan_preflight_message(&[Capability::FullBlock, Capability::FullBlockRange]);

        assert!(message.contains("raw_blob_policy=all"));
        assert!(message.contains("rebuild the canonical store"));
        assert!(message.contains("blue-green replacement"));
    }

    #[test]
    fn non_retention_capability_failure_omits_store_rebuild_guidance() {
        let message = bounded_scan_preflight_message(&[Capability::NetworkUpgradeActivations]);

        assert!(!message.contains("raw_blob_policy"));
        assert!(!message.contains("blue-green"));
    }

    #[test]
    fn canonical_empty_tree_states_produce_empty_frontiers() {
        let artifact = TreeStateArtifact::new(
            ZinderBlockHeight::new(7),
            ZinderBlockHash::from_bytes([3; 32]),
            0,
            br#"{
                "sapling":{"commitments":{"finalState":"000000"}},
                "orchard":{"commitments":{"finalState":"000000"}},
                "ironwood":{"commitments":{"finalState":"000000"}}
            }"#
            .to_vec(),
        );

        assert!(matches!(
            chain_state(artifact),
            Ok(state)
                if state.block_height() == BlockHeight::from_u32(7)
                    && state.block_hash() == BlockHash([3; 32])
                    && state.final_sapling_tree().tree_size() == 0
                    && state.final_orchard_tree().tree_size() == 0
                    && state.final_ironwood_tree().tree_size() == 0
        ));
    }

    #[test]
    fn malformed_tree_state_hex_is_invalid_data() {
        let artifact = TreeStateArtifact::new(
            ZinderBlockHeight::new(7),
            ZinderBlockHash::from_bytes([3; 32]),
            0,
            br#"{"sapling":{"commitments":{"finalState":"not-hex"}}}"#.to_vec(),
        );

        assert!(matches!(
            chain_state(artifact),
            Err(ChainError::InvalidData(_))
        ));
    }

    #[test]
    fn trailing_tree_state_bytes_are_invalid_data() {
        let artifact = TreeStateArtifact::new(
            ZinderBlockHeight::new(7),
            ZinderBlockHash::from_bytes([3; 32]),
            0,
            br#"{"sapling":{"commitments":{"finalState":"00000000"}}}"#.to_vec(),
        );

        assert!(matches!(
            chain_state(artifact),
            Err(ChainError::InvalidData(_))
        ));
    }

    #[test]
    fn expired_snapshot_maps_only_to_view_expired_and_retains_the_typed_source() {
        let ChainError::ViewExpired(source) = chain_error(IndexerError::ChainEpochPinUnavailable)
        else {
            panic!("chain epoch pin expiry must invalidate the current view");
        };

        assert!(matches!(
            source.downcast_ref::<IndexerError>(),
            Some(IndexerError::ChainEpochPinUnavailable)
        ));
    }

    #[test]
    fn unrelated_failures_retain_their_existing_categories() {
        assert!(matches!(
            chain_error(IndexerError::NoVisibleChainEpoch),
            ChainError::Unavailable(_)
        ));
        assert!(matches!(
            chain_error(IndexerError::DataLoss {
                reason: "corrupt block".to_owned(),
            }),
            ChainError::InvalidData(_)
        ));
        assert!(matches!(
            chain_error(IndexerError::FailedPrecondition {
                reason: "operator action required".to_owned(),
            }),
            ChainError::Backend(_)
        ));
    }

    #[test]
    fn whole_sync_methods_are_explicit_unsupported_errors() {
        for method in [
            "find_fork_point",
            "get_block_header",
            "stream_blocks_to_tip",
        ] {
            let ChainError::Backend(source) = unsupported_by_bounded_scan_tracer(method) else {
                panic!("whole-sync methods must remain backend errors");
            };
            let error = source
                .downcast_ref::<io::Error>()
                .expect("whole-sync method error must retain its unsupported I/O kind");

            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert_eq!(
                error.to_string(),
                format!("{method} is unsupported by the bounded-scan tracer")
            );
        }
    }

    #[tokio::test]
    async fn stream_to_tip_reports_one_explicit_error() {
        let items = unsupported_stream_by_bounded_scan_tracer("stream_blocks_to_tip")
            .collect::<Vec<_>>()
            .await;

        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], Err(ChainError::Backend(_))));
    }
}
