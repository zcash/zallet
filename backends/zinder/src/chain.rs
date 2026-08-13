//! Zinder-backed implementation of Zallet's chain boundary.

use std::{
    collections::{HashSet, VecDeque},
    io::{self, Cursor},
    num::NonZeroU32,
    ops::Range,
    sync::Arc,
};

#[cfg(feature = "bounded-scan-certification")]
use std::{
    env, fs,
    io::Write as _,
    path::Path,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

use futures::{
    FutureExt as _, StreamExt as _, TryStreamExt as _,
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
use zcash_script::script::Evaluable as _;
use zinder_client::{
    BlockBlobArtifact, BlockHash as ZinderBlockHash, BlockHeight as ZinderBlockHeight,
    BlockHeightRange as ZinderBlockHeightRange, BlockId as ZinderBlockId, BlockSelector,
    Capability, ChainEpochId, ChainEventStream, ChainIndex, EndpointBackedIndex, EventStreamStart,
    IndexStream, IndexerError, MAX_SUBTREE_ROOTS_PER_REQUEST, MempoolEntry, MempoolEvent,
    MempoolEventStream, MempoolSnapshotRequest, MempoolSnapshotView, Network as ZinderNetwork,
    OwnedChainSnapshot, RawTransactionBytes, RemoteChainIndex, RetryPolicy, ShieldedProtocol,
    SubtreeRootArtifact, SubtreeRootIndex, SubtreeRootRange, TransactionBroadcastOutcome,
    TransactionId as ZinderTransactionId, TransparentAddressScriptHash,
    TransparentAddressTransactionChunk, TransparentAddressTxIdsQuery,
    TransparentAddressTxIdsStream, TransparentAddressUnspentOutputsStream, TreeStateArtifact,
    TxStatus,
};

use crate::{open_zinder_index, probe_missing_wallet_runtime_capabilities};

/// Maximum full blocks requested from Zinder in one range call.
///
/// Zinder's native wallet endpoint rejects wider full-block ranges. Paging
/// here keeps an arbitrarily long Zallet sync demand-driven while every page
/// remains bound to the same captured chain epoch.
const FULL_BLOCK_PAGE_SIZE: u64 = 1_000;

/// Maximum hydrated mempool entries requested in one snapshot page.
///
/// The server owns the hard upper bound. Keeping the request bounded makes a
/// large mempool's memory cost explicit and lets this adapter drain all pages
/// through the durable resume anchor returned with the first page.
const MEMPOOL_SNAPSHOT_PAGE_SIZE: u32 = 1_000;

/// Maximum transparent-address history entries requested from Zinder per page.
const TRANSPARENT_ADDRESS_HISTORY_PAGE_SIZE: u32 = 1_000;

/// Genesis floor required when comparing Zallet's outputs with the complete unspent set.
const TRANSPARENT_ADDRESS_UNSPENT_START_HEIGHT: ZinderBlockHeight = ZinderBlockHeight::new(0);

#[cfg(feature = "bounded-scan-certification")]
const RANGE_BARRIER_DIRECTORY_ENV: &str = "ZIT_RANGE_BARRIER_DIR";
#[cfg(feature = "bounded-scan-certification")]
const RANGE_REQUEST_PAUSE_START_HEIGHT_ENV: &str = "ZIT_RANGE_REQUEST_PAUSE_START_HEIGHT";
#[cfg(feature = "bounded-scan-certification")]
const RANGE_REQUEST_BARRIER_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(feature = "bounded-scan-certification")]
const RANGE_REQUEST_BARRIER_POLL_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(feature = "bounded-scan-certification")]
const CERTIFICATION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
#[cfg(feature = "bounded-scan-certification")]
const RANGE_REQUEST_PAUSED_MARKER_FILENAME: &str = "range-request-paused.json";
#[cfg(feature = "bounded-scan-certification")]
const CONTINUE_RANGE_REQUEST_MARKER_FILENAME: &str = "continue-range-request";
#[cfg(feature = "bounded-scan-certification")]
static RANGE_REQUEST_ATTEMPT_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "bounded-scan-certification")]
static RANGE_REQUEST_PAUSE_CLAIMED: AtomicBool = AtomicBool::new(false);

/// Zallet's configuration-backed native Zinder backend factory.
#[derive(Clone, Copy, Debug, Default)]
pub struct ZinderBackend;

impl ChainFactory for ZinderBackend {
    type Chain = ZinderChain;

    const NAME: &'static str = "zinder";

    async fn build(&self, config: &ZalletConfig) -> Result<(Self::Chain, TaskHandle), Error> {
        let endpoint = config
            .zinder
            .wallet_query_endpoint
            .as_ref()
            .ok_or_else(|| ErrorKind::Init.context("[zinder].wallet_query_endpoint is required"))?
            .as_str()
            .to_owned();
        let chain = ZinderChain::connect(endpoint, config.consensus.network()).await?;

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
    /// Connects to Zinder and verifies every wallet-runtime requirement.
    ///
    /// Construction performs a real `ServerInfo` request so an unreachable
    /// endpoint, network mismatch, or incomplete capability set fails before
    /// this function returns a chain value.
    pub async fn connect(endpoint: String, params: Network) -> Result<Self, Error> {
        let index = open_zinder_index(endpoint, zinder_network(params)).map_err(init_error)?;
        let missing = probe_missing_wallet_runtime_capabilities(&index)
            .await
            .map_err(init_error)?;
        if !missing.is_empty() {
            return Err(ErrorKind::Init
                .context(wallet_runtime_preflight_message(&missing))
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

        subtree_roots_from_snapshot(&snapshot, protocol).await
    }
}

trait SubtreeRootSnapshot {
    type SubtreeRoot;

    fn chain_epoch_id(&self) -> ChainEpochId;

    fn completed_subtree_count(&self, protocol: ShieldedProtocol) -> u32;

    fn subtree_roots_in_range(
        &self,
        subtree_root_range: SubtreeRootRange,
    ) -> impl Future<Output = Result<Vec<Self::SubtreeRoot>, IndexerError>>;
}

impl<I: ChainIndex + ?Sized> SubtreeRootSnapshot for OwnedChainSnapshot<I> {
    type SubtreeRoot = SubtreeRootArtifact;

    fn chain_epoch_id(&self) -> ChainEpochId {
        self.chain_epoch().id
    }

    fn completed_subtree_count(&self, protocol: ShieldedProtocol) -> u32 {
        self.chain_epoch()
            .tip_metadata
            .completed_subtree_count(protocol)
    }

    fn subtree_roots_in_range(
        &self,
        subtree_root_range: SubtreeRootRange,
    ) -> impl Future<Output = Result<Vec<Self::SubtreeRoot>, IndexerError>> {
        OwnedChainSnapshot::subtree_roots_in_range(self, subtree_root_range)
    }
}

trait PinnedChainSnapshot: Clone + Send + Sync + 'static {
    fn block_id_by_selector(
        &self,
        selector: BlockSelector,
    ) -> impl Future<Output = Result<ZinderBlockId, IndexerError>> + Send;

    fn retained_full_block_at(
        &self,
        height: ZinderBlockHeight,
    ) -> impl Future<Output = Result<BlockBlobArtifact, IndexerError>> + Send;

    fn retained_full_blocks_in_range(
        &self,
        block_range: ZinderBlockHeightRange,
    ) -> impl Future<Output = Result<IndexStream<BlockBlobArtifact>, IndexerError>> + Send;
}

impl PinnedChainSnapshot for OwnedChainSnapshot<RemoteChainIndex> {
    fn block_id_by_selector(
        &self,
        selector: BlockSelector,
    ) -> impl Future<Output = Result<ZinderBlockId, IndexerError>> + Send {
        OwnedChainSnapshot::block_id_by_selector(self, selector)
    }

    async fn retained_full_block_at(
        &self,
        height: ZinderBlockHeight,
    ) -> Result<BlockBlobArtifact, IndexerError> {
        OwnedChainSnapshot::full_block_at(self, height).await
    }

    async fn retained_full_blocks_in_range(
        &self,
        block_range: ZinderBlockHeightRange,
    ) -> Result<IndexStream<BlockBlobArtifact>, IndexerError> {
        #[cfg(feature = "bounded-scan-certification")]
        {
            await_range_request_barrier(self, block_range).await?;
        }

        OwnedChainSnapshot::full_blocks_in_range(self, block_range).await
    }
}

trait TransparentAddressSnapshot: Clone + Send + Sync + 'static {
    fn chain_epoch(&self) -> zinder_client::ChainEpoch;

    fn transparent_address_unspent_outputs(
        &self,
        address_script_hash: TransparentAddressScriptHash,
        start_height: ZinderBlockHeight,
    ) -> impl Future<Output = Result<TransparentAddressUnspentOutputsStream, IndexerError>> + Send;

    fn transparent_address_tx_ids_in_range(
        &self,
        query: TransparentAddressTxIdsQuery,
    ) -> impl Future<Output = Result<TransparentAddressTxIdsStream, IndexerError>> + Send;
}

impl TransparentAddressSnapshot for OwnedChainSnapshot<RemoteChainIndex> {
    fn chain_epoch(&self) -> zinder_client::ChainEpoch {
        OwnedChainSnapshot::chain_epoch(self)
    }

    async fn transparent_address_unspent_outputs(
        &self,
        address_script_hash: TransparentAddressScriptHash,
        start_height: ZinderBlockHeight,
    ) -> Result<TransparentAddressUnspentOutputsStream, IndexerError> {
        OwnedChainSnapshot::transparent_address_unspent_outputs(
            self,
            address_script_hash,
            start_height,
        )
        .await
    }

    async fn transparent_address_tx_ids_in_range(
        &self,
        query: TransparentAddressTxIdsQuery,
    ) -> Result<TransparentAddressTxIdsStream, IndexerError> {
        OwnedChainSnapshot::transparent_address_tx_ids_in_range(self, query).await
    }
}

async fn subtree_roots_from_snapshot<S: SubtreeRootSnapshot + ?Sized>(
    snapshot: &S,
    protocol: ShieldedProtocol,
) -> Result<Vec<S::SubtreeRoot>, ChainError> {
    let root_count = snapshot.completed_subtree_count(protocol);
    let mut remaining_root_count = root_count;
    let mut next_subtree_index = SubtreeRootIndex::new(0);
    let mut subtree_roots = Vec::new();

    while remaining_root_count > 0 {
        let requested_root_count = remaining_root_count.min(MAX_SUBTREE_ROOTS_PER_REQUEST);
        let Some(max_entries) = NonZeroU32::new(requested_root_count) else {
            return Err(invalid_data(
                "subtree-root pagination produced an empty request",
            ));
        };
        let requested_range = SubtreeRootRange::new(protocol, next_subtree_index, max_entries);
        let page = snapshot
            .subtree_roots_in_range(requested_range)
            .await
            .map_err(chain_error)?;
        let expected_page_length = usize::try_from(requested_root_count).map_err(|error| {
            invalid_data(format!("subtree-root page length is invalid: {error}"))
        })?;

        if page.len() != expected_page_length {
            return Err(invalid_data(format!(
                "Zinder returned {} {protocol:?} subtree roots at index {} for chain epoch {}; \
                 expected {requested_root_count} from the epoch-advertised total of {root_count}",
                page.len(),
                next_subtree_index.value(),
                snapshot.chain_epoch_id().value(),
            )));
        }

        subtree_roots.extend(page);
        let Some(next_remaining_root_count) =
            remaining_root_count.checked_sub(requested_root_count)
        else {
            return Err(invalid_data("subtree-root page count underflowed"));
        };
        remaining_root_count = next_remaining_root_count;
        let Some(next_index) = next_subtree_index.value().checked_add(requested_root_count) else {
            return Err(invalid_data("subtree-root page index overflowed"));
        };
        next_subtree_index = SubtreeRootIndex::new(next_index);
    }

    Ok(subtree_roots)
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

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), ChainError> {
        let submitted_transaction_id = zinder_transaction_id(tx.txid());
        let mut raw_transaction = Vec::new();
        tx.write(&mut raw_transaction)
            .map_err(ChainError::backend)?;
        let outcome = self
            .index
            .broadcast_transaction(RawTransactionBytes::new(raw_transaction))
            .await
            .map_err(chain_error)?;

        broadcast_result(submitted_transaction_id, outcome)
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
            index: Arc::clone(&self.index),
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
    index: Arc<RemoteChainIndex>,
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
        locator: &BlockLocator,
    ) -> Result<Option<ChainBlock>, ChainError> {
        find_fork_point_in_snapshot(&self.snapshot, locator).await
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
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>, ChainError> {
        block_header_from_snapshot(&self.snapshot, self.tip.height(), height).await
    }

    async fn get_block(&self, height: BlockHeight) -> Result<Option<Block>, ChainError> {
        self.retained_full_block(height)
            .await?
            .map(|block| decode_retained_block(block, &self.params, height))
            .transpose()
    }

    fn stream_blocks_to_tip(&self, start: BlockHeight) -> BoxStream<'_, Result<Block, ChainError>> {
        self.decode_retained_full_blocks(stream_retained_full_blocks_to_tip(
            self.snapshot.clone(),
            start,
            self.tip.height(),
        ))
    }

    fn stream_blocks(
        &self,
        range: &Range<BlockHeight>,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        self.decode_retained_full_blocks(stream_retained_full_blocks_in_half_open_range(
            self.snapshot.clone(),
            range,
            self.tip.height(),
        ))
    }

    async fn get_mempool_stream(
        &self,
    ) -> Result<Option<BoxStream<'_, Result<Transaction, ChainError>>>, ChainError> {
        // Subscribe before reading the snapshot so no source transition can
        // disappear between the snapshot fence and the visible-tip fence.
        let chain_events = self
            .index
            .chain_events(EventStreamStart::LiveTail)
            .await
            .map_err(chain_error)?;

        let Some(mempool_snapshot) =
            collect_mempool_snapshot(&self.index, self.snapshot.chain_epoch().id, self.tip).await?
        else {
            return Ok(None);
        };
        let mempool_events = self
            .index
            .mempool_events(mempool_snapshot.event_start)
            .await
            .map_err(chain_error)?;
        let mempool_branch = consensus::BranchId::for_height(&self.params, self.tip.height() + 1);

        let mut seen = HashSet::new();
        let mut initial = VecDeque::with_capacity(mempool_snapshot.entries.len());
        for entry in mempool_snapshot.entries {
            let transaction_id = entry.transaction_id();
            if seen.insert(transaction_id) {
                initial.push_back(decode_mempool_transaction(entry, mempool_branch)?);
            }
        }

        tracing::info!(
            captured_tip_height = u32::from(self.tip.height()),
            initial_mempool_transactions = initial.len(),
            "following Zinder mempool after captured snapshot"
        );
        Ok(Some(follow_mempool_until_tip_changes(
            initial,
            seen,
            chain_events,
            mempool_events,
            self.tip,
            mempool_branch,
        )))
    }

    async fn get_transaction(&self, txid: TxId) -> Result<Option<ChainTx>, ChainError> {
        let transaction_id = zinder_transaction_id(txid);
        match self
            .snapshot
            .transaction_by_id(transaction_id)
            .await
            .map_err(chain_error)?
        {
            TxStatus::Mined(mined) => decode_mined_transaction(txid, mined).map(Some),
            TxStatus::NotFound => Ok(None),
            TxStatus::InMempool(_) => Err(invalid_data(
                "pinned Zinder transaction lookup unexpectedly consulted the live mempool",
            )),
            _ => Err(invalid_data(
                "Zinder returned an unknown pinned transaction status",
            )),
        }
    }

    async fn get_transaction_status(&self, txid: TxId) -> Result<TransactionStatus, ChainError> {
        match self
            .snapshot
            .transaction_by_id(zinder_transaction_id(txid))
            .await
            .map_err(chain_error)?
        {
            TxStatus::Mined(mined) => Ok(TransactionStatus::Mined(BlockHeight::from_u32(
                mined.location.block_height.value(),
            ))),
            TxStatus::NotFound => Ok(TransactionStatus::TxidNotRecognized),
            TxStatus::InMempool(_) => Err(invalid_data(
                "pinned Zinder transaction status unexpectedly consulted the live mempool",
            )),
            _ => Err(invalid_data(
                "Zinder returned an unknown pinned transaction status",
            )),
        }
    }

    async fn get_address_unspent_outpoints(
        &self,
        address: &TransparentAddress,
    ) -> Result<Vec<(TxId, u32)>, ChainError> {
        transparent_address_unspent_outpoints(&self.snapshot, address).await
    }

    async fn get_address_tx_ids(
        &self,
        address: &TransparentAddress,
        range: Range<BlockHeight>,
    ) -> Result<Vec<TxId>, ChainError> {
        transparent_address_tx_ids(&self.snapshot, address, &range).await
    }
}

impl ZinderChainView {
    async fn retained_full_block(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockBlobArtifact>, ChainError> {
        retained_full_block_from_snapshot(&self.snapshot, self.tip.height(), height).await
    }

    fn decode_retained_full_blocks(
        &self,
        retained_blocks: BoxStream<'static, Result<BlockBlobArtifact, ChainError>>,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        let params = self.params;

        retained_blocks
            .map(move |result| {
                result.and_then(|block| {
                    let height = BlockHeight::from_u32(block.height.value());
                    decode_retained_block(block, &params, height)
                })
            })
            .boxed()
    }
}

async fn transparent_address_unspent_outpoints<S: TransparentAddressSnapshot>(
    snapshot: &S,
    address: &TransparentAddress,
) -> Result<Vec<(TxId, u32)>, ChainError> {
    let expected_epoch = snapshot.chain_epoch();
    let address_script_hash = transparent_address_script_hash(address);
    let mut stream = snapshot
        .transparent_address_unspent_outputs(
            address_script_hash,
            TRANSPARENT_ADDRESS_UNSPENT_START_HEIGHT,
        )
        .await
        .map_err(chain_error)?;
    let mut previous_output_key = None;
    let mut seen_outpoints = HashSet::new();
    let mut outpoints = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(chain_error)?;
        validate_transparent_unspent_chunk(
            &chunk,
            expected_epoch,
            address_script_hash,
            previous_output_key,
        )?;
        let output = chunk.output;
        if !seen_outpoints.insert(output.outpoint) {
            return Err(invalid_data(format!(
                "Zinder repeated transparent outpoint {}:{}",
                hex::encode(output.outpoint.transaction_id.as_bytes()),
                output.outpoint.output_index,
            )));
        }
        previous_output_key = Some((
            output.block_height.value(),
            output.outpoint.transaction_id.as_bytes(),
            output.outpoint.output_index,
        ));
        outpoints.push((
            TxId::from_bytes(output.outpoint.transaction_id.as_bytes()),
            output.outpoint.output_index,
        ));
    }

    Ok(outpoints)
}

fn validate_transparent_unspent_chunk(
    chunk: &zinder_client::TransparentUnspentOutputChunk,
    expected_epoch: zinder_client::ChainEpoch,
    address_script_hash: TransparentAddressScriptHash,
    previous_output_key: Option<(u32, [u8; 32], u32)>,
) -> Result<(), ChainError> {
    if chunk.chain_epoch != expected_epoch {
        return Err(invalid_data(
            "Zinder changed chain epoch during a transparent unspent-output read",
        ));
    }
    let output = &chunk.output;
    if output.address_script_hash != address_script_hash
        || TransparentAddressScriptHash::of_script_pub_key(&output.script_pub_key)
            != address_script_hash
    {
        return Err(invalid_data(
            "Zinder returned a transparent unspent output for a different address",
        ));
    }
    if output.block_height > expected_epoch.visible_tip_height {
        return Err(invalid_data(format!(
            "Zinder returned a transparent unspent output at height {} above captured tip {}",
            output.block_height.value(),
            expected_epoch.visible_tip_height.value(),
        )));
    }
    let output_key = (
        output.block_height.value(),
        output.outpoint.transaction_id.as_bytes(),
        output.outpoint.output_index,
    );
    if previous_output_key.is_some_and(|previous| output_key <= previous) {
        return Err(invalid_data(
            "Zinder returned transparent unspent outputs out of canonical order",
        ));
    }

    Ok(())
}

async fn transparent_address_tx_ids<S: TransparentAddressSnapshot>(
    snapshot: &S,
    address: &TransparentAddress,
    range: &Range<BlockHeight>,
) -> Result<Vec<TxId>, ChainError> {
    let expected_epoch = snapshot.chain_epoch();
    let tip = BlockHeight::from_u32(expected_epoch.visible_tip_height.value());
    let Some(range) = zinder_range_from_half_open(range, tip) else {
        return Ok(Vec::new());
    };
    let address_script_hash = transparent_address_script_hash(address);
    let max_entries = NonZeroU32::new(TRANSPARENT_ADDRESS_HISTORY_PAGE_SIZE)
        .ok_or_else(|| invalid_data("transparent-address history page size must be nonzero"))?;
    let mut from_cursor = None;
    let mut previous_position = None;
    let mut seen_transaction_ids = HashSet::new();
    let mut transaction_ids = Vec::new();

    loop {
        let requested_cursor = from_cursor.clone();
        let query = TransparentAddressTxIdsQuery {
            address_script_hash,
            start_height: range.start,
            end_height: range.end,
            max_entries: Some(max_entries),
            from_cursor: requested_cursor.clone(),
            descending: false,
            at_epoch_id: Some(expected_epoch.id),
        };
        let mut stream = snapshot
            .transparent_address_tx_ids_in_range(query)
            .await
            .map_err(chain_error)?;
        let mut next_cursor = None;
        let mut page_entry_count = 0_u32;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(chain_error)?;
            if next_cursor.is_some() {
                return Err(invalid_data(
                    "Zinder returned transparent history after the page resume cursor",
                ));
            }
            validate_transparent_history_chunk(
                &chunk,
                expected_epoch,
                address_script_hash,
                range,
                previous_position,
            )?;
            page_entry_count = page_entry_count
                .checked_add(1)
                .ok_or_else(|| invalid_data("transparent-address history page count overflowed"))?;
            if page_entry_count > max_entries.get() {
                return Err(invalid_data(
                    "Zinder exceeded the requested transparent-address history page size",
                ));
            }
            let artifact = chunk.artifact;
            if !seen_transaction_ids.insert(artifact.transaction_id) {
                return Err(invalid_data(format!(
                    "Zinder repeated transparent address-history transaction {}",
                    hex::encode(artifact.transaction_id.as_bytes()),
                )));
            }
            previous_position = Some((artifact.block_height.value(), artifact.tx_index_in_block));
            transaction_ids.push(TxId::from_bytes(artifact.transaction_id.as_bytes()));
            next_cursor = chunk.cursor;
        }

        let Some(cursor) = next_cursor else {
            break;
        };
        if requested_cursor.as_ref() == Some(&cursor) {
            return Err(invalid_data(
                "Zinder repeated a transparent-address history cursor without completing the read",
            ));
        }
        from_cursor = Some(cursor);
    }

    Ok(transaction_ids)
}

fn validate_transparent_history_chunk(
    chunk: &TransparentAddressTransactionChunk,
    expected_epoch: zinder_client::ChainEpoch,
    address_script_hash: TransparentAddressScriptHash,
    range: ZinderBlockHeightRange,
    previous_position: Option<(u32, u32)>,
) -> Result<(), ChainError> {
    if chunk.chain_epoch != expected_epoch {
        return Err(invalid_data(
            "Zinder changed chain epoch during a transparent address-history read",
        ));
    }
    let artifact = chunk.artifact;
    if artifact.address_script_hash != address_script_hash {
        return Err(invalid_data(
            "Zinder returned transparent history for a different address",
        ));
    }
    if artifact.block_height < range.start || artifact.block_height > range.end {
        return Err(invalid_data(format!(
            "Zinder returned transparent history height {} outside requested inclusive range {}..={}",
            artifact.block_height.value(),
            range.start.value(),
            range.end.value(),
        )));
    }
    let position = (artifact.block_height.value(), artifact.tx_index_in_block);
    if previous_position.is_some_and(|previous| position <= previous) {
        return Err(invalid_data(
            "Zinder returned transparent address history out of ascending mined order",
        ));
    }

    Ok(())
}

fn transparent_address_script_hash(address: &TransparentAddress) -> TransparentAddressScriptHash {
    TransparentAddressScriptHash::of_script_pub_key(&address.script().to_bytes())
}

/// One fully paged mempool snapshot and the event position that follows it.
struct MempoolSnapshotFence {
    entries: Vec<MempoolEntry>,
    event_start: EventStreamStart<zinder_client::MempoolEventCursor>,
}

async fn collect_mempool_snapshot(
    index: &RemoteChainIndex,
    expected_epoch_id: ChainEpochId,
    expected_tip: ChainBlock,
) -> Result<Option<MempoolSnapshotFence>, ChainError> {
    let expected_source_tip = zinder_block_id(expected_tip);
    let mut next_cursor = None;
    let mut snapshot_anchor = None;
    let mut entries = Vec::new();
    let mut page_count = 0_u32;

    loop {
        let page = index
            .mempool_snapshot(MempoolSnapshotRequest {
                max_entries: MEMPOOL_SNAPSHOT_PAGE_SIZE,
                from_cursor: next_cursor.clone(),
            })
            .await
            .map_err(chain_error)?;
        page_count = page_count
            .checked_add(1)
            .ok_or_else(|| invalid_data("mempool snapshot page count overflowed"))?;
        if !mempool_snapshot_matches_view(&page, expected_epoch_id, expected_source_tip) {
            tracing::info!(
                captured_tip_height = u32::from(expected_tip.height()),
                snapshot_tip_height = page.source_tip.height.value(),
                "Zinder visible tip changed while acquiring the mempool snapshot"
            );
            return Ok(None);
        }

        match &snapshot_anchor {
            Some(anchor) if anchor != &page.events_resume_cursor => {
                return Err(invalid_data(
                    "Zinder changed the mempool event anchor during one snapshot walk",
                ));
            }
            None => snapshot_anchor = Some(page.events_resume_cursor.clone()),
            Some(_) => {}
        }
        entries.extend(page.entries);

        let returned_cursor = page.next_cursor;
        if returned_cursor == next_cursor && returned_cursor.is_some() {
            return Err(invalid_data(
                "Zinder repeated a mempool snapshot cursor without completing the snapshot",
            ));
        }
        let Some(cursor) = returned_cursor else {
            break;
        };
        next_cursor = Some(cursor);
    }

    let event_start = match snapshot_anchor.flatten() {
        Some(cursor) => EventStreamStart::AfterCursor(cursor),
        None => EventStreamStart::EarliestRetained,
    };
    tracing::debug!(
        mempool_snapshot_pages = page_count,
        "acquired Zinder mempool snapshot"
    );
    Ok(Some(MempoolSnapshotFence {
        entries,
        event_start,
    }))
}

fn mempool_snapshot_matches_view(
    page: &MempoolSnapshotView,
    expected_epoch_id: ChainEpochId,
    expected_source_tip: ZinderBlockId,
) -> bool {
    page.chain_epoch.id == expected_epoch_id && page.source_tip == expected_source_tip
}

fn follow_mempool_until_tip_changes(
    initial: VecDeque<Transaction>,
    seen: HashSet<ZinderTransactionId>,
    chain_events: ChainEventStream,
    mempool_events: MempoolEventStream,
    captured_tip: ChainBlock,
    mempool_branch: consensus::BranchId,
) -> BoxStream<'static, Result<Transaction, ChainError>> {
    stream::unfold(
        MempoolFollow {
            initial,
            seen,
            chain_events,
            mempool_events,
            captured_tip,
            mempool_branch,
            finished: false,
        },
        |mut follow| async move {
            loop {
                // `LiveTail` was opened before the snapshot walk. Poll it
                // before draining buffered snapshot entries so an already
                // observed tip change wins over stale snapshot output.
                match follow.chain_events.next().now_or_never() {
                    Some(Some(Ok(event)))
                        if chain_event_changes_visible_tip(&event, follow.captured_tip) =>
                    {
                            tracing::info!(
                                captured_tip_height = u32::from(follow.captured_tip.height()),
                                observed_tip_height = event.chain_epoch.visible_tip_height.value(),
                                "ending Zinder mempool follow after visible-tip transition"
                            );
                            return None;
                    }
                    Some(Some(Ok(_))) => continue,
                    None => {}
                    Some(Some(Err(error))) => {
                        follow.finished = true;
                        return Some((Err(chain_error(error)), follow));
                    }
                    Some(None) => {
                        follow.finished = true;
                        return Some((Err(ChainError::unavailable(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Zinder chain event stream ended before the captured visible tip changed",
                        ))), follow));
                    }
                }
                if let Some(transaction) = follow.initial.pop_front() {
                    return Some((Ok(transaction), follow));
                }
                if follow.finished {
                    return None;
                }

                tokio::select! {
                    biased;
                    chain_event = follow.chain_events.next() => match chain_event {
                        Some(Ok(event)) if chain_event_changes_visible_tip(&event, follow.captured_tip) => {
                            tracing::info!(
                                captured_tip_height = u32::from(follow.captured_tip.height()),
                                observed_tip_height = event.chain_epoch.visible_tip_height.value(),
                                "ending Zinder mempool follow after visible-tip transition"
                            );
                            return None;
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(error)) => {
                            follow.finished = true;
                            return Some((Err(chain_error(error)), follow));
                        }
                        None => {
                            follow.finished = true;
                            return Some((Err(ChainError::unavailable(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Zinder chain event stream ended before the captured visible tip changed",
                            ))), follow));
                        }
                    },
                    mempool_event = follow.mempool_events.next() => match mempool_event {
                        Some(Ok(envelope)) => {
                            if let MempoolEvent::Added { entry } = &envelope.event {
                                let first_seen_epoch = entry.first_seen_chain_epoch();
                                if visible_tip_changed(
                                    follow.captured_tip,
                                    first_seen_epoch.visible_tip_height,
                                    first_seen_epoch.visible_tip_hash,
                                ) {
                                    tracing::info!(
                                        captured_tip_height = u32::from(follow.captured_tip.height()),
                                        observed_tip_height = first_seen_epoch.visible_tip_height.value(),
                                        "ending Zinder mempool follow after newer-tip mempool event"
                                    );
                                    return None;
                                }
                            }
                            match apply_mempool_event(&mut follow.seen, envelope.event) {
                                Ok(Some(entry)) => {
                                    match decode_mempool_transaction(entry, follow.mempool_branch) {
                                        Ok(transaction) => return Some((Ok(transaction), follow)),
                                        Err(error) => {
                                            follow.finished = true;
                                            return Some((Err(error), follow));
                                        }
                                    }
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    follow.finished = true;
                                    return Some((Err(error), follow));
                                }
                            }
                        }
                        Some(Err(error)) => {
                            follow.finished = true;
                            return Some((Err(chain_error(error)), follow));
                        }
                        None => {
                            follow.finished = true;
                            return Some((Err(ChainError::unavailable(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Zinder mempool event stream ended before the captured visible tip changed",
                            ))), follow));
                        }
                    },
                }
            }
        },
    )
    .boxed()
}

struct MempoolFollow {
    initial: VecDeque<Transaction>,
    seen: HashSet<ZinderTransactionId>,
    chain_events: ChainEventStream,
    mempool_events: MempoolEventStream,
    captured_tip: ChainBlock,
    mempool_branch: consensus::BranchId,
    finished: bool,
}

fn apply_mempool_event(
    seen: &mut HashSet<ZinderTransactionId>,
    event: MempoolEvent,
) -> Result<Option<MempoolEntry>, ChainError> {
    match event {
        MempoolEvent::Added { entry } if seen.insert(entry.transaction_id()) => Ok(Some(entry)),
        MempoolEvent::Added { .. }
        | MempoolEvent::Invalidated { .. }
        | MempoolEvent::Mined { .. } => Ok(None),
        _ => Err(invalid_data("Zinder returned an unknown mempool event")),
    }
}

fn chain_event_changes_visible_tip(
    event: &zinder_client::ChainEventEnvelope,
    captured_tip: ChainBlock,
) -> bool {
    visible_tip_changed(
        captured_tip,
        event.chain_epoch.visible_tip_height,
        event.chain_epoch.visible_tip_hash,
    )
}

fn visible_tip_changed(
    captured_tip: ChainBlock,
    observed_height: ZinderBlockHeight,
    observed_hash: ZinderBlockHash,
) -> bool {
    observed_height.value() != u32::from(captured_tip.height())
        || observed_hash.as_bytes() != captured_tip.hash().0
}

fn decode_mined_transaction(
    requested_transaction_id: TxId,
    mined: zinder_client::MinedTransaction,
) -> Result<ChainTx, ChainError> {
    let raw = mined.raw_transaction_bytes.ok_or_else(|| {
        invalid_data("Zinder returned a canonical transaction without retained raw bytes")
    })?;
    let branch = consensus::BranchId::try_from(mined.chain_context.consensus_branch_id.value())
        .map_err(|error| {
            invalid_data(format!(
                "Zinder returned an invalid consensus branch id: {error}"
            ))
        })?;
    let inner = decode_transaction(&raw, branch, requested_transaction_id)?;
    let block_time = u32::try_from(mined.chain_context.block_time).map_err(|error| {
        invalid_data(format!(
            "Zinder returned an invalid mined block time: {error}"
        ))
    })?;

    Ok(ChainTx::new(
        inner,
        raw,
        Some(BlockHash(mined.location.block_hash.as_bytes())),
        Some(BlockHeight::from_u32(mined.location.block_height.value())),
        Some(block_time),
    ))
}

fn decode_mempool_transaction(
    entry: MempoolEntry,
    branch: consensus::BranchId,
) -> Result<Transaction, ChainError> {
    let expected_transaction_id = TxId::from_bytes(entry.transaction_id().as_bytes());
    decode_transaction(
        entry.raw_transaction_bytes().as_slice(),
        branch,
        expected_transaction_id,
    )
}

fn decode_transaction(
    raw: &[u8],
    branch: consensus::BranchId,
    expected_transaction_id: TxId,
) -> Result<Transaction, ChainError> {
    let transaction = Transaction::read(raw, branch).map_err(|error| {
        invalid_data(format!(
            "Zinder returned malformed transaction bytes: {error}"
        ))
    })?;
    if transaction.txid() != expected_transaction_id {
        return Err(invalid_data(format!(
            "Zinder transaction bytes decoded to {}, expected {expected_transaction_id}",
            transaction.txid(),
        )));
    }
    Ok(transaction)
}

fn zinder_transaction_id(transaction_id: TxId) -> ZinderTransactionId {
    ZinderTransactionId::from_bytes(*transaction_id.as_ref())
}

fn zinder_block_id(block: ChainBlock) -> ZinderBlockId {
    ZinderBlockId::new(
        ZinderBlockHeight::new(u32::from(block.height())),
        ZinderBlockHash::from_bytes(block.hash().0),
    )
}

async fn find_fork_point_in_snapshot<S: PinnedChainSnapshot>(
    snapshot: &S,
    locator: &BlockLocator,
) -> Result<Option<ChainBlock>, ChainError> {
    for hash in locator.hashes() {
        let selector = BlockSelector::from_hash(ZinderBlockHash::from_bytes(hash.0));
        match snapshot.block_id_by_selector(selector).await {
            Ok(block) => return Ok(Some(chain_block(block))),
            Err(IndexerError::NotFound { resource: "block" }) => {}
            Err(error) => return Err(chain_error(error)),
        }
    }

    Ok(None)
}

async fn retained_full_block_from_snapshot<S: PinnedChainSnapshot>(
    snapshot: &S,
    tip: BlockHeight,
    height: BlockHeight,
) -> Result<Option<BlockBlobArtifact>, ChainError> {
    if height > tip {
        return Ok(None);
    }

    match snapshot.retained_full_block_at(zinder_height(height)).await {
        Ok(block) => Ok(Some(block)),
        Err(IndexerError::NotFound { .. }) => Ok(None),
        Err(error) => Err(chain_error(error)),
    }
}

async fn block_header_from_snapshot<S: PinnedChainSnapshot>(
    snapshot: &S,
    tip: BlockHeight,
    height: BlockHeight,
) -> Result<Option<BlockHeader>, ChainError> {
    retained_full_block_from_snapshot(snapshot, tip, height)
        .await?
        .map(|block| decode_retained_block_header(block, height))
        .transpose()
}

fn stream_retained_full_blocks_to_tip<S: PinnedChainSnapshot>(
    snapshot: S,
    start: BlockHeight,
    tip: BlockHeight,
) -> BoxStream<'static, Result<BlockBlobArtifact, ChainError>> {
    stream_retained_full_blocks_in_range(
        snapshot,
        ZinderBlockHeightRange::inclusive(zinder_height(start), zinder_height(tip)),
    )
}

fn stream_retained_full_blocks_in_half_open_range<S: PinnedChainSnapshot>(
    snapshot: S,
    range: &Range<BlockHeight>,
    tip: BlockHeight,
) -> BoxStream<'static, Result<BlockBlobArtifact, ChainError>> {
    match zinder_range_from_half_open(range, tip) {
        Some(block_range) => stream_retained_full_blocks_in_range(snapshot, block_range),
        None => stream::empty().boxed(),
    }
}

fn stream_retained_full_blocks_in_range<S: PinnedChainSnapshot>(
    snapshot: S,
    block_range: ZinderBlockHeightRange,
) -> BoxStream<'static, Result<BlockBlobArtifact, ChainError>> {
    let next_start_height = u64::from(block_range.start.value());
    let range_end_height = u64::from(block_range.end.value());

    stream::try_unfold(next_start_height, move |next_start_height| {
        let snapshot = snapshot.clone();
        async move {
            if next_start_height > range_end_height {
                return Ok(None);
            }

            let page_end_height = next_start_height
                .saturating_add(FULL_BLOCK_PAGE_SIZE - 1)
                .min(range_end_height);
            let page_start = u32::try_from(next_start_height).map_err(|error| {
                invalid_data(format!("full-block page start is invalid: {error}"))
            })?;
            let page_end = u32::try_from(page_end_height).map_err(|error| {
                invalid_data(format!("full-block page end is invalid: {error}"))
            })?;
            let block_range = ZinderBlockHeightRange::inclusive(
                ZinderBlockHeight::new(page_start),
                ZinderBlockHeight::new(page_end),
            );
            let page = snapshot
                .retained_full_blocks_in_range(block_range)
                .await
                .map_err(chain_error)?
                .map_err(chain_error)
                .boxed();

            Ok(Some((page, page_end_height + 1)))
        }
    })
    .try_flatten()
    .boxed()
}

#[cfg(feature = "bounded-scan-certification")]
async fn await_range_request_barrier(
    snapshot: &OwnedChainSnapshot<RemoteChainIndex>,
    range: ZinderBlockHeightRange,
) -> Result<(), IndexerError> {
    let previous_attempt_count = RANGE_REQUEST_ATTEMPT_COUNT.fetch_add(1, Ordering::SeqCst);
    let attempt_number = previous_attempt_count
        .checked_add(1)
        .ok_or_else(|| range_request_barrier_error("range-request attempt counter overflowed"))?;
    let pause_start_height = optional_environment_u32(RANGE_REQUEST_PAUSE_START_HEIGHT_ENV)
        .map_err(|error| range_request_barrier_error(error.to_string()))?;
    let Some(barrier_directory) = env::var_os(RANGE_BARRIER_DIRECTORY_ENV) else {
        if pause_start_height.is_some() {
            return Err(range_request_barrier_error(format!(
                "{RANGE_BARRIER_DIRECTORY_ENV} is required when \
                 {RANGE_REQUEST_PAUSE_START_HEIGHT_ENV} is configured"
            )));
        }
        return Ok(());
    };
    let barrier_directory = Path::new(&barrier_directory);
    if !barrier_directory.is_absolute() {
        return Err(range_request_barrier_error(format!(
            "{RANGE_BARRIER_DIRECTORY_ENV} must be an absolute path: {barrier_directory:?}"
        )));
    }
    fs::create_dir_all(barrier_directory).map_err(|error| {
        range_request_barrier_error(format!(
            "cannot create range barrier directory {barrier_directory:?}: {error}"
        ))
    })?;

    let marker = serde_json::json!({
        "schema_version": CERTIFICATION_EVIDENCE_SCHEMA_VERSION,
        "attempt_number": attempt_number,
        "requested_start_height_inclusive": range.start.value(),
        "requested_end_height_inclusive": range.end.value(),
        "chain_epoch_id": snapshot.chain_epoch().id.value(),
    });
    let attempt_marker_path = range_request_attempt_marker_path(barrier_directory, attempt_number);
    write_json_atomically(&attempt_marker_path, &marker).map_err(|error| {
        range_request_barrier_error(format!(
            "cannot write range-request marker {attempt_marker_path:?}: {error}"
        ))
    })?;

    let Some(pause_start_height) = pause_start_height else {
        return Ok(());
    };
    if range.start.value() != pause_start_height
        || RANGE_REQUEST_PAUSE_CLAIMED.swap(true, Ordering::SeqCst)
    {
        return Ok(());
    }

    let paused_marker_path = barrier_directory.join(RANGE_REQUEST_PAUSED_MARKER_FILENAME);
    write_json_atomically(&paused_marker_path, &marker).map_err(|error| {
        range_request_barrier_error(format!(
            "cannot write paused range-request marker {paused_marker_path:?}: {error}"
        ))
    })?;
    let continue_range_request_path =
        barrier_directory.join(CONTINUE_RANGE_REQUEST_MARKER_FILENAME);
    let wait_for_continue_marker = async {
        loop {
            match fs::metadata(&continue_range_request_path) {
                Ok(metadata) if metadata.is_file() => return Ok(()),
                Ok(_) => {
                    return Err(range_request_barrier_error(format!(
                        "range continuation marker is not a file: \
                         {continue_range_request_path:?}"
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    tokio::time::sleep(RANGE_REQUEST_BARRIER_POLL_INTERVAL).await;
                }
                Err(error) => {
                    return Err(range_request_barrier_error(format!(
                        "cannot inspect range continuation marker \
                         {continue_range_request_path:?}: {error}"
                    )));
                }
            }
        }
    };

    tokio::time::timeout(RANGE_REQUEST_BARRIER_TIMEOUT, wait_for_continue_marker)
        .await
        .map_err(|_| {
            range_request_barrier_error(format!(
                "timed out after {RANGE_REQUEST_BARRIER_TIMEOUT:?} waiting for \
                 {continue_range_request_path:?}"
            ))
        })?
}

#[cfg(feature = "bounded-scan-certification")]
fn optional_environment_u32(name: &'static str) -> io::Result<Option<u32>> {
    match env::var(name) {
        Ok(value) => parse_u32_environment_value(name, &value).map(Some),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must contain valid UTF-8"),
        )),
    }
}

#[cfg(feature = "bounded-scan-certification")]
fn parse_u32_environment_value(name: &'static str, value: &str) -> io::Result<u32> {
    value.parse::<u32>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a decimal u32, received {value:?}: {error}"),
        )
    })
}

#[cfg(feature = "bounded-scan-certification")]
fn range_request_attempt_marker_path(
    barrier_directory: &Path,
    attempt_number: u64,
) -> std::path::PathBuf {
    barrier_directory.join(format!("range-request-attempt-{attempt_number}.json"))
}

#[cfg(feature = "bounded-scan-certification")]
fn write_json_atomically(path: &Path, evidence: &Value) -> io::Result<()> {
    let parent_directory = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("JSON evidence path has no parent directory: {path:?}"),
        )
    })?;
    fs::create_dir_all(parent_directory)?;
    let mut temporary_file = tempfile::NamedTempFile::new_in(parent_directory)?;
    serde_json::to_writer_pretty(&mut temporary_file, evidence).map_err(io::Error::other)?;
    temporary_file.write_all(b"\n")?;
    temporary_file.as_file().sync_all()?;
    temporary_file.persist_noclobber(path).map_err(|error| {
        io::Error::new(
            error.error.kind(),
            format!(
                "cannot persist JSON evidence without replacing {path:?}: {}",
                error.error
            ),
        )
    })?;
    Ok(())
}

#[cfg(feature = "bounded-scan-certification")]
fn range_request_barrier_error(message: impl Into<String>) -> IndexerError {
    IndexerError::FailedPrecondition {
        reason: format!(
            "bounded-scan range-request barrier failed: {}",
            message.into()
        ),
    }
}

fn wallet_runtime_preflight_message(missing: &[Capability]) -> String {
    let missing_names = missing
        .iter()
        .map(Capability::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let mut preflight_error =
        format!("Zinder endpoint is missing wallet-runtime capabilities: {missing_names}");

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

fn decode_retained_block(
    retained_block: BlockBlobArtifact,
    params: &Network,
    requested_height: BlockHeight,
) -> Result<Block, ChainError> {
    let block =
        Block::read(retained_block.raw_block_bytes.as_slice(), params).map_err(|error| {
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
    validate_retained_block_identity(&retained_block, block.header(), requested_height)?;
    Ok(block)
}

fn decode_retained_block_header(
    retained_block: BlockBlobArtifact,
    requested_height: BlockHeight,
) -> Result<BlockHeader, ChainError> {
    let header = BlockHeader::read(retained_block.raw_block_bytes.as_slice()).map_err(|error| {
        invalid_data(format!(
            "invalid full-block header at height {requested_height}: {error}"
        ))
    })?;
    validate_retained_block_identity(&retained_block, &header, requested_height)?;
    Ok(header)
}

fn validate_retained_block_identity(
    retained_block: &BlockBlobArtifact,
    header: &BlockHeader,
    requested_height: BlockHeight,
) -> Result<(), ChainError> {
    let retained_height = BlockHeight::from_u32(retained_block.height.value());
    if retained_height != requested_height {
        return Err(invalid_data(format!(
            "retained full block identified height {retained_height} for requested height \
             {requested_height}"
        )));
    }

    let retained_hash = BlockHash(retained_block.block_hash.as_bytes());
    if header.hash() != retained_hash {
        return Err(invalid_data(format!(
            "full-block header hash {} differs from retained block hash {retained_hash} at height \
             {requested_height}",
            header.hash()
        )));
    }

    let retained_parent_hash = BlockHash(retained_block.parent_hash.as_bytes());
    if header.prev_block != retained_parent_hash {
        return Err(invalid_data(format!(
            "full-block header parent {} differs from retained parent {retained_parent_hash} at \
             height {requested_height}",
            header.prev_block
        )));
    }

    Ok(())
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

fn broadcast_result(
    submitted_transaction_id: ZinderTransactionId,
    outcome: TransactionBroadcastOutcome,
) -> Result<(), ChainError> {
    match outcome {
        TransactionBroadcastOutcome::Accepted(accepted)
            if accepted.transaction_id == submitted_transaction_id =>
        {
            Ok(())
        }
        TransactionBroadcastOutcome::Accepted(accepted) => Err(invalid_data(format!(
            "Zinder accepted transaction {} after Zallet submitted {}",
            hex::encode(accepted.transaction_id.as_bytes()),
            hex::encode(submitted_transaction_id.as_bytes())
        ))),
        TransactionBroadcastOutcome::Duplicate(_) | TransactionBroadcastOutcome::Queued(_) => {
            Ok(())
        }
        TransactionBroadcastOutcome::InvalidEncoding(invalid_encoding) => {
            Err(invalid_data(broadcast_failure_message(
                "reported invalid encoding for",
                invalid_encoding.error_code,
                &invalid_encoding.message,
            )))
        }
        TransactionBroadcastOutcome::Rejected(rejected) => {
            Err(ChainError::backend(io::Error::other(format!(
                "Zinder rejected transaction broadcast ({:?}{}): {}",
                rejected.kind,
                optional_error_code(rejected.error_code),
                rejected.message
            ))))
        }
        TransactionBroadcastOutcome::Unknown(unknown) => Err(ChainError::backend(
            io::Error::other(broadcast_failure_message(
                "returned an unknown outcome for",
                unknown.error_code,
                &unknown.message,
            )),
        )),
        _ => Err(ChainError::backend(io::Error::other(
            "Zinder returned an unsupported transaction broadcast outcome",
        ))),
    }
}

fn broadcast_failure_message(outcome: &str, error_code: Option<i64>, message: &str) -> String {
    format!(
        "Zinder {outcome} transaction broadcast{}: {message}",
        optional_error_code(error_code)
    )
}

fn optional_error_code(error_code: Option<i64>) -> String {
    error_code.map_or_else(String::new, |code| format!(", code {code}"))
}

fn invalid_tree_state(pool: &'static str, source: impl std::fmt::Display) -> ChainError {
    invalid_data(format!("{pool} tree-state finalState is invalid: {source}"))
}

fn invalid_data(message: impl Into<String>) -> ChainError {
    ChainError::invalid_data(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::HashMap,
        future,
        sync::{Arc, Mutex},
    };

    #[cfg(feature = "bounded-scan-certification")]
    use std::{
        env,
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
    };

    #[cfg(feature = "bounded-scan-certification")]
    use zallet_core::components::bounded_scan_certification::{
        BoundedScanCertificationConfig, BoundedScanCertificationOutcome, certify_bounded_scan,
    };

    use transparent::{
        builder::Coinbase,
        bundle::{Bundle, TxIn},
    };
    use zcash_primitives::{
        block::BlockHeaderData,
        transaction::{Authorized, TransactionData, TxVersion},
    };
    use zcash_protocol::consensus::BranchId;

    use super::*;
    use zinder_client::{
        MempoolEvictionReason, TransparentAddressTxIndexArtifact, TransparentHistoryCursor,
        TransparentOutPoint, TransparentUnspentOutput, TransparentUnspentOutputChunk,
    };
    use zinder_core::{
        ArtifactSchemaVersion, ChainEpoch, ChainTipMetadata, CompactTransactionData,
        MempoolObservation, UnixTimestampMillis,
    };

    const CAPTURED_CHAIN_EPOCH_ID: ChainEpochId = ChainEpochId::new(41);
    const CONFIGURED_RECOVERY_BATCH_SIZE: u32 = 10_000;
    const TEST_STREAM_START_HEIGHT: u32 = 5;
    const TEST_BLOCK_TRANSACTION_COUNT: u8 = 1;

    #[cfg(feature = "bounded-scan-certification")]
    const ZINDER_ENDPOINT_ENV: &str = "ZIT_ZINDER_ENDPOINT";
    #[cfg(feature = "bounded-scan-certification")]
    const ZALLET_CONFIG_ENV: &str = "ZIT_ZALLET_CONFIG";
    #[cfg(feature = "bounded-scan-certification")]
    const CERTIFICATION_DATADIR_ENV: &str = "ZIT_CERTIFICATION_DATADIR";
    #[cfg(feature = "bounded-scan-certification")]
    const REQUESTED_START_HEIGHT_ENV: &str = "ZIT_REQUESTED_START_HEIGHT";
    #[cfg(feature = "bounded-scan-certification")]
    const REQUESTED_END_HEIGHT_EXCLUSIVE_ENV: &str = "ZIT_REQUESTED_END_HEIGHT_EXCLUSIVE";
    #[cfg(feature = "bounded-scan-certification")]
    const RETRY_END_HEIGHT_EXCLUSIVE_ENV: &str = "ZIT_RETRY_END_HEIGHT_EXCLUSIVE";
    #[cfg(feature = "bounded-scan-certification")]
    const CERTIFICATION_RESULT_ENV: &str = "ZIT_CERTIFICATION_RESULT";
    #[cfg(feature = "bounded-scan-certification")]
    const EPOCH_PIN_UNAVAILABLE_SOURCE_CLASSIFICATION: &str =
        "IndexerError::ChainEpochPinUnavailable";

    #[cfg(feature = "bounded-scan-certification")]
    type CertificationTestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[cfg(feature = "bounded-scan-certification")]
    #[test]
    fn range_request_pause_start_height_accepts_decimal_u32() {
        assert_eq!(
            parse_u32_environment_value(RANGE_REQUEST_PAUSE_START_HEIGHT_ENV, "1001")
                .expect("parses request start height"),
            1_001
        );
    }

    #[cfg(feature = "bounded-scan-certification")]
    #[test]
    fn range_request_pause_start_height_accepts_genesis() {
        assert!(parse_u32_environment_value(RANGE_REQUEST_PAUSE_START_HEIGHT_ENV, "0").is_ok());
    }

    #[cfg(feature = "bounded-scan-certification")]
    #[test]
    fn range_request_pause_start_height_rejects_non_decimal() {
        assert!(
            parse_u32_environment_value(RANGE_REQUEST_PAUSE_START_HEIGHT_ENV, "second").is_err()
        );
    }

    #[cfg(feature = "bounded-scan-certification")]
    struct CertificationEnvironment {
        zinder_endpoint: String,
        zallet_config: ZalletConfig,
        certification_datadir: PathBuf,
        requested_block_range: Range<u32>,
        certification_result_path: PathBuf,
    }

    #[cfg(feature = "bounded-scan-certification")]
    #[derive(Debug, Eq, PartialEq)]
    struct RangeRequestMarker {
        schema_version: u32,
        attempt_number: u64,
        requested_start_height_inclusive: u32,
        requested_end_height_inclusive: u32,
        chain_epoch_id: u64,
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn read_certification_environment() -> CertificationTestResult<CertificationEnvironment> {
        let zinder_endpoint = required_environment_text(ZINDER_ENDPOINT_ENV)?;
        let zallet_config_path = required_absolute_environment_path(ZALLET_CONFIG_ENV)?;
        let zallet_config_contents = fs::read_to_string(&zallet_config_path).map_err(|error| {
            certification_failure(format!(
                "cannot read Zallet configuration {zallet_config_path:?}: {error}"
            ))
        })?;
        let zallet_config = toml::from_str(&zallet_config_contents).map_err(|error| {
            certification_failure(format!(
                "cannot parse Zallet configuration {zallet_config_path:?}: {error}"
            ))
        })?;
        let requested_start_height = required_environment_height(REQUESTED_START_HEIGHT_ENV)?;
        let requested_end_height = required_environment_height(REQUESTED_END_HEIGHT_EXCLUSIVE_ENV)?;
        let certification_result_path =
            required_absolute_environment_path(CERTIFICATION_RESULT_ENV)?;
        if certification_result_path.try_exists()? {
            return Err(certification_failure(format!(
                "{CERTIFICATION_RESULT_ENV} must not replace stale evidence: \
                 {certification_result_path:?} already exists"
            ))
            .into());
        }

        Ok(CertificationEnvironment {
            zinder_endpoint,
            zallet_config,
            certification_datadir: required_absolute_environment_path(CERTIFICATION_DATADIR_ENV)?,
            requested_block_range: requested_start_height..requested_end_height,
            certification_result_path,
        })
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn required_environment_text(name: &'static str) -> io::Result<String> {
        match env::var(name) {
            Ok(value) if !value.is_empty() => Ok(value),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("required environment variable {name} is empty"),
            )),
            Err(env::VarError::NotPresent) => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("required environment variable {name} is missing"),
            )),
            Err(env::VarError::NotUnicode(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must contain valid UTF-8"),
            )),
        }
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn required_absolute_environment_path(name: &'static str) -> io::Result<PathBuf> {
        let path = match env::var_os(name) {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("required environment variable {name} is empty"),
            ))?,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("required environment variable {name} is missing"),
                ));
            }
        };
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be an absolute path: {path:?}"),
            ));
        }

        Ok(path)
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn required_environment_height(name: &'static str) -> io::Result<u32> {
        let encoded_height = required_environment_text(name)?;
        encoded_height.parse().map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{name} must be a decimal u32 height, received {encoded_height:?}: {error}"
                ),
            )
        })
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn certification_failure(message: impl Into<String>) -> io::Error {
        io::Error::other(message.into())
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn sqlite_wallet_artifact_paths(wallet_database_path: &Path) -> [PathBuf; 3] {
        [
            wallet_database_path.to_owned(),
            path_with_suffix(wallet_database_path, "-wal"),
            path_with_suffix(wallet_database_path, "-shm"),
        ]
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
        let mut suffixed_path = OsString::from(path);
        suffixed_path.push(suffix);
        PathBuf::from(suffixed_path)
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn find_existing_wallet_artifacts(
        wallet_artifact_paths: &[PathBuf],
    ) -> io::Result<Vec<PathBuf>> {
        wallet_artifact_paths
            .iter()
            .filter_map(|path| match path.try_exists() {
                Ok(true) => Some(Ok(path.clone())),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn is_wallet_artifact_path(path: &Path, wallet_artifact_paths: &[PathBuf]) -> bool {
        wallet_artifact_paths
            .iter()
            .any(|wallet_artifact_path| path == wallet_artifact_path)
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn read_range_request_marker(path: &Path) -> io::Result<RangeRequestMarker> {
        let encoded_marker = fs::read(path)?;
        let marker: Value = serde_json::from_slice(&encoded_marker).map_err(io::Error::other)?;
        let schema_version = u32::try_from(required_marker_u64(&marker, path, "schema_version")?)
            .map_err(|error| {
            certification_failure(format!(
                "range-request marker {path:?} has an invalid schema_version: {error}"
            ))
        })?;
        let requested_start_height_inclusive = u32::try_from(required_marker_u64(
            &marker,
            path,
            "requested_start_height_inclusive",
        )?)
        .map_err(|error| {
            certification_failure(format!(
                "range-request marker {path:?} has an invalid start height: {error}"
            ))
        })?;
        let requested_end_height_inclusive = u32::try_from(required_marker_u64(
            &marker,
            path,
            "requested_end_height_inclusive",
        )?)
        .map_err(|error| {
            certification_failure(format!(
                "range-request marker {path:?} has an invalid end height: {error}"
            ))
        })?;

        Ok(RangeRequestMarker {
            schema_version,
            attempt_number: required_marker_u64(&marker, path, "attempt_number")?,
            requested_start_height_inclusive,
            requested_end_height_inclusive,
            chain_epoch_id: required_marker_u64(&marker, path, "chain_epoch_id")?,
        })
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn required_marker_u64(marker: &Value, path: &Path, field: &'static str) -> io::Result<u64> {
        marker.get(field).and_then(Value::as_u64).ok_or_else(|| {
            certification_failure(format!(
                "range-request marker {path:?} is missing unsigned integer field {field:?}"
            ))
        })
    }

    #[cfg(feature = "bounded-scan-certification")]
    fn assert_range_request_marker(
        marker: &RangeRequestMarker,
        attempt_number: u64,
        requested_block_range: &Range<u32>,
    ) -> io::Result<()> {
        let expected_marker = RangeRequestMarker {
            schema_version: CERTIFICATION_EVIDENCE_SCHEMA_VERSION,
            attempt_number,
            requested_start_height_inclusive: requested_block_range.start,
            requested_end_height_inclusive: requested_block_range.end - 1,
            chain_epoch_id: marker.chain_epoch_id,
        };
        if marker != &expected_marker {
            return Err(certification_failure(format!(
                "range-request marker differs from the expected attempt and inclusive range: \
                 actual {marker:?}, expected {expected_marker:?}"
            )));
        }

        Ok(())
    }

    #[cfg(feature = "bounded-scan-certification")]
    #[test]
    fn certification_evidence_cannot_replace_an_existing_result() {
        let evidence_directory =
            tempfile::tempdir().expect("creates an isolated evidence directory");
        let result_path = evidence_directory.path().join("certification-result.json");
        let first_evidence = serde_json::json!({
            "schema_version": CERTIFICATION_EVIDENCE_SCHEMA_VERSION,
            "attempt": 1,
        });
        write_json_atomically(&result_path, &first_evidence)
            .expect("first atomic evidence write succeeds");

        let replacement_evidence = serde_json::json!({
            "schema_version": CERTIFICATION_EVIDENCE_SCHEMA_VERSION,
            "attempt": 2,
        });
        let error = write_json_atomically(&result_path, &replacement_evidence)
            .expect_err("atomic evidence writes must not replace an existing result");

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            serde_json::from_slice::<Value>(
                &fs::read(result_path).expect("reads the original evidence")
            )
            .expect("original evidence remains valid JSON"),
            first_evidence
        );
    }

    #[cfg(feature = "bounded-scan-certification")]
    #[test]
    fn certification_result_cannot_use_a_wallet_artifact_path() {
        let wallet_artifact_paths =
            sqlite_wallet_artifact_paths(Path::new("/certification/wallet.db"));

        assert!(
            wallet_artifact_paths
                .iter()
                .all(|path| is_wallet_artifact_path(path, &wallet_artifact_paths))
        );
        assert!(!is_wallet_artifact_path(
            Path::new("/certification/certification-result.json"),
            &wallet_artifact_paths,
        ));
    }

    #[derive(Clone, Copy)]
    enum BlockLookupResponse {
        Canonical(ZinderBlockId),
        BlockNotFound,
        UnrelatedNotFound,
        RemoteBlockNotInBestChain,
        ViewExpired,
    }

    #[derive(Clone, Default)]
    struct RecordingPinnedChainSnapshot {
        block_lookup_by_hash: Arc<HashMap<ZinderBlockHash, BlockLookupResponse>>,
        requested_block_selectors: Arc<Mutex<Vec<BlockSelector>>>,
        full_blocks_by_height: Arc<HashMap<ZinderBlockHeight, BlockBlobArtifact>>,
        requested_full_block_heights: Arc<Mutex<Vec<ZinderBlockHeight>>>,
        requested_full_block_ranges: Arc<Mutex<Vec<ZinderBlockHeightRange>>>,
        expiring_range_request_number: Option<usize>,
    }

    impl RecordingPinnedChainSnapshot {
        fn with_block_lookup(
            mut self,
            block_hash: ZinderBlockHash,
            response: BlockLookupResponse,
        ) -> Self {
            Arc::make_mut(&mut self.block_lookup_by_hash).insert(block_hash, response);
            self
        }

        fn with_retained_full_block_at(
            mut self,
            requested_height: ZinderBlockHeight,
            retained_block: BlockBlobArtifact,
        ) -> Self {
            Arc::make_mut(&mut self.full_blocks_by_height).insert(requested_height, retained_block);
            self
        }

        fn expiring_on_range_request(mut self, request_number: usize) -> Self {
            self.expiring_range_request_number = Some(request_number);
            self
        }

        fn requested_block_selectors(&self) -> Vec<BlockSelector> {
            self.requested_block_selectors
                .lock()
                .expect("focused test block-selector request lock is not poisoned")
                .clone()
        }

        fn requested_full_block_heights(&self) -> Vec<ZinderBlockHeight> {
            self.requested_full_block_heights
                .lock()
                .expect("focused test full-block request lock is not poisoned")
                .clone()
        }

        fn requested_full_block_ranges(&self) -> Vec<ZinderBlockHeightRange> {
            self.requested_full_block_ranges
                .lock()
                .expect("focused test full-block range lock is not poisoned")
                .clone()
        }
    }

    impl PinnedChainSnapshot for RecordingPinnedChainSnapshot {
        async fn block_id_by_selector(
            &self,
            selector: BlockSelector,
        ) -> Result<ZinderBlockId, IndexerError> {
            self.requested_block_selectors
                .lock()
                .expect("focused test block-selector request lock is not poisoned")
                .push(selector);

            let response = match selector {
                BlockSelector::Hash(block_hash) => self
                    .block_lookup_by_hash
                    .get(&block_hash)
                    .copied()
                    .unwrap_or(BlockLookupResponse::BlockNotFound),
                BlockSelector::Height(_) => {
                    return Err(IndexerError::InvalidRequest {
                        reason: "focused test snapshot accepts only hash selectors".to_owned(),
                    });
                }
                _ => {
                    return Err(IndexerError::InvalidRequest {
                        reason: "focused test snapshot received an unknown selector".to_owned(),
                    });
                }
            };

            match response {
                BlockLookupResponse::Canonical(block_id) => Ok(block_id),
                BlockLookupResponse::BlockNotFound => {
                    Err(IndexerError::NotFound { resource: "block" })
                }
                BlockLookupResponse::UnrelatedNotFound => Err(IndexerError::NotFound {
                    resource: "transaction",
                }),
                BlockLookupResponse::RemoteBlockNotInBestChain => {
                    Err(IndexerError::RemoteFailure {
                        reason: zinder_client::ErrorReason::BlockNotInBestChain,
                        message: "block is not in the best chain".to_owned(),
                        retry_policy: RetryPolicy::RetryWithBackoff,
                    })
                }
                BlockLookupResponse::ViewExpired => Err(IndexerError::ChainEpochPinUnavailable),
            }
        }

        async fn retained_full_block_at(
            &self,
            height: ZinderBlockHeight,
        ) -> Result<BlockBlobArtifact, IndexerError> {
            self.requested_full_block_heights
                .lock()
                .expect("focused test full-block request lock is not poisoned")
                .push(height);
            self.full_blocks_by_height
                .get(&height)
                .cloned()
                .ok_or(IndexerError::NotFound {
                    resource: "full block",
                })
        }

        async fn retained_full_blocks_in_range(
            &self,
            block_range: ZinderBlockHeightRange,
        ) -> Result<IndexStream<BlockBlobArtifact>, IndexerError> {
            let request_number = {
                let mut requested_ranges = self
                    .requested_full_block_ranges
                    .lock()
                    .expect("focused test full-block range lock is not poisoned");
                requested_ranges.push(block_range);
                requested_ranges.len()
            };
            if self.expiring_range_request_number == Some(request_number) {
                return Err(IndexerError::ChainEpochPinUnavailable);
            }

            Ok(Box::pin(stream::iter(block_range.into_iter().map(
                |height| {
                    Ok(BlockBlobArtifact::new(
                        height,
                        zinder_block_hash(height.value()),
                        zinder_block_hash(height.value().saturating_sub(1)),
                        Vec::new(),
                    ))
                },
            ))))
        }
    }

    type TransparentUnspentResponse =
        Result<Vec<Result<TransparentUnspentOutputChunk, IndexerError>>, IndexerError>;
    type TransparentHistoryResponse =
        Result<Vec<Result<TransparentAddressTransactionChunk, IndexerError>>, IndexerError>;

    #[derive(Clone)]
    struct RecordingTransparentAddressSnapshot {
        chain_epoch: ChainEpoch,
        unspent_responses: Arc<Mutex<VecDeque<TransparentUnspentResponse>>>,
        history_responses: Arc<Mutex<VecDeque<TransparentHistoryResponse>>>,
        unspent_requests: Arc<Mutex<Vec<(TransparentAddressScriptHash, ZinderBlockHeight)>>>,
        history_queries: Arc<Mutex<Vec<TransparentAddressTxIdsQuery>>>,
    }

    impl RecordingTransparentAddressSnapshot {
        fn new(chain_epoch: ChainEpoch) -> Self {
            Self {
                chain_epoch,
                unspent_responses: Arc::new(Mutex::new(VecDeque::new())),
                history_responses: Arc::new(Mutex::new(VecDeque::new())),
                unspent_requests: Arc::new(Mutex::new(Vec::new())),
                history_queries: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn push_unspent_response(&self, response: TransparentUnspentResponse) {
            self.unspent_responses
                .lock()
                .expect("focused transparent-unspent response lock is not poisoned")
                .push_back(response);
        }

        fn push_history_response(&self, response: TransparentHistoryResponse) {
            self.history_responses
                .lock()
                .expect("focused transparent-history response lock is not poisoned")
                .push_back(response);
        }

        fn unspent_requests(&self) -> Vec<(TransparentAddressScriptHash, ZinderBlockHeight)> {
            self.unspent_requests
                .lock()
                .expect("focused transparent-unspent request lock is not poisoned")
                .clone()
        }

        fn history_queries(&self) -> Vec<TransparentAddressTxIdsQuery> {
            self.history_queries
                .lock()
                .expect("focused transparent-history request lock is not poisoned")
                .clone()
        }
    }

    impl TransparentAddressSnapshot for RecordingTransparentAddressSnapshot {
        fn chain_epoch(&self) -> ChainEpoch {
            self.chain_epoch
        }

        async fn transparent_address_unspent_outputs(
            &self,
            address_script_hash: TransparentAddressScriptHash,
            start_height: ZinderBlockHeight,
        ) -> Result<TransparentAddressUnspentOutputsStream, IndexerError> {
            self.unspent_requests
                .lock()
                .expect("focused transparent-unspent request lock is not poisoned")
                .push((address_script_hash, start_height));
            let response = self
                .unspent_responses
                .lock()
                .expect("focused transparent-unspent response lock is not poisoned")
                .pop_front()
                .unwrap_or_else(|| Ok(Vec::new()));
            response.map(|items| {
                let stream: TransparentAddressUnspentOutputsStream = Box::pin(stream::iter(items));
                stream
            })
        }

        async fn transparent_address_tx_ids_in_range(
            &self,
            query: TransparentAddressTxIdsQuery,
        ) -> Result<TransparentAddressTxIdsStream, IndexerError> {
            self.history_queries
                .lock()
                .expect("focused transparent-history request lock is not poisoned")
                .push(query);
            let response = self
                .history_responses
                .lock()
                .expect("focused transparent-history response lock is not poisoned")
                .pop_front()
                .unwrap_or_else(|| Ok(Vec::new()));
            response.map(|items| {
                let stream: TransparentAddressTxIdsStream = Box::pin(stream::iter(items));
                stream
            })
        }
    }

    fn transparent_test_epoch(tip_height: u32) -> ChainEpoch {
        ChainEpoch {
            id: CAPTURED_CHAIN_EPOCH_ID,
            network: ZinderNetwork::ZcashRegtest,
            visible_tip_height: ZinderBlockHeight::new(tip_height),
            visible_tip_hash: zinder_block_hash(tip_height),
            settled_tip_height: ZinderBlockHeight::new(tip_height),
            settled_tip_hash: zinder_block_hash(tip_height),
            artifact_schema_version: ArtifactSchemaVersion::new(7),
            tip_metadata: ChainTipMetadata::empty(),
            created_at: UnixTimestampMillis::new(1),
        }
    }

    fn transparent_test_address() -> TransparentAddress {
        TransparentAddress::PublicKeyHash([3; 20])
    }

    fn transparent_unspent_chunk(
        chain_epoch: ChainEpoch,
        address_script_hash: TransparentAddressScriptHash,
        script_pub_key: Vec<u8>,
        block_height: u32,
        transaction_id_byte: u8,
        output_index: u32,
    ) -> TransparentUnspentOutputChunk {
        TransparentUnspentOutputChunk {
            chain_epoch,
            output: TransparentUnspentOutput::new(
                address_script_hash,
                script_pub_key,
                TransparentOutPoint::new(
                    ZinderTransactionId::from_bytes([transaction_id_byte; 32]),
                    output_index,
                ),
                1,
                ZinderBlockHeight::new(block_height),
                zinder_block_hash(block_height),
            ),
        }
    }

    fn transparent_history_chunk(
        chain_epoch: ChainEpoch,
        address_script_hash: TransparentAddressScriptHash,
        block_height: u32,
        tx_index_in_block: u32,
        transaction_id_byte: u8,
        cursor: Option<TransparentHistoryCursor>,
    ) -> TransparentAddressTransactionChunk {
        TransparentAddressTransactionChunk {
            chain_epoch,
            artifact: TransparentAddressTxIndexArtifact::new(
                address_script_hash,
                ZinderBlockHeight::new(block_height),
                tx_index_in_block,
                ZinderTransactionId::from_bytes([transaction_id_byte; 32]),
                zinder_block_hash(block_height),
            ),
            cursor,
        }
    }

    #[tokio::test]
    async fn unspent_outpoints_use_complete_captured_address_set() {
        let chain_epoch = transparent_test_epoch(20);
        let snapshot = RecordingTransparentAddressSnapshot::new(chain_epoch);
        let address = transparent_test_address();
        let script_pub_key = address.script().to_bytes();
        let address_script_hash = TransparentAddressScriptHash::of_script_pub_key(&script_pub_key);
        snapshot.push_unspent_response(Ok(vec![
            Ok(transparent_unspent_chunk(
                chain_epoch,
                address_script_hash,
                script_pub_key.clone(),
                10,
                1,
                0,
            )),
            Ok(transparent_unspent_chunk(
                chain_epoch,
                address_script_hash,
                script_pub_key,
                11,
                2,
                3,
            )),
        ]));

        let outpoints = transparent_address_unspent_outpoints(&snapshot, &address)
            .await
            .expect("valid transparent unspent outputs are collected");

        assert_eq!(
            outpoints,
            vec![
                (TxId::from_bytes([1; 32]), 0),
                (TxId::from_bytes([2; 32]), 3),
            ]
        );
        assert_eq!(
            snapshot.unspent_requests(),
            vec![(
                address_script_hash,
                TRANSPARENT_ADDRESS_UNSPENT_START_HEIGHT,
            )]
        );
    }

    #[tokio::test]
    async fn address_history_maps_half_open_range_and_follows_ascending_pages() {
        let chain_epoch = transparent_test_epoch(20);
        let snapshot = RecordingTransparentAddressSnapshot::new(chain_epoch);
        let address = transparent_test_address();
        let address_script_hash = transparent_address_script_hash(&address);
        let resume_cursor = TransparentHistoryCursor::from_bytes(vec![4, 2]);
        snapshot.push_history_response(Ok(vec![
            Ok(transparent_history_chunk(
                chain_epoch,
                address_script_hash,
                10,
                1,
                1,
                None,
            )),
            Ok(transparent_history_chunk(
                chain_epoch,
                address_script_hash,
                12,
                0,
                2,
                Some(resume_cursor.clone()),
            )),
        ]));
        snapshot.push_history_response(Ok(vec![Ok(transparent_history_chunk(
            chain_epoch,
            address_script_hash,
            19,
            2,
            3,
            None,
        ))]));

        let transaction_ids = transparent_address_tx_ids(
            &snapshot,
            &address,
            &(BlockHeight::from_u32(10)..BlockHeight::from_u32(20)),
        )
        .await
        .expect("valid transparent history pages are collected");

        assert_eq!(
            transaction_ids,
            vec![
                TxId::from_bytes([1; 32]),
                TxId::from_bytes([2; 32]),
                TxId::from_bytes([3; 32]),
            ]
        );
        let queries = snapshot.history_queries();
        assert_eq!(queries.len(), 2);
        for query in &queries {
            assert_eq!(query.address_script_hash, address_script_hash);
            assert_eq!(query.start_height, ZinderBlockHeight::new(10));
            assert_eq!(query.end_height, ZinderBlockHeight::new(19));
            assert_eq!(
                query.max_entries,
                NonZeroU32::new(TRANSPARENT_ADDRESS_HISTORY_PAGE_SIZE)
            );
            assert!(!query.descending);
            assert_eq!(query.at_epoch_id, Some(CAPTURED_CHAIN_EPOCH_ID));
        }
        assert!(queries[0].from_cursor.is_none());
        assert_eq!(queries[1].from_cursor, Some(resume_cursor));
    }

    #[tokio::test]
    async fn address_history_rejects_changed_epoch_without_reacquiring() {
        let chain_epoch = transparent_test_epoch(20);
        let snapshot = RecordingTransparentAddressSnapshot::new(chain_epoch);
        let address = transparent_test_address();
        let mut other_epoch = chain_epoch;
        other_epoch.id = ChainEpochId::new(CAPTURED_CHAIN_EPOCH_ID.value() + 1);
        snapshot.push_history_response(Ok(vec![Ok(transparent_history_chunk(
            other_epoch,
            transparent_address_script_hash(&address),
            10,
            0,
            1,
            None,
        ))]));

        assert!(matches!(
            transparent_address_tx_ids(
                &snapshot,
                &address,
                &(BlockHeight::from_u32(10)..BlockHeight::from_u32(20)),
            )
            .await,
            Err(ChainError::InvalidData(_))
        ));
        assert_eq!(snapshot.history_queries().len(), 1);
    }

    #[tokio::test]
    async fn address_history_maps_lost_epoch_to_view_expired() {
        let chain_epoch = transparent_test_epoch(20);
        let snapshot = RecordingTransparentAddressSnapshot::new(chain_epoch);
        snapshot.push_history_response(Err(IndexerError::ChainEpochPinUnavailable));

        assert!(matches!(
            transparent_address_tx_ids(
                &snapshot,
                &transparent_test_address(),
                &(BlockHeight::from_u32(10)..BlockHeight::from_u32(20)),
            )
            .await,
            Err(ChainError::ViewExpired(_))
        ));
        assert_eq!(snapshot.history_queries().len(), 1);
    }

    #[tokio::test]
    async fn address_history_rejects_wrong_address_range_order_and_duplicate_txids() {
        let chain_epoch = transparent_test_epoch(20);
        let address = transparent_test_address();
        let address_script_hash = transparent_address_script_hash(&address);
        let other_script_hash = TransparentAddressScriptHash::from_bytes([8; 32]);
        let range = BlockHeight::from_u32(10)..BlockHeight::from_u32(20);
        let invalid_pages = [
            vec![Ok(transparent_history_chunk(
                chain_epoch,
                other_script_hash,
                10,
                0,
                1,
                None,
            ))],
            vec![Ok(transparent_history_chunk(
                chain_epoch,
                address_script_hash,
                20,
                0,
                1,
                None,
            ))],
            vec![
                Ok(transparent_history_chunk(
                    chain_epoch,
                    address_script_hash,
                    11,
                    0,
                    1,
                    None,
                )),
                Ok(transparent_history_chunk(
                    chain_epoch,
                    address_script_hash,
                    10,
                    0,
                    2,
                    None,
                )),
            ],
            vec![
                Ok(transparent_history_chunk(
                    chain_epoch,
                    address_script_hash,
                    10,
                    0,
                    1,
                    None,
                )),
                Ok(transparent_history_chunk(
                    chain_epoch,
                    address_script_hash,
                    11,
                    0,
                    1,
                    None,
                )),
            ],
        ];

        for invalid_page in invalid_pages {
            let snapshot = RecordingTransparentAddressSnapshot::new(chain_epoch);
            snapshot.push_history_response(Ok(invalid_page));

            assert!(matches!(
                transparent_address_tx_ids(&snapshot, &address, &range).await,
                Err(ChainError::InvalidData(_))
            ));
        }
    }

    #[tokio::test]
    async fn address_history_rejects_nonterminal_and_repeated_cursors() {
        let chain_epoch = transparent_test_epoch(20);
        let address = transparent_test_address();
        let address_script_hash = transparent_address_script_hash(&address);
        let cursor = TransparentHistoryCursor::from_bytes(vec![5, 1]);
        let range = BlockHeight::from_u32(10)..BlockHeight::from_u32(20);

        let nonterminal_cursor = RecordingTransparentAddressSnapshot::new(chain_epoch);
        nonterminal_cursor.push_history_response(Ok(vec![
            Ok(transparent_history_chunk(
                chain_epoch,
                address_script_hash,
                10,
                0,
                1,
                Some(cursor.clone()),
            )),
            Ok(transparent_history_chunk(
                chain_epoch,
                address_script_hash,
                11,
                0,
                2,
                None,
            )),
        ]));
        assert!(matches!(
            transparent_address_tx_ids(&nonterminal_cursor, &address, &range).await,
            Err(ChainError::InvalidData(_))
        ));

        let repeated_cursor = RecordingTransparentAddressSnapshot::new(chain_epoch);
        repeated_cursor.push_history_response(Ok(vec![Ok(transparent_history_chunk(
            chain_epoch,
            address_script_hash,
            10,
            0,
            1,
            Some(cursor.clone()),
        ))]));
        repeated_cursor.push_history_response(Ok(vec![Ok(transparent_history_chunk(
            chain_epoch,
            address_script_hash,
            11,
            0,
            2,
            Some(cursor),
        ))]));
        assert!(matches!(
            transparent_address_tx_ids(&repeated_cursor, &address, &range).await,
            Err(ChainError::InvalidData(_))
        ));
    }

    #[tokio::test]
    async fn unspent_outpoints_reject_wrong_address_order_duplicates_and_future_rows() {
        let chain_epoch = transparent_test_epoch(20);
        let address = transparent_test_address();
        let script_pub_key = address.script().to_bytes();
        let address_script_hash = TransparentAddressScriptHash::of_script_pub_key(&script_pub_key);
        let other_script_hash = TransparentAddressScriptHash::from_bytes([8; 32]);
        let invalid_pages = [
            vec![Ok(transparent_unspent_chunk(
                chain_epoch,
                other_script_hash,
                script_pub_key.clone(),
                10,
                1,
                0,
            ))],
            vec![Ok(transparent_unspent_chunk(
                chain_epoch,
                address_script_hash,
                script_pub_key.clone(),
                21,
                1,
                0,
            ))],
            vec![
                Ok(transparent_unspent_chunk(
                    chain_epoch,
                    address_script_hash,
                    script_pub_key.clone(),
                    11,
                    2,
                    0,
                )),
                Ok(transparent_unspent_chunk(
                    chain_epoch,
                    address_script_hash,
                    script_pub_key.clone(),
                    10,
                    1,
                    0,
                )),
            ],
            vec![
                Ok(transparent_unspent_chunk(
                    chain_epoch,
                    address_script_hash,
                    script_pub_key.clone(),
                    10,
                    1,
                    0,
                )),
                Ok(transparent_unspent_chunk(
                    chain_epoch,
                    address_script_hash,
                    script_pub_key.clone(),
                    10,
                    1,
                    0,
                )),
            ],
        ];

        for invalid_page in invalid_pages {
            let snapshot = RecordingTransparentAddressSnapshot::new(chain_epoch);
            snapshot.push_unspent_response(Ok(invalid_page));

            assert!(matches!(
                transparent_address_unspent_outpoints(&snapshot, &address).await,
                Err(ChainError::InvalidData(_))
            ));
        }
    }

    fn wallet_block_hash(height: u32) -> BlockHash {
        let encoded_height = height.to_le_bytes();
        BlockHash(std::array::from_fn(|index| {
            encoded_height[index % encoded_height.len()]
        }))
    }

    fn zinder_block_hash(height: u32) -> ZinderBlockHash {
        ZinderBlockHash::from_bytes(wallet_block_hash(height).0)
    }

    fn locator_block(height: u32) -> ChainBlock {
        ChainBlock::new(BlockHeight::from_u32(height), wallet_block_hash(height))
    }

    fn test_transaction(height: BlockHeight) -> Transaction {
        TransactionData::<Authorized>::from_parts(
            TxVersion::suggested_for_branch(BranchId::Sprout),
            BranchId::Sprout,
            0,
            height,
            None,
            None,
            None,
            None,
        )
        .freeze()
        .expect("focused test transaction is structurally valid")
    }

    fn test_mempool_entry(first_seen_height: u32) -> MempoolEntry {
        let transaction = test_transaction(BlockHeight::from_u32(first_seen_height));
        let mut raw = Vec::new();
        transaction
            .write(&mut raw)
            .expect("focused mempool transaction serializes");

        MempoolEntry::new(
            ZinderTransactionId::from_bytes(*transaction.txid().as_ref()),
            None,
            RawTransactionBytes::new(raw),
            CompactTransactionData::default(),
            MempoolObservation {
                first_seen_unix_millis: UnixTimestampMillis::new(1),
                first_seen_chain_epoch: ChainEpoch {
                    id: ChainEpochId::new(u64::from(first_seen_height)),
                    network: ZinderNetwork::ZcashRegtest,
                    visible_tip_height: ZinderBlockHeight::new(first_seen_height),
                    visible_tip_hash: zinder_block_hash(first_seen_height),
                    settled_tip_height: ZinderBlockHeight::new(first_seen_height),
                    settled_tip_hash: zinder_block_hash(first_seen_height),
                    artifact_schema_version: ArtifactSchemaVersion::new(7),
                    tip_metadata: ChainTipMetadata::empty(),
                    created_at: UnixTimestampMillis::new(1),
                },
            },
        )
        .expect("focused mempool entry is structurally valid")
    }

    fn retained_test_block(
        height: BlockHeight,
        equihash_solution: Vec<u8>,
    ) -> (BlockBlobArtifact, Vec<u8>) {
        let nonce_byte =
            u8::try_from(u32::from(height)).expect("focused test height fits one nonce byte");
        let header = BlockHeaderData {
            version: 4,
            prev_block: BlockHash([nonce_byte.saturating_sub(1); 32]),
            merkle_root: [0; 32],
            final_sapling_root: [0; 32],
            time: 0,
            bits: 0,
            nonce: [nonce_byte; 32],
            solution: equihash_solution,
        }
        .freeze()
        .expect("focused test block header is structurally valid");
        let coinbase_authorization = Coinbase;
        let transparent_bundle = Bundle {
            vin: vec![
                TxIn::<Coinbase>::coinbase(height, None)
                    .expect("focused test coinbase height is structurally valid"),
            ],
            vout: Vec::new(),
            authorization: coinbase_authorization.clone(),
        }
        .map_authorization(coinbase_authorization);
        let transaction = TransactionData::<Authorized>::from_parts(
            TxVersion::suggested_for_branch(BranchId::Sprout),
            BranchId::Sprout,
            0,
            height,
            Some(transparent_bundle),
            None,
            None,
            None,
        )
        .freeze()
        .expect("focused test coinbase transaction is structurally valid");

        let mut header_bytes = Vec::new();
        header
            .write(&mut header_bytes)
            .expect("serializes the complete focused test header");
        let mut block_bytes = header_bytes.clone();
        block_bytes.push(TEST_BLOCK_TRANSACTION_COUNT);
        transaction
            .write(&mut block_bytes)
            .expect("serializes the focused test coinbase transaction");

        (
            BlockBlobArtifact::new(
                zinder_height(height),
                ZinderBlockHash::from_bytes(header.hash().0),
                ZinderBlockHash::from_bytes(header.prev_block.0),
                block_bytes,
            ),
            header_bytes,
        )
    }

    fn full_block_page_size() -> u32 {
        u32::try_from(FULL_BLOCK_PAGE_SIZE).expect("full-block page size fits u32")
    }

    async fn collect_half_open_block_heights(
        snapshot: &RecordingPinnedChainSnapshot,
        range: Range<BlockHeight>,
        tip: BlockHeight,
    ) -> Result<Vec<u32>, ChainError> {
        stream_retained_full_blocks_in_half_open_range(snapshot.clone(), &range, tip)
            .map_ok(|block| block.height.value())
            .try_collect()
            .await
    }

    #[tokio::test]
    async fn buffered_chain_stream_failure_wins_before_snapshot_entries() {
        use futures::StreamExt as _;

        let captured_tip = locator_block(10);
        let mut mempool_stream = follow_mempool_until_tip_changes(
            VecDeque::from([test_transaction(BlockHeight::from_u32(1))]),
            HashSet::new(),
            Box::pin(stream::iter([Err(IndexerError::FailedPrecondition {
                reason: "focused buffered chain event failure".to_owned(),
            })])),
            Box::pin(stream::pending::<
                Result<zinder_client::MempoolEventEnvelope, IndexerError>,
            >()),
            captured_tip,
            BranchId::Sprout,
        );

        assert!(matches!(
            mempool_stream.next().await,
            Some(Err(ChainError::Backend(_)))
        ));
    }

    #[tokio::test]
    async fn newer_tip_mempool_add_ends_follow_before_emitting_transaction() {
        use futures::StreamExt as _;

        let captured_tip = locator_block(10);
        let mut mempool_stream = follow_mempool_until_tip_changes(
            VecDeque::new(),
            HashSet::new(),
            Box::pin(stream::pending::<
                Result<zinder_client::ChainEventEnvelope, IndexerError>,
            >()),
            Box::pin(stream::iter([Ok(zinder_client::MempoolEventEnvelope {
                cursor: zinder_client::MempoolEventCursor::from_bytes(vec![1]),
                event_sequence: 1,
                source_observed_unix_millis: 1,
                event: MempoolEvent::Added {
                    entry: test_mempool_entry(11),
                },
            })])),
            captured_tip,
            BranchId::Sprout,
        );

        assert!(mempool_stream.next().await.is_none());
    }

    #[test]
    fn visible_tip_transition_is_distinguished_from_settlement_only_event() {
        let captured_tip = locator_block(10);

        assert!(!visible_tip_changed(
            captured_tip,
            ZinderBlockHeight::new(10),
            zinder_block_hash(10),
        ));
        assert!(visible_tip_changed(
            captured_tip,
            ZinderBlockHeight::new(11),
            zinder_block_hash(11),
        ));
    }

    #[test]
    fn mempool_removals_do_not_allow_a_seen_transaction_id_to_emit_again() {
        let transaction_id = ZinderTransactionId::from_bytes([7; 32]);
        let mut seen = HashSet::from([transaction_id]);

        let invalidated = apply_mempool_event(
            &mut seen,
            MempoolEvent::Invalidated {
                transaction_id,
                reason: MempoolEvictionReason::Unknown,
            },
        )
        .expect("an invalidation is an ordinary mempool transition");
        assert!(invalidated.is_none());
        assert!(seen.contains(&transaction_id));

        let mined = apply_mempool_event(
            &mut seen,
            MempoolEvent::Mined {
                transaction_id,
                mined_height: ZinderBlockHeight::new(11),
                block_hash: zinder_block_hash(11),
            },
        )
        .expect("a mined transition is an ordinary mempool transition");
        assert!(mined.is_none());
        assert!(seen.contains(&transaction_id));
    }

    #[tokio::test]
    async fn fork_lookup_returns_the_highest_matching_ancestor_below_tip() {
        let tip_height = 12;
        let highest_ancestor_height = 11;
        let lower_ancestor_height = 10;
        let snapshot = RecordingPinnedChainSnapshot::default()
            .with_block_lookup(
                zinder_block_hash(highest_ancestor_height),
                BlockLookupResponse::Canonical(ZinderBlockId::new(
                    ZinderBlockHeight::new(highest_ancestor_height),
                    zinder_block_hash(highest_ancestor_height),
                )),
            )
            .with_block_lookup(
                zinder_block_hash(lower_ancestor_height),
                BlockLookupResponse::Canonical(ZinderBlockId::new(
                    ZinderBlockHeight::new(lower_ancestor_height),
                    zinder_block_hash(lower_ancestor_height),
                )),
            );
        let locator = BlockLocator::from_blocks([
            locator_block(tip_height),
            locator_block(highest_ancestor_height),
            locator_block(lower_ancestor_height),
        ]);

        let fork_point = find_fork_point_in_snapshot(&snapshot, &locator)
            .await
            .expect("canonical ancestor lookup succeeds");

        assert_eq!(fork_point, Some(locator_block(highest_ancestor_height)));
        assert_eq!(
            snapshot.requested_block_selectors(),
            vec![
                BlockSelector::from_hash(zinder_block_hash(tip_height)),
                BlockSelector::from_hash(zinder_block_hash(highest_ancestor_height)),
            ],
        );
    }

    #[tokio::test]
    async fn fork_lookup_skips_unknown_hash_and_returns_lower_canonical_ancestor() {
        let unknown_height = 12;
        let canonical_height = 11;
        let snapshot = RecordingPinnedChainSnapshot::default()
            .with_block_lookup(
                zinder_block_hash(unknown_height),
                BlockLookupResponse::BlockNotFound,
            )
            .with_block_lookup(
                zinder_block_hash(canonical_height),
                BlockLookupResponse::Canonical(ZinderBlockId::new(
                    ZinderBlockHeight::new(canonical_height),
                    zinder_block_hash(canonical_height),
                )),
            );
        let locator = BlockLocator::from_blocks([
            locator_block(unknown_height),
            locator_block(canonical_height),
        ]);

        let fork_point = find_fork_point_in_snapshot(&snapshot, &locator)
            .await
            .expect("ordinary absent hashes do not fail fork lookup");

        assert_eq!(fork_point, Some(locator_block(canonical_height)));
        assert_eq!(snapshot.requested_block_selectors().len(), 2);
    }

    #[tokio::test]
    async fn fork_lookup_propagates_not_found_for_an_unrelated_resource() {
        let unavailable_height = 12;
        let snapshot = RecordingPinnedChainSnapshot::default().with_block_lookup(
            zinder_block_hash(unavailable_height),
            BlockLookupResponse::UnrelatedNotFound,
        );
        let locator = BlockLocator::from_blocks([locator_block(unavailable_height)]);

        let error = find_fork_point_in_snapshot(&snapshot, &locator)
            .await
            .expect_err("an unrelated absent resource must not advance the block locator");
        let ChainError::Unavailable(source) = error else {
            panic!("an unrelated not-found failure must remain unavailable");
        };

        assert!(matches!(
            source.downcast_ref::<IndexerError>(),
            Some(IndexerError::NotFound {
                resource: "transaction"
            })
        ));
        assert_eq!(snapshot.requested_block_selectors().len(), 1);
    }

    #[tokio::test]
    async fn fork_lookup_propagates_remote_failure_with_block_not_in_best_chain_reason() {
        let unavailable_height = 12;
        let snapshot = RecordingPinnedChainSnapshot::default().with_block_lookup(
            zinder_block_hash(unavailable_height),
            BlockLookupResponse::RemoteBlockNotInBestChain,
        );
        let locator = BlockLocator::from_blocks([locator_block(unavailable_height)]);

        let error = find_fork_point_in_snapshot(&snapshot, &locator)
            .await
            .expect_err("a reason-only remote failure must not be treated as absence");
        let ChainError::Unavailable(source) = error else {
            panic!("a retryable remote failure must remain unavailable");
        };

        assert!(matches!(
            source.downcast_ref::<IndexerError>(),
            Some(IndexerError::RemoteFailure {
                reason: zinder_client::ErrorReason::BlockNotInBestChain,
                ..
            })
        ));
        assert_eq!(snapshot.requested_block_selectors().len(), 1);
    }

    #[tokio::test]
    async fn fork_lookup_preserves_view_expiry() {
        let expired_height = 12;
        let snapshot = RecordingPinnedChainSnapshot::default().with_block_lookup(
            zinder_block_hash(expired_height),
            BlockLookupResponse::ViewExpired,
        );
        let locator = BlockLocator::from_blocks([locator_block(expired_height)]);

        let error = find_fork_point_in_snapshot(&snapshot, &locator)
            .await
            .expect_err("epoch expiry must invalidate the owning workflow's snapshot");

        assert!(matches!(error, ChainError::ViewExpired(_)));
    }

    #[tokio::test]
    async fn block_header_is_decoded_from_complete_retained_block_bytes() {
        const HEADER_HEIGHT: u32 = 7;
        const TIP_HEIGHT: u32 = 9;
        const EQUIHASH_SOLUTION: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd];

        let height = BlockHeight::from_u32(HEADER_HEIGHT);
        let (retained_block, expected_header_bytes) =
            retained_test_block(height, EQUIHASH_SOLUTION.to_vec());
        let snapshot = RecordingPinnedChainSnapshot::default()
            .with_retained_full_block_at(ZinderBlockHeight::new(HEADER_HEIGHT), retained_block);

        let header =
            block_header_from_snapshot(&snapshot, BlockHeight::from_u32(TIP_HEIGHT), height)
                .await
                .expect("retained full-block read succeeds")
                .expect("requested height is at or below the tip");
        let mut actual_header_bytes = Vec::new();
        header
            .write(&mut actual_header_bytes)
            .expect("serializes the decoded complete header");

        assert_eq!(actual_header_bytes, expected_header_bytes);
        assert_eq!(header.solution, EQUIHASH_SOLUTION);
        assert_eq!(
            snapshot.requested_full_block_heights(),
            vec![ZinderBlockHeight::new(HEADER_HEIGHT)]
        );
    }

    #[tokio::test]
    async fn block_header_rejects_mismatched_retained_identity() {
        const HEADER_HEIGHT: u32 = 7;
        const TIP_HEIGHT: u32 = 9;
        const DIFFERENT_HEIGHT: u32 = 8;
        const MISMATCH_HASH_BYTES: [u8; 32] = [0xff; 32];

        let height = BlockHeight::from_u32(HEADER_HEIGHT);
        let (retained_block, _) = retained_test_block(height, Vec::new());

        let mut wrong_height = retained_block.clone();
        wrong_height.height = ZinderBlockHeight::new(DIFFERENT_HEIGHT);
        let mut wrong_hash = retained_block.clone();
        wrong_hash.block_hash = ZinderBlockHash::from_bytes(MISMATCH_HASH_BYTES);
        let mut wrong_parent = retained_block;
        wrong_parent.parent_hash = ZinderBlockHash::from_bytes(MISMATCH_HASH_BYTES);

        for mismatched_block in [wrong_height, wrong_hash, wrong_parent] {
            let snapshot = RecordingPinnedChainSnapshot::default().with_retained_full_block_at(
                ZinderBlockHeight::new(HEADER_HEIGHT),
                mismatched_block,
            );

            let error =
                block_header_from_snapshot(&snapshot, BlockHeight::from_u32(TIP_HEIGHT), height)
                    .await
                    .expect_err("retained identity must match the decoded consensus header");

            assert!(matches!(error, ChainError::InvalidData(_)));
        }
    }

    #[tokio::test]
    async fn half_open_empty_range_issues_no_page() {
        let start = BlockHeight::from_u32(TEST_STREAM_START_HEIGHT);
        let snapshot = RecordingPinnedChainSnapshot::default();

        let heights = collect_half_open_block_heights(&snapshot, start..start, start)
            .await
            .expect("empty half-open range succeeds");

        assert!(heights.is_empty());
        assert!(snapshot.requested_full_block_ranges().is_empty());
    }

    #[tokio::test]
    async fn half_open_one_block_range_uses_one_inclusive_page() {
        let start = BlockHeight::from_u32(TEST_STREAM_START_HEIGHT);
        let end = start + 1;
        let snapshot = RecordingPinnedChainSnapshot::default();

        let heights = collect_half_open_block_heights(&snapshot, start..end, start)
            .await
            .expect("one-block half-open range succeeds");

        assert_eq!(heights, vec![TEST_STREAM_START_HEIGHT]);
        assert_eq!(
            snapshot.requested_full_block_ranges(),
            vec![ZinderBlockHeightRange::inclusive(
                zinder_height(start),
                zinder_height(start),
            )]
        );
    }

    #[tokio::test]
    async fn half_open_exactly_1000_blocks_use_one_page() {
        let page_size = full_block_page_size();
        let start = BlockHeight::from_u32(TEST_STREAM_START_HEIGHT);
        let end = start + page_size;
        let snapshot = RecordingPinnedChainSnapshot::default();

        let heights = collect_half_open_block_heights(&snapshot, start..end, end)
            .await
            .expect("one full half-open page succeeds");

        assert_eq!(
            heights,
            (TEST_STREAM_START_HEIGHT..TEST_STREAM_START_HEIGHT + page_size).collect::<Vec<_>>()
        );
        assert_eq!(
            snapshot.requested_full_block_ranges(),
            vec![ZinderBlockHeightRange::inclusive(
                zinder_height(start),
                zinder_height(end - 1),
            )]
        );
    }

    #[tokio::test]
    async fn half_open_more_than_1000_blocks_preserve_order_across_pages() {
        let page_size = full_block_page_size();
        let start = BlockHeight::from_u32(TEST_STREAM_START_HEIGHT);
        let second_page_start = start + page_size;
        let end = second_page_start + 1;
        let snapshot = RecordingPinnedChainSnapshot::default();

        let heights = collect_half_open_block_heights(&snapshot, start..end, end)
            .await
            .expect("two-page half-open range succeeds");

        assert_eq!(
            heights,
            (TEST_STREAM_START_HEIGHT..TEST_STREAM_START_HEIGHT + page_size + 1)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            snapshot.requested_full_block_ranges(),
            vec![
                ZinderBlockHeightRange::inclusive(
                    zinder_height(start),
                    zinder_height(second_page_start - 1),
                ),
                ZinderBlockHeightRange::inclusive(
                    zinder_height(second_page_start),
                    zinder_height(second_page_start),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn half_open_10000_block_recovery_batch_uses_bounded_pages() {
        let page_size = full_block_page_size();
        let start = BlockHeight::from_u32(TEST_STREAM_START_HEIGHT);
        let end = start + CONFIGURED_RECOVERY_BATCH_SIZE;
        let expected_page_count = CONFIGURED_RECOVERY_BATCH_SIZE / page_size;
        let snapshot = RecordingPinnedChainSnapshot::default();

        let heights = collect_half_open_block_heights(&snapshot, start..end, end)
            .await
            .expect("configured-size recovery range succeeds");
        let requests = snapshot.requested_full_block_ranges();
        let expected_requests = (0..expected_page_count)
            .map(|page_index| {
                let page_start = start + page_index * page_size;
                ZinderBlockHeightRange::inclusive(
                    zinder_height(page_start),
                    zinder_height(page_start + page_size - 1),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            heights.len(),
            usize::try_from(CONFIGURED_RECOVERY_BATCH_SIZE)
                .expect("configured recovery batch size fits usize")
        );
        assert_eq!(
            heights.first(),
            Some(&TEST_STREAM_START_HEIGHT),
            "the configured-size range starts at its requested height"
        );
        assert_eq!(
            heights.last(),
            Some(&(TEST_STREAM_START_HEIGHT + CONFIGURED_RECOVERY_BATCH_SIZE - 1)),
            "the configured-size range ends before its half-open bound"
        );
        assert_eq!(requests, expected_requests);
    }

    #[tokio::test]
    async fn half_open_page_two_expiry_remains_view_expired() {
        const EXPIRING_REQUEST_NUMBER: usize = 2;

        let page_size = full_block_page_size();
        let start = BlockHeight::from_u32(TEST_STREAM_START_HEIGHT);
        let end = start + page_size + 1;
        let snapshot = RecordingPinnedChainSnapshot::default()
            .expiring_on_range_request(EXPIRING_REQUEST_NUMBER);

        let error = collect_half_open_block_heights(&snapshot, start..end, end)
            .await
            .expect_err("the second half-open page expires the captured view");

        assert!(matches!(error, ChainError::ViewExpired(_)));
        assert_eq!(snapshot.requested_full_block_ranges().len(), 2);
    }

    #[tokio::test]
    async fn second_page_request_waits_until_first_page_is_consumed() {
        let page_size = full_block_page_size();
        let start = BlockHeight::from_u32(TEST_STREAM_START_HEIGHT);
        let second_page_start = start + page_size;
        let end = second_page_start + 1;
        let snapshot = RecordingPinnedChainSnapshot::default();
        let mut blocks =
            stream_retained_full_blocks_in_half_open_range(snapshot.clone(), &(start..end), end);

        assert!(snapshot.requested_full_block_ranges().is_empty());
        for expected_height in TEST_STREAM_START_HEIGHT..TEST_STREAM_START_HEIGHT + page_size {
            let block = blocks
                .try_next()
                .await
                .expect("first-page block read succeeds")
                .expect("first page contains every requested block");
            assert_eq!(block.height.value(), expected_height);
        }
        assert_eq!(
            snapshot.requested_full_block_ranges().len(),
            1,
            "page two must not be requested while page one still has data"
        );

        let first_second_page_block = blocks
            .try_next()
            .await
            .expect("second-page block read succeeds")
            .expect("the second page contains its first block");
        assert_eq!(
            first_second_page_block.height,
            zinder_height(second_page_start)
        );
        assert_eq!(snapshot.requested_full_block_ranges().len(), 2);
    }

    #[tokio::test]
    async fn stream_to_tip_issues_no_page_when_start_is_above_tip() {
        const START_HEIGHT: u32 = 5;

        let snapshot = RecordingPinnedChainSnapshot::default();
        let blocks = stream_retained_full_blocks_to_tip(
            snapshot.clone(),
            BlockHeight::from_u32(START_HEIGHT),
            BlockHeight::from_u32(START_HEIGHT - 1),
        )
        .try_collect::<Vec<_>>()
        .await
        .expect("empty stream succeeds");

        assert!(blocks.is_empty());
        assert!(snapshot.requested_full_block_ranges().is_empty());
    }

    #[tokio::test]
    async fn stream_to_tip_uses_one_inclusive_page_for_one_block() {
        const HEIGHT: u32 = 5;

        let snapshot = RecordingPinnedChainSnapshot::default();
        let blocks = stream_retained_full_blocks_to_tip(
            snapshot.clone(),
            BlockHeight::from_u32(HEIGHT),
            BlockHeight::from_u32(HEIGHT),
        )
        .try_collect::<Vec<_>>()
        .await
        .expect("one-block stream succeeds");

        assert_eq!(
            blocks
                .into_iter()
                .map(|block| block.height.value())
                .collect::<Vec<_>>(),
            vec![HEIGHT]
        );
        assert_eq!(
            snapshot.requested_full_block_ranges(),
            vec![ZinderBlockHeightRange::inclusive(
                ZinderBlockHeight::new(HEIGHT),
                ZinderBlockHeight::new(HEIGHT),
            )]
        );
    }

    #[tokio::test]
    async fn stream_to_tip_keeps_exactly_1000_blocks_in_one_page() {
        const START_HEIGHT: u32 = 5;

        let page_size = u32::try_from(FULL_BLOCK_PAGE_SIZE).expect("full-block page size fits u32");
        let tip_height = START_HEIGHT + page_size - 1;
        let snapshot = RecordingPinnedChainSnapshot::default();
        let blocks = stream_retained_full_blocks_to_tip(
            snapshot.clone(),
            BlockHeight::from_u32(START_HEIGHT),
            BlockHeight::from_u32(tip_height),
        )
        .try_collect::<Vec<_>>()
        .await
        .expect("one complete page succeeds");

        assert_eq!(
            blocks.len(),
            usize::try_from(page_size).expect("full-block page size fits usize")
        );
        assert_eq!(
            snapshot.requested_full_block_ranges(),
            vec![ZinderBlockHeightRange::inclusive(
                ZinderBlockHeight::new(START_HEIGHT),
                ZinderBlockHeight::new(tip_height),
            )]
        );
    }

    #[tokio::test]
    async fn stream_to_tip_pages_more_than_1000_blocks_in_order() {
        const START_HEIGHT: u32 = 5;

        let page_size = u32::try_from(FULL_BLOCK_PAGE_SIZE).expect("full-block page size fits u32");
        let second_page_height = START_HEIGHT + page_size;
        let snapshot = RecordingPinnedChainSnapshot::default();
        let blocks = stream_retained_full_blocks_to_tip(
            snapshot.clone(),
            BlockHeight::from_u32(START_HEIGHT),
            BlockHeight::from_u32(second_page_height),
        )
        .try_collect::<Vec<_>>()
        .await
        .expect("two-page stream succeeds");

        assert_eq!(
            blocks
                .into_iter()
                .map(|block| block.height.value())
                .collect::<Vec<_>>(),
            (START_HEIGHT..=second_page_height).collect::<Vec<_>>()
        );
        assert_eq!(
            snapshot.requested_full_block_ranges(),
            vec![
                ZinderBlockHeightRange::inclusive(
                    ZinderBlockHeight::new(START_HEIGHT),
                    ZinderBlockHeight::new(second_page_height - 1),
                ),
                ZinderBlockHeightRange::inclusive(
                    ZinderBlockHeight::new(second_page_height),
                    ZinderBlockHeight::new(second_page_height),
                ),
            ]
        );
    }

    #[tokio::test]
    async fn stream_to_tip_preserves_page_two_view_expiry() {
        const START_HEIGHT: u32 = 5;
        const EXPIRING_REQUEST_NUMBER: usize = 2;

        let page_size = u32::try_from(FULL_BLOCK_PAGE_SIZE).expect("full-block page size fits u32");
        let second_page_height = START_HEIGHT + page_size;
        let snapshot = RecordingPinnedChainSnapshot::default()
            .expiring_on_range_request(EXPIRING_REQUEST_NUMBER);
        let error = stream_retained_full_blocks_to_tip(
            snapshot.clone(),
            BlockHeight::from_u32(START_HEIGHT),
            BlockHeight::from_u32(second_page_height),
        )
        .try_collect::<Vec<_>>()
        .await
        .expect_err("the second page expires the captured chain view");

        assert!(matches!(error, ChainError::ViewExpired(_)));
        assert_eq!(snapshot.requested_full_block_ranges().len(), 2);
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RecordedSubtreeRootRequest {
        range: SubtreeRootRange,
        chain_epoch_id: ChainEpochId,
    }

    struct RecordingSubtreeRootSnapshot {
        root_count: u32,
        chain_epoch_id: ChainEpochId,
        returned_root_count_override: Option<(SubtreeRootIndex, u32)>,
        requests: RefCell<Vec<RecordedSubtreeRootRequest>>,
    }

    impl RecordingSubtreeRootSnapshot {
        fn new(root_count: u32) -> Self {
            Self {
                root_count,
                chain_epoch_id: CAPTURED_CHAIN_EPOCH_ID,
                returned_root_count_override: None,
                requests: RefCell::new(Vec::new()),
            }
        }

        fn with_returned_root_count_at(
            mut self,
            start_index: SubtreeRootIndex,
            returned_root_count: u32,
        ) -> Self {
            self.returned_root_count_override = Some((start_index, returned_root_count));
            self
        }
    }

    impl SubtreeRootSnapshot for RecordingSubtreeRootSnapshot {
        type SubtreeRoot = SubtreeRootIndex;

        fn chain_epoch_id(&self) -> ChainEpochId {
            self.chain_epoch_id
        }

        fn completed_subtree_count(&self, _protocol: ShieldedProtocol) -> u32 {
            self.root_count
        }

        fn subtree_roots_in_range(
            &self,
            subtree_root_range: SubtreeRootRange,
        ) -> impl Future<Output = Result<Vec<Self::SubtreeRoot>, IndexerError>> {
            self.requests.borrow_mut().push(RecordedSubtreeRootRequest {
                range: subtree_root_range,
                chain_epoch_id: self.chain_epoch_id,
            });

            let returned_root_count = self
                .returned_root_count_override
                .filter(|(start_index, _)| *start_index == subtree_root_range.start_index)
                .map_or(subtree_root_range.max_entries.get(), |(_, count)| count);
            let returned_end_index = subtree_root_range
                .start_index
                .value()
                .checked_add(returned_root_count)
                .expect("focused test page indices fit u32");
            let subtree_roots = (subtree_root_range.start_index.value()..returned_end_index)
                .map(SubtreeRootIndex::new)
                .collect();

            future::ready(Ok(subtree_roots))
        }
    }

    #[test]
    fn zinder_types_satisfy_chain_trait_bounds() {
        fn assert_chain<T: Chain>() {}
        fn assert_chain_view<T: ChainView>() {}

        assert_chain::<ZinderChain>();
        assert_chain_view::<ZinderChainView>();
    }

    #[tokio::test]
    async fn exactly_1024_subtree_roots_use_one_page() {
        let snapshot = RecordingSubtreeRootSnapshot::new(MAX_SUBTREE_ROOTS_PER_REQUEST);

        let subtree_roots = subtree_roots_from_snapshot(&snapshot, ShieldedProtocol::Sapling)
            .await
            .expect("one bounded subtree-root page should succeed");

        assert_eq!(
            subtree_roots.len(),
            usize::try_from(MAX_SUBTREE_ROOTS_PER_REQUEST)
                .expect("u32 root counts fit usize on supported targets")
        );
        assert_eq!(
            snapshot.requests.into_inner(),
            vec![RecordedSubtreeRootRequest {
                range: SubtreeRootRange::new(
                    ShieldedProtocol::Sapling,
                    SubtreeRootIndex::new(0),
                    NonZeroU32::new(MAX_SUBTREE_ROOTS_PER_REQUEST)
                        .expect("the exported request limit is non-zero"),
                ),
                chain_epoch_id: CAPTURED_CHAIN_EPOCH_ID,
            }],
        );
    }

    #[tokio::test]
    async fn exactly_1025_subtree_roots_use_two_bounded_pages() {
        let root_count = MAX_SUBTREE_ROOTS_PER_REQUEST
            .checked_add(1)
            .expect("the request limit leaves room for a second page");
        let snapshot = RecordingSubtreeRootSnapshot::new(root_count);

        let subtree_roots = subtree_roots_from_snapshot(&snapshot, ShieldedProtocol::Sapling)
            .await
            .expect("two bounded subtree-root pages should succeed");
        let requests = snapshot.requests.into_inner();

        assert_eq!(
            subtree_roots.len(),
            usize::try_from(root_count).expect("u32 root counts fit usize")
        );
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].range.start_index, SubtreeRootIndex::new(0));
        assert_eq!(
            requests[0].range.max_entries.get(),
            MAX_SUBTREE_ROOTS_PER_REQUEST
        );
        assert_eq!(
            requests[1].range.start_index,
            SubtreeRootIndex::new(MAX_SUBTREE_ROOTS_PER_REQUEST)
        );
        assert_eq!(requests[1].range.max_entries.get(), 1);
    }

    #[tokio::test]
    async fn multiple_subtree_root_pages_preserve_every_ordered_index() {
        let root_count = MAX_SUBTREE_ROOTS_PER_REQUEST
            .checked_mul(2)
            .and_then(|count| count.checked_add(7))
            .expect("the focused test root count fits u32");
        let snapshot = RecordingSubtreeRootSnapshot::new(root_count);

        let subtree_roots = subtree_roots_from_snapshot(&snapshot, ShieldedProtocol::Sapling)
            .await
            .expect("multiple bounded subtree-root pages should succeed");

        assert_eq!(
            subtree_roots,
            (0..root_count)
                .map(SubtreeRootIndex::new)
                .collect::<Vec<_>>()
        );
        assert_eq!(snapshot.requests.into_inner().len(), 3);
    }

    #[tokio::test]
    async fn every_subtree_root_page_uses_the_same_epoch_pin() {
        let root_count = MAX_SUBTREE_ROOTS_PER_REQUEST
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .expect("the focused test root count fits u32");
        let snapshot = RecordingSubtreeRootSnapshot::new(root_count);

        subtree_roots_from_snapshot(&snapshot, ShieldedProtocol::Sapling)
            .await
            .expect("multiple bounded subtree-root pages should succeed");

        assert!(
            snapshot
                .requests
                .into_inner()
                .iter()
                .all(|request| request.chain_epoch_id == CAPTURED_CHAIN_EPOCH_ID)
        );
    }

    #[tokio::test]
    async fn a_short_subtree_root_page_fails_without_returning_partial_roots() {
        let root_count = MAX_SUBTREE_ROOTS_PER_REQUEST
            .checked_add(3)
            .expect("the request limit leaves room for a short second page");
        let snapshot = RecordingSubtreeRootSnapshot::new(root_count)
            .with_returned_root_count_at(SubtreeRootIndex::new(MAX_SUBTREE_ROOTS_PER_REQUEST), 2);

        let result = subtree_roots_from_snapshot(&snapshot, ShieldedProtocol::Sapling).await;
        let Err(ChainError::InvalidData(source)) = result else {
            panic!("a short page must fail instead of returning partial roots");
        };

        assert_eq!(snapshot.requests.into_inner().len(), 2);
        assert!(
            source
                .to_string()
                .contains("returned 2 Sapling subtree roots")
        );
        assert!(source.to_string().contains("expected 3"));
        assert!(source.to_string().contains("chain epoch 41"));
    }

    #[tokio::test]
    async fn an_overlong_subtree_root_page_fails_without_returning_partial_roots() {
        let root_count = MAX_SUBTREE_ROOTS_PER_REQUEST
            .checked_add(3)
            .expect("the request limit leaves room for an overlong second page");
        let snapshot = RecordingSubtreeRootSnapshot::new(root_count)
            .with_returned_root_count_at(SubtreeRootIndex::new(MAX_SUBTREE_ROOTS_PER_REQUEST), 4);

        let result = subtree_roots_from_snapshot(&snapshot, ShieldedProtocol::Sapling).await;
        let Err(ChainError::InvalidData(source)) = result else {
            panic!("an overlong page must fail instead of returning partial roots");
        };

        assert_eq!(snapshot.requests.into_inner().len(), 2);
        assert!(
            source
                .to_string()
                .contains("returned 4 Sapling subtree roots")
        );
        assert!(source.to_string().contains("expected 3"));
        assert!(source.to_string().contains("chain epoch 41"));
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
            wallet_runtime_preflight_message(&[Capability::FullBlock, Capability::FullBlockRange]);

        assert!(message.contains("raw_blob_policy=all"));
        assert!(message.contains("rebuild the canonical store"));
        assert!(message.contains("blue-green replacement"));
    }

    #[test]
    fn non_retention_capability_failure_omits_store_rebuild_guidance() {
        let message = wallet_runtime_preflight_message(&[Capability::NetworkUpgradeActivations]);

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
    fn accepted_broadcast_requires_the_submitted_transaction_id() {
        let submitted_transaction_id = ZinderTransactionId::from_bytes([7; 32]);

        assert!(
            broadcast_result(
                submitted_transaction_id,
                TransactionBroadcastOutcome::Accepted(zinder_core::BroadcastAccepted {
                    transaction_id: submitted_transaction_id,
                }),
            )
            .is_ok()
        );
        assert!(matches!(
            broadcast_result(
                submitted_transaction_id,
                TransactionBroadcastOutcome::Accepted(zinder_core::BroadcastAccepted {
                    transaction_id: ZinderTransactionId::from_bytes([8; 32]),
                }),
            ),
            Err(ChainError::InvalidData(_))
        ));
    }

    #[test]
    fn already_known_or_queued_broadcasts_are_successful() {
        assert!(
            broadcast_result(
                ZinderTransactionId::from_bytes([7; 32]),
                TransactionBroadcastOutcome::Duplicate(zinder_core::BroadcastDuplicate {
                    error_code: Some(-27),
                    message: "transaction already in block chain".to_owned(),
                }),
            )
            .is_ok()
        );
        assert!(
            broadcast_result(
                ZinderTransactionId::from_bytes([7; 32]),
                TransactionBroadcastOutcome::Queued(zinder_core::BroadcastQueued {
                    message: "transaction is queued for verification".to_owned(),
                }),
            )
            .is_ok()
        );
    }

    #[test]
    fn rejected_broadcast_retains_the_typed_reason() {
        let error = broadcast_result(
            ZinderTransactionId::from_bytes([7; 32]),
            TransactionBroadcastOutcome::Rejected(zinder_core::BroadcastRejected {
                kind: zinder_core::BroadcastRejectionReason::BadExpiryHeight,
                error_code: Some(-25),
                message: "transaction expired".to_owned(),
            }),
        )
        .expect_err("rejected broadcast must fail");

        assert!(matches!(error, ChainError::Backend(_)));
        assert_eq!(
            error.to_string(),
            "chain backend error: Zinder rejected transaction broadcast \
             (BadExpiryHeight, code -25): transaction expired"
        );
    }

    #[test]
    fn invalid_encoding_is_invalid_data_and_unknown_is_backend_failure() {
        let invalid_encoding = broadcast_result(
            ZinderTransactionId::from_bytes([7; 32]),
            TransactionBroadcastOutcome::InvalidEncoding(zinder_core::BroadcastInvalidEncoding {
                error_code: Some(-22),
                message: "could not decode transaction".to_owned(),
            }),
        )
        .expect_err("invalid encoding must fail");
        let unknown = broadcast_result(
            ZinderTransactionId::from_bytes([7; 32]),
            TransactionBroadcastOutcome::Unknown(zinder_core::BroadcastUnknown {
                error_code: Some(-1),
                message: "unclassified node response".to_owned(),
            }),
        )
        .expect_err("unknown outcome must fail");

        assert!(matches!(invalid_encoding, ChainError::InvalidData(_)));
        assert!(matches!(unknown, ChainError::Backend(_)));
        assert!(invalid_encoding.to_string().contains("code -22"));
        assert!(unknown.to_string().contains("code -1"));
    }

    #[cfg(feature = "bounded-scan-certification")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires an externally orchestrated Zinder certification runtime"]
    async fn endpoint_without_full_blocks_fails_before_wallet_open() -> CertificationTestResult {
        let certification_environment = read_certification_environment()?;
        let certification_config = BoundedScanCertificationConfig::new(
            &certification_environment.certification_datadir,
            certification_environment.zallet_config.clone(),
            certification_environment.requested_block_range.clone(),
        )?;
        let wallet_artifact_paths =
            sqlite_wallet_artifact_paths(&certification_config.wallet_database_path());
        if is_wallet_artifact_path(
            &certification_environment.certification_result_path,
            &wallet_artifact_paths,
        ) {
            return Err(certification_failure(format!(
                "{CERTIFICATION_RESULT_ENV} must not alias wallet.db or its WAL/SHM sidecars: {:?}",
                certification_environment.certification_result_path
            ))
            .into());
        }
        let wallet_artifacts_before = find_existing_wallet_artifacts(&wallet_artifact_paths)?;
        if !wallet_artifacts_before.is_empty() {
            return Err(certification_failure(format!(
                "negative certification wallet artifacts already exist before admission: \
                 {wallet_artifacts_before:?}"
            ))
            .into());
        }

        let params = certification_environment.zallet_config.consensus.network();
        let index = open_zinder_index(
            certification_environment.zinder_endpoint.clone(),
            zinder_network(params),
        )?;
        let missing_capabilities = probe_missing_wallet_runtime_capabilities(&index).await?;
        let expected_missing_capabilities = vec![Capability::FullBlock, Capability::FullBlockRange];
        if missing_capabilities != expected_missing_capabilities {
            return Err(certification_failure(format!(
                "Transactions endpoint missing-capability list differs from the exact wallet-runtime \
                 requirement order: actual {missing_capabilities:?}, \
                 expected {expected_missing_capabilities:?}"
            ))
            .into());
        }

        let connection_error =
            match ZinderChain::connect(certification_environment.zinder_endpoint, params).await {
                Ok(_) => {
                    return Err(certification_failure(
                        "Transactions endpoint unexpectedly passed wallet-runtime admission",
                    )
                    .into());
                }
                Err(error) => error,
            };
        let expected_rejection = wallet_runtime_preflight_message(&expected_missing_capabilities);
        if !connection_error.to_string().contains(&expected_rejection) {
            return Err(certification_failure(format!(
                "ZinderChain::connect rejected for an unexpected reason: {connection_error}"
            ))
            .into());
        }

        let wallet_artifacts_after = find_existing_wallet_artifacts(&wallet_artifact_paths)?;
        if !wallet_artifacts_after.is_empty() {
            return Err(certification_failure(format!(
                "negative certification created wallet artifacts despite failed admission: \
                 {wallet_artifacts_after:?}"
            ))
            .into());
        }

        let missing_capability_names = missing_capabilities
            .iter()
            .map(Capability::as_str)
            .collect::<Vec<_>>();
        let wallet_artifact_path_names = wallet_artifact_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        let evidence = serde_json::json!({
            "schema_version": CERTIFICATION_EVIDENCE_SCHEMA_VERSION,
            "missing_capabilities": missing_capability_names,
            "connection_rejected": true,
            "wallet_artifact_paths": wallet_artifact_path_names,
            "wallet_artifacts_absent_before_admission": true,
            "wallet_artifacts_absent_after_admission": true,
        });
        write_json_atomically(
            &certification_environment.certification_result_path,
            &evidence,
        )?;
        let wallet_artifacts_after_result_write =
            find_existing_wallet_artifacts(&wallet_artifact_paths)?;
        if !wallet_artifacts_after_result_write.is_empty() {
            return Err(certification_failure(format!(
                "negative certification result persistence created wallet artifacts: \
                 {wallet_artifacts_after_result_write:?}"
            ))
            .into());
        }

        Ok(())
    }

    #[cfg(feature = "bounded-scan-certification")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires an externally orchestrated Zinder certification runtime"]
    async fn endpoint_certifies_birthday_through_tip() -> CertificationTestResult {
        let certification_environment = read_certification_environment()?;
        let certification_config = BoundedScanCertificationConfig::new(
            &certification_environment.certification_datadir,
            certification_environment.zallet_config.clone(),
            certification_environment.requested_block_range,
        )?;
        let chain = ZinderChain::connect(
            certification_environment.zinder_endpoint,
            certification_environment.zallet_config.consensus.network(),
        )
        .await?;
        let certification_outcome = certify_bounded_scan(&chain, &certification_config).await?;
        let certification_evidence = match certification_outcome {
            BoundedScanCertificationOutcome::Certified(evidence) => evidence,
            BoundedScanCertificationOutcome::ChainViewExpired { .. } => {
                return Err(certification_failure(
                    "bounded scan unexpectedly expired instead of certifying the endpoint",
                )
                .into());
            }
            _ => {
                return Err(certification_failure(
                    "bounded scan returned an unsupported certification outcome",
                )
                .into());
            }
        };
        let certification_evidence = serde_json::to_value(certification_evidence)?;
        write_json_atomically(
            &certification_environment.certification_result_path,
            &certification_evidence,
        )?;

        Ok(())
    }

    #[cfg(feature = "bounded-scan-certification")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires an externally orchestrated Zinder certification runtime"]
    async fn expired_epoch_reacquires_complete_bounded_scan() -> CertificationTestResult {
        let certification_environment = read_certification_environment()?;
        let retry_end_height = required_environment_height(RETRY_END_HEIGHT_EXCLUSIVE_ENV)?;
        let expected_retry_end_height = certification_environment
            .requested_block_range
            .end
            .checked_add(1)
            .ok_or_else(|| {
                certification_failure(format!(
                    "{REQUESTED_END_HEIGHT_EXCLUSIVE_ENV} cannot advance by one block"
                ))
            })?;
        if retry_end_height != expected_retry_end_height {
            return Err(certification_failure(format!(
                "{RETRY_END_HEIGHT_EXCLUSIVE_ENV} must equal \
                 {REQUESTED_END_HEIGHT_EXCLUSIVE_ENV} + 1 for one-block epoch rotation: \
                 received {retry_end_height}, expected {expected_retry_end_height}"
            ))
            .into());
        }
        let barrier_directory = required_absolute_environment_path(RANGE_BARRIER_DIRECTORY_ENV)?;
        if optional_environment_u32(RANGE_REQUEST_PAUSE_START_HEIGHT_ENV)?
            != Some(certification_environment.requested_block_range.start)
        {
            return Err(certification_failure(format!(
                "{RANGE_REQUEST_PAUSE_START_HEIGHT_ENV} must equal \
                 {REQUESTED_START_HEIGHT_ENV} for epoch-expiry certification"
            ))
            .into());
        }

        let first_attempt_marker_path = range_request_attempt_marker_path(&barrier_directory, 1);
        let second_attempt_marker_path = range_request_attempt_marker_path(&barrier_directory, 2);
        let paused_marker_path = barrier_directory.join(RANGE_REQUEST_PAUSED_MARKER_FILENAME);
        let continue_range_request_path =
            barrier_directory.join(CONTINUE_RANGE_REQUEST_MARKER_FILENAME);
        let barrier_paths = [
            &first_attempt_marker_path,
            &second_attempt_marker_path,
            &paused_marker_path,
            &continue_range_request_path,
        ];
        for barrier_path in barrier_paths {
            if barrier_path.try_exists()? {
                return Err(certification_failure(format!(
                    "epoch-expiry certification requires a fresh barrier directory; \
                     stale path exists: {barrier_path:?}"
                ))
                .into());
            }
        }

        let first_requested_block_range = certification_environment.requested_block_range.clone();
        let first_certification_config = BoundedScanCertificationConfig::new(
            &certification_environment.certification_datadir,
            certification_environment.zallet_config.clone(),
            first_requested_block_range.clone(),
        )?;
        let chain = ZinderChain::connect(
            certification_environment.zinder_endpoint,
            certification_environment.zallet_config.consensus.network(),
        )
        .await?;
        let first_outcome = certify_bounded_scan(&chain, &first_certification_config).await?;
        let (chain_error, expiry_evidence) = match first_outcome {
            BoundedScanCertificationOutcome::ChainViewExpired {
                chain_error,
                evidence,
            } => (chain_error, evidence),
            BoundedScanCertificationOutcome::Certified(_) => {
                return Err(certification_failure(
                    "first bounded scan unexpectedly certified instead of observing epoch expiry",
                )
                .into());
            }
            _ => {
                return Err(certification_failure(
                    "first bounded scan returned an unsupported certification outcome",
                )
                .into());
            }
        };
        let ChainError::ViewExpired(expiry_source) = chain_error else {
            return Err(certification_failure(
                "expired certification outcome did not retain ChainError::ViewExpired",
            )
            .into());
        };
        let Some(indexer_error) = expiry_source.downcast_ref::<IndexerError>() else {
            return Err(certification_failure(
                "expired view source did not downcast to zinder_client::IndexerError",
            )
            .into());
        };
        if !matches!(indexer_error, IndexerError::ChainEpochPinUnavailable) {
            return Err(certification_failure(format!(
                "expired view retained the wrong IndexerError variant: {indexer_error:?}"
            ))
            .into());
        }
        if expiry_evidence.block_metadata_before != expiry_evidence.block_metadata_after {
            return Err(certification_failure(format!(
                "expired bounded scan changed block metadata: before {:?}, after {:?}",
                expiry_evidence.block_metadata_before, expiry_evidence.block_metadata_after
            ))
            .into());
        }
        if !expiry_evidence.block_metadata_before.is_empty()
            || !expiry_evidence.block_metadata_after.is_empty()
        {
            return Err(certification_failure(format!(
                "fresh rotation wallet contained block metadata around the expired attempt: \
                 before {:?}, after {:?}",
                expiry_evidence.block_metadata_before, expiry_evidence.block_metadata_after
            ))
            .into());
        }

        let retry_requested_block_range = first_requested_block_range.start..retry_end_height;
        let retry_certification_config = BoundedScanCertificationConfig::new(
            &certification_environment.certification_datadir,
            certification_environment.zallet_config,
            retry_requested_block_range.clone(),
        )?;
        let retry_outcome = certify_bounded_scan(&chain, &retry_certification_config).await?;
        let retry_evidence = match retry_outcome {
            BoundedScanCertificationOutcome::Certified(evidence) => evidence,
            BoundedScanCertificationOutcome::ChainViewExpired { .. } => {
                return Err(certification_failure(
                    "retry bounded scan expired instead of certifying the replacement epoch",
                )
                .into());
            }
            _ => {
                return Err(certification_failure(
                    "retry bounded scan returned an unsupported certification outcome",
                )
                .into());
            }
        };

        let first_attempt_marker = read_range_request_marker(&first_attempt_marker_path)?;
        let second_attempt_marker = read_range_request_marker(&second_attempt_marker_path)?;
        assert_range_request_marker(&first_attempt_marker, 1, &first_requested_block_range)?;
        assert_range_request_marker(&second_attempt_marker, 2, &retry_requested_block_range)?;
        if first_attempt_marker.chain_epoch_id == second_attempt_marker.chain_epoch_id {
            return Err(certification_failure(format!(
                "bounded-scan retry reused chain epoch {} instead of reacquiring a new epoch",
                first_attempt_marker.chain_epoch_id
            ))
            .into());
        }

        let evidence = serde_json::json!({
            "schema_version": CERTIFICATION_EVIDENCE_SCHEMA_VERSION,
            "expiry_evidence": expiry_evidence,
            "expiry_source_classification": EPOCH_PIN_UNAVAILABLE_SOURCE_CLASSIFICATION,
            "retry_evidence": retry_evidence,
            "range_request_attempts": [
                {
                    "attempt_number": first_attempt_marker.attempt_number,
                    "chain_epoch_id": first_attempt_marker.chain_epoch_id,
                    "requested_start_height_inclusive":
                        first_attempt_marker.requested_start_height_inclusive,
                    "requested_end_height_inclusive":
                        first_attempt_marker.requested_end_height_inclusive,
                },
                {
                    "attempt_number": second_attempt_marker.attempt_number,
                    "chain_epoch_id": second_attempt_marker.chain_epoch_id,
                    "requested_start_height_inclusive":
                        second_attempt_marker.requested_start_height_inclusive,
                    "requested_end_height_inclusive":
                        second_attempt_marker.requested_end_height_inclusive,
                },
            ],
        });
        write_json_atomically(
            &certification_environment.certification_result_path,
            &evidence,
        )?;

        Ok(())
    }
}
