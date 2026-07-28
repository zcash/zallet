//! Zinder-backed implementation of Zallet's chain boundary.

use std::{
    io::{self, Cursor},
    num::NonZeroU32,
    ops::Range,
    sync::Arc,
};

#[cfg(all(test, feature = "bounded-scan-certification"))]
use std::{
    env, fs,
    io::Write as _,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
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
    BlockBlobArtifact, BlockHash as ZinderBlockHash, BlockHeight as ZinderBlockHeight,
    BlockHeightRange as ZinderBlockHeightRange, BlockId as ZinderBlockId, BlockSelector,
    Capability, ChainEpochId, ChainIndex, IndexStream, IndexerError, MAX_SUBTREE_ROOTS_PER_REQUEST,
    Network as ZinderNetwork, OwnedChainSnapshot, RemoteChainIndex, RetryPolicy, ShieldedProtocol,
    SubtreeRootArtifact, SubtreeRootIndex, SubtreeRootRange, TreeStateArtifact,
};

use crate::{open_zinder_index, probe_missing_wallet_runtime_capabilities};

/// Maximum full blocks requested from Zinder in one range call.
///
/// Zinder's native wallet endpoint rejects wider full-block ranges. Paging
/// here keeps an arbitrarily long Zallet sync demand-driven while every page
/// remains bound to the same captured chain epoch.
const FULL_BLOCK_PAGE_SIZE: u64 = 1_000;

#[cfg(all(test, feature = "bounded-scan-certification"))]
const RANGE_BARRIER_DIRECTORY_ENV: &str = "ZIT_RANGE_BARRIER_DIR";
#[cfg(all(test, feature = "bounded-scan-certification"))]
const BLOCK_FIRST_RANGE_REQUEST_ENV: &str = "ZIT_BLOCK_FIRST_RANGE_REQUEST";
#[cfg(all(test, feature = "bounded-scan-certification"))]
const RANGE_REQUEST_BARRIER_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(all(test, feature = "bounded-scan-certification"))]
const RANGE_REQUEST_BARRIER_POLL_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(all(test, feature = "bounded-scan-certification"))]
const CERTIFICATION_EVIDENCE_SCHEMA_VERSION: u32 = 1;
#[cfg(all(test, feature = "bounded-scan-certification"))]
const PREDECESSOR_LOADED_MARKER_FILENAME: &str = "predecessor-loaded.json";
#[cfg(all(test, feature = "bounded-scan-certification"))]
const CONTINUE_RANGE_REQUEST_MARKER_FILENAME: &str = "continue-range-request";
#[cfg(all(test, feature = "bounded-scan-certification"))]
static RANGE_REQUEST_ATTEMPT_COUNT: AtomicU64 = AtomicU64::new(0);

/// Factory-shaped entry point for the Zinder chain backend.
///
/// The endpoint is supplied by the composition root rather than added to
/// Zallet's production configuration. This type is not registered by a Zallet
/// binary and does not make this crate a production backend.
#[derive(Clone)]
pub struct ZinderBackend {
    endpoint: String,
}

impl ZinderBackend {
    /// Creates a backend factory for one native Zinder wallet endpoint.
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
        #[cfg(all(test, feature = "bounded-scan-certification"))]
        {
            await_range_request_barrier(self, block_range).await?;
        }

        OwnedChainSnapshot::full_blocks_in_range(self, block_range).await
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

    async fn broadcast_transaction(&self, _tx: &Transaction) -> Result<(), ChainError> {
        Err(unsupported_chain_operation("broadcast_transaction"))
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

    async fn get_mempool_stream(&self) -> Result<Option<BoxStream<'_, Transaction>>, ChainError> {
        Err(unsupported_chain_operation("get_mempool_stream"))
    }

    async fn get_transaction(&self, _txid: TxId) -> Result<Option<ChainTx>, ChainError> {
        Err(unsupported_chain_operation("get_transaction"))
    }

    async fn get_transaction_status(&self, _txid: TxId) -> Result<TransactionStatus, ChainError> {
        Err(unsupported_chain_operation("get_transaction_status"))
    }

    async fn get_address_unspent_outpoints(
        &self,
        _address: &TransparentAddress,
    ) -> Result<Vec<(TxId, u32)>, ChainError> {
        Err(unsupported_chain_operation("get_address_unspent_outpoints"))
    }

    async fn get_address_tx_ids(
        &self,
        _address: &TransparentAddress,
        _range: Range<BlockHeight>,
    ) -> Result<Vec<TxId>, ChainError> {
        Err(unsupported_chain_operation("get_address_tx_ids"))
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

#[cfg(all(test, feature = "bounded-scan-certification"))]
async fn await_range_request_barrier(
    snapshot: &OwnedChainSnapshot<RemoteChainIndex>,
    range: ZinderBlockHeightRange,
) -> Result<(), IndexerError> {
    let previous_attempt_count = RANGE_REQUEST_ATTEMPT_COUNT.fetch_add(1, Ordering::SeqCst);
    let attempt_number = previous_attempt_count
        .checked_add(1)
        .ok_or_else(|| range_request_barrier_error("range-request attempt counter overflowed"))?;
    let Some(barrier_directory) = env::var_os(RANGE_BARRIER_DIRECTORY_ENV) else {
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

    if attempt_number != 1 {
        return Ok(());
    }
    let should_block_first_request = required_environment_bool(BLOCK_FIRST_RANGE_REQUEST_ENV)
        .map_err(|error| range_request_barrier_error(error.to_string()))?;
    if !should_block_first_request {
        return Ok(());
    }

    let predecessor_loaded_path = barrier_directory.join(PREDECESSOR_LOADED_MARKER_FILENAME);
    write_json_atomically(&predecessor_loaded_path, &marker).map_err(|error| {
        range_request_barrier_error(format!(
            "cannot write predecessor-loaded marker {predecessor_loaded_path:?}: {error}"
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

#[cfg(all(test, feature = "bounded-scan-certification"))]
fn required_environment_bool(name: &'static str) -> io::Result<bool> {
    match env::var(name) {
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Ok(value) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be exactly `true` or `false`, received {value:?}"),
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

#[cfg(all(test, feature = "bounded-scan-certification"))]
fn range_request_attempt_marker_path(
    barrier_directory: &Path,
    attempt_number: u64,
) -> std::path::PathBuf {
    barrier_directory.join(format!("range-request-attempt-{attempt_number}.json"))
}

#[cfg(all(test, feature = "bounded-scan-certification"))]
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

#[cfg(all(test, feature = "bounded-scan-certification"))]
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

fn invalid_tree_state(pool: &'static str, source: impl std::fmt::Display) -> ChainError {
    invalid_data(format!("{pool} tree-state finalState is invalid: {source}"))
}

fn invalid_data(message: impl Into<String>) -> ChainError {
    ChainError::invalid_data(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

fn unsupported_chain_operation(method: &'static str) -> ChainError {
    ChainError::backend(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{method} is not implemented by the Zinder backend"),
    ))
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
    use zinder_client::ChainEpochId;

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
        if !required_environment_bool(BLOCK_FIRST_RANGE_REQUEST_ENV)? {
            return Err(certification_failure(format!(
                "{BLOCK_FIRST_RANGE_REQUEST_ENV} must be `true` for epoch-expiry certification"
            ))
            .into());
        }

        let first_attempt_marker_path = range_request_attempt_marker_path(&barrier_directory, 1);
        let second_attempt_marker_path = range_request_attempt_marker_path(&barrier_directory, 2);
        let predecessor_loaded_path = barrier_directory.join(PREDECESSOR_LOADED_MARKER_FILENAME);
        let continue_range_request_path =
            barrier_directory.join(CONTINUE_RANGE_REQUEST_MARKER_FILENAME);
        let barrier_paths = [
            &first_attempt_marker_path,
            &second_attempt_marker_path,
            &predecessor_loaded_path,
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
