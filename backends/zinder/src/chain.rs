//! The Zinder-backed implementation of [`Chain`] and [`ChainView`].
//!
//! Talks to a co-located `zinder-query` over gRPC using the vendored
//! `WalletQuery` wire contract (`zallet/proto/zinder/`). Every canonical read is
//! pinned to the `ChainEpoch` captured by [`Chain::snapshot`], so a sequence of
//! reads through one [`ZinderChainView`] reflects a single chain history.

mod convert;
mod error;
mod proto;

use std::collections::{HashSet, VecDeque};
use std::ops::Range;
use std::time::Duration;

use futures::stream::BoxStream;
use futures::{StreamExt as _, stream};
use incrementalmerkletree::frontier::CommitmentTree;
use serde_json::Value;
use tonic::Code;
use tonic::transport::Channel;
use tracing::{info, warn};
use transparent::bundle::OutPoint;
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
    consensus::{BlockHeight, BranchId, Parameters as _},
};

use self::error::map_status;
use self::proto::wallet as pw;
use self::proto::wallet::wallet_query_client::WalletQueryClient;
use zallet_core::{
    components::{
        TaskHandle,
        chain::{
            BlockLocator, Chain, ChainBlock, ChainError, ChainFactory, ChainTx, ChainView,
            ReportedUpgrade, SpendStatus, UpgradeStatus,
        },
    },
    config::ZalletConfig,
    error::{Error, ErrorKind},
    network::Network,
};

/// The gRPC `WalletQuery` client this backend drives.
type WalletClient = WalletQueryClient<Channel>;

/// Capabilities the deployment must advertise for this backend to function.
const REQUIRED_CAPABILITIES: &[&str] = &[
    "wallet.read.network_upgrade_activations_v1",
    "wallet.read.full_block_at_v1",
    "wallet.read.full_block_range_v1",
    "wallet.read.transaction_bytes_v1",
    "wallet.read.transparent_spends_by_outpoint_v1",
    "wallet.read.transparent_unspent_outputs_by_outpoint_v1",
    "wallet.broadcast.transaction_v1",
    "wallet.events.chain_v1",
];

/// Minimum in-place wire-contract revision this backend understands (ADR-0027).
const MIN_CONTRACT_REVISION: u32 = 1;

/// Blocks per `FullBlocksInRange` request (one request per wallet scan batch).
const FULL_BLOCK_WINDOW: u32 = 1000;

/// Entries per `MempoolSnapshot` page.
const MEMPOOL_PAGE_SIZE: u32 = 1000;

/// Entries per `SubtreeRoots` page.
const SUBTREE_PAGE_SIZE: u32 = 1000;

/// Client-side decode ceiling. Full blocks reach ~2 MiB; the streamed
/// range serves one block per chunk, so this bounds a single chunk generously.
const MAX_DECODING_MESSAGE_SIZE: usize = 256 * 1024 * 1024;

/// How often the mempool stream re-reads the visible epoch to detect a tip
/// advance the chain-event tail could not deliver. `ChainEvents` is served from
/// the writer while canonical reads come from the read replica, so an advance
/// the tail reports against the writer can land before the replica reveals it;
/// the tail then waits on the next event and never re-fires. Polling the epoch
/// bounds that gap so the wallet always converges to the readable tip.
const TIP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The Zinder public network name for a configured [`Network`].
fn zinder_network_name(network: &Network) -> &'static str {
    use zcash_protocol::consensus::NetworkType;
    match network.network_type() {
        NetworkType::Main => "zcash-mainnet",
        NetworkType::Test => "zcash-testnet",
        NetworkType::Regtest => "zcash-regtest",
    }
}

/// A handle to chain data served by a co-located `zinder-query`.
#[derive(Clone)]
pub struct ZinderChain {
    client: WalletClient,
    params: Network,
}

impl std::fmt::Debug for ZinderChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZinderChain").finish_non_exhaustive()
    }
}

impl ZinderChain {
    async fn new(config: &ZalletConfig) -> Result<(Self, TaskHandle), Error> {
        let params = config.consensus.network();

        let address = config
            .indexer
            .zinder
            .as_ref()
            .ok_or_else(|| {
                ErrorKind::Init
                    .context("the zinder backend requires an [indexer.zinder] config section")
            })?
            .grpc_address
            .clone();

        let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
            .map_err(|e| {
                ErrorKind::Init.context(format!(
                    "invalid indexer.zinder.grpc_address '{address}': {e}"
                ))
            })?;
        let channel = endpoint.connect().await.map_err(|e| {
            ErrorKind::Init.context(format!(
                "failed to connect to zinder-query at '{address}': {e}"
            ))
        })?;
        let client =
            WalletQueryClient::new(channel).max_decoding_message_size(MAX_DECODING_MESSAGE_SIZE);

        let chain = Self { client, params };
        chain.preflight().await?;

        // Lifecycle task, matching the other backends' shape: it runs until the
        // process shuts down and aborts it.
        let task = zallet_core::spawn!("Zinder chain backend", async move {
            std::future::pending::<()>().await;
            Ok::<(), Error>(())
        });

        Ok((chain, task))
    }

    /// Fails construction unless the deployment matches the configured network,
    /// meets the contract-revision floor, and advertises every required
    /// capability.
    async fn preflight(&self) -> Result<(), Error> {
        let mut client = self.client.clone();
        let info = client
            .server_info(pw::ServerInfoRequest {})
            .await
            .map_err(|status| {
                ErrorKind::Init.context(format!("zinder-query ServerInfo failed: {status}"))
            })?
            .into_inner()
            .info
            .ok_or_else(|| {
                ErrorKind::Init.context("zinder-query ServerInfo returned no descriptor")
            })?;
        let common = info.common.ok_or_else(|| {
            ErrorKind::Init.context("zinder-query ServerInfo returned no common descriptor")
        })?;

        let expected = zinder_network_name(&self.params);
        if common.network != expected {
            return Err(ErrorKind::Init
                .context(format!(
                    "zinder-query serves network '{}', but this wallet is configured for '{expected}'",
                    common.network
                ))
                .into());
        }

        if common.contract_revision < MIN_CONTRACT_REVISION {
            return Err(ErrorKind::Init
                .context(format!(
                    "zinder-query advertises contract_revision {}, but this backend requires >= {MIN_CONTRACT_REVISION}",
                    common.contract_revision
                ))
                .into());
        }

        let missing: Vec<&str> = REQUIRED_CAPABILITIES
            .iter()
            .copied()
            .filter(|cap| !common.capabilities.iter().any(|c| c == cap))
            .collect();
        if !missing.is_empty() {
            return Err(ErrorKind::Init
                .context(format!(
                    "zinder-query is missing required capabilities: {}",
                    missing.join(", ")
                ))
                .into());
        }

        // The mempool capabilities are always advertised, but on `zinder-query`
        // `MempoolSnapshot`/`MempoolEvents` are proxies that fail unless the
        // ingest-control writer endpoint is wired. The capability set cannot
        // vouch for the proxy, so probe it live and fail fast with an
        // operator-actionable message rather than crashing on the first
        // steady-state mempool read.
        client
            .mempool_snapshot(pw::MempoolSnapshotRequest {
                max_entries: 1,
                from_cursor: Vec::new(),
            })
            .await
            .map_err(|status| {
                ErrorKind::Init.context(format!(
                    "zinder-query cannot serve the mempool surface, which the zinder \
                     backend requires; is the ingest-control proxy configured? ({status})"
                ))
            })?;

        info!(
            "Connected to zinder-query {} on {}, contract_revision {}",
            common.service_version, common.network, common.contract_revision
        );
        Ok(())
    }

    /// Reads every subtree root for one shielded protocol, paging until drained.
    async fn subtree_roots(
        &self,
        protocol: pw::ShieldedProtocol,
    ) -> Result<Vec<pw::SubtreeRoot>, ChainError> {
        let mut client = self.client.clone();
        let mut start_index = 0u32;
        let mut roots = Vec::new();
        // Pin the walk to the first page's epoch so later pages cannot mix two
        // chain histories across a commit or reorg landing mid-walk. A pin
        // expiry then surfaces as `Unavailable` via `map_status`.
        let mut at_epoch_id: Option<u64> = None;
        loop {
            let response = client
                .subtree_roots(pw::SubtreeRootsRequest {
                    shielded_protocol: protocol as i32,
                    start_index,
                    max_entries: SUBTREE_PAGE_SIZE,
                    at_epoch_id,
                })
                .await
                .map_err(|status| map_status(&status))?
                .into_inner();
            if at_epoch_id.is_none() {
                at_epoch_id = response
                    .chain_view
                    .and_then(|view| view.chain_epoch)
                    .map(|epoch| epoch.chain_epoch_id);
            }
            let page_full = response.subtree_roots.len() == SUBTREE_PAGE_SIZE as usize;
            let last_index = response.subtree_roots.last().map(|r| r.subtree_index);
            roots.extend(response.subtree_roots);
            match last_index {
                Some(index) if page_full => start_index = index + 1,
                _ => break,
            }
        }
        Ok(roots)
    }
}

/// Factory for the `zinder` chain backend.
#[derive(Clone, Copy, Debug)]
pub struct ZinderBackend;

impl ChainFactory for ZinderBackend {
    type Chain = ZinderChain;

    const NAME: &'static str = "zinder";

    async fn build(&self, config: &ZalletConfig) -> Result<(ZinderChain, TaskHandle), Error> {
        ZinderChain::new(config).await
    }
}

impl Chain for ZinderChain {
    type View = ZinderChainView;

    fn params(&self) -> &Network {
        &self.params
    }

    async fn reported_upgrades(&self) -> Result<Vec<ReportedUpgrade>, Error> {
        let mut client = self.client.clone();
        let tip_height = client
            .latest_block(pw::LatestBlockRequest { at_epoch_id: None })
            .await
            .map_err(|status| {
                ErrorKind::Init.context(format!("zinder-query LatestBlock failed: {status}"))
            })?
            .into_inner()
            .latest_block
            .ok_or_else(|| ErrorKind::Init.context("zinder-query LatestBlock returned no tip"))?
            .height;
        let response = client
            .network_upgrade_activations(pw::NetworkUpgradeActivationsRequest {})
            .await
            .map_err(|status| {
                ErrorKind::Init.context(format!(
                    "zinder-query NetworkUpgradeActivations failed: {status}"
                ))
            })?
            .into_inner();

        Ok(reported_upgrades_at_tip(response.activations, tip_height))
    }

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), ChainError> {
        let mut raw = Vec::new();
        tx.write(&mut raw).map_err(ChainError::backend)?;

        let mut client = self.client.clone();
        let outcome = client
            .broadcast_transaction(pw::BroadcastTransactionRequest {
                raw_transaction: raw,
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner()
            .outcome;

        use pw::broadcast_transaction_response::Outcome;
        match outcome {
            // Accepted, an already-known duplicate, and a benign queued
            // re-broadcast all mean the network has the transaction.
            Some(Outcome::Accepted(_) | Outcome::Duplicate(_) | Outcome::Queued(_)) => Ok(()),
            Some(Outcome::InvalidEncoding(details)) => Err(ChainError::backend(format!(
                "broadcast rejected (invalid encoding): {}",
                details.message
            ))),
            Some(Outcome::Rejected(details)) => Err(ChainError::backend(format!(
                "broadcast rejected: {}",
                details.message
            ))),
            Some(Outcome::Unknown(details)) => Err(ChainError::backend(format!(
                "broadcast failed: {}",
                details.message
            ))),
            None => Err(ChainError::backend("broadcast returned no outcome")),
        }
    }

    async fn get_sapling_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<sapling::Node>>, ChainError> {
        self.subtree_roots(pw::ShieldedProtocol::Sapling)
            .await?
            .into_iter()
            .map(|root| {
                let bytes: [u8; 32] = root.root_hash.as_slice().try_into().map_err(|_| {
                    ChainError::invalid_data("sapling subtree root is not 32 bytes")
                })?;
                let node = Option::from(sapling::Node::from_bytes(bytes)).ok_or_else(|| {
                    ChainError::invalid_data("non-canonical sapling subtree root")
                })?;
                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(root.completing_block_height),
                    node,
                ))
            })
            .collect()
    }

    async fn get_orchard_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError> {
        self.subtree_roots(pw::ShieldedProtocol::Orchard)
            .await?
            .into_iter()
            .map(|root| {
                let bytes: [u8; 32] = root.root_hash.as_slice().try_into().map_err(|_| {
                    ChainError::invalid_data("orchard subtree root is not 32 bytes")
                })?;
                let node = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&bytes))
                    .ok_or_else(|| {
                        ChainError::invalid_data("non-canonical orchard subtree root")
                    })?;
                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(root.completing_block_height),
                    node,
                ))
            })
            .collect()
    }

    async fn get_ironwood_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError> {
        self.subtree_roots(pw::ShieldedProtocol::Ironwood)
            .await?
            .into_iter()
            .map(|root| {
                let bytes: [u8; 32] = root.root_hash.as_slice().try_into().map_err(|_| {
                    ChainError::invalid_data("ironwood subtree root is not 32 bytes")
                })?;
                let node = Option::from(orchard::tree::MerkleHashOrchard::from_bytes(&bytes))
                    .ok_or_else(|| {
                        ChainError::invalid_data("non-canonical ironwood subtree root")
                    })?;
                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(root.completing_block_height),
                    node,
                ))
            })
            .collect()
    }

    async fn snapshot(&self) -> Result<ZinderChainView, ChainError> {
        let mut client = self.client.clone();
        let response = client
            .latest_block(pw::LatestBlockRequest { at_epoch_id: None })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        let epoch_id = response
            .chain_view
            .and_then(|view| view.chain_epoch)
            .map(|epoch| epoch.chain_epoch_id)
            .ok_or_else(|| ChainError::invalid_data("LatestBlock returned no chain epoch"))?;
        let tip =
            convert::chain_block(&response.latest_block.ok_or_else(|| {
                ChainError::invalid_data("LatestBlock returned no block metadata")
            })?)?;

        Ok(ZinderChainView {
            client: self.client.clone(),
            params: self.params,
            epoch_id,
            tip,
        })
    }
}

/// A pinned view of the chain as of the epoch captured by [`Chain::snapshot`].
///
/// Every canonical read threads `epoch_id`, so the sequence is mutually
/// consistent. A read against an expired epoch surfaces
/// [`ChainError::Unavailable`], which drives the wallet's re-pin loop.
#[derive(Clone)]
pub struct ZinderChainView {
    client: WalletClient,
    params: Network,
    epoch_id: u64,
    tip: ChainBlock,
}

impl ZinderChainView {
    /// Resolves a block hash to its identity on the pinned best chain, or `None`
    /// when the hash is unknown or off the best chain at this epoch.
    async fn block_by_hash(&self, hash: &BlockHash) -> Result<Option<ChainBlock>, ChainError> {
        let mut client = self.client.clone();
        let request = pw::BlockSelectorRequest {
            selector: Some(pw::BlockSelector {
                selector: Some(pw::block_selector::Selector::Hash(
                    convert::rpc_hex_block_hash(hash),
                )),
            }),
            at_epoch_id: Some(self.epoch_id),
        };
        match client.block_id_by_selector(request).await {
            Ok(response) => {
                let metadata = response.into_inner().block_id.ok_or_else(|| {
                    ChainError::invalid_data("BlockIdBySelector returned no block id")
                })?;
                Ok(Some(convert::chain_block(&metadata)?))
            }
            // NOT_FOUND covers both an unknown hash and one that is not on the
            // best chain at this epoch.
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(map_status(&status)),
        }
    }

    /// Fetches the full serialized block at `height`, or `None` if above the
    /// view's tip. A NOT_FOUND at or below the tip is a hard error, never `None`.
    async fn full_block_bytes(&self, height: BlockHeight) -> Result<Option<Vec<u8>>, ChainError> {
        if height > self.tip.height() {
            return Ok(None);
        }
        let mut client = self.client.clone();
        let block = client
            .full_block(pw::FullBlockRequest {
                height: u32::from(height),
                at_epoch_id: Some(self.epoch_id),
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner()
            .full_block
            .ok_or_else(|| ChainError::invalid_data("FullBlock returned no block"))?;
        Ok(Some(block.payload_bytes))
    }

    /// Resolves the canonical location of `txid` at the pinned epoch, or `None`
    /// on NOT_FOUND.
    async fn transaction_location(
        &self,
        txid: TxId,
    ) -> Result<Option<pw::transaction_location::Location>, ChainError> {
        let mut client = self.client.clone();
        let request = pw::TransactionRequest {
            transaction_id: convert::rpc_hex_txid(&txid),
            at_epoch_id: Some(self.epoch_id),
        };
        match client.transaction(request).await {
            Ok(response) => Ok(response
                .into_inner()
                .location
                .and_then(|location| location.location)),
            Err(status) if status.code() == Code::NotFound => Ok(None),
            Err(status) => Err(map_status(&status)),
        }
    }

    /// Walks the mempool snapshot for `txid`, returning its hydrated entry.
    async fn find_in_mempool(&self, txid: &TxId) -> Result<Option<pw::MempoolEntry>, ChainError> {
        let target = convert::rpc_hex_txid(txid);
        let mut client = self.client.clone();
        let mut cursor = Vec::new();
        loop {
            let response = client
                .mempool_snapshot(pw::MempoolSnapshotRequest {
                    max_entries: MEMPOOL_PAGE_SIZE,
                    from_cursor: std::mem::take(&mut cursor),
                })
                .await
                .map_err(|status| map_status(&status))?
                .into_inner();
            if let Some(entry) = response
                .entries
                .into_iter()
                .find(|entry| entry.transaction_id == target)
            {
                return Ok(Some(entry));
            }
            if response.next_cursor.is_empty() {
                return Ok(None);
            }
            cursor = response.next_cursor;
        }
    }

    /// Builds a [`ChainTx`] from a mined-transaction response.
    fn build_mined_tx(&self, mined: pw::MinedTransaction) -> Result<ChainTx, ChainError> {
        let location = mined
            .location
            .ok_or_else(|| ChainError::invalid_data("mined transaction missing location"))?;
        let details = mined
            .details
            .ok_or_else(|| ChainError::invalid_data("mined transaction missing details"))?;
        let raw = mined.raw_transaction_bytes.ok_or_else(|| {
            ChainError::backend(
                "zinder-query returned a mined transaction without raw bytes; the deployment must retain transaction blobs",
            )
        })?;
        let branch =
            BranchId::try_from(details.consensus_branch_id).map_err(ChainError::invalid_data)?;
        let inner = Transaction::read(&raw[..], branch).map_err(ChainError::invalid_data)?;
        Ok(ChainTx::new(
            inner,
            raw,
            Some(convert::block_hash(&location.block_hash)?),
            Some(BlockHeight::from_u32(location.block_height)),
            Some(convert::block_time(details.block_time)?),
        ))
    }

    /// Builds a [`ChainTx`] from raw mempool transaction bytes, parsed at the
    /// branch of the next block to be mined.
    fn build_mempool_tx(&self, raw: Vec<u8>) -> Result<ChainTx, ChainError> {
        let branch = BranchId::for_height(&self.params, self.tip.height() + 1);
        let inner = Transaction::read(&raw[..], branch).map_err(ChainError::invalid_data)?;
        Ok(ChainTx::new(inner, raw, None, None, None))
    }

    /// Pages the mempool snapshot into parsed transactions, the set of txids
    /// seen, and the `MempoolEvents` resume cursor anchored at the walk start.
    async fn snapshot_mempool(
        &self,
        branch: BranchId,
    ) -> Result<(Vec<Transaction>, HashSet<[u8; 32]>, Vec<u8>), ChainError> {
        let mut client = self.client.clone();
        let mut transactions = Vec::new();
        let mut seen = HashSet::new();
        let mut resume = Vec::new();
        let mut cursor = Vec::new();
        let mut first_page = true;
        loop {
            let response = client
                .mempool_snapshot(pw::MempoolSnapshotRequest {
                    max_entries: MEMPOOL_PAGE_SIZE,
                    from_cursor: std::mem::take(&mut cursor),
                })
                .await
                .map_err(|status| map_status(&status))?
                .into_inner();
            if first_page {
                resume = response.events_resume_cursor.clone();
                first_page = false;
            }
            for entry in response.entries {
                match convert::internal_bytes(&entry.transaction_id) {
                    Ok(internal) if seen.insert(internal) => {
                        match Transaction::read(&entry.raw_transaction_bytes[..], branch) {
                            Ok(tx) => transactions.push(tx),
                            Err(e) => warn!("skipping undecodable mempool snapshot entry: {e}"),
                        }
                    }
                    _ => {}
                }
            }
            if response.next_cursor.is_empty() {
                break;
            }
            cursor = response.next_cursor;
        }
        Ok((transactions, seen, resume))
    }

    /// Subscribes to `MempoolEvents` and yields each newly-added transaction,
    /// deduplicated against `seen` and applied idempotently (ADR-0027).
    async fn open_mempool_live(
        &self,
        resume: Vec<u8>,
        seen: HashSet<[u8; 32]>,
        branch: BranchId,
    ) -> Result<BoxStream<'static, Transaction>, ChainError> {
        let mut client = self.client.clone();
        let position = if resume.is_empty() {
            pw::event_stream_start::Position::EarliestRetained(pw::EarliestRetained {})
        } else {
            pw::event_stream_start::Position::AfterCursor(resume)
        };
        let stream = client
            .mempool_events(pw::MempoolEventsRequest {
                start: Some(pw::EventStreamStart {
                    position: Some(position),
                }),
                family: pw::MempoolEventStreamFamily::Mempool as i32,
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        let live = stream::unfold((stream, seen), move |(mut stream, mut seen)| async move {
            loop {
                match stream.message().await {
                    Ok(Some(envelope)) => {
                        if let Some(pw::mempool_event_envelope::Event::Added(added)) =
                            envelope.event
                        {
                            if let Some(entry) = added.entry {
                                match convert::internal_bytes(&entry.transaction_id) {
                                    Ok(internal) if seen.insert(internal) => {
                                        match Transaction::read(
                                            &entry.raw_transaction_bytes[..],
                                            branch,
                                        ) {
                                            Ok(tx) => return Some((tx, (stream, seen))),
                                            Err(e) => {
                                                warn!("skipping undecodable mempool event: {e}");
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Ok(None) => return None,
                    Err(status) => {
                        warn!("mempool events stream ended: {status}");
                        return None;
                    }
                }
            }
        })
        .boxed();
        Ok(live)
    }

    /// Yields once the visible epoch moves off the pinned one, polling on a
    /// fixed interval. This backstops the chain-event tail against the
    /// writer/replica read skew documented on [`TIP_POLL_INTERVAL`]: a tip
    /// advance the tail reported against the writer is picked up here once the
    /// replica reveals it, so the composed stream ends and the wallet re-pins.
    fn open_epoch_poll(&self) -> BoxStream<'static, ()> {
        let client = self.client.clone();
        let epoch_id = self.epoch_id;
        stream::unfold(client, move |mut client| async move {
            loop {
                tokio::time::sleep(TIP_POLL_INTERVAL).await;
                let visible = client
                    .latest_block(pw::LatestBlockRequest { at_epoch_id: None })
                    .await
                    .ok()
                    .and_then(|response| response.into_inner().chain_view)
                    .and_then(|view| view.chain_epoch)
                    .map(|epoch| epoch.chain_epoch_id);
                match visible {
                    Some(current) if current == epoch_id => {}
                    // A moved epoch, an absent epoch, or an errored read all
                    // mean the pinned view can no longer be trusted; end so the
                    // caller re-pins.
                    _ => return Some(((), client)),
                }
            }
        })
        .boxed()
    }

    /// Subscribes to the chain-event tail, yielding one `()` per event; the
    /// first item (or the stream ending) signals a tip change.
    async fn open_chain_tail(&self) -> Result<BoxStream<'static, ()>, ChainError> {
        let mut client = self.client.clone();
        let stream = client
            .chain_events(pw::ChainEventsRequest {
                start: Some(pw::EventStreamStart {
                    position: Some(pw::event_stream_start::Position::LiveTail(pw::LiveTail {})),
                }),
                family: pw::ChainEventStreamFamily::Tip as i32,
                address_filter: Vec::new(),
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        let chain = stream::unfold(stream, |mut stream| async move {
            match stream.message().await {
                Ok(Some(_)) => Some(((), stream)),
                _ => None,
            }
        })
        .boxed();
        Ok(chain)
    }

    /// Streams blocks over the inclusive height range `[start, end]`, one
    /// `FullBlocksInRange` request per [`FULL_BLOCK_WINDOW`]-sized window.
    fn stream_blocks_inner(
        &self,
        start: BlockHeight,
        end_inclusive: BlockHeight,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        let start = u32::from(start);
        let end = u32::from(end_inclusive);
        let client = self.client.clone();
        let params = self.params;
        let epoch_id = self.epoch_id;
        let open = move |window_start: u32, window_end: u32| {
            open_full_block_window(client.clone(), params, epoch_id, window_start, window_end)
        };
        flatten_windows(open, start, end)
    }
}

impl ChainView for ZinderChainView {
    async fn tip(&self) -> Result<ChainBlock, ChainError> {
        Ok(self.tip)
    }

    async fn find_fork_point(
        &self,
        locator: &BlockLocator,
    ) -> Result<Option<ChainBlock>, ChainError> {
        for hash in locator.hashes() {
            if let Some(block) = self.block_by_hash(hash).await? {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }

    async fn tree_state_as_of(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ChainState>, ChainError> {
        if height > self.tip.height() {
            return Ok(None);
        }
        // Zinder's canonical chain starts at height 1; genesis is not indexed. The
        // pre-genesis commitment trees are empty; the genesis hash the scanner
        // checks against block 1's prev-hash is read from block 1's header.
        if height == BlockHeight::from_u32(0) {
            let genesis_hash = match self.full_block_bytes(BlockHeight::from_u32(1)).await? {
                Some(bytes) => {
                    BlockHeader::read(&bytes[..])
                        .map_err(ChainError::invalid_data)?
                        .prev_block
                }
                None => BlockHash([0; 32]),
            };
            return Ok(Some(ChainState::empty(
                BlockHeight::from_u32(0),
                genesis_hash,
            )));
        }
        let mut client = self.client.clone();
        let response = client
            .tree_state_at_height(pw::TreeStateAtHeightRequest {
                height: u32::from(height),
                at_epoch_id: Some(self.epoch_id),
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();
        let hash = convert::block_hash(&response.block_hash)?;
        let payload: Value =
            serde_json::from_slice(&response.payload_bytes).map_err(ChainError::invalid_data)?;

        // An absent pool, or one with no `finalState`, is inactive at this
        // height: an empty tree, not an error.
        let final_sapling_tree = match pool_final_state(&payload, "sapling")? {
            None => CommitmentTree::empty(),
            Some(hex_state) => {
                read_commitment_tree::<sapling::Node, _, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>(
                    &hex::decode(hex_state).map_err(ChainError::invalid_data)?[..],
                )
                .map_err(ChainError::invalid_data)?
            }
        }
        .to_frontier();
        let final_orchard_tree = match pool_final_state(&payload, "orchard")? {
            None => CommitmentTree::empty(),
            Some(hex_state) => {
                read_commitment_tree::<
                    orchard::tree::MerkleHashOrchard,
                    _,
                    { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
                >(&hex::decode(hex_state).map_err(ChainError::invalid_data)?[..])
                .map_err(ChainError::invalid_data)?
            }
        }
        .to_frontier();
        let final_ironwood_tree = match pool_final_state(&payload, "ironwood")? {
            None => CommitmentTree::empty(),
            Some(hex_state) => {
                read_commitment_tree::<
                    orchard::tree::MerkleHashOrchard,
                    _,
                    { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
                >(&hex::decode(hex_state).map_err(ChainError::invalid_data)?[..])
                .map_err(ChainError::invalid_data)?
            }
        }
        .to_frontier();

        Ok(Some(ChainState::new(
            height,
            hash,
            final_sapling_tree,
            final_orchard_tree,
            final_ironwood_tree,
        )))
    }

    async fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>, ChainError> {
        match self.full_block_bytes(height).await? {
            // The header is the prefix of the block serialization.
            Some(bytes) => Ok(Some(
                BlockHeader::read(&bytes[..]).map_err(ChainError::invalid_data)?,
            )),
            None => Ok(None),
        }
    }

    async fn get_block(&self, height: BlockHeight) -> Result<Option<Block>, ChainError> {
        match self.full_block_bytes(height).await? {
            Some(bytes) => Ok(Some(
                Block::read(&bytes[..], &self.params).map_err(ChainError::invalid_data)?,
            )),
            None => Ok(None),
        }
    }

    fn stream_blocks_to_tip(&self, start: BlockHeight) -> BoxStream<'_, Result<Block, ChainError>> {
        self.stream_blocks_inner(start, self.tip.height())
    }

    fn stream_blocks(
        &self,
        range: &Range<BlockHeight>,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        if range.start >= range.end {
            return stream::empty().boxed();
        }
        self.stream_blocks_inner(range.start, range.end - 1)
    }

    async fn get_mempool_stream(&self) -> Result<Option<BoxStream<'_, Transaction>>, ChainError> {
        // Subscribe to the chain tail before checking the epoch or walking the
        // mempool. `live_tail` delivers only events applied after the
        // subscription is accepted (ADR-0027), so opening it first guarantees
        // any block committed during the snapshot walk still lands on the tail
        // and ends the composed stream. Opening it after the walk would miss a
        // tip change in that window, stranding the wallet at a stale tip.
        let chain = self.open_chain_tail().await?;

        // If the visible epoch already moved past the pinned one, the caller
        // must re-pin: drop the tail and return no stream.
        let mut client = self.client.clone();
        let current_epoch = client
            .latest_block(pw::LatestBlockRequest { at_epoch_id: None })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner()
            .chain_view
            .and_then(|view| view.chain_epoch)
            .map(|epoch| epoch.chain_epoch_id);
        if current_epoch != Some(self.epoch_id) {
            return Ok(None);
        }

        // End the composed stream on either a pushed chain event or a polled
        // epoch advance, so a tip change is never missed when the event lands
        // against the writer before the read replica reveals it.
        let tip_changed = stream::select(chain, self.open_epoch_poll()).boxed();

        let branch = BranchId::for_height(&self.params, self.tip.height() + 1);
        let (initial, seen, resume) = self.snapshot_mempool(branch).await?;
        let live = self.open_mempool_live(resume, seen, branch).await?;
        Ok(Some(compose_mempool_stream(initial, live, tip_changed)))
    }

    async fn get_transaction(&self, txid: TxId) -> Result<Option<ChainTx>, ChainError> {
        use pw::transaction_location::Location;
        match self.transaction_location(txid).await? {
            Some(Location::Mined(mined)) => Ok(Some(self.build_mined_tx(mined)?)),
            Some(Location::InMempool(mempool)) => {
                Ok(Some(self.build_mempool_tx(mempool.payload_bytes)?))
            }
            // A conflicting-chain (orphaned) transaction carries no bytes on the
            // wire, so this returns `Ok(None)`; the enhancement path then
            // records `TxidNotRecognized`, while `get_transaction_status` maps
            // the same location to `NotInMainChain`. The two surfaces diverge
            // for a re-minable side-chain transaction during a short reorg.
            // `Ok(None)` is the least-bad option today: `Err` would kill the
            // data-requests task. Resolving the divergence needs the wire to
            // carry `payload_bytes` on `ConflictingChainTransaction`.
            Some(Location::Conflicting(_)) => Ok(None),
            None => match self.find_in_mempool(&txid).await? {
                Some(entry) => Ok(Some(self.build_mempool_tx(entry.raw_transaction_bytes)?)),
                None => Ok(None),
            },
        }
    }

    async fn get_transaction_status(&self, txid: TxId) -> Result<TransactionStatus, ChainError> {
        use pw::transaction_location::Location;
        match self.transaction_location(txid).await? {
            Some(Location::Mined(mined)) => {
                let height = mined
                    .location
                    .map(|location| BlockHeight::from_u32(location.block_height))
                    .ok_or_else(|| {
                        ChainError::invalid_data("mined transaction missing location")
                    })?;
                Ok(TransactionStatus::Mined(height))
            }
            Some(Location::InMempool(_) | Location::Conflicting(_)) => {
                Ok(TransactionStatus::NotInMainChain)
            }
            None => {
                // A tx that was mined, then reorged out and dropped from the
                // mempool, is not recoverable here: report it as unrecognized.
                if self.find_in_mempool(&txid).await?.is_some() {
                    Ok(TransactionStatus::NotInMainChain)
                } else {
                    Ok(TransactionStatus::TxidNotRecognized)
                }
            }
        }
    }

    async fn outpoint_spend_status(&self, outpoint: &OutPoint) -> Result<SpendStatus, ChainError> {
        let wire = convert::wire_outpoint(outpoint);
        let mut client = self.client.clone();

        // Spentness is decided only by absence from the durable unspent set.
        let unspent = client
            .transparent_unspent_outputs_by_outpoint(
                pw::TransparentUnspentOutputsByOutpointRequest {
                    outpoints: vec![wire.clone()],
                    at_epoch_id: Some(self.epoch_id),
                },
            )
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();
        if unspent
            .entries
            .iter()
            .any(|entry| entry.outpoint.as_ref() == Some(&wire))
        {
            return Ok(SpendStatus::Unspent);
        }

        // Spent: resolve the spender identity only; never infer unspent here.
        let spends = client
            .transparent_spends_by_outpoint(pw::TransparentSpendsByOutpointRequest {
                outpoints: vec![wire.clone()],
                at_epoch_id: Some(self.epoch_id),
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();
        match spends
            .spends
            .into_iter()
            .find(|spend| spend.spent_outpoint.as_ref() == Some(&wire))
        {
            Some(spend) => Ok(SpendStatus::SpentBy(convert::txid(
                &spend.spending_transaction_id,
            )?)),
            None => Ok(SpendStatus::SpentSpenderUnknown),
        }
    }

    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    async fn block_height(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, ChainError> {
        Ok(self.block_by_hash(hash).await?.map(|block| block.height()))
    }
}

/// Extracts a pool's `finalState` commitment-tree hex from a `z_gettreestate`
/// JSON payload. `None` means the pool is inactive at this height (an empty
/// tree); an object without `finalState` is malformed.
fn pool_final_state(payload: &Value, pool: &str) -> Result<Option<String>, ChainError> {
    let Some(pool_value) = payload.get(pool) else {
        return Ok(None);
    };
    let Some(fields) = pool_value.as_object() else {
        return Err(ChainError::invalid_data(format!(
            "{pool} tree-state pool is not an object"
        )));
    };
    let Some(commitments) = fields.get("commitments") else {
        return Ok(None);
    };
    if let Some(final_state) = commitments.get("finalState").and_then(Value::as_str) {
        return Ok(Some(final_state.to_owned()));
    }
    match commitments.as_object() {
        Some(map) if map.is_empty() => Ok(None),
        _ => Err(ChainError::invalid_data(format!(
            "{pool} tree-state commitments missing finalState"
        ))),
    }
}

/// Converts Zinder's node-discovered activation schedule into Zallet's
/// startup-comparison shape at the currently visible tip.
fn reported_upgrades_at_tip(
    activations: Vec<pw::NetworkUpgradeActivation>,
    tip_height: u32,
) -> Vec<ReportedUpgrade> {
    activations
        .into_iter()
        .map(|activation| {
            ReportedUpgrade::new(
                activation.consensus_branch_id,
                activation.name,
                activation.activation_height,
                if activation.activation_height <= tip_height {
                    UpgradeStatus::Active
                } else {
                    UpgradeStatus::Pending
                },
            )
        })
        .collect()
}

/// One `FullBlocksInRange` window: connect lazily, then stream chunks.
enum FullBlockWindow {
    Connect {
        client: WalletClient,
        start: u32,
        end: u32,
        epoch_id: u64,
    },
    Streaming(tonic::Streaming<pw::FullBlocksInRangeChunk>),
    Done,
}

/// Opens one range window as a stream of parsed blocks. A mid-stream terminal
/// status is surfaced as an error item, then the window ends.
fn open_full_block_window(
    client: WalletClient,
    params: Network,
    epoch_id: u64,
    start: u32,
    end: u32,
) -> BoxStream<'static, Result<Block, ChainError>> {
    stream::unfold(
        FullBlockWindow::Connect {
            client,
            start,
            end,
            epoch_id,
        },
        move |state| async move { full_block_window_next(state, params).await },
    )
    .boxed()
}

async fn full_block_window_next(
    state: FullBlockWindow,
    params: Network,
) -> Option<(Result<Block, ChainError>, FullBlockWindow)> {
    match state {
        FullBlockWindow::Connect {
            mut client,
            start,
            end,
            epoch_id,
        } => {
            let request = pw::FullBlocksInRangeRequest {
                start_height: start,
                end_height: end,
                at_epoch_id: Some(epoch_id),
            };
            match client.full_blocks_in_range(request).await {
                Ok(response) => read_full_block_chunk(response.into_inner(), params).await,
                Err(status) => Some((Err(map_status(&status)), FullBlockWindow::Done)),
            }
        }
        FullBlockWindow::Streaming(stream) => read_full_block_chunk(stream, params).await,
        FullBlockWindow::Done => None,
    }
}

async fn read_full_block_chunk(
    mut stream: tonic::Streaming<pw::FullBlocksInRangeChunk>,
    params: Network,
) -> Option<(Result<Block, ChainError>, FullBlockWindow)> {
    match stream.message().await {
        Ok(Some(chunk)) => match chunk.full_block {
            Some(block) => match Block::read(&block.payload_bytes[..], &params) {
                Ok(block) => Some((Ok(block), FullBlockWindow::Streaming(stream))),
                Err(e) => Some((Err(ChainError::invalid_data(e)), FullBlockWindow::Done)),
            },
            None => Some((
                Err(ChainError::invalid_data("full block chunk missing payload")),
                FullBlockWindow::Done,
            )),
        },
        Ok(None) => None,
        Err(status) => Some((Err(map_status(&status)), FullBlockWindow::Done)),
    }
}

/// Flattens per-window streams into one contiguous stream over the inclusive
/// range `[start, end_inclusive]`, opening [`FULL_BLOCK_WINDOW`]-sized windows on
/// demand and stopping on the first error item (partial-range delivery).
fn flatten_windows<T, F, S>(
    open_window: F,
    start: u32,
    end_inclusive: u32,
) -> BoxStream<'static, Result<T, ChainError>>
where
    T: Send + 'static,
    F: FnMut(u32, u32) -> S + Send + 'static,
    S: futures::Stream<Item = Result<T, ChainError>> + Send + Unpin + 'static,
{
    struct State<F, S> {
        open: F,
        next_start: Option<u32>,
        end: u32,
        inner: Option<S>,
    }
    let next_start = (start <= end_inclusive).then_some(start);
    let state = State {
        open: open_window,
        next_start,
        end: end_inclusive,
        inner: None::<S>,
    };
    stream::unfold(state, |mut state| async move {
        loop {
            if let Some(inner) = state.inner.as_mut() {
                match inner.next().await {
                    Some(Ok(item)) => return Some((Ok(item), state)),
                    Some(Err(e)) => {
                        state.inner = None;
                        state.next_start = None;
                        return Some((Err(e), state));
                    }
                    None => state.inner = None,
                }
            }
            match state.next_start {
                None => return None,
                Some(window_start) => {
                    let window_end = state
                        .end
                        .min(window_start.saturating_add(FULL_BLOCK_WINDOW - 1));
                    state.inner = Some((state.open)(window_start, window_end));
                    state.next_start = (window_end < state.end).then_some(window_end + 1);
                }
            }
        }
    })
    .boxed()
}

/// Composes a mempool stream: emit the snapshot transactions, then live
/// additions, ending the moment a chain event arrives (a tip change).
fn compose_mempool_stream<T: Send + 'static>(
    initial: Vec<T>,
    live: BoxStream<'static, T>,
    chain: BoxStream<'static, ()>,
) -> BoxStream<'static, T> {
    struct State<T> {
        initial: VecDeque<T>,
        live: BoxStream<'static, T>,
        chain: BoxStream<'static, ()>,
    }
    let state = State {
        initial: VecDeque::from(initial),
        live,
        chain,
    };
    stream::unfold(state, |mut state| async move {
        if let Some(item) = state.initial.pop_front() {
            return Some((item, state));
        }
        tokio::select! {
            biased;
            _ = state.chain.next() => None,
            item = state.live.next() => item.map(|item| (item, state)),
        }
    })
    .boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn compose_ends_on_chain_event_even_with_pending_live() {
        // A chain event ends the stream even while the live source has more to
        // give: the snapshot drains first, then the chain event pre-empts.
        let initial = vec![1u32, 2u32];
        let live = stream::pending::<u32>().boxed();
        let chain = stream::once(async {}).boxed();
        let out: Vec<u32> = compose_mempool_stream(initial, live, chain).collect().await;
        assert_eq!(out, vec![1, 2]);
    }

    #[tokio::test]
    async fn compose_emits_live_then_ends_when_live_closes() {
        let live = stream::iter([9u32, 10u32]).boxed();
        let chain = stream::pending().boxed();
        let out: Vec<u32> = compose_mempool_stream(Vec::new(), live, chain)
            .collect()
            .await;
        assert_eq!(out, vec![9, 10]);
    }

    #[tokio::test]
    async fn compose_ends_immediately_on_chain_event() {
        let live = stream::pending::<u32>().boxed();
        let chain = stream::once(async {}).boxed();
        let out: Vec<u32> = compose_mempool_stream(Vec::new(), live, chain)
            .collect()
            .await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn flatten_windows_surfaces_mid_batch_error_then_stops() {
        // A window that fails mid-batch (an epoch-pin expiry mapped to
        // Unavailable) delivers its prefix, then the error, then ends.
        let open = |_start: u32, _end: u32| {
            stream::iter(vec![
                Ok(1u32),
                Ok(2u32),
                Err(ChainError::unavailable("epoch pin expired")),
            ])
            .boxed()
        };
        let items: Vec<Result<u32, ChainError>> = flatten_windows(open, 0, 5).collect().await;
        assert_eq!(items.len(), 3);
        assert!(matches!(items[0], Ok(1)));
        assert!(matches!(items[1], Ok(2)));
        assert!(matches!(items[2], Err(ChainError::Unavailable(_))));
    }

    #[tokio::test]
    async fn flatten_windows_spans_multiple_windows() {
        // Each window yields its start height; 0..=2500 spans three windows at
        // the 1000-block boundary.
        let open = |start: u32, _end: u32| stream::iter(vec![Ok(start)]).boxed();
        let items: Vec<Result<u32, ChainError>> = flatten_windows(open, 0, 2500).collect().await;
        let starts: Vec<u32> = items.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(starts, vec![0, 1000, 2000]);
    }

    #[tokio::test]
    async fn flatten_windows_empty_for_reversed_range() {
        let open = |start: u32, _end: u32| stream::iter(vec![Ok(start)]).boxed();
        let items: Vec<Result<u32, ChainError>> = flatten_windows(open, 10, 5).collect().await;
        assert!(items.is_empty());
    }

    #[test]
    fn network_names_match_zinder() {
        use zcash_protocol::consensus::NetworkType;
        assert_eq!(
            zinder_network_name(&Network::from_type(NetworkType::Main, &[])),
            "zcash-mainnet"
        );
        assert_eq!(
            zinder_network_name(&Network::from_type(NetworkType::Test, &[])),
            "zcash-testnet"
        );
        assert_eq!(
            zinder_network_name(&Network::from_type(NetworkType::Regtest, &[])),
            "zcash-regtest"
        );
    }

    #[test]
    fn pool_final_state_reads_hex_and_treats_absence_as_empty() {
        let payload = serde_json::json!({
            "sapling": { "commitments": { "finalState": "abcd" } },
            "orchard": { "commitments": {} },
            "ironwood": { "commitments": { "finalState": "1234" } },
        });
        assert_eq!(
            pool_final_state(&payload, "sapling").unwrap(),
            Some("abcd".to_owned())
        );
        // Empty commitments object: inactive pool.
        assert_eq!(pool_final_state(&payload, "orchard").unwrap(), None);
        assert_eq!(
            pool_final_state(&payload, "ironwood").unwrap(),
            Some("1234".to_owned())
        );
        // Absent pool: inactive.
        assert_eq!(pool_final_state(&payload, "sprout").unwrap(), None);
    }

    #[test]
    fn pool_final_state_rejects_malformed_commitments() {
        let payload = serde_json::json!({
            "sapling": { "commitments": { "notFinalState": 3 } },
        });
        assert!(matches!(
            pool_final_state(&payload, "sapling"),
            Err(ChainError::InvalidData(_))
        ));
    }

    #[test]
    fn reported_upgrades_are_classified_at_the_visible_tip() {
        let upgrades = reported_upgrades_at_tip(
            vec![
                pw::NetworkUpgradeActivation {
                    consensus_branch_id: 0x5437_f330,
                    name: "NU6.2".to_owned(),
                    activation_height: 5,
                },
                pw::NetworkUpgradeActivation {
                    consensus_branch_id: 0x37a5_165b,
                    name: "NU6.3".to_owned(),
                    activation_height: 6,
                },
            ],
            5,
        );

        assert_eq!(upgrades.len(), 2);
        assert!(matches!(upgrades[0].status(), UpgradeStatus::Active));
        assert!(matches!(upgrades[1].status(), UpgradeStatus::Pending));
    }
}
