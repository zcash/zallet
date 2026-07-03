//! The zebra-state + Zebra-RPC backed implementation of [`Chain`] and [`ChainView`].
//!
//! Reads finalized chain data directly from a local zebrad's state database (opened
//! read-only as a RocksDB secondary), follows the non-finalized tip over zebrad's gRPC
//! indexer interface, and uses a small direct JSON-RPC client for mempool access and
//! transaction submission.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{StreamExt as _, stream::BoxStream};
use incrementalmerkletree::frontier::CommitmentTree;
use jsonrpsee::tracing::warn;
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
    consensus::{BlockHeight, BranchId},
};
use zebra_state::ReadStateService;

#[cfg(feature = "spend-index")]
use super::SpendStatus;
use super::read_state::{AbortOnDrop, init_read_state_service};
use super::{
    BlockLocator, Chain, ChainBlock, ChainError, ChainFactory, ChainTx, ChainView, ReportedUpgrade,
};
use crate::{
    components::TaskHandle,
    config::ZalletConfig,
    error::{Error, ErrorKind},
    network::Network,
};
#[cfg(feature = "spend-index")]
use transparent::bundle::OutPoint;

mod convert;
mod reader;
mod rpc;
use reader::{ChainReader, ReadStateChainReader};
use rpc::ValidatorRpcClient;

/// The maximum reorg depth (`zebra-state`'s `MAX_BLOCK_REORG_HEIGHT`); blocks deeper than
/// this below the captured tip are treated as finalized and served by height.
const MAX_REORG_DEPTH: u32 = 1000;

/// A handle to chain data read from a local zebrad's `zebra-state`.
#[derive(Clone)]
pub(crate) struct ZebraChain {
    read_state_service: ReadStateService,
    validator_rpc: ValidatorRpcClient,
    params: Network,
    _syncer: Arc<AbortOnDrop>,
}

impl std::fmt::Debug for ZebraChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZebraChain").finish_non_exhaustive()
    }
}

impl ZebraChain {
    pub(crate) async fn new(config: &ZalletConfig) -> Result<(Self, TaskHandle), Error> {
        let params = config.consensus.network();

        let rss = config.indexer.read_state_service.as_ref().ok_or_else(|| {
            ErrorKind::Init.context(
                "the zebra-state backend requires an [indexer.read_state_service] config section",
            )
        })?;

        // Validator JSON-RPC client (mempool reads + transaction submission), using the
        // existing [indexer] validator connection settings.
        let validator_address = config
            .indexer
            .validator_address
            .as_deref()
            .ok_or_else(|| ErrorKind::Init.context("indexer.validator_address is required"))?;
        let validator_rpc = ValidatorRpcClient::new(
            validator_address,
            config.indexer.validator_user.as_deref().unwrap_or_default(),
            config
                .indexer
                .validator_password
                .as_deref()
                .unwrap_or_default(),
            config.indexer.validator_cookie_path.as_deref(),
        )?;

        // Open zebrad's state read-only and start the non-finalized syncer.
        let (read_state_service, sync_task) = init_read_state_service(config, &params, rss).await?;

        let chain = Self {
            read_state_service,
            validator_rpc,
            params,
            _syncer: Arc::new(AbortOnDrop(sync_task)),
        };

        // Lifecycle task. The syncer is owned by `_syncer` (aborted when the last
        // `ZebraChain` clone drops). This task exists to match the backend lifecycle
        // shape; it runs until aborted on shutdown.
        // TODO: signal syncer failure through this task once the syncer exposes it.
        let task = crate::spawn!("Zebra read-state syncer", async move {
            std::future::pending::<()>().await;
            Ok::<(), Error>(())
        });

        Ok((chain, task))
    }
}

/// Factory for the `zebra-state` chain backend.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ZebraBackend;

impl ChainFactory for ZebraBackend {
    type Chain = ZebraChain;

    async fn build(&self, config: &ZalletConfig) -> Result<(ZebraChain, TaskHandle), Error> {
        ZebraChain::new(config).await
    }
}

impl Chain for ZebraChain {
    type View = ZebraChainView<ReadStateChainReader>;

    fn params(&self) -> &Network {
        &self.params
    }

    async fn reported_upgrades(&self) -> Result<Vec<ReportedUpgrade>, Error> {
        // The backing zebrad is a separate process that may follow newer consensus rules
        // than this build of Zallet recognizes, so we ask it which upgrades it follows.
        let info = self.validator_rpc.get_blockchain_info().await?;

        info.upgrades
            .into_iter()
            .map(|(branch_id, upgrade)| {
                let branch_id = u32::from_str_radix(&branch_id, 16).map_err(|e| {
                    ErrorKind::Init
                        .context(format!("invalid consensus branch ID {branch_id:?}: {e}"))
                })?;
                Ok(ReportedUpgrade {
                    branch_id,
                    name: upgrade.name,
                    activation_height: upgrade.activation_height,
                    status: upgrade.status,
                })
            })
            .collect()
    }

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), ChainError> {
        let mut tx_bytes = vec![];
        tx.write(&mut tx_bytes).map_err(ChainError::backend)?;
        self.validator_rpc
            .send_raw_transaction(hex::encode(&tx_bytes))
            .await
            .map_err(ChainError::backend)?;
        Ok(())
    }

    async fn get_sapling_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<sapling::Node>>, ChainError> {
        self.reader().sapling_subtree_roots().await
    }

    async fn get_orchard_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError> {
        self.reader().orchard_subtree_roots().await
    }

    async fn snapshot(&self) -> Result<Self::View, ChainError> {
        let reader = self.reader();
        let tip = reader
            .tip()
            .await?
            .ok_or_else(|| ChainError::unavailable("the chain state has no tip yet"))?;
        let finalized_floor =
            BlockHeight::from_u32(u32::from(tip.height).saturating_sub(MAX_REORG_DEPTH));
        let mut cache = BTreeMap::new();
        cache.insert(tip.height, tip.hash);
        Ok(ZebraChainView {
            reader,
            validator_rpc: self.validator_rpc.clone(),
            params: self.params,
            tip,
            finalized_floor,
            cache: Arc::new(Mutex::new(cache)),
        })
    }
}

impl ZebraChain {
    fn reader(&self) -> ReadStateChainReader {
        ReadStateChainReader {
            read_state: self.read_state_service.clone(),
        }
    }
}

/// A pinned view of the chain as of a captured tip.
///
/// Reads in the finalized region (`height <= finalized_floor`) are served by height
/// directly (stable on disk); non-finalized reads are pinned to the captured tip's chain
/// by resolving each height to a hash (memoized in `cache`) and reading by that hash.
#[derive(Clone)]
pub(crate) struct ZebraChainView<R: ChainReader = ReadStateChainReader> {
    reader: R,
    validator_rpc: ValidatorRpcClient,
    params: Network,
    tip: ChainBlock,
    finalized_floor: BlockHeight,
    cache: Arc<Mutex<BTreeMap<BlockHeight, BlockHash>>>,
}

impl<R: ChainReader> ZebraChainView<R> {
    /// The pinned hash at `height` for this view, or `None` if above the captured tip.
    async fn resolve(&self, height: BlockHeight) -> Result<Option<BlockHash>, ChainError> {
        if height > self.tip.height {
            return Ok(None);
        }
        if height <= self.finalized_floor {
            // Finalized region: stable on disk, served by height.
            return self.reader.best_chain_block_hash(height).await;
        }
        // Fast path: already memoized.
        if let Some(h) = self.cache.lock().unwrap().get(&height).copied() {
            return Ok(Some(h));
        }
        // Walk down from the lowest cached entry at or above `height`, memoizing every step.
        let (mut cur_height, mut cur_hash) = {
            let cache = self.cache.lock().unwrap();
            cache
                .range(height..)
                .next()
                .map(|(h, hash)| (*h, *hash))
                .expect("the tip is always cached at or above any non-finalized height")
        };
        while cur_height > height {
            let header = self
                .reader
                .block_header_by_hash(cur_hash)
                .await?
                .ok_or_else(|| {
                    ChainError::unavailable("pinned block reorged away during resolve")
                })?;
            cur_hash = header.previous_block_hash;
            cur_height = BlockHeight::from_u32(u32::from(cur_height) - 1);
            self.cache.lock().unwrap().insert(cur_height, cur_hash);
        }
        Ok(Some(cur_hash))
    }

    fn stream_blocks_inner(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        let view = self.clone();
        futures::stream::try_unfold(start, move |height| {
            let view = view.clone();
            async move {
                if height > end {
                    return Ok(None);
                }
                match view.get_block(height).await? {
                    Some(block) => Ok(Some((block, height + 1))),
                    None => Ok(None),
                }
            }
        })
        .boxed()
    }
}

impl<R: ChainReader> ChainView for ZebraChainView<R> {
    async fn tip(&self) -> Result<ChainBlock, ChainError> {
        Ok(self.tip)
    }

    async fn find_fork_point(
        &self,
        locator: &BlockLocator,
    ) -> Result<Option<ChainBlock>, ChainError> {
        self.reader.find_fork_point(locator).await
    }

    async fn tree_state_as_of(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ChainState>, ChainError> {
        let Some(hash) = self.resolve(height).await? else {
            return Ok(None);
        };
        // For a finalized pinned hash, `None` tree bytes mean the pool was not yet active
        // at that height (empty tree). For a non-finalized pinned hash (best-chain-only
        // treestate lookups), `None` means the hash reorged off the best chain.
        let pinned_finalized = height <= self.finalized_floor;

        let final_sapling_tree = match self.reader.sapling_tree_bytes(hash).await? {
            Some(bytes) => {
                read_commitment_tree::<sapling::Node, _, { sapling::NOTE_COMMITMENT_TREE_DEPTH }>(
                    &bytes[..],
                )
                .map_err(ChainError::invalid_data)?
            }
            None if pinned_finalized => CommitmentTree::empty(),
            None => {
                return Err(ChainError::unavailable(
                    "pinned sapling treestate reorged away",
                ));
            }
        }
        .to_frontier();

        let final_orchard_tree = match self.reader.orchard_tree_bytes(hash).await? {
            Some(bytes) => read_commitment_tree::<
                orchard::tree::MerkleHashOrchard,
                _,
                { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
            >(&bytes[..])
            .map_err(ChainError::invalid_data)?,
            None if pinned_finalized => CommitmentTree::empty(),
            None => {
                return Err(ChainError::unavailable(
                    "pinned orchard treestate reorged away",
                ));
            }
        }
        .to_frontier();

        Ok(Some(ChainState::new(
            height,
            hash,
            final_sapling_tree,
            final_orchard_tree,
        )))
    }

    async fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>, ChainError> {
        let Some(hash) = self.resolve(height).await? else {
            return Ok(None);
        };
        let Some(bytes) = self.reader.raw_block_by_hash(hash).await? else {
            return Ok(None);
        };
        // The header is the prefix of the block serialization.
        Ok(Some(
            BlockHeader::read(&bytes[..]).map_err(ChainError::invalid_data)?,
        ))
    }

    async fn get_block(&self, height: BlockHeight) -> Result<Option<Block>, ChainError> {
        let Some(hash) = self.resolve(height).await? else {
            return Ok(None);
        };
        let Some(bytes) = self.reader.raw_block_by_hash(hash).await? else {
            return Ok(None);
        };
        Ok(Some(convert::block(&bytes, &self.params)?))
    }

    fn stream_blocks_to_tip(&self, start: BlockHeight) -> BoxStream<'_, Result<Block, ChainError>> {
        self.stream_blocks_inner(start, self.tip.height)
    }

    fn stream_blocks(
        &self,
        range: &Range<BlockHeight>,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        self.stream_blocks_inner(range.start, range.end - 1)
    }

    async fn get_mempool_stream(&self) -> Result<Option<BoxStream<'_, Transaction>>, ChainError> {
        // If the tip already moved past the captured view, signal "tip changed" (no stream).
        let current_tip = self.reader.tip().await?;
        if current_tip.map(|t| t.hash) != Some(self.tip.hash) {
            return Ok(None);
        }

        // Mempool transactions are parsed at the branch of the next block to be mined.
        let branch_id = BranchId::for_height(&self.params, self.tip.height + 1);

        struct State<R> {
            reader: R,
            rpc: ValidatorRpcClient,
            tip_hash: BlockHash,
            branch_id: BranchId,
            seen: HashSet<String>,
            pending: VecDeque<Transaction>,
            interval: tokio::time::Interval,
        }

        let state = State {
            reader: self.reader.clone(),
            rpc: self.validator_rpc.clone(),
            tip_hash: self.tip.hash,
            branch_id,
            seen: HashSet::new(),
            pending: VecDeque::new(),
            interval: tokio::time::interval(Duration::from_secs(1)),
        };

        let stream = futures::stream::unfold(state, |mut s| async move {
            loop {
                // Drain any transactions buffered from the last poll.
                if let Some(tx) = s.pending.pop_front() {
                    return Some((tx, s));
                }

                s.interval.tick().await;

                // End the stream when the chain tip changes (a new block or a reorg).
                match s.reader.tip().await {
                    Ok(Some(tip)) if tip.hash == s.tip_hash => {}
                    _ => return None,
                }

                // Poll the mempool and buffer newly-seen transactions.
                let txids = match s.rpc.get_raw_mempool().await {
                    Ok(txids) => txids,
                    Err(e) => {
                        warn!("error fetching mempool: {e}");
                        continue;
                    }
                };
                for txid in txids {
                    if !s.seen.insert(txid.clone()) {
                        continue;
                    }
                    let raw_hex = match s.rpc.get_raw_transaction(txid).await {
                        Ok(hex) => hex,
                        Err(e) => {
                            warn!("error fetching mempool transaction: {e}");
                            continue;
                        }
                    };
                    let bytes = match hex::decode(&raw_hex) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            warn!("invalid mempool transaction hex: {e}");
                            continue;
                        }
                    };
                    match Transaction::read(&bytes[..], s.branch_id) {
                        Ok(tx) => s.pending.push_back(tx),
                        Err(e) => warn!("invalid mempool transaction: {e}"),
                    }
                }
            }
        })
        .boxed();

        Ok(Some(stream))
    }

    async fn get_transaction(&self, txid: TxId) -> Result<Option<ChainTx>, ChainError> {
        let ztxid = convert::to_zebra_txid(txid);

        // Best chain (mined).
        if let Some(mined) = self.reader.transaction(ztxid).await? {
            let inner = convert::transaction(&mined.raw, &self.params, mined.height)?;
            return Ok(Some(ChainTx {
                inner,
                raw: mined.raw,
                block_hash: self.resolve(mined.height).await?,
                mined_height: Some(mined.height),
                block_time: Some(mined.block_time),
            }));
        }

        // Side (non-best) chain: parse at the mempool branch (recent, same network upgrade).
        let mempool_height = self.tip.height + 1;
        if let Some(side) = self.reader.side_chain_transaction(ztxid).await? {
            let inner = convert::transaction(&side.raw, &self.params, mempool_height)?;
            return Ok(Some(ChainTx {
                inner,
                raw: side.raw,
                block_hash: Some(side.block_hash),
                mined_height: None,
                block_time: None,
            }));
        }

        // Mempool.
        let mempool = self
            .validator_rpc
            .get_raw_mempool()
            .await
            .map_err(ChainError::backend)?;
        if mempool.iter().any(|t| *t == txid.to_string()) {
            let raw_hex = self
                .validator_rpc
                .get_raw_transaction(txid.to_string())
                .await
                .map_err(ChainError::backend)?;
            let raw = hex::decode(raw_hex).map_err(ChainError::invalid_data)?;
            let inner = convert::transaction(&raw, &self.params, mempool_height)?;
            return Ok(Some(ChainTx {
                inner,
                raw,
                block_hash: None,
                mined_height: None,
                block_time: None,
            }));
        }

        Ok(None)
    }

    async fn get_transaction_status(&self, txid: TxId) -> Result<TransactionStatus, ChainError> {
        let ztxid = convert::to_zebra_txid(txid);
        if let Some(mined) = self.reader.transaction(ztxid).await? {
            return Ok(TransactionStatus::Mined(mined.height));
        }
        if self.reader.side_chain_transaction(ztxid).await?.is_some() {
            return Ok(TransactionStatus::NotInMainChain);
        }
        let mempool = self
            .validator_rpc
            .get_raw_mempool()
            .await
            .map_err(ChainError::backend)?;
        if mempool.iter().any(|t| *t == txid.to_string()) {
            return Ok(TransactionStatus::NotInMainChain);
        }
        Ok(TransactionStatus::TxidNotRecognized)
    }

    #[cfg(feature = "spend-index")]
    async fn outpoint_spend_status(&self, outpoint: &OutPoint) -> Result<SpendStatus, ChainError> {
        let zoutpoint = convert::to_zebra_outpoint(outpoint);
        // Authoritative spentness from the UTXO set, independent of the (optional, lazily-built)
        // spend index.
        if self.reader.is_unspent(zoutpoint).await? {
            return Ok(SpendStatus::Unspent);
        }
        // Spent: resolve the spending transaction via the spend index. A missing entry means the
        // index has not caught up yet (ZcashFoundation/zebra#10806), so signal a retry rather
        // than treating the output as unspent.
        match self.reader.spending_transaction(zoutpoint).await? {
            Some(h) => Ok(SpendStatus::SpentBy(convert::from_zebra_tx_hash(h))),
            None => Ok(SpendStatus::SpentSpenderUnknown),
        }
    }

    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    async fn block_height(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, ChainError> {
        Ok(self
            .reader
            .block_header_by_hash(*hash)
            .await?
            .map(|info| info.height))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use zcash_client_backend::data_api::chain::CommitmentTreeRoot;
    use zcash_protocol::consensus::NetworkType;

    use super::reader::{ChainReader, HeaderInfo, MinedTxInfo, SideTxInfo};
    use super::*;

    /// Deterministic block hash for a height (`< 256`): `[height; 32]`.
    fn h(height: u32) -> BlockHash {
        BlockHash([height as u8; 32])
    }

    /// A mock linear chain: `block_header_by_hash([n; 32])` yields parent `[n-1; 32]`,
    /// and counts header lookups so tests can assert the resolve walk doesn't re-fetch
    /// cached ranges.
    #[derive(Clone)]
    struct MockChainReader {
        tip_height: u32,
        header_calls: Arc<AtomicU32>,
    }

    impl ChainReader for MockChainReader {
        async fn tip(&self) -> Result<Option<ChainBlock>, ChainError> {
            Ok(Some(ChainBlock {
                height: BlockHeight::from_u32(self.tip_height),
                hash: h(self.tip_height),
            }))
        }
        async fn best_chain_block_hash(
            &self,
            height: BlockHeight,
        ) -> Result<Option<BlockHash>, ChainError> {
            Ok(Some(h(u32::from(height))))
        }
        async fn raw_block_by_hash(&self, _hash: BlockHash) -> Result<Option<Vec<u8>>, ChainError> {
            Ok(None)
        }
        async fn block_header_by_hash(
            &self,
            hash: BlockHash,
        ) -> Result<Option<HeaderInfo>, ChainError> {
            self.header_calls.fetch_add(1, Ordering::SeqCst);
            let height = u32::from(hash.0[0]);
            Ok(Some(HeaderInfo {
                height: BlockHeight::from_u32(height),
                previous_block_hash: h(height.saturating_sub(1)),
            }))
        }
        async fn sapling_tree_bytes(&self, _: BlockHash) -> Result<Option<Vec<u8>>, ChainError> {
            Ok(None)
        }
        async fn orchard_tree_bytes(&self, _: BlockHash) -> Result<Option<Vec<u8>>, ChainError> {
            Ok(None)
        }
        async fn find_fork_point(
            &self,
            _: &BlockLocator,
        ) -> Result<Option<ChainBlock>, ChainError> {
            Ok(None)
        }
        async fn transaction(
            &self,
            _: zebra_chain::transaction::Hash,
        ) -> Result<Option<MinedTxInfo>, ChainError> {
            Ok(None)
        }
        async fn side_chain_transaction(
            &self,
            _: zebra_chain::transaction::Hash,
        ) -> Result<Option<SideTxInfo>, ChainError> {
            Ok(None)
        }
        async fn sapling_subtree_roots(
            &self,
        ) -> Result<Vec<CommitmentTreeRoot<sapling::Node>>, ChainError> {
            Ok(vec![])
        }
        async fn orchard_subtree_roots(
            &self,
        ) -> Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError> {
            Ok(vec![])
        }
        #[cfg(feature = "spend-index")]
        async fn is_unspent(
            &self,
            _: zebra_chain::transparent::OutPoint,
        ) -> Result<bool, ChainError> {
            Ok(true)
        }
        #[cfg(feature = "spend-index")]
        async fn spending_transaction(
            &self,
            _: zebra_chain::transparent::OutPoint,
        ) -> Result<Option<zebra_chain::transaction::Hash>, ChainError> {
            Ok(None)
        }
    }

    fn test_view(
        tip_height: u32,
        floor: u32,
        calls: Arc<AtomicU32>,
    ) -> ZebraChainView<MockChainReader> {
        let tip = ChainBlock {
            height: BlockHeight::from_u32(tip_height),
            hash: h(tip_height),
        };
        let mut cache = BTreeMap::new();
        cache.insert(tip.height, tip.hash);
        ZebraChainView {
            reader: MockChainReader {
                tip_height,
                header_calls: calls,
            },
            validator_rpc: ValidatorRpcClient::new("127.0.0.1:1", "", "", None).unwrap(),
            params: Network::from_type(NetworkType::Main, &[]),
            tip,
            finalized_floor: BlockHeight::from_u32(floor),
            cache: Arc::new(Mutex::new(cache)),
        }
    }

    #[tokio::test]
    async fn resolve_walks_and_memoizes() {
        let calls = Arc::new(AtomicU32::new(0));
        let view = test_view(10, 2, calls.clone());

        // The tip is seeded in the cache: a hit, no header walk.
        assert_eq!(
            view.resolve(BlockHeight::from_u32(10)).await.unwrap(),
            Some(h(10))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        // Non-finalized walk from the tip down to 7: three header lookups.
        assert_eq!(
            view.resolve(BlockHeight::from_u32(7)).await.unwrap(),
            Some(h(7))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // Resolving 5 reuses the cached 7..=10; only two more lookups (7→6→5).
        assert_eq!(
            view.resolve(BlockHeight::from_u32(5)).await.unwrap(),
            Some(h(5))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 5);

        // Finalized region (<= floor) is served by height, with no header walk.
        assert_eq!(
            view.resolve(BlockHeight::from_u32(1)).await.unwrap(),
            Some(h(1))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 5);

        // Above the captured tip.
        assert_eq!(view.resolve(BlockHeight::from_u32(11)).await.unwrap(), None);
    }
}
