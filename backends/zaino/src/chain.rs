//! The Zaino-backed implementation of [`Chain`] and [`ChainView`].

use std::fmt;
use std::ops::Range;

use futures::{StreamExt, stream::BoxStream};
use incrementalmerkletree::frontier::CommitmentTree;
use jsonrpsee::tracing::{error, info, warn};
use tokio::net::lookup_host;
#[cfg(not(feature = "spend-index"))]
use transparent::address::TransparentAddress;
use zaino_common::{CacheConfig, DatabaseConfig, StorageConfig};
use zaino_fetch::jsonrpsee::connector::JsonRpSeeConnector;
use zaino_state::{
    ChainIndex as _, ChainIndexConfig, ChainIndexSnapshot, NodeBackedChainIndex,
    NodeBackedChainIndexSubscriber, StatusType,
    chain_index::{
        ShieldedPool,
        source::{State, ValidatorConnector},
        types::{BestChainLocation, NonBestChainLocation},
    },
};
use zcash_client_backend::data_api::{
    TransactionStatus,
    chain::{ChainState, CommitmentTreeRoot},
};
#[cfg(not(feature = "spend-index"))]
use zcash_keys::address::Address;
use zcash_primitives::{
    block::{Block, BlockHash, BlockHeader},
    merkle_tree::read_commitment_tree,
    transaction::Transaction,
};
use zcash_protocol::{
    TxId,
    consensus::{self, BlockHeight},
};
#[cfg(not(feature = "spend-index"))]
use zebra_rpc::client::{GetAddressBalanceRequest, GetAddressTxIdsRequest};
use zebra_rpc::methods::NetworkUpgradeStatus;

use zallet_core::{
    components::TaskHandle,
    config::ZalletConfig,
    error::{Error, ErrorKind},
    network::Network,
};

use zallet_core::components::chain::{
    BlockLocator, Chain, ChainBlock, ChainError, ChainFactory, ChainTx, ChainView, ReportedUpgrade,
    UpgradeStatus,
};
use zallet_zebra_read_state::{AbortOnDrop, init_read_state_service, network_to_zebra};

/// Classifies a block-fetch error, distinguishing transient reorg-window failures from
/// genuine backend errors.
///
/// Zebra returns RPC error -5 ("block height not in best chain") when a block is requested
/// by height but it no longer exists in the best chain — this happens during reorgs and is
/// transient. Returning `Unavailable` instead of `Backend` lets callers retry rather than
/// treating the error as fatal.
fn block_fetch_error(
    e: impl Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
) -> ChainError {
    let e: Box<dyn std::error::Error + Send + Sync + 'static> = e.into();
    if e.to_string().contains("block height not in best chain") {
        ChainError::Unavailable(e)
    } else {
        ChainError::Backend(e)
    }
}

/// Converts the wallet's network parameters into Zaino's network type.
fn network_to_zaino(network: Network) -> zaino_common::Network {
    use zcash_protocol::consensus;
    match network {
        Network::Consensus(network) => match network {
            consensus::Network::MainNetwork => zaino_common::Network::Mainnet,
            consensus::Network::TestNetwork => zaino_common::Network::Testnet,
        },
        // TODO: This does not create a compatible regtest network because Zebra does
        // not have the necessary flexibility.
        Network::RegTest(local_network) => {
            zaino_common::Network::Regtest(zaino_common::network::ActivationHeights {
                before_overwinter: Some(1),
                overwinter: local_network.overwinter.map(|h| h.into()),
                sapling: local_network.sapling.map(|h| h.into()),
                blossom: local_network.blossom.map(|h| h.into()),
                heartwood: local_network.heartwood.map(|h| h.into()),
                canopy: local_network.canopy.map(|h| h.into()),
                nu5: local_network.nu5.map(|h| h.into()),
                nu6: local_network.nu6.map(|h| h.into()),
                nu6_1: local_network.nu6_1.map(|h| h.into()),
                nu6_2: local_network.nu6_2.map(|h| h.into()),
                nu6_3: local_network.nu6_3.map(|h| h.into()),
                nu7: None,
            })
        }
    }
}

/// Converts a `zcash_protocol` block height into a Zaino block height.
fn to_zaino_height(height: BlockHeight) -> zaino_state::Height {
    u32::from(height)
        .try_into()
        .expect("we won't hit max height for a while")
}

/// The Zaino finalised-state database schema version to target.
///
/// `1` selects Zaino's latest v1 finalised-state schema. We run the indexer in ephemeral
/// mode (see [`ChainIndexConfig::new`] below), so no persistent finalised-state database
/// is actually opened and this value has no on-disk effect; it is set to the current
/// schema version for forward-compatibility if ephemeral mode is ever disabled.
const ZAINO_FINALISED_DB_VERSION: u32 = 1;

#[derive(Clone)]
pub struct ZainoChain {
    subscriber: NodeBackedChainIndexSubscriber,
    /// Used for submitting transactions to the network (`ChainIndex` is a read-only view
    /// of the chain).
    fetcher: JsonRpSeeConnector,
    params: Network,
}

impl fmt::Debug for ZainoChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZainoChain").finish_non_exhaustive()
    }
}

impl ZainoChain {
    pub async fn new(config: &ZalletConfig) -> Result<(Self, TaskHandle), Error> {
        let params = config.consensus.network();

        let resolved_validator_address = match config.indexer.validator_address.as_deref() {
            Some(addr_str) => match lookup_host(addr_str).await {
                Ok(mut addrs) => match addrs.next() {
                    Some(socket_addr) => {
                        info!(
                            "Resolved validator_address '{}' to {}",
                            addr_str, socket_addr
                        );
                        Ok(socket_addr)
                    }
                    None => {
                        error!(
                            "validator_address '{}' resolved to no IP addresses",
                            addr_str
                        );
                        Err(ErrorKind::Init.context(format!(
                            "validator_address '{addr_str}' resolved to no IP addresses"
                        )))
                    }
                },
                Err(e) => {
                    error!("Failed to resolve validator_address '{}': {}", addr_str, e);
                    Err(ErrorKind::Init.context(format!(
                        "Failed to resolve validator_address '{addr_str}': {e}"
                    )))
                }
            },
            None => {
                // Default to localhost and standard port based on network
                let default_port = match params {
                    Network::Consensus(consensus::Network::MainNetwork) => 8232, // Mainnet default RPC port for Zebra/zcashd
                    _ => 18232, // Testnet/Regtest default RPC port for Zebra/zcashd
                };
                let default_addr_str = format!("127.0.0.1:{default_port}");
                info!(
                    "validator_address not set, defaulting to {}",
                    default_addr_str
                );
                match default_addr_str.parse::<std::net::SocketAddr>() {
                    Ok(socket_addr) => Ok(socket_addr),
                    Err(e) => {
                        // This should ideally not happen with a hardcoded IP and port
                        error!(
                            "Failed to parse default validator_address '{}': {}",
                            default_addr_str, e
                        );
                        Err(ErrorKind::Init.context(format!(
                            "Failed to parse default validator_address '{default_addr_str}': {e}"
                        )))
                    }
                }
            }
        }?;

        let fetcher = JsonRpSeeConnector::new_from_config_parts(
            &resolved_validator_address.to_string(),
            config.indexer.validator_user.clone().unwrap_or_default(),
            config
                .indexer
                .validator_password
                .clone()
                .unwrap_or_default(),
            config.indexer.validator_cookie_path.clone(),
        )
        .await
        .map_err(|e| ErrorKind::Init.context(e))?;

        let indexer_config = ChainIndexConfig::new(
            StorageConfig {
                cache: CacheConfig::default(),
                database: DatabaseConfig {
                    path: config.indexer_db_path().to_path_buf(),
                    // Unused in ephemeral mode (no persistent finalised-state
                    // database is opened).
                    size: zaino_common::DatabaseSize(0),
                    // Unused in ephemeral mode (the finalised-state bulk-sync
                    // write path is never exercised); inherit Zaino's default.
                    ..Default::default()
                },
            },
            ZAINO_FINALISED_DB_VERSION,
            network_to_zaino(params),
            // Run the finalised state ephemerally: no persistent database, finalised
            // reads are served from the backing validator.
            true,
        );

        // Select the chain-data source. By default Zaino fetches all chain data over
        // JSON-RPC; if `[indexer.read_state_service]` is configured, it instead reads
        // finalized state directly from a co-located zebrad (read-only secondary) and
        // follows the non-finalized tip over zebrad's gRPC indexer interface.
        let (source, sync_handle) = match &config.indexer.read_state_service {
            None => (ValidatorConnector::Fetch(fetcher.clone()), None),
            Some(rss) => {
                let (read_state_service, sync_task) = {
                    use zcash_protocol::consensus::Parameters as _;
                    let zebra_network = network_to_zebra(params.network_type())
                        .map_err(|e| ErrorKind::Init.context(e))?;
                    init_read_state_service(
                        &zebra_network,
                        &rss.grpc_address,
                        config.resolve_datadir_path(&rss.zebra_state_path),
                    )
                    .await
                    .map_err(|e| ErrorKind::Init.context(e))?
                };
                let source = ValidatorConnector::State(State {
                    read_state_service,
                    mempool_fetcher: fetcher.clone(),
                    network: network_to_zaino(params),
                });
                (source, Some(AbortOnDrop::new(sync_task)))
            }
        };

        info!("Starting Zaino indexer");
        let indexer = NodeBackedChainIndex::new(source, indexer_config)
            .await
            .map_err(|e| ErrorKind::Init.context(e))?;
        info!("Started Zaino indexer");

        let chain = Self {
            subscriber: indexer.subscriber(),
            fetcher,
            params,
        };

        // Spawn a task that stops the indexer when appropriate internal signals occur.
        let task = zallet_core::spawn!("Indexer shutdown", async move {
            // Hold the read-state syncer for the lifetime of this task. Dropping the guard
            // aborts the syncer on every shutdown path, including when this task is itself
            // aborted externally, so the syncer never outlives the indexer.
            let _sync_handle = sync_handle;

            let mut server_interval =
                tokio::time::interval(tokio::time::Duration::from_millis(100));

            loop {
                server_interval.tick().await;

                match indexer.status() {
                    // Check for errors.
                    StatusType::Offline | StatusType::CriticalError => {
                        indexer
                            .shutdown()
                            .await
                            .map_err(|e| ErrorKind::Generic.context(e))?;
                        return Err(ErrorKind::Generic.into());
                    }

                    // Check for shutdown signals.
                    StatusType::Closing => return Ok(()),

                    _ => (),
                }
            }
        });

        Ok((chain, task))
    }
}

/// The single place the Zaino connector’s status enum is mapped onto the backend-neutral
/// [`UpgradeStatus`]. The `zebra` backend deserializes into `UpgradeStatus` directly, so this
/// is the only status conversion in the tree.
///
/// A plain function rather than a `From` impl: both types are foreign to this crate, so
/// the orphan rule forbids the impl.
fn upgrade_status(status: NetworkUpgradeStatus) -> UpgradeStatus {
    match status {
        NetworkUpgradeStatus::Active => UpgradeStatus::Active,
        NetworkUpgradeStatus::Pending => UpgradeStatus::Pending,
        NetworkUpgradeStatus::Disabled => UpgradeStatus::Disabled,
    }
}

/// Factory for the `zaino` chain backend.
#[derive(Clone, Copy, Debug)]
pub struct ZainoBackend;

impl ChainFactory for ZainoBackend {
    type Chain = ZainoChain;

    const NAME: &'static str = "zaino";

    async fn build(&self, config: &ZalletConfig) -> Result<(ZainoChain, TaskHandle), Error> {
        ZainoChain::new(config).await
    }
}

impl Chain for ZainoChain {
    type View = ZainoChainView;

    fn params(&self) -> &Network {
        &self.params
    }

    async fn reported_upgrades(&self) -> Result<Vec<ReportedUpgrade>, Error> {
        let info = self
            .fetcher
            .get_blockchain_info()
            .await
            .map_err(|e| ErrorKind::Init.context(e))?;

        Ok(info
            .upgrades
            .iter()
            .map(|(branch, info)| {
                let (name, activation_height, status) = (*info).into_parts();
                ReportedUpgrade::new(
                    branch.inner(),
                    name.to_string(),
                    activation_height.0,
                    upgrade_status(status),
                )
            })
            .collect())
    }

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<(), ChainError> {
        let mut tx_bytes = vec![];
        tx.write(&mut tx_bytes).map_err(ChainError::backend)?;

        self.fetcher
            .send_raw_transaction(hex::encode(&tx_bytes))
            .await
            .map_err(ChainError::backend)?;

        Ok(())
    }

    async fn get_sapling_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<sapling::Node>>, ChainError> {
        self.subscriber
            .get_subtree_roots(ShieldedPool::Sapling, 0, None)
            .await
            .map_err(ChainError::backend)?
            .into_iter()
            .map(|(root_hash, end_height)| {
                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(end_height),
                    sapling::Node::from_bytes(root_hash)
                        .expect("zaino should provide canonical encodings"),
                ))
            })
            .collect::<Result<Vec<_>, ChainError>>()
    }

    async fn get_orchard_subtree_roots(
        &self,
    ) -> Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError> {
        self.subscriber
            .get_subtree_roots(ShieldedPool::Orchard, 0, None)
            .await
            .map_err(ChainError::backend)?
            .into_iter()
            .map(|(root_hash, end_height)| {
                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(end_height),
                    orchard::tree::MerkleHashOrchard::from_bytes(&root_hash)
                        .expect("zaino should provide canonical encodings"),
                ))
            })
            .collect::<Result<Vec<_>, ChainError>>()
    }

    async fn snapshot(&self) -> Result<ZainoChainView, ChainError> {
        let snapshot = self
            .subscriber
            .snapshot_nonfinalized_state()
            .await
            .map_err(ChainError::backend)?;

        Ok(ZainoChainView {
            chain: self.subscriber.clone(),
            snapshot,
            params: self.params,
        })
    }
}

/// A stable view of the chain as of a particular chain tip.
///
/// The data viewable through an instance of `ZainoChainView` is guaranteed to be available
/// as long as (any clone of) the instance is live, regardless of what new blocks or
/// reorgs are observed by the underlying chain indexer.
#[derive(Clone)]
pub struct ZainoChainView {
    chain: NodeBackedChainIndexSubscriber,
    snapshot: ChainIndexSnapshot,
    params: Network,
}

impl ChainView for ZainoChainView {
    async fn tip(&self) -> Result<ChainBlock, ChainError> {
        let best_tip = self
            .chain
            .best_chaintip(&self.snapshot)
            .await
            .map_err(ChainError::backend)?;

        Ok(chain_block_from_zaino((best_tip.hash, best_tip.height)))
    }

    async fn find_fork_point(
        &self,
        locator: &BlockLocator,
    ) -> Result<Option<ChainBlock>, ChainError> {
        for known_tip in locator.hashes() {
            if let Some(fork) = self
                .chain
                .find_fork_point(&self.snapshot, &zaino_state::BlockHash(known_tip.0))
                .await
                .map_err(ChainError::backend)?
            {
                return Ok(Some(chain_block_from_zaino(fork)));
            }
        }
        Ok(None)
    }

    async fn tree_state_as_of(
        &self,
        height: BlockHeight,
    ) -> Result<Option<ChainState>, ChainError> {
        let block_hash = self
            .chain
            .get_block_hash(&self.snapshot, to_zaino_height(height))
            .await
            .map_err(ChainError::backend)?;

        let chain_state = if let Some(hash) = block_hash {
            let (sapling_treestate, orchard_treestate) = self
                .chain
                .get_treestate(&hash)
                .await
                .map_err(ChainError::backend)?;

            let final_sapling_tree = match sapling_treestate {
                None => CommitmentTree::empty(),
                Some(sapling_tree_bytes) => read_commitment_tree::<
                    sapling::Node,
                    _,
                    { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                >(&sapling_tree_bytes[..])
                .map_err(ChainError::backend)?,
            }
            .to_frontier();

            let final_orchard_tree = match orchard_treestate {
                None => CommitmentTree::empty(),
                Some(orchard_tree_bytes) => read_commitment_tree::<
                    orchard::tree::MerkleHashOrchard,
                    _,
                    { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
                >(&orchard_tree_bytes[..])
                .map_err(ChainError::backend)?,
            }
            .to_frontier();

            // Zaino's treestate lookup exposes no separate Ironwood note commitment tree,
            // and Ironwood (NU6.3) is not active on any chain Zallet syncs today, so its
            // final tree is always empty here. When an Ironwood treestate is surfaced, read
            // it like the Orchard tree above; Ironwood shares the Orchard tree's shape.
            let final_ironwood_tree = CommitmentTree::<
                orchard::tree::MerkleHashOrchard,
                { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
            >::empty()
            .to_frontier();

            Some(ChainState::new(
                height,
                BlockHash(hash.0),
                final_sapling_tree,
                final_orchard_tree,
                final_ironwood_tree,
            ))
        } else {
            None
        };

        Ok(chain_state)
    }

    async fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<BlockHeader>, ChainError> {
        self.get_block_inner(height, |block_bytes| {
            // Read the header, ignore the transactions.
            BlockHeader::read(block_bytes.as_slice()).map_err(ChainError::backend)
        })
        .await
    }

    async fn get_block(&self, height: BlockHeight) -> Result<Option<Block>, ChainError> {
        self.get_block_inner(height, |block_bytes| {
            Block::read(block_bytes.as_slice(), &self.params).map_err(ChainError::backend)
        })
        .await
    }

    fn stream_blocks_to_tip(&self, start: BlockHeight) -> BoxStream<'_, Result<Block, ChainError>> {
        self.stream_blocks_inner(start, None)
    }

    fn stream_blocks(
        &self,
        range: &Range<BlockHeight>,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        self.stream_blocks_inner(range.start, Some(range.end - 1))
    }

    async fn get_mempool_stream(&self) -> Result<Option<BoxStream<'_, Transaction>>, ChainError> {
        let mempool_height = self.tip().await?.height() + 1;
        let consensus_branch_id = consensus::BranchId::for_height(&self.params, mempool_height);

        Ok(self
            .chain
            .get_mempool_stream(Some(&self.snapshot))
            .map(move |stream| {
                stream
                    .filter_map(move |result| async move {
                        result
                            .inspect_err(|e| warn!("Error receiving transaction: {e}"))
                            .ok()
                            .and_then(|raw_tx| {
                                Transaction::read(raw_tx.as_slice(), consensus_branch_id)
                                    .inspect_err(|e| {
                                        warn!("Received invalid transaction from mempool: {e}");
                                    })
                                    .ok()
                            })
                    })
                    .boxed()
            }))
    }

    async fn get_transaction(&self, txid: TxId) -> Result<Option<ChainTx>, ChainError> {
        let zaino_txid = zaino_state::TransactionHash::from(*txid.as_ref());

        let (inner, raw) = match self
            .chain
            .get_raw_transaction(&self.snapshot, &zaino_txid)
            .await
            .map_err(ChainError::backend)?
        {
            None => return Ok(None),
            Some((raw_tx, branch_id)) => {
                let consensus_branch_id = match branch_id {
                    // If `try_from` fails, it indicates a dependency versioning problem.
                    Some(id) => consensus::BranchId::try_from(id).map_err(ChainError::backend)?,
                    // Zaino could not determine the consensus branch ID. This happens for
                    // mempool transactions (when the snapshot's mempool height is unknown)
                    // and for pre-Overwinter transactions (which predate consensus branch
                    // IDs). A transaction cannot be mined across a network upgrade
                    // boundary, and an unmined transaction must be minable at the current
                    // chain tip, so the branch ID at the mempool height (tip + 1) is the
                    // correct parsing target. This matches the fallback used by
                    // `get_mempool_stream`.
                    None => {
                        let mempool_height = self.tip().await?.height() + 1;
                        consensus::BranchId::for_height(&self.params, mempool_height)
                    }
                };

                let tx = Transaction::read(raw_tx.as_slice(), consensus_branch_id)
                    .map_err(ChainError::backend)?;

                (tx, raw_tx)
            }
        };

        let (block_hash, mined_height, in_best_chain) = match self
            .chain
            .get_transaction_status(&self.snapshot, &zaino_txid)
            .await
            .map_err(ChainError::backend)?
        {
            (Some(BestChainLocation::Block(hash, height)), _) => (
                Some(BlockHash(hash.0)),
                Some(BlockHeight::from_u32(height.into())),
                true,
            ),
            (Some(BestChainLocation::Mempool(_)), _) => (None, None, false),
            (None, orphans) => match orphans.into_iter().next() {
                Some(NonBestChainLocation::Block(hash, height)) => (
                    Some(BlockHash(hash.0)),
                    Some(BlockHeight::from_u32(height.into())),
                    false,
                ),
                Some(NonBestChainLocation::Mempool(_)) | None => (None, None, false),
            },
        };

        // Only populate the block time for transactions mined into the main chain. The
        // time of an orphaned block is misleading (the transaction is not in the main
        // chain) and can differ from the canonical block at the same height.
        let block_time = match (in_best_chain, mined_height) {
            (true, Some(height)) => self
                .get_block_header(height)
                .await?
                .map(|header| header.time),
            _ => None,
        };

        Ok(Some(ChainTx::new(
            inner,
            raw,
            block_hash,
            mined_height,
            block_time,
        )))
    }

    async fn get_transaction_status(&self, txid: TxId) -> Result<TransactionStatus, ChainError> {
        let zaino_txid = zaino_state::TransactionHash::from(*txid.as_ref());

        let status = self
            .chain
            .get_transaction_status(&self.snapshot, &zaino_txid)
            .await
            .map_err(ChainError::backend)?;

        Ok(match status {
            (Some(BestChainLocation::Block(_, height)), _) => {
                TransactionStatus::Mined(BlockHeight::from_u32(height.into()))
            }
            (Some(BestChainLocation::Mempool(_)), _) => TransactionStatus::NotInMainChain,
            (None, orphans) if orphans.is_empty() => TransactionStatus::TxidNotRecognized,
            (None, _) => TransactionStatus::NotInMainChain,
        })
    }

    #[cfg(not(feature = "spend-index"))]
    async fn get_address_unspent_outpoints(
        &self,
        address: &TransparentAddress,
    ) -> Result<Vec<(TxId, u32)>, ChainError> {
        let addr_str = Address::Transparent(*address).encode(&self.params);
        let utxos = self
            .chain
            .get_address_utxos(GetAddressBalanceRequest::new(vec![addr_str]))
            .await
            .map_err(ChainError::backend)?;
        Ok(utxos
            .into_iter()
            .map(|utxo| (TxId::from_bytes(utxo.txid().0), utxo.output_index().index()))
            .collect())
    }

    #[cfg(not(feature = "spend-index"))]
    async fn get_address_tx_ids(
        &self,
        address: &TransparentAddress,
        range: Range<BlockHeight>,
    ) -> Result<Vec<TxId>, ChainError> {
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let addr_str = Address::Transparent(*address).encode(&self.params);
        let start = u32::from(range.start);
        // `range` is non-empty, so `range.end >= start + 1 >= 1`.
        let end_inclusive = u32::from(range.end) - 1;
        let hashes = self
            .chain
            .get_address_txids(GetAddressTxIdsRequest::new(
                vec![addr_str],
                Some(start),
                Some(end_inclusive),
            ))
            .await
            .map_err(ChainError::backend)?;
        Ok(hashes
            .into_iter()
            .map(|hash| TxId::from_bytes(hash.0))
            .collect())
    }

    /// Returns the height of the given block, if it is in the main chain within this
    /// chain view.
    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    async fn block_height(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, ChainError> {
        Ok(self
            .chain
            .get_block_height(&self.snapshot, zaino_state::BlockHash(hash.0))
            .await
            .map_err(ChainError::backend)?
            .map(|height| BlockHeight::from_u32(height.into())))
    }
}

impl ZainoChainView {
    async fn get_block_inner<T>(
        &self,
        height: BlockHeight,
        f: impl FnOnce(Vec<u8>) -> Result<T, ChainError>,
    ) -> Result<Option<T>, ChainError> {
        let height = to_zaino_height(height);
        // TODO: Should return `impl futures::TryStream` if it is to be fallible.
        if let Some(stream) = self
            .chain
            .get_block_range(&self.snapshot, height, Some(height))
        {
            tokio::pin!(stream);
            let block_bytes = match stream.next().await {
                None => return Ok(None),
                Some(ret) => ret.map_err(block_fetch_error),
            }?;

            f(block_bytes).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Produces a contiguous stream of blocks from `start` to `end` inclusive.
    fn stream_blocks_inner(
        &self,
        start: BlockHeight,
        end: Option<BlockHeight>,
    ) -> BoxStream<'_, Result<Block, ChainError>> {
        // TODO: Should return `impl futures::TryStream` if it is to be fallible.
        if let Some(stream) = self.chain.get_block_range(
            &self.snapshot,
            to_zaino_height(start),
            end.map(to_zaino_height),
        ) {
            stream
                .map(|res| {
                    res.map_err(block_fetch_error).and_then(|block_bytes| {
                        Block::read(block_bytes.as_slice(), &self.params)
                            .map_err(ChainError::invalid_data)
                    })
                })
                .boxed()
        } else {
            futures::stream::empty().boxed()
        }
    }
}

/// Builds a [`ChainBlock`] from Zaino's (hash, height) pair.
fn chain_block_from_zaino(
    (hash, height): (zaino_state::BlockHash, zaino_state::Height),
) -> ChainBlock {
    ChainBlock::new(BlockHeight::from_u32(height.into()), BlockHash(hash.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_not_in_best_chain_is_unavailable() {
        // The exact message zebra returns (embedded inside a tonic Status message).
        let e = "unexpected error response from server: RPC Error (code: -5): block height not in best chain";
        assert!(
            matches!(block_fetch_error(e), ChainError::Unavailable(_)),
            "expected Unavailable for the reorg-window -5 error"
        );
    }

    #[test]
    fn unrelated_backend_errors_remain_fatal() {
        for msg in ["connection refused", "timed out", "internal server error"] {
            assert!(
                matches!(block_fetch_error(msg), ChainError::Backend(_)),
                "expected Backend for '{msg}'"
            );
        }
    }
}
