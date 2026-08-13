//! The wallet's view of the Zcash chain.
//!
//! [`Chain`] and [`ChainView`] are the backend-neutral interface the rest of the wallet
//! uses to read chain data. The backend implementations live in the `zaino` and `zebra`
//! modules, selected by cargo feature.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;
use std::ops::Range;

use futures::{future::BoxFuture, stream::BoxStream};
use nonempty::NonEmpty;
use serde::Deserialize;
use tracing::{error, info, warn};
#[cfg(not(feature = "spend-index"))]
use transparent::address::TransparentAddress;
#[cfg(feature = "spend-index")]
use transparent::bundle::OutPoint;
use zcash_client_backend::data_api::{
    TransactionStatus,
    chain::{ChainState, CommitmentTreeRoot},
};
use zcash_primitives::{
    block::{Block, BlockHash, BlockHeader},
    transaction::Transaction,
};
use zcash_protocol::{
    TxId,
    consensus::{self, BlockHeight},
};

use crate::error::{Error, ErrorKind};
use crate::fl;
use crate::network::{NETWORK_UPGRADES, Network};

use crate::{components::TaskHandle, config::ZalletConfig};

mod error;
pub use error::ChainError;

/// A capability for constructing the process's chain backend.
///
/// Implemented by a unit struct in each backend module. The selected factory is
/// registered at boot and consumed through a dyn-safe runtime boundary;
/// everything downstream of construction is statically dispatched over [`Chain`].
pub trait ChainFactory: Send + Sync + 'static {
    /// The concrete chain backend this factory constructs.
    type Chain: Chain;

    /// Which backend this factory provides, as named by the config file's top-level
    /// `backend` key.
    ///
    /// Must be a valid backend name (nonempty, lowercase alphanumeric plus hyphens),
    /// and by convention matches the `zallet-<NAME>` binary that ships the backend.
    const NAME: &'static str;

    /// Connects to and structurally admits the chain-data source described by `config`,
    /// returning the backend handle and the task driving its indexer.
    ///
    /// `Ok` guarantees that backend-specific discovery has found every service and
    /// capability required to implement this binary's complete [`Chain`] contract.
    /// Factories must reject a partially usable composition with an initialization error.
    /// This admission guarantee covers the composed service shape, not perpetual runtime
    /// availability; individual chain operations can still fail. Consensus compatibility
    /// is checked separately after construction.
    fn build(
        &self,
        config: &ZalletConfig,
    ) -> impl Future<Output = Result<(Self::Chain, TaskHandle), Error>> + Send;
}

/// The dyn-safe boundary through which commands reach the registered chain backend.
///
/// The blanket impl over [`ChainFactory`] encloses the whole chain-dependent tail of
/// each command, so the concrete [`Chain`] type never crosses this boundary — type
/// erasure costs one virtual call per command invocation.
pub trait ChainRuntime: Send + Sync {
    /// Which backend this runtime provides, as named by the config file's top-level
    /// `backend` key.
    fn backend_name(&self) -> &'static str;

    /// Runs the chain-dependent body of `zallet start`.
    fn run_start(&self) -> BoxFuture<'_, Result<(), Error>>;

    /// Runs the chain-dependent body of `zallet migrate-zcashd-wallet`.
    ///
    /// The command type is crate-private on purpose: this method exists for the
    /// command layer inside this crate, and backend crates only ever *implement* it
    /// (via the blanket impl), never call it.
    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    #[allow(private_interfaces)]
    fn run_migrate_zcashd_wallet<'a>(
        &'a self,
        cmd: &'a crate::cli::MigrateZcashdWalletCmd,
    ) -> BoxFuture<'a, Result<(), Error>>;

    /// Runs the chain-dependent body of `zallet import-address`.
    ///
    /// The command type is crate-private for the same reason as
    /// [`Self::run_migrate_zcashd_wallet`]'s.
    #[cfg(all(zallet_build = "wallet", feature = "transparent-key-import"))]
    #[allow(private_interfaces)]
    fn run_import_address<'a>(
        &'a self,
        cmd: &'a crate::cli::ImportAddressCmd,
    ) -> BoxFuture<'a, Result<(), Error>>;
}

impl<F: ChainFactory> ChainRuntime for F {
    fn backend_name(&self) -> &'static str {
        F::NAME
    }

    fn run_start(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(crate::cli::StartCmd::run_with(self))
    }

    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    #[allow(private_interfaces)]
    fn run_migrate_zcashd_wallet<'a>(
        &'a self,
        cmd: &'a crate::cli::MigrateZcashdWalletCmd,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(cmd.run_with(self))
    }

    #[cfg(all(zallet_build = "wallet", feature = "transparent-key-import"))]
    #[allow(private_interfaces)]
    fn run_import_address<'a>(
        &'a self,
        cmd: &'a crate::cli::ImportAddressCmd,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(cmd.run_with(self))
    }
}

/// A handle to a source of Zcash chain data.
///
/// Cheap to clone; clones share the underlying source.
pub trait Chain: Clone + Send + Sync + 'static {
    /// A consistent, reorg-immune view of the chain captured by [`Chain::snapshot`].
    type View: ChainView;

    /// The network this backend follows, used to look up the activation heights this
    /// build of Zallet expects when checking consensus compatibility.
    fn params(&self) -> &Network;

    /// The network upgrades the backing full node reports, in backend-neutral form.
    ///
    /// Consumed by `check_consensus_compatibility` to confirm the node’s consensus
    /// rules are compatible with this build of Zallet.
    fn reported_upgrades(&self)
    -> impl Future<Output = Result<Vec<ReportedUpgrade>, Error>> + Send;

    /// Broadcasts a transaction to the network's mempool.
    fn broadcast_transaction(
        &self,
        tx: &Transaction,
    ) -> impl Future<Output = Result<(), ChainError>> + Send;

    /// Returns the Sapling note commitment subtree roots, in index order.
    fn get_sapling_subtree_roots(
        &self,
    ) -> impl Future<Output = Result<Vec<CommitmentTreeRoot<sapling::Node>>, ChainError>> + Send;

    /// Returns the Orchard note commitment subtree roots, in index order.
    fn get_orchard_subtree_roots(
        &self,
    ) -> impl Future<
        Output = Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError>,
    > + Send;

    /// Returns the Ironwood note commitment subtree roots, in index order.
    ///
    /// Ironwood (NU6.3) shares the Orchard commitment tree's node type. These roots are
    /// required for received Ironwood notes to become spendable: without them the
    /// Ironwood tree never stabilizes and notes stay pending.
    fn get_ironwood_subtree_roots(
        &self,
    ) -> impl Future<
        Output = Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError>,
    > + Send;

    /// Captures a consistent view of the chain as of the current tip.
    ///
    /// Every read through the returned [`ChainView`] reflects one fixed chain history for
    /// the lifetime of the view, regardless of reorgs or new blocks observed afterward.
    fn snapshot(&self) -> impl Future<Output = Result<Self::View, ChainError>> + Send;
}

/// The status of a network upgrade as reported by a backing full node.
///
/// This is the single neutral representation both backends produce. The `zebra` backend
/// deserializes the node’s `getblockchaininfo` status string directly into it; the `zaino`
/// backend converts its connector’s status enum via [`From`]. The `Deserialize` encoding is
/// the lowercase status string the node reports (`"active"`, `"pending"`, `"disabled"`).
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpgradeStatus {
    /// The upgrade has activated on the node’s chain.
    Active,
    /// The upgrade is scheduled but has not yet activated.
    Pending,
    /// The upgrade has no activation height on the node’s network.
    Disabled,
}

/// A network upgrade reported by a backing full node, in a backend-neutral form.
///
/// Each [`Chain`] backend converts its own representation into this so that the
/// consensus-compatibility check (`check_consensus_compatibility`) is backend-neutral.
#[derive(Clone)]
pub struct ReportedUpgrade {
    branch_id: u32,
    name: String,
    activation_height: u32,
    status: UpgradeStatus,
}

impl ReportedUpgrade {
    /// Records a network upgrade as reported by the backing full node.
    ///
    /// The `activation_height` is ignored when `status` is [`UpgradeStatus::Disabled`],
    /// since a disabled upgrade never activates.
    pub fn new(
        branch_id: u32,
        name: String,
        activation_height: u32,
        status: UpgradeStatus,
    ) -> Self {
        Self {
            branch_id,
            name,
            activation_height,
            status,
        }
    }

    /// The consensus branch ID the node reports for this upgrade.
    pub fn branch_id(&self) -> u32 {
        self.branch_id
    }

    /// The node’s name for the upgrade, used for diagnostics only.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The activation height the node reports.
    pub fn activation_height(&self) -> u32 {
        self.activation_height
    }

    /// Whether the node treats the upgrade as active, pending, or disabled.
    pub fn status(&self) -> UpgradeStatus {
        self.status
    }
}

/// A way in which the backing full node’s consensus rules are incompatible with this
/// build of Zallet, such that Zallet could not maintain a correct view of the chain.
enum Incompatibility {
    /// The full node follows a network upgrade whose consensus branch ID this build of
    /// Zallet does not recognize, and so cannot interpret.
    UnknownUpgrade {
        /// The consensus branch ID reported by the full node.
        branch_id: u32,
        /// The full node’s name for the upgrade, used for diagnostics only.
        name: String,
        /// The height at which the full node activates this upgrade — the point past which
        /// this build can no longer interpret the chain.
        activation_height: u32,
    },
    /// The full node and this build of Zallet both recognize the upgrade’s consensus
    /// branch ID, but disagree about the height at which it activates, and so about
    /// where its consensus rules take effect.
    ActivationHeightMismatch {
        /// The recognized consensus branch ID.
        branch_id: u32,
        /// The full node’s name for the upgrade, used for diagnostics only.
        name: String,
        /// The activation height this build of Zallet expects, or `None` if it treats
        /// the upgrade as not scheduled on this network.
        expected: Option<u32>,
        /// The activation height the full node reports, or `None` if the full node
        /// treats the upgrade as disabled on this network.
        node: Option<u32>,
        /// The height at which the two sides’ rules first diverge: the earlier of `expected`
        /// and `node`.
        divergence_height: u32,
    },
}

impl Incompatibility {
    /// The height at or after which this build’s interpretation of the chain could diverge
    /// from the full node’s. The wallet can operate correctly below this height.
    fn divergence_height(&self) -> u32 {
        match self {
            Self::UnknownUpgrade {
                activation_height, ..
            } => *activation_height,
            Self::ActivationHeightMismatch {
                divergence_height, ..
            } => *divergence_height,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::UnknownUpgrade {
                branch_id,
                name,
                activation_height,
            } => format!(
                "{name} (branch ID {branch_id:08x}, unrecognized, activates at height {activation_height})"
            ),
            Self::ActivationHeightMismatch {
                branch_id,
                name,
                expected,
                node,
                ..
            } => {
                let side = |height: &Option<u32>| match height {
                    Some(height) => format!("activates it at height {height}"),
                    None => "does not schedule it".to_string(),
                };
                format!(
                    "{name} (branch ID {branch_id:08x}): full node {}, but this Zallet build {}",
                    side(node),
                    side(expected),
                )
            }
        }
    }
}

/// Identifies the ways in which the consensus rules of the backing full node and this build
/// of Zallet are incompatible on `params`’s network.
///
/// Every consensus branch ID either side knows about is examined once: the union of the
/// upgrades the node reports and the upgrades this build schedules ([`NETWORK_UPGRADES`]).
/// For each, [`branch_incompatibility`] compares the node’s activation height against this
/// build’s. An upgrade neither side schedules never takes effect, so it is not flagged;
/// otherwise the sides diverge when they disagree about where — or whether — it activates.
fn detect_incompatibilities<P: consensus::Parameters>(
    params: &P,
    upgrades: &[ReportedUpgrade],
) -> Vec<Incompatibility> {
    // Index the node’s reported upgrades by consensus branch ID.
    let reported: HashMap<u32, &ReportedUpgrade> =
        upgrades.iter().map(|u| (u.branch_id, u)).collect();

    // Examine every branch ID either side knows about. Collecting into a `BTreeSet` dedups
    // the overlap (an upgrade both sides know) and gives a deterministic order.
    let ours = NETWORK_UPGRADES.iter().map(|branch| u32::from(*branch));
    reported
        .keys()
        .copied()
        .chain(ours)
        .collect::<BTreeSet<u32>>()
        .into_iter()
        .filter_map(|branch_id| {
            branch_incompatibility(params, branch_id, reported.get(&branch_id).copied())
        })
        .collect()
}

/// Compares one consensus branch ID between the node — which reports it as `reported`, or not
/// at all (`None`) — and this build, yielding an [`Incompatibility`] if their rules diverge.
///
/// An upgrade with no activation height on a side is treated as not scheduled there:
/// [`UpgradeStatus::Disabled`] (or simply unreported) on the node, or a `None` from
/// [`consensus::BranchId::height_bounds`] on our side.
fn branch_incompatibility<P: consensus::Parameters>(
    params: &P,
    branch_id: u32,
    reported: Option<&ReportedUpgrade>,
) -> Option<Incompatibility> {
    // The height at which the full node switches to this upgrade’s consensus rules, or `None`
    // if it does not schedule the upgrade (disabled, or not reported at all).
    let node = reported.and_then(|upgrade| match upgrade.status {
        UpgradeStatus::Disabled => None,
        UpgradeStatus::Active | UpgradeStatus::Pending => Some(upgrade.activation_height),
    });

    match consensus::BranchId::try_from(branch_id) {
        // We recognize this branch ID, so we know which consensus rules it selects. Verify
        // that we also agree on where they take effect.
        Ok(branch) => {
            let expected = branch
                .height_bounds(params)
                .map(|(activation, _)| u32::from(activation));
            // Divergence begins at the earlier of the two scheduled heights.
            match (expected, node) {
                (Some(expected), Some(node)) if expected == node => None,
                (Some(expected), Some(node)) => Some(expected.min(node)),
                (Some(height), None) => Some(height),
                (None, mheight) => mheight,
            }
            .map(
                |divergence_height| Incompatibility::ActivationHeightMismatch {
                    branch_id,
                    // The node’s name for the upgrade if it reported one, else our own.
                    name: reported.map_or_else(|| format!("{branch:?}"), |u| u.name.clone()),
                    expected,
                    node,
                    divergence_height,
                },
            )
        }
        // We cannot interpret this branch ID at all. Flag it unless the node leaves it
        // disabled/unreported, in which case it never takes effect here. (An unrecognized
        // branch is never one this build schedules, so the node always named it.)
        Err(_) => node.map(|activation_height| Incompatibility::UnknownUpgrade {
            branch_id,
            name: reported.map_or_else(String::new, |u| u.name.clone()),
            activation_height,
        }),
    }
}

/// What `check_consensus_compatibility` should do about the detected incompatibilities,
/// given the node’s current tip. There is no “compatible” variant: [`classify`] is only
/// reached once at least one incompatibility exists, so compatibility is handled by its
/// caller before classification.
enum Decision {
    /// At least one incompatibility has already taken effect (its divergence height is at or
    /// below the current tip), so this build cannot be trusted: refuse to start.
    Diverged(Vec<Incompatibility>),
    /// All incompatibilities are still in the future. Warn, run normally, and shut down once
    /// the chain reaches `height` (the earliest divergence).
    Pending {
        height: u32,
        upgrades: Vec<Incompatibility>,
    },
}

/// Classifies `incompatibilities` against the node’s current `tip` height. An incompatibility
/// whose divergence height is at or below the tip has already taken effect. The input is
/// [`NonEmpty`] because there is nothing to classify when no incompatibilities were detected.
fn classify(incompatibilities: NonEmpty<Incompatibility>, tip: u32) -> Decision {
    // The earliest divergence height across all incompatibilities.
    let earliest = incompatibilities
        .minimum_by_key(|i| i.divergence_height())
        .divergence_height();

    // Anything whose divergence height is at or below the tip has already taken effect.
    let (active, pending): (Vec<_>, Vec<_>) = incompatibilities
        .into_iter()
        .partition(|i| i.divergence_height() <= tip);

    if active.is_empty() {
        // Nothing has diverged yet, so `pending` holds every incompatibility and `earliest`
        // is their earliest divergence: run normally and shut down once the chain reaches it.
        Decision::Pending {
            height: earliest,
            upgrades: pending,
        }
    } else {
        Decision::Diverged(active)
    }
}

/// Checks whether `chain`’s backing full node follows consensus rules compatible with this
/// build of Zallet.
///
/// * Returns `Err` (refusing startup) if any incompatibility has already taken effect on the
///   node’s current chain.
/// * Returns `Ok(Some(height))` if the only incompatibilities are still in the future: the
///   caller should run normally but shut down once the chain reaches `height`.
/// * Returns `Ok(None)` if the node is fully compatible.
pub(crate) async fn check_consensus_compatibility(
    chain: &impl Chain,
) -> Result<Option<BlockHeight>, Error> {
    let upgrades = chain.reported_upgrades().await?;
    let Some(incompatibilities) =
        NonEmpty::from_vec(detect_incompatibilities(chain.params(), &upgrades))
    else {
        info!("Backing full node consensus rules are compatible with this Zallet build");
        return Ok(None);
    };

    // Classify against the node’s current tip: anything at or below it has already diverged.
    let tip = u32::from(chain.snapshot().await?.tip().await?.height);
    let describe = |upgrades: &[Incompatibility]| {
        upgrades
            .iter()
            .map(Incompatibility::describe)
            .collect::<Vec<_>>()
            .join(", ")
    };

    match classify(incompatibilities, tip) {
        Decision::Diverged(active) => {
            let upgrades = describe(&active);
            error!("Backing full node follows incompatible consensus rules: {upgrades}");
            Err(ErrorKind::Init
                .context(fl!("err-init-incompatible-consensus", upgrades = upgrades))
                .into())
        }
        Decision::Pending { height, upgrades } => {
            let upgrades = describe(&upgrades);
            warn!(
                "{}",
                fl!(
                    "warn-init-pending-incompatible-consensus",
                    upgrades = upgrades,
                    height = height
                )
            );
            Ok(Some(BlockHeight::from_u32(height)))
        }
    }
}

/// A shielded pool with a note commitment tree that [`ChainView::tree_state_as_of`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreePool {
    /// The Sapling pool, active from the Sapling network upgrade.
    Sapling,
    /// The Orchard pool, active from NU5.
    Orchard,
    /// The Ironwood pool, active from NU6.3. Shares the Orchard tree's shape.
    Ironwood,
}

impl TreePool {
    /// The network upgrade that activates this pool. Before it, the pool's note commitment
    /// tree is empty and validators legitimately report no tree at all.
    fn activated_by(self) -> consensus::NetworkUpgrade {
        match self {
            TreePool::Sapling => consensus::NetworkUpgrade::Sapling,
            TreePool::Orchard => consensus::NetworkUpgrade::Nu5,
            TreePool::Ironwood => consensus::NetworkUpgrade::Nu6_3,
        }
    }
}

impl fmt::Display for TreePool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreePool::Sapling => write!(f, "Sapling"),
            TreePool::Orchard => write!(f, "Orchard"),
            TreePool::Ironwood => write!(f, "Ironwood"),
        }
    }
}

/// Whether a validator reporting *no* note commitment tree for `pool` at `height` legitimately
/// means "the empty tree", rather than "I could not read it".
///
/// A validator has no tree to report for heights before the pool activates, so there the empty
/// tree is the correct answer. From activation onward a missing tree is an invariant violation
/// — corruption, an interrupted format upgrade, or a block the validator cannot resolve — and
/// substituting an empty frontier silently corrupts the wallet's shardtree (see
/// [`ChainView::tree_state_as_of`]). `zebra-state` takes the same position internally, treating
/// a missing post-activation tree as a panic rather than masking it.
///
/// Note this is deliberately a question about an *absent* tree, not an empty one: a tree that is
/// present but empty is perfectly legitimate just after activation, and on networks where the
/// pool has activated but no notes have been created yet.
///
/// Returns `true` when the pool has not activated at `height`, including on networks where the
/// activating upgrade is not scheduled at all.
pub fn empty_tree_is_legitimate(params: &Network, pool: TreePool, height: BlockHeight) -> bool {
    use consensus::Parameters as _;

    // Not scheduled at all, or scheduled above `height`: either way the pool is inactive here.
    params
        .activation_height(pool.activated_by())
        .is_none_or(|activation| height < activation)
}

/// A consistent, reorg-immune view of the chain as of a fixed tip.
///
/// A sequence of reads through one `ChainView` is mutually consistent.
pub trait ChainView: Clone + Send + Sync + 'static {
    /// Returns this view's chain tip.
    fn tip(&self) -> impl Future<Output = Result<ChainBlock, ChainError>> + Send;

    /// Returns the most recent entry of the caller-supplied block [`BlockLocator`] that
    /// lies on this view's best chain — the fork point — or `None` if no locator entry is
    /// on the best chain.
    fn find_fork_point(
        &self,
        locator: &BlockLocator,
    ) -> impl Future<Output = Result<Option<ChainBlock>, ChainError>> + Send;

    /// Returns the final note commitment tree state for each shielded pool as of `height`,
    /// or `None` if `height` is above this view's tip.
    ///
    /// # Correctness
    ///
    /// The frontiers in the returned [`ChainState`] are the wallet's *only* protection
    /// against note commitment tree corruption. `put_blocks` appears to validate them, but
    /// in Zallet's usage that check is circular: the scanned block's final tree size is
    /// derived from the same [`ChainState`] the check compares it against (Zallet builds
    /// `BlockMetadata` from `from_state`, and `scanning::full::scan_block` derives
    /// `*_final_tree_size` from that metadata). A wrong frontier of *any* size — including
    /// an empty one — is therefore committed to the wallet's shardtree without complaint,
    /// and only surfaces later as a `Conflict` when a correct frontier disagrees with it.
    /// By then the wallet is unrecoverable without a manual rewind.
    ///
    /// Implementations must therefore never substitute a placeholder frontier for one they
    /// could not read. Use [`empty_tree_is_legitimate`] to distinguish "this pool was not
    /// active yet, so the empty tree is the right answer" from "I could not read this
    /// tree", and report the latter as [`ChainError::Unavailable`] so the sync engine
    /// retries instead of corrupting the wallet.
    fn tree_state_as_of(
        &self,
        height: BlockHeight,
    ) -> impl Future<Output = Result<Option<ChainState>, ChainError>> + Send;

    /// Returns the block header at `height`, or `None` if above this view's tip.
    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> impl Future<Output = Result<Option<BlockHeader>, ChainError>> + Send;

    /// Returns the block at `height`, or `None` if above this view's tip.
    fn get_block(
        &self,
        height: BlockHeight,
    ) -> impl Future<Output = Result<Option<Block>, ChainError>> + Send;

    /// Streams blocks from `start` to this view's tip, inclusive.
    fn stream_blocks_to_tip(&self, start: BlockHeight) -> BoxStream<'_, Result<Block, ChainError>>;

    /// Streams blocks over `range`.
    fn stream_blocks(&self, range: &Range<BlockHeight>)
    -> BoxStream<'_, Result<Block, ChainError>>;

    /// Streams the current mempool. The stream ends when this view's tip changes.
    ///
    /// Returns `None` if the tip has already changed since the view was captured.
    /// Errors encountered while acquiring the stream are returned by the outer result;
    /// errors encountered while consuming it are yielded as stream items. A cleanly
    /// completed stream is the signal that the view's tip changed.
    fn get_mempool_stream(
        &self,
    ) -> impl Future<
        Output = Result<Option<BoxStream<'_, Result<Transaction, ChainError>>>, ChainError>,
    > + Send;

    /// Returns the transaction with the given txid, if known.
    fn get_transaction(
        &self,
        txid: TxId,
    ) -> impl Future<Output = Result<Option<ChainTx>, ChainError>> + Send;

    /// Returns the current status of the given transaction.
    fn get_transaction_status(
        &self,
        txid: TxId,
    ) -> impl Future<Output = Result<TransactionStatus, ChainError>> + Send;

    /// Returns the spend status of the transparent output `outpoint` on this view's chain.
    ///
    /// Spentness is authoritative (taken from the node's UTXO set); a per-outpoint spend index
    /// is used only to resolve the spending transaction. A spent output whose spender cannot yet
    /// be resolved is reported as [`SpendStatus::SpentSpenderUnknown`] so the caller retries
    /// rather than concluding the output is unspent (see ZcashFoundation/zebra#10806).
    #[cfg(feature = "spend-index")]
    fn outpoint_spend_status(
        &self,
        outpoint: &OutPoint,
    ) -> impl Future<Output = Result<SpendStatus, ChainError>> + Send;

    /// Returns the outpoints `(txid, output_index)` currently unspent at `address` on this
    /// view's chain, used (without a per-outpoint spend index) to cheaply decide whether any of
    /// the wallet's tracked outputs at the address have been spent.
    #[cfg(not(feature = "spend-index"))]
    fn get_address_unspent_outpoints(
        &self,
        address: &TransparentAddress,
    ) -> impl Future<Output = Result<Vec<(TxId, u32)>, ChainError>> + Send;

    /// Returns the txids of transactions involving `address` mined within `range`
    /// (start inclusive, end exclusive), used to recover the spending transaction once a missed
    /// spend has been detected on a backend without a per-outpoint spend index.
    #[cfg(not(feature = "spend-index"))]
    fn get_address_tx_ids(
        &self,
        address: &TransparentAddress,
        range: Range<BlockHeight>,
    ) -> impl Future<Output = Result<Vec<TxId>, ChainError>> + Send;

    /// Returns the height of the given block if it is on this view's main chain.
    ///
    /// Gated to the `zcashd-import` migration: its only caller resolves block hashes to
    /// heights for transactions imported from a `zcashd` wallet, so backends need not
    /// implement it in builds that cannot perform that import.
    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    fn block_height(
        &self,
        hash: &BlockHash,
    ) -> impl Future<Output = Result<Option<BlockHeight>, ChainError>> + Send;
}

/// A block's height and hash.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ChainBlock {
    height: BlockHeight,
    hash: BlockHash,
}

impl ChainBlock {
    /// Pairs a block's height with its hash.
    pub fn new(height: BlockHeight, hash: BlockHash) -> Self {
        Self { height, hash }
    }

    /// The block's height.
    pub fn height(&self) -> BlockHeight {
        self.height
    }

    /// The block's hash.
    pub fn hash(&self) -> BlockHash {
        self.hash
    }
}

/// An ordered list of a caller's own block hashes, highest chain height first, used to
/// locate where the caller's chain diverges from a backend's best chain (see
/// [`ChainView::find_fork_point`]).
pub struct BlockLocator(Vec<BlockHash>);

impl BlockLocator {
    /// Builds a locator from the caller's known blocks, highest height first.
    ///
    /// # Panics
    ///
    /// Panics unless `blocks` are in strictly-decreasing height order. This is a
    /// construction invariant, not input validation: a locator must list blocks from the
    /// chain tip downward so that fork-point detection returns the *highest* shared block,
    /// and the only producer builds it from its own contiguous history — so a violation is
    /// always a programming error, caught here rather than surfacing as a silently wrong
    /// fork point.
    pub fn from_blocks(blocks: impl IntoIterator<Item = ChainBlock>) -> Self {
        let mut hashes = Vec::new();
        let mut prev_height: Option<BlockHeight> = None;
        for block in blocks {
            if let Some(prev) = prev_height {
                assert!(
                    block.height < prev,
                    "block locator heights must strictly decrease, but {} follows {}",
                    block.height,
                    prev,
                );
            }
            prev_height = Some(block.height);
            hashes.push(block.hash);
        }
        Self(hashes)
    }

    /// The locator's block hashes, highest chain height first.
    pub fn hashes(&self) -> &[BlockHash] {
        &self.0
    }
}

/// A transaction together with the chain metadata the wallet needs to ingest it.
pub struct ChainTx {
    inner: Transaction,
    raw: Vec<u8>,
    block_hash: Option<BlockHash>,
    mined_height: Option<BlockHeight>,
    block_time: Option<u32>,
}

impl ChainTx {
    /// Combines a transaction with the chain metadata a backend knows about it.
    ///
    /// The metadata options are deliberately independent, reflecting the three states a
    /// backend reports: mined in the best chain (all `Some`), mined in a side chain
    /// (`block_hash` alone may be `Some`), or in the mempool (all `None`).
    pub fn new(
        inner: Transaction,
        raw: Vec<u8>,
        block_hash: Option<BlockHash>,
        mined_height: Option<BlockHeight>,
        block_time: Option<u32>,
    ) -> Self {
        Self {
            inner,
            raw,
            block_hash,
            mined_height,
            block_time,
        }
    }

    /// The parsed transaction.
    pub fn inner(&self) -> &Transaction {
        &self.inner
    }

    /// The transaction's raw serialized bytes.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The hash of the block containing the transaction, if mined.
    pub fn block_hash(&self) -> Option<BlockHash> {
        self.block_hash
    }

    /// The height of the block containing the transaction, if mined.
    pub fn mined_height(&self) -> Option<BlockHeight> {
        self.mined_height
    }

    /// The timestamp of the block containing the transaction, if mined.
    pub fn block_time(&self) -> Option<u32> {
        self.block_time
    }

    /// Splits the transaction from its raw bytes, for consumers that need ownership.
    pub fn into_parts(self) -> (Transaction, Vec<u8>) {
        (self.inner, self.raw)
    }
}

/// The spend status of a transparent output, as reported by [`ChainView::outpoint_spend_status`].
#[cfg(feature = "spend-index")]
pub enum SpendStatus {
    /// The output is unspent on this view's chain.
    Unspent,
    /// The output was spent by the transaction with this txid.
    SpentBy(TxId),
    /// The output is spent, but the spending transaction cannot yet be resolved (e.g. the
    /// backend's spend index has not finished building); the caller should retry later.
    SpentSpenderUnknown,
}

#[cfg(test)]
pub(crate) use tests::MockChain;

#[cfg(test)]
mod tests {
    use std::{
        ops::Range,
        sync::{Arc, Mutex},
    };

    use futures::{
        StreamExt as _,
        stream::{self, BoxStream},
    };
    use zcash_client_backend::data_api::{
        TransactionStatus,
        chain::{ChainState, CommitmentTreeRoot},
    };
    use zcash_primitives::{
        block::{Block, BlockHash, BlockHeader},
        transaction::Transaction,
    };
    use zcash_protocol::{
        TxId,
        consensus::{BlockHeight, BranchId, Network},
    };

    #[cfg(feature = "spend-index")]
    use super::SpendStatus;
    use super::{
        BlockLocator, Chain, ChainBlock, ChainError, ChainTx, ChainView, Decision, Error,
        Incompatibility, NonEmpty, ReportedUpgrade, UpgradeStatus, branch_incompatibility,
        check_consensus_compatibility, classify, detect_incompatibilities,
    };
    #[cfg(not(feature = "spend-index"))]
    use transparent::address::TransparentAddress;
    #[cfg(feature = "spend-index")]
    use transparent::bundle::OutPoint;

    /// A trivial in-memory [`ChainView`], proving the trait is implementable by a non-Zaino
    /// backend and locking the contract.
    #[derive(Clone)]
    pub(crate) struct MockChainView {
        tip: ChainBlock,
        scan_ranges: Option<Arc<Mutex<Vec<Range<BlockHeight>>>>>,
    }

    impl ChainView for MockChainView {
        async fn tip(&self) -> Result<ChainBlock, ChainError> {
            Ok(self.tip)
        }

        async fn find_fork_point(
            &self,
            locator: &BlockLocator,
        ) -> Result<Option<ChainBlock>, ChainError> {
            // The mock knows only its own tip, so the fork point is locatable only when
            // the caller's locator includes that block; otherwise it cannot be located.
            Ok(locator
                .hashes()
                .contains(&self.tip.hash)
                .then_some(self.tip))
        }

        async fn tree_state_as_of(
            &self,
            height: BlockHeight,
        ) -> Result<Option<ChainState>, ChainError> {
            Ok(self
                .scan_ranges
                .as_ref()
                .map(|_| ChainState::empty(height, BlockHash([0; 32]))))
        }

        async fn get_block_header(
            &self,
            _height: BlockHeight,
        ) -> Result<Option<BlockHeader>, ChainError> {
            Ok(None)
        }

        async fn get_block(&self, _height: BlockHeight) -> Result<Option<Block>, ChainError> {
            Ok(None)
        }

        fn stream_blocks_to_tip(
            &self,
            _start: BlockHeight,
        ) -> BoxStream<'_, Result<Block, ChainError>> {
            stream::empty().boxed()
        }

        fn stream_blocks(
            &self,
            range: &Range<BlockHeight>,
        ) -> BoxStream<'_, Result<Block, ChainError>> {
            if let Some(scan_ranges) = &self.scan_ranges {
                scan_ranges
                    .lock()
                    .expect("mock scan range observer is not poisoned")
                    .push(range.clone());
            }
            stream::empty().boxed()
        }

        async fn get_mempool_stream(
            &self,
        ) -> Result<Option<BoxStream<'_, Result<Transaction, ChainError>>>, ChainError> {
            Ok(None)
        }

        async fn get_transaction(&self, _txid: TxId) -> Result<Option<ChainTx>, ChainError> {
            Ok(None)
        }

        async fn get_transaction_status(
            &self,
            _txid: TxId,
        ) -> Result<TransactionStatus, ChainError> {
            Ok(TransactionStatus::TxidNotRecognized)
        }

        #[cfg(feature = "spend-index")]
        async fn outpoint_spend_status(
            &self,
            _outpoint: &OutPoint,
        ) -> Result<SpendStatus, ChainError> {
            Ok(SpendStatus::Unspent)
        }

        #[cfg(not(feature = "spend-index"))]
        async fn get_address_unspent_outpoints(
            &self,
            _address: &TransparentAddress,
        ) -> Result<Vec<(TxId, u32)>, ChainError> {
            Ok(Vec::new())
        }

        #[cfg(not(feature = "spend-index"))]
        async fn get_address_tx_ids(
            &self,
            _address: &TransparentAddress,
            _range: Range<BlockHeight>,
        ) -> Result<Vec<TxId>, ChainError> {
            Ok(Vec::new())
        }

        #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
        async fn block_height(&self, _hash: &BlockHash) -> Result<Option<BlockHeight>, ChainError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn mock_view_reports_its_tip() {
        let tip = ChainBlock {
            height: BlockHeight::from_u32(42),
            hash: BlockHash([7u8; 32]),
        };
        let view = MockChainView {
            tip,
            scan_ranges: None,
        };
        assert_eq!(view.tip().await.unwrap(), tip);
        // The fork point resolves when the locator includes the view's own tip, and
        // not for a locator that excludes it.
        let on_chain = BlockLocator::from_blocks([tip]);
        assert_eq!(view.find_fork_point(&on_chain).await.unwrap(), Some(tip));
        let off_chain = BlockLocator::from_blocks([ChainBlock {
            height: BlockHeight::from_u32(41),
            hash: BlockHash([0u8; 32]),
        }]);
        assert_eq!(view.find_fork_point(&off_chain).await.unwrap(), None);
    }

    fn block(height: u32, hash: u8) -> ChainBlock {
        ChainBlock {
            height: BlockHeight::from_u32(height),
            hash: BlockHash([hash; 32]),
        }
    }

    #[test]
    fn block_locator_keeps_hashes_in_descending_order() {
        let locator = BlockLocator::from_blocks([block(10, 10), block(9, 9), block(5, 5)]);
        assert_eq!(
            locator.hashes(),
            &[BlockHash([10; 32]), BlockHash([9; 32]), BlockHash([5; 32])],
        );
    }

    #[test]
    #[should_panic(expected = "strictly decrease")]
    fn block_locator_rejects_non_descending_heights() {
        // Equal heights violate the strictly-decreasing construction invariant.
        let _ = BlockLocator::from_blocks([block(10, 10), block(10, 9)]);
    }

    /// The network whose activation heights we test against. Mainnet implements
    /// [`zcash_protocol::consensus::Parameters`].
    const PARAMS: Network = Network::MainNetwork;

    /// An invalid consensus branch ID, standing in for a network upgrade
    /// from the future that this build of Zallet has never heard of.
    const UNKNOWN_BRANCH_ID: u32 = 0xdead_beef;

    /// The mainnet activation height this build of Zallet expects for `branch`.
    fn expected_height(branch: BranchId) -> u32 {
        u32::from(
            branch
                .height_bounds(&PARAMS)
                .expect("branch is scheduled on mainnet")
                .0,
        )
    }

    fn upgrade(branch_id: u32, height: u32, status: UpgradeStatus) -> ReportedUpgrade {
        ReportedUpgrade {
            branch_id,
            // The upgrade name is diagnostic only; the branch ID and height drive the
            // check, so the name is fixed here.
            name: "test".into(),
            activation_height: height,
            status,
        }
    }

    /// The full symmetric check (both passes).
    fn detect(upgrades: &[ReportedUpgrade]) -> Vec<Incompatibility> {
        detect_incompatibilities(&PARAMS, upgrades)
    }

    /// Compares only the node-reported upgrades, for tests that exercise that direction in
    /// isolation — without [`detect_incompatibilities`] also flagging every upgrade this build
    /// schedules that the minimal input omits.
    fn detect_node(upgrades: &[ReportedUpgrade]) -> Vec<Incompatibility> {
        upgrades
            .iter()
            .filter_map(|upgrade| branch_incompatibility(&PARAMS, upgrade.branch_id, Some(upgrade)))
            .collect()
    }

    #[test]
    fn recognized_upgrade_with_matching_height_is_compatible() {
        let branch = BranchId::Nu5;
        let known = u32::from(branch);
        let height = expected_height(branch);
        assert!(detect_node(&[upgrade(known, height, UpgradeStatus::Active)]).is_empty());
    }

    #[test]
    fn recognized_upgrade_with_mismatched_height_is_flagged() {
        let branch = BranchId::Nu5;
        let known = u32::from(branch);
        let wrong = expected_height(branch) + 1;
        let result = detect_node(&[upgrade(known, wrong, UpgradeStatus::Active)]);
        assert_eq!(result.len(), 1);
        assert!(matches!(
            result[0],
            Incompatibility::ActivationHeightMismatch {
                branch_id,
                expected: Some(_),
                node: Some(node),
                ..
            } if branch_id == known && node == wrong
        ));
    }

    #[test]
    fn recognized_upgrade_disabled_by_node_is_flagged() {
        // This build expects Nu5 to activate on mainnet, so a full node that reports it
        // disabled disagrees about whether its consensus rules apply at all.
        let known = u32::from(BranchId::Nu5);
        let result = detect_node(&[upgrade(known, 0, UpgradeStatus::Disabled)]);
        assert_eq!(result.len(), 1);
        assert!(matches!(
            result[0],
            Incompatibility::ActivationHeightMismatch {
                expected: Some(_),
                node: None,
                ..
            }
        ));
    }

    #[test]
    fn unknown_active_upgrade_is_flagged() {
        let result = detect_node(&[upgrade(UNKNOWN_BRANCH_ID, 1, UpgradeStatus::Active)]);
        assert_eq!(result.len(), 1);
        assert!(matches!(
            result[0],
            Incompatibility::UnknownUpgrade {
                branch_id: UNKNOWN_BRANCH_ID,
                activation_height: 1,
                ..
            }
        ));
    }

    #[test]
    fn unknown_pending_upgrade_is_flagged() {
        let result = detect_node(&[upgrade(UNKNOWN_BRANCH_ID, 42, UpgradeStatus::Pending)]);
        assert_eq!(result.len(), 1);
        assert!(matches!(
            result[0],
            Incompatibility::UnknownUpgrade {
                activation_height: 42,
                ..
            }
        ));
    }

    #[test]
    fn unknown_disabled_upgrade_is_ignored() {
        assert!(detect_node(&[upgrade(UNKNOWN_BRANCH_ID, 1, UpgradeStatus::Disabled)]).is_empty());
    }

    #[test]
    fn divergence_height_of_unknown_upgrade_is_its_activation_height() {
        let result = detect_node(&[upgrade(UNKNOWN_BRANCH_ID, 555, UpgradeStatus::Pending)]);
        assert_eq!(result[0].divergence_height(), 555);
    }

    #[test]
    fn divergence_height_of_mismatch_is_the_earlier_height() {
        // This build expects Nu5 at its mainnet height; the node reports a later one. The
        // earlier (our expected) height is where divergence begins.
        let branch = BranchId::Nu5;
        let ours = expected_height(branch);
        let later = ours + 100;
        let result = detect_node(&[upgrade(u32::from(branch), later, UpgradeStatus::Pending)]);
        assert_eq!(result[0].divergence_height(), ours);
    }

    /// Wraps [`classify`] (which takes a [`NonEmpty`]) for the tests below, every one of
    /// which feeds it a non-empty set. The empty case has no classification to make and is
    /// handled by `check_consensus_compatibility`, not `classify`, so it is tested there.
    fn decide(incompatibilities: Vec<Incompatibility>, tip: u32) -> Decision {
        classify(
            NonEmpty::from_vec(incompatibilities).expect("test input is non-empty"),
            tip,
        )
    }

    #[test]
    fn classify_all_future_is_pending_at_earliest_divergence() {
        // Two pending unknown upgrades at different heights, both above the tip.
        let earlier = detect_node(&[upgrade(UNKNOWN_BRANCH_ID, 200, UpgradeStatus::Pending)]);
        let later = detect_node(&[upgrade(0xfeed_face, 300, UpgradeStatus::Pending)]);
        let both = earlier.into_iter().chain(later).collect();
        match decide(both, 100) {
            Decision::Pending { height, upgrades } => {
                assert_eq!(height, 200);
                assert_eq!(upgrades.len(), 2);
            }
            _ => panic!("expected Pending"),
        }
    }

    #[test]
    fn classify_at_or_below_tip_is_diverged() {
        let incompatibilities =
            detect_node(&[upgrade(UNKNOWN_BRANCH_ID, 100, UpgradeStatus::Active)]);
        assert!(matches!(
            decide(incompatibilities, 100),
            Decision::Diverged(_)
        ));
    }

    #[test]
    fn classify_mixed_active_and_pending_is_diverged() {
        let active = detect_node(&[upgrade(UNKNOWN_BRANCH_ID, 100, UpgradeStatus::Active)]);
        let pending = detect_node(&[upgrade(0xfeed_face, 300, UpgradeStatus::Pending)]);
        let both = active.into_iter().chain(pending).collect();
        match decide(both, 150) {
            // Only the already-diverged upgrade blocks startup.
            Decision::Diverged(active) => assert_eq!(active.len(), 1),
            _ => panic!("expected Diverged"),
        }
    }

    /// The upgrade this build expects for `branch` on mainnet, reported active at the height
    /// this build schedules it — or `None` if `branch` is not scheduled on mainnet.
    fn reported_upgrade(branch: BranchId) -> Option<ReportedUpgrade> {
        let height = u32::from(branch.height_bounds(&PARAMS)?.0);
        Some(upgrade(u32::from(branch), height, UpgradeStatus::Active))
    }

    /// Every upgrade this build schedules on mainnet, each reported at the height it expects —
    /// a fully compatible node-reported set.
    fn all_known() -> Vec<ReportedUpgrade> {
        crate::network::NETWORK_UPGRADES
            .iter()
            .copied()
            .filter_map(reported_upgrade)
            .collect()
    }

    /// [`all_known`] minus `omit`, so the only possible incompatibility is that omission.
    fn all_known_except(omit: BranchId) -> Vec<ReportedUpgrade> {
        crate::network::NETWORK_UPGRADES
            .iter()
            .copied()
            .filter(|&branch| branch != omit)
            .filter_map(reported_upgrade)
            .collect()
    }

    #[test]
    fn upgrade_known_to_zallet_but_omitted_by_node_is_flagged() {
        let omitted = BranchId::Nu6_2;
        let result = detect(&all_known_except(omitted));
        assert_eq!(result.len(), 1);
        assert!(matches!(
            result[0],
            Incompatibility::ActivationHeightMismatch {
                branch_id,
                expected: Some(_),
                node: None,
                ..
            } if branch_id == u32::from(omitted)
        ));
        assert_eq!(result[0].divergence_height(), expected_height(omitted));
    }

    #[test]
    fn omitted_future_upgrade_defers_then_diverges() {
        let omitted = BranchId::Nu6_2;
        let height = expected_height(omitted);

        // Tip below the omitted upgrade's height: warn and defer to it.
        match decide(detect(&all_known_except(omitted)), height - 1) {
            Decision::Pending { height: h, .. } => assert_eq!(h, height),
            _ => panic!("expected Pending"),
        }
        // Tip at or above it: this build has already diverged.
        assert!(matches!(
            decide(detect(&all_known_except(omitted)), height),
            Decision::Diverged(_)
        ));
    }

    #[test]
    fn fully_reported_upgrades_are_compatible() {
        assert!(detect(&all_known()).is_empty());
    }

    /// A minimal [`Chain`] that serves a fixed upgrade set and tip on mainnet.
    ///
    /// `params`, `reported_upgrades`, and `snapshot` support consensus checks. Operations
    /// outside that scope return a backend error, which also lets component tests exercise
    /// startup failure after accepting this chain.
    #[derive(Clone)]
    pub(crate) struct MockChain {
        params: super::Network,
        upgrades: Vec<ReportedUpgrade>,
        tip: BlockHeight,
        scan_ranges: Option<Arc<Mutex<Vec<Range<BlockHeight>>>>>,
    }

    impl MockChain {
        pub(crate) fn reporting(upgrades: Vec<ReportedUpgrade>, tip: u32) -> Self {
            Self::reporting_with_optional_scan_observer(upgrades, tip, None)
        }

        pub(crate) fn reporting_with_scan_observer(
            upgrades: Vec<ReportedUpgrade>,
            tip: u32,
            scan_ranges: Arc<Mutex<Vec<Range<BlockHeight>>>>,
        ) -> Self {
            Self::reporting_with_optional_scan_observer(upgrades, tip, Some(scan_ranges))
        }

        fn reporting_with_optional_scan_observer(
            upgrades: Vec<ReportedUpgrade>,
            tip: u32,
            scan_ranges: Option<Arc<Mutex<Vec<Range<BlockHeight>>>>>,
        ) -> Self {
            Self {
                params: super::Network::Consensus(Network::MainNetwork),
                upgrades,
                tip: BlockHeight::from_u32(tip),
                scan_ranges,
            }
        }
    }

    impl Chain for MockChain {
        type View = MockChainView;

        fn params(&self) -> &super::Network {
            &self.params
        }

        async fn reported_upgrades(&self) -> Result<Vec<ReportedUpgrade>, Error> {
            Ok(self.upgrades.clone())
        }

        async fn broadcast_transaction(&self, _tx: &Transaction) -> Result<(), ChainError> {
            Err(ChainError::backend(
                "mock chain does not broadcast transactions",
            ))
        }

        async fn get_sapling_subtree_roots(
            &self,
        ) -> Result<Vec<CommitmentTreeRoot<sapling::Node>>, ChainError> {
            Err(ChainError::backend(
                "mock chain does not serve wallet subtree roots",
            ))
        }

        async fn get_orchard_subtree_roots(
            &self,
        ) -> Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError> {
            Err(ChainError::backend(
                "mock chain does not serve wallet subtree roots",
            ))
        }

        async fn get_ironwood_subtree_roots(
            &self,
        ) -> Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError> {
            Err(ChainError::backend(
                "mock chain does not serve wallet subtree roots",
            ))
        }

        async fn snapshot(&self) -> Result<Self::View, ChainError> {
            Ok(MockChainView {
                tip: ChainBlock {
                    height: self.tip,
                    hash: BlockHash([0u8; 32]),
                },
                scan_ranges: self.scan_ranges.clone(),
            })
        }
    }

    /// A [`MockChain`] on mainnet reporting `upgrades`, with its tip at `tip`.
    fn mock_chain(upgrades: Vec<ReportedUpgrade>, tip: u32) -> MockChain {
        MockChain::reporting(upgrades, tip)
    }

    #[tokio::test]
    async fn check_reports_compatible_when_all_upgrades_match() {
        // Every scheduled mainnet upgrade reported at its expected height: no incompatibility,
        // so the check reports full compatibility and sets no shutdown height.
        let chain = mock_chain(all_known(), 3_000_000);
        assert_eq!(check_consensus_compatibility(&chain).await.unwrap(), None);
    }

    #[tokio::test]
    async fn check_refuses_start_when_an_incompatibility_has_already_activated() {
        // An unrecognized upgrade already active low on the chain has diverged by the tip, so
        // the wallet must refuse to start.
        let mut upgrades = all_known();
        upgrades.push(upgrade(UNKNOWN_BRANCH_ID, 1, UpgradeStatus::Active));
        let chain = mock_chain(upgrades, 3_000_000);
        assert!(check_consensus_compatibility(&chain).await.is_err());
    }

    #[tokio::test]
    async fn check_defers_shutdown_when_the_only_incompatibility_is_pending() {
        // An unrecognized upgrade scheduled above the tip: run now, but report the height at
        // which the wallet must shut down before the node's rules diverge from ours.
        let future = 9_000_000;
        let mut upgrades = all_known();
        upgrades.push(upgrade(UNKNOWN_BRANCH_ID, future, UpgradeStatus::Pending));
        let chain = mock_chain(upgrades, 3_000_000);
        assert_eq!(
            check_consensus_compatibility(&chain).await.unwrap(),
            Some(BlockHeight::from_u32(future)),
        );
    }

    mod empty_tree {
        use super::super::{TreePool, empty_tree_is_legitimate};
        use crate::network::Network as WalletNetwork;
        use zcash_protocol::consensus::{BlockHeight, NetworkType};

        fn mainnet() -> WalletNetwork {
            WalletNetwork::from_type(NetworkType::Main, &[])
        }

        fn h(height: u32) -> BlockHeight {
            BlockHeight::from_u32(height)
        }

        /// Mainnet activation heights, from `zcash_protocol`.
        const SAPLING: u32 = 419_200;
        const NU5: u32 = 1_687_104;
        const NU6_3: u32 = 3_428_143;

        #[test]
        fn absent_tree_is_empty_below_activation() {
            assert!(empty_tree_is_legitimate(
                &mainnet(),
                TreePool::Ironwood,
                h(NU6_3 - 1)
            ));
            assert!(empty_tree_is_legitimate(
                &mainnet(),
                TreePool::Orchard,
                h(NU5 - 1)
            ));
            assert!(empty_tree_is_legitimate(
                &mainnet(),
                TreePool::Sapling,
                h(SAPLING - 1)
            ));
        }

        #[test]
        fn absent_tree_is_an_error_at_activation() {
            // The activation height itself is already "active": the pool's tree exists from
            // this block onward, so a validator reporting none is wrong.
            assert!(!empty_tree_is_legitimate(
                &mainnet(),
                TreePool::Ironwood,
                h(NU6_3)
            ));
            assert!(!empty_tree_is_legitimate(
                &mainnet(),
                TreePool::Orchard,
                h(NU5)
            ));
            assert!(!empty_tree_is_legitimate(
                &mainnet(),
                TreePool::Sapling,
                h(SAPLING)
            ));
        }

        #[test]
        fn absent_ironwood_tree_is_an_error_at_the_reported_failure_height() {
            // The mainnet height from the beta.2 crash report: ~9.9k blocks past NU6.3, where
            // substituting an empty Ironwood frontier corrupted the wallet's shardtree.
            assert!(!empty_tree_is_legitimate(
                &mainnet(),
                TreePool::Ironwood,
                h(3_438_008)
            ));
        }

        #[test]
        fn pools_are_judged_independently() {
            // Between NU5 and NU6.3, Orchard is active but Ironwood is not, so the same
            // height gives opposite answers per pool. A guard that ignored the pool would
            // either corrupt Orchard state or spuriously reject Ironwood reads.
            let between = h(NU6_3 - 1);
            assert!(!empty_tree_is_legitimate(
                &mainnet(),
                TreePool::Orchard,
                between
            ));
            assert!(empty_tree_is_legitimate(
                &mainnet(),
                TreePool::Ironwood,
                between
            ));
        }

        #[test]
        fn absent_tree_is_empty_when_the_upgrade_is_not_scheduled() {
            // Regtest with no nuparams schedules nothing, so no pool ever activates and an
            // absent tree is always the empty tree. This is what keeps the guard from
            // firing on networks where Ironwood is simply not in play.
            let unscheduled = WalletNetwork::from_type(NetworkType::Regtest, &[]);
            assert!(empty_tree_is_legitimate(
                &unscheduled,
                TreePool::Ironwood,
                h(1_000_000)
            ));
        }
    }
}
