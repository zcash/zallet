//! The Zallet sync engine.
//!
//! # Design
//!
//! Zallet uses `zcash_client_sqlite` for its wallet, which stores its own view of the
//! chain. The goal of this engine is to keep the wallet's chain view as closely synced to
//! the network's chain as possible. This means handling environmental events such as:
//!
//! - A new block being mined.
//! - A reorg to a different chain.
//! - A transaction being added to the mempool.
//! - A new viewing capability being added to the wallet.
//! - The wallet starting up after being offline for some time.
//!
//! To handle this, we split the chain into two "regions of responsibility":
//!
//! - The [`steady_state`] task handles the region of the chain within 100 blocks of the
//!   network chain tip (corresponding to Zebra's "non-finalized state"). This task is
//!   started once when Zallet starts, and any error will cause Zallet to shut down.
//! - The [`recover_history`] task handles the region of the chain farther than 100 blocks
//!   from the network chain tip (corresponding to Zebra's "finalized state"). This task
//!   is active whenever there are unscanned blocks in this region.
//!
//! Note the boundary between these regions may be less than 100 blocks from the network
//! chain tip at times, due to how reorgs are implemented in Zebra; the boundary ratchets
//! forward as the chain tip height increases, but never backwards.
//!
//! TODO: Integrate or remove these other notes:
//!
//! - Zebra discards the non-finalized chain tip on restart, so Zallet needs to tolerate
//!   the `ChainView` being up to 100 blocks behind the wallet's view of the chain tip at
//!   process start.

use std::ops::ControlFlow;
use std::sync::{
    Arc,
    atomic::{AtomicU32, Ordering},
};
use std::time::Duration;

use futures::{StreamExt as _, TryStreamExt as _};
use jsonrpsee::tracing::{self, debug, info, warn};
#[cfg(not(feature = "spend-index"))]
use std::collections::HashSet;
#[cfg(not(feature = "spend-index"))]
use std::ops::Range;
use tokio::{sync::Notify, task::AbortHandle, time};
#[cfg(not(feature = "spend-index"))]
use zcash_client_backend::data_api::{
    CoinbaseFilter, InputSource, TransactionsInvolvingAddress,
    wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
};
use zcash_client_backend::{
    data_api::{
        TransactionDataRequest, TransactionStatus, WalletRead, WalletWrite,
        scanning::{ScanPriority, ScanRange},
        wallet::decrypt_and_store_transaction,
    },
    scanning::ScanningKeys,
    sync::decryptor,
};
use zcash_client_sqlite::AccountUuid;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_primitives::block::BlockHash;
#[cfg(not(feature = "spend-index"))]
use zcash_protocol::TxId;
use zcash_protocol::consensus::BlockHeight;
use zip32::Scope;

use super::{
    TaskHandle,
    chain::{Chain, ChainBlock, ChainError, ChainView},
    database::{Database, DbConnection},
};
use crate::{config::ZalletConfig, error::Error, fl, network::Network};

mod error;
pub(crate) use error::SyncError;

pub(crate) mod status;
pub(crate) use status::{SyncStatus, SyncStatusReader, SyncStatusWriter};

mod locator;
mod steps;

#[derive(Debug)]
pub(crate) struct WalletSync {}

/// Handle the RPC layer uses to reload the sync engine's viewing keys after a key import.
pub(crate) type WalletDecryptorHandle = decryptor::Handle<AccountUuid, (AccountUuid, Scope)>;

/// Engine half of the batch decryptor, driven by the sync tasks spawned by [`WalletSync::spawn`].
pub(crate) type WalletDecryptorEngine = decryptor::Engine<AccountUuid, (AccountUuid, Scope)>;

/// Owns cancellation for wallet-sync tasks until the complete task set is returned.
struct PendingWalletSyncTasks {
    abort_handles: Vec<AbortHandle>,
}

impl PendingWalletSyncTasks {
    fn new(first_task: &TaskHandle) -> Self {
        Self {
            abort_handles: vec![first_task.abort_handle()],
        }
    }

    fn include(&mut self, task: &TaskHandle) {
        self.abort_handles.push(task.abort_handle());
    }

    fn transfer_to_caller(mut self) {
        self.abort_handles.clear();
    }
}

impl Drop for PendingWalletSyncTasks {
    fn drop(&mut self) {
        for abort_handle in &self.abort_handles {
            abort_handle.abort();
        }
    }
}

impl WalletSync {
    /// Builds the batch decryptor. Split from [`WalletSync::spawn`] so the RPC server can be
    /// handed a handle before `spawn`'s initial scan, which would otherwise delay RPC startup.
    pub(crate) fn build_decryptor() -> (WalletDecryptorHandle, WalletDecryptorEngine) {
        // The batch decryptor's built-in defaults (queue size 1000, batch-size threshold
        // 200, batch start delay 500ms) are appropriate for Zallet, so use them as-is.
        decryptor::new().build()
    }

    /// Initializes wallet sync and returns its complete task set.
    ///
    /// On success, the caller owns cancellation for every returned task and must register
    /// that ownership before its next cancellable await.
    pub(crate) async fn spawn<C: Chain>(
        config: &ZalletConfig,
        db: Database,
        chain: C,
        shutdown_height: Option<BlockHeight>,
        decryptor: WalletDecryptorHandle,
        decryptor_engine: WalletDecryptorEngine,
        status: SyncStatusWriter,
    ) -> Result<(TaskHandle, TaskHandle, TaskHandle, TaskHandle), Error> {
        let params = config.consensus.network();
        let recover_batch_size = config.sync.recover_batch_size();

        // Spawn the processing tasks.
        let batch_decryptor_task = {
            let mut db_data = db.handle().await?;
            crate::spawn!("Batch decryptor", async move {
                batch_decryptor(params, db_data.as_mut(), decryptor_engine).await?;
                Ok(())
            })
        };
        let mut pending_tasks = PendingWalletSyncTasks::new(&batch_decryptor_task);

        // Ensure the wallet is in a state that the sync tasks can work with.
        let mut db_data = db.handle().await?;
        let (starting_tip, starting_boundary) = initialize(
            &chain,
            &params,
            db_data.as_mut(),
            decryptor.clone(),
            shutdown_height,
            &status,
        )
        .await?;

        // Manage the boundary between the `steady_state` and `recover_history` tasks with
        // an atomic.
        let current_boundary = Arc::new(AtomicU32::new(starting_boundary.into()));

        // TODO: Zaino should provide us an API that allows us to be notified when the chain tip
        // changes; here, we produce our own signal via the "mempool stream closing" side effect
        // that occurs in the light client API when the chain tip changes.
        let tip_change_signal_source = Arc::new(Notify::new());
        let req_tip_change_signal_receiver = tip_change_signal_source.clone();

        // Spawn the ongoing sync tasks.
        let steady_state_task = {
            let chain = chain.clone();
            let lower_boundary = current_boundary.clone();
            let decryptor = decryptor.clone();
            let status = status.clone();
            crate::spawn!("Steady state sync", async move {
                steady_state(
                    chain,
                    &params,
                    db_data.as_mut(),
                    starting_tip,
                    lower_boundary,
                    tip_change_signal_source,
                    decryptor,
                    shutdown_height,
                    status,
                )
                .await?;
                Ok(())
            })
        };
        pending_tasks.include(&steady_state_task);

        let recover_history_task = {
            let chain = chain.clone();
            let mut db_data = db.handle().await?;
            let upper_boundary = current_boundary.clone();
            crate::spawn!("Recover history", async move {
                recover_history(
                    chain,
                    &params,
                    db_data.as_mut(),
                    upper_boundary,
                    decryptor,
                    recover_batch_size,
                    shutdown_height,
                    status,
                )
                .await?;
                Ok(())
            })
        };
        pending_tasks.include(&recover_history_task);

        let mut db_data = db.handle().await?;
        let data_requests_task = crate::spawn!("Data requests", async move {
            data_requests(
                chain,
                &params,
                db_data.as_mut(),
                req_tip_change_signal_receiver,
            )
            .await?;
            Ok(())
        });
        pending_tasks.include(&data_requests_task);

        // This handoff and the return must stay free of awaits: the caller registers every
        // returned handle with its own abort-on-drop owner in the same executor poll.
        pending_tasks.transfer_to_caller();

        Ok((
            steady_state_task,
            recover_history_task,
            batch_decryptor_task,
            data_requests_task,
        ))
    }
}

fn update_boundary(current_boundary: BlockHeight, tip_height: BlockHeight) -> BlockHeight {
    current_boundary.max(tip_height - 100)
}

/// Selects the next scan range for [`initialize`]'s catch-up loop from the wallet's
/// suggestions.
///
/// Every candidate is first clamped to `current_tip`: `suggest_scan_ranges` can return
/// ranges beyond the current chain view's tip when the wallet database previously
/// observed a higher tip than the view now serves (e.g. Zebra's read-only secondary
/// exposing finalized state that lags what the wallet saw before a restart). Such
/// ranges contain nothing scannable, and before this clamp existed, handing one to
/// `scan_blocks` returned `Ok` with no progress and no state change, so the
/// `initialize` loop spun at full speed — burning a core and logging tens of lines per
/// second — until the chain view happened to advance past the range (#636). Clamping
/// scans whatever prefix of a range is actually available now; a range entirely above
/// the tip is dropped, and if nothing scannable remains the caller's no-range arm exits
/// to `steady_state`, which waits for tip changes properly.
///
/// Beyond the clamp, `Verify` ranges are taken as-is, and ranges at `Historic` priority
/// or above are truncated to start at `starting_boundary` (history below the boundary
/// belongs to the `recover_history` task). Lower-priority ranges are not scanned here.
fn select_initial_scan_range(
    suggested: impl IntoIterator<Item = ScanRange>,
    current_tip: BlockHeight,
    starting_boundary: BlockHeight,
) -> Option<ScanRange> {
    suggested
        .into_iter()
        .filter_map(|r| {
            let r = r.truncate_end(current_tip + 1)?;
            if r.priority() == ScanPriority::Verify {
                Some(r)
            } else if r.priority() >= ScanPriority::Historic {
                r.truncate_start(starting_boundary)
            } else {
                None
            }
        })
        .next()
}

/// Prepares the wallet state for syncing.
///
/// Returns the boundary block between [`steady_state`] and [`recover_history`] syncing.
#[tracing::instrument(skip_all)]
async fn initialize<C: Chain>(
    chain: &C,
    params: &Network,
    db_data: &mut DbConnection,
    decryptor: WalletDecryptorHandle,
    shutdown_height: Option<BlockHeight>,
    status: &SyncStatusWriter,
) -> Result<(ChainBlock, BlockHeight), SyncError> {
    info!("Initializing wallet for syncing");

    // Notify the wallet of the current subtree roots.
    steps::update_subtree_roots(chain, db_data).await?;

    // Perform initial scanning prior to firing off the main tasks:
    // - Detect reorgs that might have occurred while the wallet was offline, by
    //   explicitly syncing any `ScanPriority::Verify` ranges.
    // - Ensure that the `steady_state` task starts from the wallet's view of the chain
    //   tip, by explicitly syncing any unscanned ranges from the boundary onward.
    //
    // This ensures that the `recover_history` task only operates over the finalized chain
    // state and doesn't attempt to handle reorgs (which are the responsibility of the
    // `steady_state` task).
    let (current_tip, starting_boundary) = loop {
        // Notify the wallet of the current chain tip.
        let chain_view = chain.snapshot().await.map_err(SyncError::Chain)?;
        let current_tip = chain_view.tip().await.map_err(SyncError::Chain)?;
        info!("Latest block height is {}", current_tip.height());
        db_data.update_chain_tip(current_tip.height())?;
        status.set_tip(current_tip.height());

        // Set the starting boundary between the `steady_state` and `recover_history` tasks.
        let starting_boundary = update_boundary(BlockHeight::from_u32(0), current_tip.height());

        let scan_range = match select_initial_scan_range(
            db_data.suggest_scan_ranges()?,
            current_tip.height(),
            starting_boundary,
        ) {
            Some(r) => r,
            None => {
                // The scan-range loop is about to exit without scanning the tip
                // block — e.g. when the wallet has no shielded scan work and
                // `suggest_scan_ranges` returns nothing in the bands the filter
                // accepts. That would leave `block_metadata(chain_height)`
                // unpopulated, which strands any caller asking the wallet for its
                // view of the tip via `getwalletstatus.wallet_tip` (cf.
                // integration-tests `rebuild_cache`).
                //
                // Best-effort: commit metadata for the tip block here, against the
                // *same* `chain_view` snapshot we just read `current_tip` from so
                // tree state and the block payload come from a single consistent
                // chain view. If the indexer can't serve the block right now, log
                // and continue — `steady_state` will populate metadata as soon as
                // the index catches up. We skip at height 0 because `scan_block`
                // would ask for `tree_state_as_of(height - 1)` and underflow on
                // `BlockHeight`; there is also no useful work to do at genesis.
                if current_tip.height() > BlockHeight::from_u32(0)
                    && db_data.block_metadata(current_tip.height())?.is_none()
                {
                    let attempt = async {
                        let tip_block = chain_view
                            .get_block(current_tip.height())
                            .await
                            .map_err(SyncError::Chain)?
                            .ok_or_else(|| {
                                SyncError::Chain(ChainError::backend(format!(
                                    "chain view did not return its own tip \
                                     block at height {}",
                                    current_tip.height()
                                )))
                            })?;
                        steps::scan_block(
                            &chain_view,
                            db_data,
                            params,
                            tip_block,
                            &decryptor,
                            shutdown_height,
                        )
                        .await
                    };
                    // Only transient failures may be swallowed here. `initialize` hands
                    // `current_tip` to `steady_state` as its starting `prev_tip` whether or
                    // not this scan committed anything, so ignoring a real error leaves
                    // `steady_state` believing the wallet is at a block it never stored. The
                    // next tip change then finds no wallet hash at that height, locates a
                    // lower fork point, and misreads the situation as a reorg -- which is
                    // one way the wallet's tree ends up diverging from the chain's.
                    match attempt.await {
                        Ok(_) => {}
                        Err(e) if is_retryable(&e) => warn!(
                            "Best-effort tip scan during initialize failed; \
                             steady_state will populate metadata once the indexer \
                             catches up: {e}"
                        ),
                        Err(e) => return Err(e),
                    }
                }
                break (current_tip, starting_boundary);
            }
        };

        match steps::scan_blocks(
            chain_view,
            db_data,
            params,
            &scan_range,
            &decryptor,
            shutdown_height,
        )
        .await
        {
            Ok(flow) if flow.is_break() => {
                // The chain has already reached the consensus-divergence height during
                // initial scanning. Stop here with the tip we have; `steady_state` will
                // shut the wallet down rather than advance past the boundary.
                break (current_tip, starting_boundary);
            }
            Ok(_) => {}
            // A stale-view error here means the initial "Verify"/catch-up scan captured
            // a snapshot referencing a non-finalized block that was reorged away before
            // it could be read — the same transient condition `steady_state` already
            // tolerates (see `is_retryable`). Unlike `steady_state`'s loop, this one has
            // no built-in retry, so without this it crashed the whole wallet on startup
            // whenever a reorg happened to be in progress right as it started.
            Err(error) if is_retryable(&error) => {
                warn!(
                    "Chain view became stale during initial scan, re-pinning to the current tip: {error}"
                );
                time::sleep(REORG_RETRY_BACKOFF).await;
            }
            Err(error) => return Err(error),
        }
    };

    // Publish the height to which the wallet is now fully scanned, so the RPC layer can
    // tell whether the wallet has caught up enough to be usable.
    status.set_fully_synced(db_data.block_fully_scanned()?.map(|m| m.block_height()));

    info!(
        "Initial boundary between recovery and steady-state sync is {}",
        starting_boundary,
    );
    Ok((current_tip, starting_boundary))
}

/// How long to wait before re-pinning the chain view after a stale-view error, so a
/// backend that is briefly unable to serve reads (still syncing its non-finalized state,
/// or a reorg in progress) is not polled in a tight loop.
const REORG_RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// Whether a sync error reflects a chain view that went stale mid-read — the captured
/// snapshot referenced a non-finalized block that was reorged away — and so should be
/// retried by re-pinning to the current tip, rather than propagated as fatal.
fn is_retryable(error: &SyncError) -> bool {
    matches!(error, SyncError::Chain(ChainError::Unavailable(_)))
}

/// How far back to step each time the wallet's recorded history is found to be off the
/// backend's best chain. Reorgs are almost always only a few blocks, so the fallback walk
/// below is rarely exercised; it mirrors the mobile wallets, which on a hash mismatch
/// truncate and step back a small fixed amount at a time along their own view of the chain.
const FORK_SEARCH_STEP: u32 = 10;

/// Locates the block from which to resume scanning after the wallet's view of the chain
/// diverges from the backend's best chain.
///
/// First asks the backend for the most recent entry of a [block locator](locator) spanning
/// the reorg window that is on the best chain, which resolves ordinary reorgs in a single
/// round-trip. An **empty** locator means the wallet has no recorded history yet (a fresh
/// wallet), so it simply syncs forward from `prev_tip`.
///
/// If the wallet has fallen far enough behind that its recorded history is below the
/// backend's non-finalized state — so `find_fork_point` cannot locate the divergence — the
/// search falls back to the mobile-wallet behaviour: walk the wallet's own view of the
/// chain back [`FORK_SEARCH_STEP`] blocks at a time, comparing each of the wallet's block
/// hashes against the backend's best chain, until one matches (the resume point) or the
/// wallet birthday is reached (a genuine divergence, which halts syncing).
async fn locate_fork_point<V: ChainView>(
    chain_view: &V,
    db_data: &DbConnection,
    prev_tip: ChainBlock,
) -> Result<ChainBlock, SyncError> {
    let birthday = db_data
        .get_wallet_birthday()?
        .unwrap_or(BlockHeight::from_u32(0));

    // Fast path: locate the fork point within the reorg window in one round-trip.
    let locator = locator::build_block_locator(db_data, prev_tip.height())?;
    match chain_view
        .find_fork_point(&locator)
        .await
        .map_err(SyncError::Chain)?
    {
        Some(fork_point) => return Ok(fork_point),
        // A fresh wallet has no recorded history to fork from; sync forward from prev_tip.
        None if locator.hashes().is_empty() => return Ok(prev_tip),
        None => {}
    }

    // The wallet's recent history is not on the best chain. Walk its own view of the chain
    // back a fixed step at a time, looking for one of its blocks still on the best chain.
    debug!(
        "wallet tip {} (height {}) is not on the best chain; stepping back to find a resume point",
        prev_tip.hash(),
        prev_tip.height(),
    );
    step_back_to_best_chain(chain_view, prev_tip, birthday, |height| {
        Ok(db_data.get_block_hash(height)?)
    })
    .await
}

/// How far below the wallet's tip each successive note-commitment-tree recovery attempt rolls
/// back, in blocks.
///
/// The rungs are: one block (a single bad checkpoint); the wallet's per-block checkpoint depth,
/// which drops out of that window onto the retained periodic anchors; then anchor-interval
/// multiples growing by 4x. The last rung reaches roughly two and a half weeks below the tip,
/// which covers a divergence introduced well before it was noticed, without letting a
/// misdiagnosis walk the wallet back to its birthday one attempt at a time.
///
/// These mirror `zcash_client_sqlite`'s pruning depth (100) and `zcash_client_backend`'s anchor
/// retention interval (288). Both are crate-private upstream, so they are duplicated here; the
/// exact values only affect how quickly recovery escalates, not its correctness.
const TREE_RECOVERY_LADDER: &[u32] = &[1, 100, 288, 288 * 4, 288 * 16, 288 * 64];

/// How many times [`recover_history`] re-attempts a scan that failed with a note commitment
/// tree divergence before giving up, and the delay before each retry.
///
/// History recovery does not repair the tree itself; it waits for [`steady_state`], which owns
/// that recovery, to rewind and re-queue the affected ranges underneath it. These bound how
/// long it is willing to wait.
const TREE_DIVERGENCE_RETRIES: u32 = 5;
const TREE_DIVERGENCE_BACKOFF: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(15),
    Duration::from_secs(30),
];

/// Whether an error means the wallet's note commitment tree disagrees with the chain's.
///
/// This is a different condition from [`SqliteClientError::BlockConflict`], which says the
/// wallet is on a *different chain* at a known height and is resolved by the fork-point search.
/// A tree conflict says the wallet's *tree* disagrees, which happens both after an undetected
/// reorg and while the wallet is on the canonical chain — for instance when it stored a
/// frontier that was wrong at the time and only now meets one that contradicts it. In the
/// latter case the fork-point search finds nothing wrong and cannot help, so this class needs
/// its own recovery.
///
/// All three variants are included because the same physical failure surfaces under different
/// ones depending on which code path hit it.
fn is_tree_divergence(error: &SyncError) -> bool {
    match error {
        SyncError::Tree(_) => true,
        SyncError::Other(e) => matches!(
            **e,
            SqliteClientError::PutBlocksCommitmentTree { .. }
                | SqliteClientError::CommitmentTree(_)
                | SqliteClientError::TruncateCommitmentTree { .. }
        ),
        _ => false,
    }
}

/// Bookkeeping for note-commitment-tree divergence recovery, carried across [`steady_state`]
/// loop iterations.
#[derive(Debug, Default, PartialEq, Eq)]
struct TreeRecovery {
    /// Rollback attempts made since the divergence was first observed.
    attempts: usize,
    /// The wallet tip at which the divergence was first observed.
    ///
    /// Recovery counts as successful, and `attempts` resets, only once the wallet climbs back
    /// *above* this. Resetting on any successful scan instead would let a one-block rollback
    /// followed by a one-block rescan cycle forever: each rescan would look like progress,
    /// clear the counter, and hit the same conflict again with the ladder back at its first
    /// rung.
    high_water: Option<BlockHeight>,
}

impl TreeRecovery {
    /// Records a divergence observed with the wallet at `wallet_tip`, returning how far below
    /// it to roll back, or `None` once the attempt budget is exhausted.
    fn next_depth(&mut self, wallet_tip: BlockHeight) -> Option<u32> {
        self.high_water.get_or_insert(wallet_tip);
        let depth = TREE_RECOVERY_LADDER.get(self.attempts).copied()?;
        self.attempts += 1;
        Some(depth)
    }

    /// Records that the wallet has scanned up to `wallet_tip`, returning whether this cleared
    /// an in-progress recovery.
    fn note_progress(&mut self, wallet_tip: BlockHeight) -> bool {
        match self.high_water {
            Some(high_water) if wallet_tip > high_water => {
                *self = Self::default();
                true
            }
            _ => false,
        }
    }

    /// The tip at which the current divergence was first seen, for error reporting.
    fn observed_at(&self, wallet_tip: BlockHeight) -> BlockHeight {
        self.high_water.unwrap_or(wallet_tip)
    }
}

/// The height to roll back to for a tree-divergence recovery attempt of the given `depth`,
/// floored at the wallet's `birthday`.
///
/// Returns `None` when the floor leaves nowhere to go: rolling back to where the wallet already
/// is cannot make progress, and retrying from there would spin.
fn tree_recovery_target(
    wallet_tip: BlockHeight,
    depth: u32,
    birthday: BlockHeight,
) -> Option<BlockHeight> {
    let target = BlockHeight::from_u32(
        u32::from(wallet_tip)
            .saturating_sub(depth)
            .max(u32::from(birthday)),
    );
    (target < wallet_tip).then_some(target)
}

/// Resolves the block to resume scanning from after a rewind, given the height the wallet was
/// asked to rewind to and the block it actually landed on.
///
/// Split out from [`truncate_to_wallet_checkpoint`] so the decision is testable without a
/// database.
fn resume_point(
    requested: BlockHeight,
    actual: Option<(BlockHeight, BlockHash)>,
) -> Result<ChainBlock, SyncError> {
    let (height, hash) = actual.ok_or_else(|| {
        SyncError::Chain(ChainError::backend(format!(
            "the wallet has no block recorded at {requested} after truncating to it",
        )))
    })?;

    if height < requested {
        warn!(
            "Requested a rewind to {requested}, but the wallet could only rewind to {height} \
             (older checkpoints have been pruned); resuming from {}",
            height + 1,
        );
    }

    Ok(ChainBlock::new(height, hash))
}

/// Truncates the wallet to `target`, returning the block the wallet actually ended up on.
///
/// [`WalletWrite::truncate_to_height`] snaps the request *down* to the highest height that is
/// a checkpoint in every active pool's note commitment tree. Checkpoints are pruned beyond a
/// bounded depth, retaining only periodic anchors below that, so for a rollback deeper than
/// that window the wallet can land well below `target`.
///
/// Callers must resume scanning from the block this returns, not from `target`. Resuming from
/// `target + 1` after landing lower leaves a gap in the wallet's history and applies the
/// blocks above it onto a stale frontier, which silently diverges the wallet's note commitment
/// tree from the chain's and only surfaces later as an unrecoverable `shardtree` conflict.
fn truncate_to_wallet_checkpoint(
    db_data: &mut DbConnection,
    target: BlockHeight,
) -> Result<ChainBlock, SyncError> {
    let actual = match db_data.truncate_to_height(target) {
        Ok(height) => height,
        // No shared checkpoint at or below `target`, but the wallet told us the lowest height
        // it can reach. Rewinding further than asked is always safe: it only means rescanning
        // more. Rewinding *less* far is what corrupts the tree.
        Err(SqliteClientError::RequestedRewindInvalid {
            safe_rewind_height: Some(safe),
            requested_height,
        }) => {
            warn!(
                "The wallet cannot rewind to {requested_height}; rewinding to the lowest \
                 available checkpoint {safe} instead",
            );
            db_data.truncate_to_height(safe)?
        }
        Err(e) => return Err(e.into()),
    };

    // `truncate_to_height` deletes `blocks` rows strictly above the height it returns, so the
    // row at that height survives and its hash is the wallet's new tip.
    resume_point(actual, db_data.get_block_hash(actual)?.map(|h| (actual, h)))
}

/// Rolls the wallet back to recover from a note commitment tree divergence, returning the
/// block to resume scanning from.
///
/// Each call rolls back further than the last (see [`TREE_RECOVERY_LADDER`]), because the
/// conflicting data can be arbitrarily far below where the conflict was noticed: the wallet
/// stores a bad frontier silently and only fails when a later, correct one contradicts it.
/// Truncation removes tree data above the checkpoint it lands on, so a rollback only repairs
/// the wallet if it reaches past the bad data.
///
/// Recovery is bounded, and gives up with [`SyncError::WalletTreeDiverged`] rather than
/// rewinding indefinitely: past the ladder's reach the wallet is rescanning a lot of history
/// on a guess, and the operator is better placed to choose.
fn recover_from_tree_divergence(
    db_data: &mut DbConnection,
    prev_tip: &ChainBlock,
    recovery: &mut TreeRecovery,
) -> Result<ChainBlock, SyncError> {
    let birthday = db_data
        .get_wallet_birthday()?
        .unwrap_or(BlockHeight::from_u32(0));
    // Take the next rung first: it also records the high-water mark that `observed_at` reads.
    let depth = recovery.next_depth(prev_tip.height());
    let observed_at = recovery.observed_at(prev_tip.height());
    let give_up = move |rolled_back_to| SyncError::WalletTreeDiverged {
        observed_at,
        rolled_back_to,
        birthday,
    };

    let target = depth
        .and_then(|depth| tree_recovery_target(prev_tip.height(), depth, birthday))
        .ok_or_else(|| give_up(prev_tip.height()))?;

    let resume_from = truncate_to_wallet_checkpoint(db_data, target)?;

    // A rung that did not actually move the wallet down cannot break the conflict, and
    // retrying from the same place would spin. This is reachable even with a target below
    // `prev_tip`: truncation snaps to a checkpoint, and if the wallet is already sitting on
    // the lowest one it has, it stays put.
    if resume_from.height() >= prev_tip.height() {
        return Err(give_up(resume_from.height()));
    }

    Ok(resume_from)
}

/// The next height to probe when walking back from `height` toward `birthday`, and whether
/// that probe is the birthday floor (so the search must stop after it).
fn rewind_step(height: BlockHeight, birthday: BlockHeight) -> (BlockHeight, bool) {
    let next = u32::from(height)
        .saturating_sub(FORK_SEARCH_STEP)
        .max(u32::from(birthday));
    (BlockHeight::from_u32(next), next <= u32::from(birthday))
}

/// Walks the wallet's own view of the chain back from `prev_tip` a fixed [`FORK_SEARCH_STEP`]
/// at a time, returning the first of the wallet's blocks whose hash is on the backend's best
/// chain — the point to resume scanning from. `wallet_hash` supplies the wallet's recorded
/// block hash at a height (`None` if it has none there).
///
/// Returns [`SyncError::WalletDivergedBelowBirthday`] if the walk reaches the wallet birthday
/// without rejoining the best chain.
async fn step_back_to_best_chain<V, F>(
    chain_view: &V,
    prev_tip: ChainBlock,
    birthday: BlockHeight,
    wallet_hash: F,
) -> Result<ChainBlock, SyncError>
where
    V: ChainView,
    F: Fn(BlockHeight) -> Result<Option<BlockHash>, SyncError>,
{
    let mut height = prev_tip.height();
    loop {
        let (next, reached_birthday) = rewind_step(height, birthday);
        height = next;
        if let Some(wh) = wallet_hash(height)? {
            let best_chain_hash = chain_view
                .get_block_header(height)
                .await
                .map_err(SyncError::Chain)?
                .map(|header| header.hash());
            if best_chain_hash == Some(wh) {
                return Ok(ChainBlock::new(height, wh));
            }
        }
        if reached_birthday {
            return Err(SyncError::WalletDivergedBelowBirthday { birthday });
        }
    }
}

/// Keeps the wallet state up-to-date with the chain tip, and handles the mempool.
#[tracing::instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
async fn steady_state<C: Chain>(
    chain: C,
    params: &Network,
    db_data: &mut DbConnection,
    mut prev_tip: ChainBlock,
    lower_boundary: Arc<AtomicU32>,
    tip_change_signal: Arc<Notify>,
    decryptor: WalletDecryptorHandle,
    shutdown_height: Option<BlockHeight>,
    status: SyncStatusWriter,
) -> Result<(), SyncError> {
    info!("Steady-state sync task started");

    // Wake up any tasks waiting on the tip-change signal, so they can service work that
    // accumulated while the wallet was offline.
    tip_change_signal.notify_one();

    let mut tree_recovery = TreeRecovery::default();

    loop {
        match steady_state_iteration(
            &chain,
            params,
            db_data,
            &mut prev_tip,
            &lower_boundary,
            &tip_change_signal,
            &decryptor,
            shutdown_height,
            &status,
        )
        .await
        {
            Ok(ControlFlow::Continue(())) => {
                if tree_recovery.note_progress(prev_tip.height()) {
                    info!(
                        "Wallet recovered from the note commitment tree divergence; rescanned \
                         past {}",
                        prev_tip.height(),
                    );
                }
            }
            // The chain reached a consensus-divergence height. Warn and end the task, which
            // triggers a graceful shutdown of the whole wallet. The iteration reports the
            // boundary height it stopped at, so we log that directly.
            Ok(ControlFlow::Break(height)) => {
                warn!(
                    "{}",
                    fl!(
                        "warn-init-consensus-divergence-reached",
                        height = u32::from(height)
                    )
                );
                return Ok(());
            }
            Err(error) => {
                // A stale-view error means the captured snapshot referenced a non-finalized
                // block that was reorged away mid-read. Discard the view, pause briefly, and
                // loop to re-pin to the current tip. Progress already committed to the wallet
                // (and recorded in `prev_tip`) is preserved across the retry.
                if is_retryable(&error) {
                    warn!("Chain view became stale, re-pinning to the current tip: {error}");
                    time::sleep(REORG_RETRY_BACKOFF).await;
                    continue;
                }
                // A block conflict means the backend's best chain reorged away the block
                // previously stored at this height. The conflict only tells us that
                // *this* height is wrong, not how deep the reorg actually goes — a reorg
                // that replaced more than one block would leave the block just below the
                // conflict wrong too, and `put_block` only ever checks for a collision at
                // the exact height it's writing, not that its parent still matches what's
                // stored one below it. So don't assume a depth-1 rewind is enough: treat
                // the wallet's last known-good position (`height - 1`) as a fresh
                // "previous tip" and run it through the same fork-point search used for
                // ordinary reorg detection, which walks back as far as it actually needs to.
                if let SyncError::Other(ref e) = error
                    && let SqliteClientError::BlockConflict(height) = **e
                {
                    let rewind_height = height - 1;
                    warn!(
                        "Block at height {height} conflicts with previously stored data \
                         (likely a reorg); searching for the fork point and retrying"
                    );
                    let candidate_tip = ChainBlock::new(
                        rewind_height,
                        db_data.get_block_hash(rewind_height)?.ok_or_else(|| {
                            SyncError::WalletDivergedBelowBirthday {
                                birthday: rewind_height,
                            }
                        })?,
                    );
                    let chain_view = chain.snapshot().await.map_err(SyncError::Chain)?;
                    let fork_point = locate_fork_point(&chain_view, db_data, candidate_tip).await?;
                    // Enter the recovering (safe-mode) state for the rewind and rescan;
                    // `steady_state_iteration` clears it once we reach the chain tip again.
                    // The wallet may only be able to rewind below the fork point, so resume
                    // from wherever it actually landed.
                    let resume_from = truncate_to_wallet_checkpoint(db_data, fork_point.height())?;
                    status.begin_recovery(resume_from.height());
                    prev_tip = resume_from;
                    continue;
                }
                // The wallet's note commitment tree disagrees with the chain's. Unlike a block
                // conflict this is not necessarily a reorg, so the fork-point search cannot
                // resolve it -- on the canonical chain it would find nothing wrong and rewind
                // nowhere. `put_blocks` is transactional, so without recovery here the failing
                // write rolls back, the task exits, and (since any sync-task exit shuts the
                // process down) the wallet crash-loops on the same block forever. Roll back to
                // a progressively older checkpoint and rescan instead.
                if is_tree_divergence(&error) {
                    warn!(
                        "The wallet's note commitment tree diverges from the chain's at {}; \
                         rolling back and rescanning (attempt {} of {}): {error}",
                        prev_tip.height(),
                        tree_recovery.attempts + 1,
                        TREE_RECOVERY_LADDER.len(),
                    );
                    let resume_from =
                        recover_from_tree_divergence(db_data, &prev_tip, &mut tree_recovery)?;
                    status.begin_recovery(resume_from.height());
                    prev_tip = resume_from;
                    continue;
                }
                return Err(error);
            }
        }
    }
}

/// Performs one pass of [`steady_state`]: captures a fresh chain view, applies any new or
/// reorged blocks to the wallet (advancing `prev_tip`), then streams the mempool until the
/// view's tip changes.
#[allow(clippy::too_many_arguments)]
async fn steady_state_iteration<C: Chain>(
    chain: &C,
    params: &Network,
    db_data: &mut DbConnection,
    prev_tip: &mut ChainBlock,
    lower_boundary: &AtomicU32,
    tip_change_signal: &Notify,
    decryptor: &WalletDecryptorHandle,
    shutdown_height: Option<BlockHeight>,
    status: &SyncStatusWriter,
) -> Result<ControlFlow<BlockHeight>, SyncError> {
    let chain_view = chain.snapshot().await.map_err(SyncError::Chain)?;
    let current_tip = chain_view.tip().await.map_err(SyncError::Chain)?;
    let tip_changed = current_tip != *prev_tip;

    if tip_changed {
        info!(
            "New chain tip: {} {}",
            current_tip.height(),
            current_tip.hash()
        );
        lower_boundary
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current_boundary| {
                Some(
                    update_boundary(
                        BlockHeight::from_u32(current_boundary),
                        current_tip.height(),
                    )
                    .into(),
                )
            })
            .expect("closure always returns Some");
        tip_change_signal.notify_one();
        status.set_tip(current_tip.height());

        // Find where the wallet's history rejoins the backend's best chain.
        let fork_point = locate_fork_point(&chain_view, db_data, *prev_tip).await?;
        assert!(fork_point.height() <= current_tip.height());

        // If the fork point is equal to `prev_tip` then no reorg has occurred.
        if fork_point != *prev_tip {
            // Ensured by `find_fork_point`.
            assert!(fork_point.height() < prev_tip.height());

            // Rewind the wallet to the fork point. `truncate_to_height` fully resets
            // the wallet state to that height, so the blocks in the old fork need no
            // further handling.
            info!(
                "Chain reorg detected, rewinding to {} {}",
                fork_point.height(),
                fork_point.hash()
            );
            // Enter the recovering (safe-mode) state for the duration of the rewind and
            // rescan; it is cleared below once we reach the chain tip again.
            // The wallet may only be able to rewind below the fork point, so resume from
            // wherever it actually landed rather than assuming the fork point.
            let resume_from = truncate_to_wallet_checkpoint(db_data, fork_point.height())?;
            status.begin_recovery(resume_from.height());
            *prev_tip = resume_from;
        };

        // Fetch blocks that need to be applied to the wallet. This must be built *after* any
        // rewind above: the wallet can land below the fork point, and streaming from the fork
        // point would skip the blocks in between, applying the rest onto a stale frontier.
        let blocks_to_apply = chain_view.stream_blocks_to_tip(prev_tip.height() + 1);
        tokio::pin!(blocks_to_apply);

        // Notify the wallet of block connections.
        while let Some(block) = blocks_to_apply.try_next().await.map_err(SyncError::Chain)? {
            let height = block.claimed_height();
            assert_eq!(height, prev_tip.height() + 1);
            let current_block = ChainBlock::new(height, block.header().hash());

            // `scan_block` refuses to scan at or above a known consensus-divergence height,
            // reporting the boundary instead. From there the backing node follows rules this
            // build cannot interpret, so we stop without recording the unscanned block as our
            // tip; ending the task triggers a graceful shutdown.
            match steps::scan_block(
                &chain_view,
                db_data,
                params,
                block,
                decryptor,
                shutdown_height,
            )
            .await?
            {
                ControlFlow::Break(boundary) => return Ok(ControlFlow::Break(boundary)),
                ControlFlow::Continue(()) => {}
            }
            db_data.update_chain_tip(height)?;

            // Now that we're done applying the block, update our chain pointer.
            *prev_tip = current_block;
        }
    }

    // The backing node's tip may itself sit at or beyond the divergence height — e.g. the
    // chain advanced past it between the startup compatibility check and now, leaving the
    // apply loop above with no blocks below the boundary to scan. In that case we must not
    // stream its mempool either, as those transactions are validated under rules this build
    // cannot interpret. Stop and shut down.
    if let Some(boundary) = shutdown_height.filter(|h| current_tip.height() >= *h) {
        return Ok(ControlFlow::Break(boundary));
    }

    // The wallet has applied every block up to the current tip. Publish how far it is
    // fully scanned (which also reflects `recover_history`'s backfill), mark that steady
    // state has reached the tip, and clear any recovering state now that the rewind (if
    // any) has been rescanned.
    status.set_fully_synced(db_data.block_fully_scanned()?.map(|m| m.block_height()));
    status.mark_tip_reached();
    // TODO(zcash/zallet#195): when this actually clears an in-progress recovery (i.e. on
    // the `Recovering` → synced edge, not on every tip-reached), trigger an online backup
    // so the recovered state is durably captured before any subsequent failure.
    status.end_recovery();

    // If we have caught up to the chain tip, stream the mempool state into the wallet.
    match chain_view
        .get_mempool_stream()
        .await
        .map_err(SyncError::Chain)?
    {
        Some(mempool_stream) => {
            info!("Reached chain tip, streaming mempool");
            tokio::pin!(mempool_stream);
            while let Some(tx) = mempool_stream.next().await {
                info!("Scanning mempool tx {}", tx.txid());
                // TODO: Route individual-transaction scanning through the batch
                // decryptor (`Handle::queue_tx`) once a single-tx store path exists.
                // See zcash/zallet#477.
                decrypt_and_store_transaction(params, db_data, &tx, None)?;
            }

            // Mempool stream ended, signalling that the chain tip has changed.
        }
        // The chain tip already changed since this view was captured; loop around
        // immediately to observe it.
        //
        // Yield to the runtime and pause briefly before re-iterating. `snapshot`,
        // `tip`, and `get_mempool_stream` can all return `Poll::Ready` from cached
        // state (MockChain does, and the Zaino `FetchServiceSubscriber` was observed
        // doing so in #136), so without this yield an aborted `steady_state` task
        // can complete a full iteration without ever polling its abort status,
        // spinning until the backend's view changes. The yield lets tokio observe
        // the abort and end the task; the sleep bounds the CPU cost of a non-aborted
        // task that is legitimately re-polling a backend serving a stale cached view
        // (a backend contract violation, but one Zaino has been observed to exhibit).
        None if tip_changed => {
            tokio::task::yield_now().await;
            time::sleep(Duration::from_millis(500)).await;
        }
        // The chain tip has not changed, and no mempool stream is available (e.g.
        // because the chain indexer is still syncing its finalized state). Pause
        // briefly to avoid spinning.
        None => time::sleep(Duration::from_millis(500)).await,
    }

    Ok(ControlFlow::Continue(()))
}

/// Recovers historic wallet state.
///
/// This function only operates on finalized chain state, and does not handle reorgs.
#[tracing::instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
async fn recover_history<C: Chain>(
    chain: C,
    params: &Network,
    db_data: &mut DbConnection,
    upper_boundary: Arc<AtomicU32>,
    decryptor: WalletDecryptorHandle,
    batch_size: u32,
    shutdown_height: Option<BlockHeight>,
    status: SyncStatusWriter,
) -> Result<(), SyncError> {
    info!("History recovery sync task started");

    let mut interval = time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    // The first tick completes immediately. We want to use it for a conditional delay, so
    // get that out of the way.
    interval.tick().await;

    loop {
        // Get the next suggested scan range. We drop the rest because we re-fetch the
        // entire list regularly.
        let upper_boundary = BlockHeight::from_u32(upper_boundary.load(Ordering::Acquire));
        let scan_range = match db_data
            .suggest_scan_ranges()?
            .into_iter()
            .filter_map(|r| r.truncate_end(upper_boundary))
            .next()
        {
            Some(r) => r,
            None => {
                // Wait for scan ranges to become available.
                debug!("No scan ranges, sleeping");
                interval.tick().await;
                continue;
            }
        };

        // Limit the number of blocks we download and scan at any one time.
        for scan_range in (0..).scan(Some(scan_range), |acc, _| {
            acc.clone().map(|remaining| {
                if let Some((cur, next)) =
                    remaining.split_at(remaining.block_range().start + batch_size)
                {
                    *acc = Some(next);
                    cur
                } else {
                    *acc = None;
                    remaining
                }
            })
        }) {
            // A note commitment tree divergence can surface here just as easily as in
            // `steady_state`, but this task must not repair it: it holds its own database
            // connection, so rolling back here would race `steady_state` doing the same.
            // `steady_state` owns that recovery and re-queues the affected ranges, so wait
            // for it rather than failing immediately -- an exit here shuts the whole wallet
            // down.
            let mut attempt = 0;
            let outcome = loop {
                let chain_view = chain.snapshot().await.map_err(SyncError::Chain)?;
                match steps::scan_blocks(
                    chain_view,
                    db_data,
                    params,
                    &scan_range,
                    &decryptor,
                    shutdown_height,
                )
                .await
                {
                    Ok(outcome) => break outcome,
                    Err(error)
                        if is_tree_divergence(&error) && attempt < TREE_DIVERGENCE_RETRIES =>
                    {
                        let backoff = TREE_DIVERGENCE_BACKOFF[attempt as usize];
                        warn!(
                            "History recovery hit a note commitment tree divergence scanning \
                             {scan_range}; waiting {backoff:?} for steady-state sync to repair \
                             it (attempt {} of {TREE_DIVERGENCE_RETRIES}): {error}",
                            attempt + 1,
                        );
                        time::sleep(backoff).await;
                        attempt += 1;
                    }
                    Err(error) => return Err(error),
                }
            };
            if outcome.is_break() {
                // Reached the consensus-divergence height. History recovery operates below
                // the boundary in practice, so this is belt-and-suspenders; stop scanning
                // this range and let the next loop re-evaluate.
                break;
            }

            // Backfilling historic ranges advances the fully-scanned height; republish it
            // so the RPC layer sees the wallet approach a complete view of the chain.
            status.set_fully_synced(db_data.block_fully_scanned()?.map(|m| m.block_height()));

            // If scanning these blocks caused a suggested range to be added that has a
            // higher priority than the current range, invalidate the current ranges.
            let latest_ranges = db_data.suggest_scan_ranges()?;
            let scan_ranges_updated = latest_ranges
                .first()
                .is_some_and(|range| range.priority() > scan_range.priority());

            if scan_ranges_updated {
                break;
            }
        }
    }
}

/// Computes the half-open block range `[start, end)` to query for a transparent-address data
/// request, and the height to report to `notify_address_checked` as the highest block inspected.
///
/// `block_range_end` is exclusive; when unset it defaults to one past `view_tip` so the tip block
/// is covered, and an explicit end is clamped to that bound. `as_of_height` is the last block
/// covered (`end - 1`).
#[cfg(not(feature = "spend-index"))]
fn address_request_bounds(
    block_range_start: BlockHeight,
    block_range_end: Option<BlockHeight>,
    view_tip: BlockHeight,
) -> (Range<BlockHeight>, BlockHeight) {
    let tip_exclusive = view_tip + 1;
    let end = block_range_end
        .map(|e| std::cmp::min(e, tip_exclusive))
        .unwrap_or(tip_exclusive);
    let end = std::cmp::max(end, block_range_start);
    let as_of_height = BlockHeight::from_u32(u32::from(end).saturating_sub(1));
    (block_range_start..end, as_of_height)
}

/// Services a [`TransactionDataRequest::TransactionsInvolvingAddress`] spend-search request on a
/// backend without a per-outpoint spend index (the `zaino` build).
///
/// Cheap path first: diff the wallet's tracked unspent outputs at the address against the chain's
/// current unspent set. Only if one of ours is missing (i.e. actually spent on chain) is the
/// potentially-large address transaction history fetched and ingested to record the spend. The
/// address is then recorded as checked so the request is not re-issued for the same range. (For
/// requests with no tracked outputs at the address — e.g. ephemeral-address discovery — this just
/// advances the watermark; full-block scanning covers those receipts.)
#[cfg(not(feature = "spend-index"))]
async fn service_address_request<V: ChainView>(
    chain_view: &V,
    params: &Network,
    db_data: &mut DbConnection,
    request: TransactionsInvolvingAddress,
    view_tip: BlockHeight,
) -> Result<(), SyncError> {
    let address = request.address();
    let (range, as_of_height) = address_request_bounds(
        request.block_range_start(),
        request.block_range_end(),
        view_tip,
    );

    let chain_unspent: HashSet<(TxId, u32)> = chain_view
        .get_address_unspent_outpoints(&address)
        .await
        .map_err(SyncError::Chain)?
        .into_iter()
        .collect();
    let our_outputs = db_data.get_spendable_transparent_outputs(
        &address,
        TargetHeight::from(view_tip + 1),
        ConfirmationsPolicy::MIN,
        CoinbaseFilter::AllTransparentOutputs,
        // This is spend detection, not input selection: we need every tracked output
        // regardless of lock state to compare against the chain's unspent set, so a
        // locked output is not mistaken for a spent one.
        LockFilter::Unfiltered,
    )?;
    let any_spent = our_outputs.iter().any(|output| {
        let outpoint = output.outpoint();
        !chain_unspent.contains(&(*outpoint.txid(), outpoint.n()))
    });

    if any_spent {
        let txids = chain_view
            .get_address_tx_ids(&address, range)
            .await
            .map_err(SyncError::Chain)?;
        for txid in txids {
            if let Some(tx) = chain_view
                .get_transaction(txid)
                .await
                .map_err(SyncError::Chain)?
            {
                decrypt_and_store_transaction(params, db_data, tx.inner(), tx.mined_height())?;
            }
        }
    }

    db_data.notify_address_checked(request, as_of_height)?;
    Ok(())
}

/// Fetches information that the wallet requests to complete its view of transaction
/// history.
#[tracing::instrument(skip_all)]
async fn data_requests<C: Chain>(
    chain: C,
    params: &Network,
    db_data: &mut DbConnection,
    tip_change_signal: Arc<Notify>,
) -> Result<(), SyncError> {
    loop {
        // Wait for the chain tip to advance
        tip_change_signal.notified().await;

        let chain_view = chain.snapshot().await.map_err(SyncError::Chain)?;

        let requests = db_data.transaction_data_requests()?;
        if requests.is_empty() {
            // Wait for new requests.
            debug!("No transaction data requests, sleeping until the chain tip changes.");
            continue;
        }

        let view_tip = chain_view.tip().await.map_err(SyncError::Chain)?.height();
        info!("{} transaction data requests to service", requests.len());
        for request in requests {
            match request {
                TransactionDataRequest::GetStatus(txid) => {
                    if txid.is_null() {
                        continue;
                    }

                    info!("Getting status of {txid}");
                    match chain_view.get_transaction_status(txid).await {
                        Ok(status) => db_data.set_transaction_status(txid, status)?,
                        // Invalid data from the chain source indicates a bug, corruption,
                        // or a version mismatch; retrying cannot help.
                        Err(e @ ChainError::InvalidData(_)) => return Err(SyncError::Chain(e)),
                        Err(e) => warn!("Failed to get status of {txid} (will retry): {e}"),
                    }
                }
                TransactionDataRequest::Enhancement(txid) => {
                    if txid.is_null() {
                        continue;
                    }

                    info!("Enhancing {txid}");
                    match chain_view.get_transaction(txid).await {
                        Ok(Some(tx)) => {
                            // TODO: Route individual-transaction scanning through the batch
                            // decryptor (`Handle::queue_tx`) once a single-tx store path
                            // exists. See zcash/zallet#477.
                            decrypt_and_store_transaction(
                                params,
                                db_data,
                                tx.inner(),
                                tx.mined_height(),
                            )?;
                        }
                        Ok(None) => {
                            db_data.set_transaction_status(
                                txid,
                                TransactionStatus::TxidNotRecognized,
                            )?;
                        }
                        // Invalid data from the chain source indicates a bug, corruption,
                        // or a version mismatch; retrying cannot help.
                        Err(e @ ChainError::InvalidData(_)) => return Err(SyncError::Chain(e)),
                        Err(e) => warn!("Failed to enhance {txid} (will retry): {e}"),
                    }
                }
                // With `spend-index`, spend detection uses `GetSpendingTx` (below) and any
                // remaining `TransactionsInvolvingAddress` requests are ephemeral-address
                // discovery, covered by full-block scanning. Without it (the `zaino` build),
                // these carry the spend-search requests and are serviced via address queries.
                #[cfg(feature = "spend-index")]
                TransactionDataRequest::TransactionsInvolvingAddress(_) => (),
                #[cfg(not(feature = "spend-index"))]
                TransactionDataRequest::TransactionsInvolvingAddress(request) => {
                    if let Err(e) =
                        service_address_request(&chain_view, params, db_data, request, view_tip)
                            .await
                    {
                        warn!("Failed to service transparent-address data request: {e}");
                    }
                }
                #[cfg(feature = "spend-index")]
                TransactionDataRequest::GetSpendingTx(outpoint) => {
                    use crate::components::chain::SpendStatus;
                    match chain_view.outpoint_spend_status(&outpoint).await {
                        Ok(SpendStatus::Unspent) => {
                            // Confirmed unspent through the snapshot tip; record so the request
                            // is not re-issued for this range.
                            db_data.notify_output_verified_unspent(outpoint, view_tip)?;
                        }
                        Ok(SpendStatus::SpentBy(txid)) => {
                            info!("Recovering spend of {outpoint:?} by {txid}");
                            if let Some(tx) = chain_view
                                .get_transaction(txid)
                                .await
                                .map_err(SyncError::Chain)?
                            {
                                decrypt_and_store_transaction(
                                    params,
                                    db_data,
                                    tx.inner(),
                                    tx.mined_height(),
                                )?;
                            }
                        }
                        Ok(SpendStatus::SpentSpenderUnknown) => {
                            // Spent, but the spend index has not yet recorded the spender
                            // (ZcashFoundation/zebra#10806); leave queued to retry later.
                            debug!("Spend of {outpoint:?} not yet resolvable; will retry");
                        }
                        Err(e) => warn!("Failed to service spend query for {outpoint:?}: {e}"),
                    }
                }
            }
        }
    }
}

/// Processes the queue of transactions that need to be scanned with the wallet's viewing
/// keys.
#[tracing::instrument(skip_all)]
async fn batch_decryptor(
    params: Network,
    db_data: &mut DbConnection,
    decryptor: decryptor::Engine<AccountUuid, (AccountUuid, Scope)>,
) -> Result<(), SyncError> {
    decryptor
        .run(params, || {
            // Fetch the UnifiedFullViewingKeys we are tracking.
            let account_ufvks = db_data.get_unified_full_viewing_keys()?;
            let scanning_keys = ScanningKeys::from_account_ufvks(account_ufvks);
            Ok::<_, SyncError>(scanning_keys)
        })
        .await
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, time::Duration};

    use super::{
        ChainError, PendingWalletSyncTasks, SyncError, TREE_RECOVERY_LADDER, TreeRecovery,
        WalletSync, is_retryable, is_tree_divergence, resume_point, rewind_step,
        select_initial_scan_range, status, steady_state, tree_recovery_target,
    };
    use crate::{
        components::{
            TaskHandle,
            chain::{ChainBlock, MockChain},
            database::Database,
        },
        config::ZalletConfig,
        error::{Error, ErrorKind},
    };
    use shardtree::error::{QueryError, ShardTreeError};
    use tokio::sync::Notify;
    use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{ShieldedPool, consensus::BlockHeight};

    struct TaskCancellationProbe(mpsc::Sender<()>);

    impl Drop for TaskCancellationProbe {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    async fn observed_pending_task(task_cancelled: mpsc::Sender<()>) -> TaskHandle {
        let cancellation_probe = TaskCancellationProbe(task_cancelled);
        let (task_started, task_started_receiver) = futures::channel::oneshot::channel();
        let task = tokio::spawn(async move {
            let _cancellation_probe = cancellation_probe;
            let _ = task_started.send(());
            std::future::pending::<Result<(), Error>>().await
        });
        task_started_receiver
            .await
            .expect("cancellation-observed task starts");
        task
    }

    async fn assert_task_cancelled(task_cancelled: mpsc::Receiver<()>) {
        tokio::task::spawn_blocking(move || task_cancelled.recv_timeout(Duration::from_secs(1)))
            .await
            .expect("cancellation observer does not panic")
            .expect("partially initialized wallet sync task is cancelled");
    }

    fn h(height: u32) -> BlockHeight {
        BlockHeight::from_u32(height)
    }

    fn hash(seed: u8) -> BlockHash {
        BlockHash([seed; 32])
    }

    // `truncate_to_height` snaps the requested height down to the highest height that is a
    // checkpoint in every pool's tree, so the wallet can land below where it was asked to
    // rewind to. Resuming from the requested height rather than the real one leaves a gap in
    // the wallet's history and applies later blocks onto a stale frontier -- the silent
    // divergence that only surfaces much later as an unrecoverable shardtree conflict.
    #[test]
    fn resume_point_uses_the_height_the_wallet_actually_reached() {
        let resumed = resume_point(h(3_438_008), Some((h(3_434_976), hash(7)))).unwrap();
        assert_eq!(resumed.height(), h(3_434_976));
        assert_eq!(resumed.hash(), hash(7));
    }

    #[test]
    fn resume_point_is_the_request_when_the_rewind_was_exact() {
        let resumed = resume_point(h(500), Some((h(500), hash(1)))).unwrap();
        assert_eq!(resumed.height(), h(500));
        assert_eq!(resumed.hash(), hash(1));
    }

    // The wallet should always have a block at the height it truncated to, since truncation
    // deletes only rows strictly above it. If it does not, resuming would fabricate a tip.
    #[test]
    fn resume_point_errors_when_the_wallet_has_no_block_there() {
        assert!(matches!(
            resume_point(h(500), None),
            Err(SyncError::Chain(ChainError::Backend(_))),
        ));
    }

    #[test]
    fn tree_recovery_rolls_back_further_each_attempt() {
        let mut recovery = TreeRecovery::default();
        let depths: Vec<_> = std::iter::from_fn(|| recovery.next_depth(h(1_000_000))).collect();
        assert_eq!(depths, TREE_RECOVERY_LADDER);
        // Budget exhausted: the caller must give up rather than keep rewinding.
        assert_eq!(recovery.next_depth(h(1_000_000)), None);
    }

    #[test]
    fn tree_recovery_records_the_tip_where_the_divergence_was_first_seen() {
        let mut recovery = TreeRecovery::default();
        recovery.next_depth(h(1_000));
        // Later attempts happen from lower tips as the wallet rolls back, but the reported
        // origin stays where the problem was first noticed.
        recovery.next_depth(h(900));
        assert_eq!(recovery.observed_at(h(900)), h(1_000));
    }

    // The invariant that keeps recovery from spinning. Resetting on any successful scan would
    // let "roll back one block, rescan one block, conflict again" repeat forever, because each
    // rescan looks like progress and puts the ladder back on its first rung.
    #[test]
    fn tree_recovery_does_not_reset_below_the_high_water_mark() {
        let mut recovery = TreeRecovery::default();
        recovery.next_depth(h(1_000));
        recovery.next_depth(h(999));
        let attempts = recovery.attempts;

        assert!(!recovery.note_progress(h(999)));
        assert!(!recovery.note_progress(h(1_000)));
        assert_eq!(recovery.attempts, attempts);
        assert_eq!(recovery.observed_at(h(999)), h(1_000));
    }

    #[test]
    fn tree_recovery_resets_once_resynced_past_the_high_water_mark() {
        let mut recovery = TreeRecovery::default();
        recovery.next_depth(h(1_000));

        assert!(recovery.note_progress(h(1_001)));
        assert_eq!(recovery, TreeRecovery::default());
        // A fresh divergence starts the ladder over from the new tip.
        assert_eq!(
            recovery.next_depth(h(1_001)),
            TREE_RECOVERY_LADDER.first().copied()
        );
    }

    #[test]
    fn tree_recovery_progress_is_a_no_op_when_no_recovery_is_underway() {
        let mut recovery = TreeRecovery::default();
        assert!(!recovery.note_progress(h(5_000)));
        assert_eq!(recovery, TreeRecovery::default());
    }

    #[test]
    fn tree_recovery_target_rolls_back_by_the_depth() {
        assert_eq!(tree_recovery_target(h(1_000), 288, h(0)), Some(h(712)));
    }

    #[test]
    fn tree_recovery_target_is_floored_at_the_birthday() {
        assert_eq!(
            tree_recovery_target(h(1_000), 100_000, h(950)),
            Some(h(950))
        );
    }

    // Once the birthday floor coincides with where the wallet already is, rolling back cannot
    // make progress; recovery must give up rather than retry in place.
    #[test]
    fn tree_recovery_target_gives_up_at_the_birthday() {
        assert_eq!(tree_recovery_target(h(950), 100_000, h(950)), None);
        assert_eq!(tree_recovery_target(h(940), 100_000, h(950)), None);
    }

    #[test]
    fn tree_conflicts_are_recognised_as_divergence() {
        use zcash_client_sqlite::error::SqliteClientError;

        assert!(is_tree_divergence(&SyncError::Other(Box::new(
            SqliteClientError::TruncateCommitmentTree {
                pool: ShieldedPool::Ironwood,
                height: h(3_438_008),
                error: ShardTreeError::Query(QueryError::CheckpointPruned),
            }
        ))));
    }

    #[test]
    fn other_errors_are_not_tree_divergence() {
        use zcash_client_sqlite::error::SqliteClientError;

        // A block conflict is the wallet being on a different *chain*, which the fork-point
        // search already handles; routing it into tree recovery would rewind unnecessarily.
        assert!(!is_tree_divergence(&SyncError::Other(Box::new(
            SqliteClientError::BlockConflict(h(3_438_008))
        ))));
        assert!(!is_tree_divergence(&SyncError::BatchDecryptorUnavailable));
        assert!(!is_tree_divergence(&SyncError::Chain(
            ChainError::unavailable("indexer is catching up")
        )));
    }

    fn range(start: u32, end: u32, priority: ScanPriority) -> ScanRange {
        ScanRange::from_parts(h(start)..h(end), priority)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn late_wallet_sync_error_cancels_all_earlier_tasks() {
        let (batch_cancelled, batch_cancelled_receiver) = mpsc::channel();
        let batch_task = observed_pending_task(batch_cancelled).await;
        let (steady_cancelled, steady_cancelled_receiver) = mpsc::channel();
        let steady_task = observed_pending_task(steady_cancelled).await;
        let (recovery_cancelled, recovery_cancelled_receiver) = mpsc::channel();
        let recovery_task = observed_pending_task(recovery_cancelled).await;

        let initialization: Result<(), Error> = async {
            let mut pending_tasks = PendingWalletSyncTasks::new(&batch_task);
            pending_tasks.include(&steady_task);
            pending_tasks.include(&recovery_task);
            Err(ErrorKind::Init
                .context("simulated late wallet sync failure")
                .into())
        }
        .await;

        initialization.expect_err("late wallet sync initialization fails");
        assert_task_cancelled(batch_cancelled_receiver).await;
        assert_task_cancelled(steady_cancelled_receiver).await;
        assert_task_cancelled(recovery_cancelled_receiver).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wallet_sync_initialization_cancellation_stops_all_earlier_tasks() {
        let (batch_cancelled, batch_cancelled_receiver) = mpsc::channel();
        let batch_task = observed_pending_task(batch_cancelled).await;
        let (steady_cancelled, steady_cancelled_receiver) = mpsc::channel();
        let steady_task = observed_pending_task(steady_cancelled).await;
        let (recovery_cancelled, recovery_cancelled_receiver) = mpsc::channel();
        let recovery_task = observed_pending_task(recovery_cancelled).await;
        let (initialization_waiting, initialization_waiting_receiver) =
            futures::channel::oneshot::channel();

        let initialization = tokio::spawn(async move {
            let mut pending_tasks = PendingWalletSyncTasks::new(&batch_task);
            pending_tasks.include(&steady_task);
            pending_tasks.include(&recovery_task);
            let _ = initialization_waiting.send(());
            std::future::pending::<()>().await;
            pending_tasks.transfer_to_caller();
        });

        initialization_waiting_receiver
            .await
            .expect("wallet sync initialization reaches its cancellable await");
        initialization.abort();
        initialization
            .await
            .expect_err("wallet sync initialization is cancelled");

        assert_task_cancelled(batch_cancelled_receiver).await;
        assert_task_cancelled(steady_cancelled_receiver).await;
        assert_task_cancelled(recovery_cancelled_receiver).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wallet_sync_error_shuts_down_the_spawned_batch_decryptor() {
        crate::i18n::load_languages(&[]);

        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let database = Database::open(&config)
            .await
            .expect("creates a wallet database");
        let (decryptor, decryptor_engine) = WalletSync::build_decryptor();
        let decryptor_observer = decryptor.clone();
        let (status, _status_reader) = status::channel(config.sync.lock_threshold());

        let result = WalletSync::spawn(
            &config,
            database,
            MockChain::reporting(Vec::new(), 0),
            None,
            decryptor,
            decryptor_engine,
            status,
        )
        .await;

        assert!(result.is_err(), "mock chain rejects wallet sync startup");
        // `reload_keys` returns `None` only when the decryptor handle has no engine to
        // reload, which itself indicates the engine was dropped during the failed
        // startup. Either outcome proves the batch decryptor is not left running;
        // assert the `Some` case explicitly, and accept `None` as equivalent shutdown.
        if let Some(reload_finished) = decryptor_observer.reload_keys().await {
            assert!(
                reload_finished.await.is_err(),
                "failed wallet sync startup must not leave its batch decryptor running",
            );
        }
        // `None` means there is no engine to reload — the decryptor is already down.
    }

    // Regression for zallet#136: when a sibling task fails and `steady_state` is
    // aborted, the task must exit at its next yield point. The `None if tip_changed`
    // arm of `steady_state_iteration` previously returned without an intervening
    // await, so against a `ChainView` whose `snapshot`, `tip`, and
    // `get_mempool_stream` all return `Poll::Ready` from cached state (the in-tree
    // `MockChain`, and the Zaino `FetchServiceSubscriber` as reported in #136), the
    // task could complete a full iteration without ever polling its abort status and
    // spin indefinitely. The fix inserts `tokio::task::yield_now().await` in that arm;
    // this test asserts the aborted task now exits within a bounded time.
    #[tokio::test(flavor = "multi_thread")]
    async fn aborted_steady_state_exits_when_the_backend_returns_cached_state() {
        crate::i18n::load_languages(&[]);

        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let database = Database::open(&config)
            .await
            .expect("creates a wallet database");
        let (decryptor, decryptor_engine) = WalletSync::build_decryptor();
        // Drop the engine half; the steady-state task only needs the handle, and we
        // do not drive batch decryption here.
        drop(decryptor_engine);

        // A MockChain whose every view operation returns `Poll::Ready`: `snapshot`
        // and `tip` are synchronous, and `get_mempool_stream` returns `Ok(None)`.
        // Its tip sits at height 100, while the wallet starts from height 0, so
        // every iteration takes the `tip_changed` branch and lands in the
        // `None if tip_changed` arm — the exact no-yield fast path from #136.
        let chain = MockChain::reporting(Vec::new(), 100);
        let params = config.consensus.network();
        // The status channel is write-only here; the reader half is dropped and the
        // steady-state task's status writes go unobserved.
        let (status, _status_reader) = status::channel(config.sync.lock_threshold());

        let mut db_data = database.handle().await.expect("opens the wallet database");
        // `prev_tip` differs from the chain tip in height, so `tip_changed` is true;
        // the fresh wallet has an empty block locator, so `locate_fork_point`
        // returns `prev_tip` and no reorg rewind or block scanning occurs. The
        // `stream_blocks_to_tip` call yields an empty stream, so the inner while
        // loop never updates `prev_tip`, leaving `tip_changed` true on every
        // subsequent iteration as well.
        let prev_tip = ChainBlock::new(BlockHeight::from_u32(0), BlockHash([0xff; 32]));
        let lower_boundary = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let tip_change_signal = std::sync::Arc::new(Notify::new());

        let steady_state_task = tokio::spawn(async move {
            steady_state(
                chain,
                &params,
                db_data.as_mut(),
                prev_tip,
                lower_boundary,
                tip_change_signal,
                decryptor,
                None,
                status,
            )
            .await
        });

        // Give the task a chance to enter its loop, then abort it. Without the
        // `yield_now().await` in the `None if tip_changed` arm, the task never
        // yields to check its abort status and the timeout below fires.
        tokio::time::sleep(Duration::from_millis(50)).await;
        steady_state_task.abort();

        let join_result = tokio::time::timeout(Duration::from_secs(2), steady_state_task)
            .await
            .expect(
                "aborted steady_state must exit within a bounded time when the backend \
                 returns cached state (zallet#136)",
            );
        // A tokio task aborted before completion joins with `Err(JoinError::Cancelled)`.
        assert!(
            join_result.is_err(),
            "aborted steady_state task must not complete normally: {join_result:?}",
        );
    }

    // The #636 repro: the wallet DB has recorded a higher chain tip than the current
    // chain view serves, so the only suggestion starts above the tip. It must be
    // dropped entirely (letting `initialize` exit to `steady_state`) instead of being
    // handed to `scan_blocks`, which would return `Ok` without progress and spin the
    // loop at full speed.
    #[test]
    fn initial_scan_range_above_tip_is_dropped() {
        let suggested = vec![range(3_413_618, 3_414_133, ScanPriority::Historic)];
        assert_eq!(
            select_initial_scan_range(suggested, h(3_413_617), h(3_413_517)),
            None,
        );
    }

    #[test]
    fn initial_scan_range_straddling_tip_is_clamped() {
        // Only the prefix up to and including the tip is scannable now.
        let suggested = vec![range(1_000, 1_500, ScanPriority::ChainTip)];
        assert_eq!(
            select_initial_scan_range(suggested, h(1_200), h(900)),
            Some(range(1_000, 1_201, ScanPriority::ChainTip)),
        );
    }

    #[test]
    fn initial_scan_range_at_or_below_tip_is_unchanged() {
        // A range ending exactly at the tip (exclusive end == tip + 1) is untouched.
        let suggested = vec![range(1_000, 1_201, ScanPriority::ChainTip)];
        assert_eq!(
            select_initial_scan_range(suggested, h(1_200), h(900)),
            Some(range(1_000, 1_201, ScanPriority::ChainTip)),
        );
    }

    #[test]
    fn initial_scan_range_verify_is_kept_whole_but_clamped() {
        // Verify ranges are not truncated at the starting boundary...
        let suggested = vec![range(500, 600, ScanPriority::Verify)];
        assert_eq!(
            select_initial_scan_range(suggested, h(1_200), h(900)),
            Some(range(500, 600, ScanPriority::Verify)),
        );
        // ...but are still clamped to the tip like everything else.
        let suggested = vec![range(1_100, 1_500, ScanPriority::Verify)];
        assert_eq!(
            select_initial_scan_range(suggested, h(1_200), h(900)),
            Some(range(1_100, 1_201, ScanPriority::Verify)),
        );
    }

    #[test]
    fn initial_scan_range_historic_is_truncated_to_boundary() {
        let suggested = vec![range(500, 1_000, ScanPriority::Historic)];
        assert_eq!(
            select_initial_scan_range(suggested, h(1_200), h(900)),
            Some(range(900, 1_000, ScanPriority::Historic)),
        );
        // Entirely below the boundary: nothing left for the initialize loop.
        let suggested = vec![range(500, 800, ScanPriority::Historic)];
        assert_eq!(select_initial_scan_range(suggested, h(1_200), h(900)), None);
    }

    #[test]
    fn initial_scan_range_low_priority_is_skipped() {
        let suggested = vec![
            range(1_000, 1_100, ScanPriority::Scanned),
            range(1_100, 1_150, ScanPriority::Ignored),
            range(950, 1_000, ScanPriority::OpenAdjacent),
        ];
        // The two low-priority ranges are skipped; the first acceptable one wins.
        assert_eq!(
            select_initial_scan_range(suggested, h(1_200), h(900)),
            Some(range(950, 1_000, ScanPriority::OpenAdjacent)),
        );
    }

    #[test]
    fn initial_scan_range_skips_above_tip_to_next_candidate() {
        // An above-tip range must not mask a scannable one later in the list.
        let suggested = vec![
            range(1_300, 1_400, ScanPriority::ChainTip),
            range(1_000, 1_100, ScanPriority::Historic),
        ];
        assert_eq!(
            select_initial_scan_range(suggested, h(1_200), h(900)),
            Some(range(1_000, 1_100, ScanPriority::Historic)),
        );
    }

    #[test]
    fn rewind_step_jumps_back_by_the_step() {
        // Well above the birthday: step back exactly FORK_SEARCH_STEP, not the floor.
        assert_eq!(rewind_step(h(5000), h(1000)), (h(4990), false));
    }

    #[test]
    fn rewind_step_is_floored_at_the_birthday() {
        // A step that would cross the birthday is clamped to it and flagged as the last.
        assert_eq!(rewind_step(h(5000), h(4995)), (h(4995), true));
        // Landing exactly on the birthday is also the last step.
        assert_eq!(rewind_step(h(1010), h(1000)), (h(1000), true));
        // A normal step that happens to land on the birthday is the last step.
        assert_eq!(rewind_step(h(1009), h(1000)), (h(1000), true));
        // Two clear steps above the birthday is a normal, non-final step.
        assert_eq!(rewind_step(h(1015), h(1000)), (h(1005), false));
    }

    #[test]
    fn rewind_step_at_birthday_stops() {
        // Already at the birthday: cannot step further, so this is the final probe.
        assert_eq!(rewind_step(h(1000), h(1000)), (h(1000), true));
    }

    #[test]
    fn stale_view_errors_are_retryable() {
        assert!(is_retryable(&SyncError::Chain(ChainError::unavailable(
            "pinned block reorged away",
        ))));
    }

    #[test]
    fn other_errors_are_fatal() {
        assert!(!is_retryable(&SyncError::Chain(ChainError::backend(
            "boom"
        ))));
        assert!(!is_retryable(&SyncError::Chain(ChainError::invalid_data(
            "bad bytes",
        ))));
        assert!(!is_retryable(&SyncError::BatchDecryptorUnavailable));
    }

    #[cfg(not(feature = "spend-index"))]
    #[test]
    fn address_request_bounds_clamps_and_reports_as_of() {
        use super::address_request_bounds;

        let tip = BlockHeight::from_u32(4_090_000);

        // Explicit end below the tip is used as-is; as_of is end - 1.
        let (range, as_of) = address_request_bounds(
            BlockHeight::from_u32(1_810_000),
            Some(BlockHeight::from_u32(1_900_000)),
            tip,
        );
        assert_eq!(
            range,
            BlockHeight::from_u32(1_810_000)..BlockHeight::from_u32(1_900_000)
        );
        assert_eq!(as_of, BlockHeight::from_u32(1_899_999));

        // Open end defaults to tip + 1; as_of is the tip.
        let (range, as_of) = address_request_bounds(BlockHeight::from_u32(1_810_000), None, tip);
        assert_eq!(
            range,
            BlockHeight::from_u32(1_810_000)..BlockHeight::from_u32(4_090_001)
        );
        assert_eq!(as_of, tip);

        // An end past the tip is clamped to tip + 1.
        let (range, as_of) = address_request_bounds(
            BlockHeight::from_u32(1_810_000),
            Some(BlockHeight::from_u32(9_000_000)),
            tip,
        );
        assert_eq!(
            range,
            BlockHeight::from_u32(1_810_000)..BlockHeight::from_u32(4_090_001)
        );
        assert_eq!(as_of, tip);
    }
}

#[cfg(test)]
mod fork_fallback_tests {
    use std::collections::BTreeMap;
    use std::ops::Range;

    use futures::{
        StreamExt as _,
        stream::{self, BoxStream},
    };
    use zcash_client_backend::data_api::{TransactionStatus, chain::ChainState};
    use zcash_primitives::{
        block::{Block, BlockHash, BlockHeader, BlockHeaderData},
        transaction::Transaction,
    };
    use zcash_protocol::{TxId, consensus::BlockHeight};

    use super::{ChainBlock, ChainView, SyncError, step_back_to_best_chain};
    #[cfg(feature = "spend-index")]
    use crate::components::chain::SpendStatus;
    use crate::components::chain::{BlockLocator, ChainError, ChainTx};
    #[cfg(not(feature = "spend-index"))]
    use transparent::address::TransparentAddress;
    #[cfg(feature = "spend-index")]
    use transparent::bundle::OutPoint;

    fn h(height: u32) -> BlockHeight {
        BlockHeight::from_u32(height)
    }

    /// Builds a distinct, deterministic block header whose hash varies with `seed`.
    fn header(seed: u8) -> BlockHeader {
        BlockHeaderData {
            version: 4,
            prev_block: BlockHash([0; 32]),
            merkle_root: [0; 32],
            final_sapling_root: [0; 32],
            time: 0,
            bits: 0,
            nonce: [seed; 32],
            solution: vec![],
        }
        .freeze()
        .unwrap()
    }

    /// A [`ChainView`] whose best chain is a fixed set of header seeds by height (`BlockHeader`
    /// is not `Clone`, so headers are rebuilt from their seed on demand). `find_fork_point`
    /// always returns `None` (forcing the step-back fallback); every other method is a stub.
    #[derive(Clone)]
    struct MockChainView {
        headers: BTreeMap<BlockHeight, u8>,
    }

    impl ChainView for MockChainView {
        async fn tip(&self) -> Result<ChainBlock, ChainError> {
            unimplemented!("not used by the fork-point fallback")
        }

        async fn find_fork_point(
            &self,
            _locator: &BlockLocator,
        ) -> Result<Option<ChainBlock>, ChainError> {
            Ok(None)
        }

        async fn tree_state_as_of(
            &self,
            _height: BlockHeight,
        ) -> Result<Option<ChainState>, ChainError> {
            Ok(None)
        }

        async fn get_block_header(
            &self,
            height: BlockHeight,
        ) -> Result<Option<BlockHeader>, ChainError> {
            Ok(self.headers.get(&height).map(|&seed| header(seed)))
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
            _range: &Range<BlockHeight>,
        ) -> BoxStream<'_, Result<Block, ChainError>> {
            stream::empty().boxed()
        }

        async fn get_mempool_stream(
            &self,
        ) -> Result<Option<BoxStream<'_, Transaction>>, ChainError> {
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
    async fn steps_back_to_the_matching_block() {
        // Backend best chain: distinct header seeds at the heights the walk will probe.
        let view = MockChainView {
            headers: BTreeMap::from([(h(90), 90), (h(80), 80), (h(70), 70)]),
        };

        // Wallet view: on a fork at 90 and 80 (mismatched hashes), rejoining the best chain
        // at 70 (its recorded hash there matches the backend's).
        let wallet = BTreeMap::from([
            (h(90), header(190).hash()),
            (h(80), header(180).hash()),
            (h(70), header(70).hash()),
        ]);

        let prev_tip = ChainBlock::new(h(100), header(200).hash());
        let resume = step_back_to_best_chain(&view, prev_tip, h(0), |height| {
            Ok(wallet.get(&height).copied())
        })
        .await
        .unwrap();

        assert_eq!(resume, ChainBlock::new(h(70), header(70).hash()));
    }

    #[tokio::test]
    async fn halts_at_the_birthday_when_never_rejoining() {
        let view = MockChainView {
            headers: BTreeMap::from([(h(90), 90), (h(80), 80), (h(70), 70)]),
        };

        // Wallet view is on a fork all the way down to the birthday at height 70.
        let wallet = BTreeMap::from([
            (h(90), header(190).hash()),
            (h(80), header(180).hash()),
            (h(70), header(170).hash()),
        ]);

        let prev_tip = ChainBlock::new(h(100), header(200).hash());
        let result = step_back_to_best_chain(&view, prev_tip, h(70), |height| {
            Ok(wallet.get(&height).copied())
        })
        .await;

        assert!(matches!(
            result,
            Err(SyncError::WalletDivergedBelowBirthday { birthday }) if birthday == h(70)
        ));
    }
}
