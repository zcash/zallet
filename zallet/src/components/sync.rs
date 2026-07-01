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
use tokio::{sync::Notify, time};
#[cfg(not(feature = "spend-index"))]
use zcash_client_backend::data_api::{
    CoinbaseFilter, InputSource, TransactionsInvolvingAddress,
    wallet::{ConfirmationsPolicy, TargetHeight},
};
use zcash_client_backend::{
    data_api::{
        TransactionDataRequest, TransactionStatus, WalletRead, WalletWrite, scanning::ScanPriority,
        wallet::decrypt_and_store_transaction,
    },
    scanning::ScanningKeys,
    sync::decryptor,
};
use zcash_client_sqlite::AccountUuid;
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
use crate::{config::ZalletConfig, error::Error, network::Network};

mod error;
pub(crate) use error::SyncError;

mod locator;
mod steps;

#[derive(Debug)]
pub(crate) struct WalletSync {}

impl WalletSync {
    pub(crate) async fn spawn<C: Chain>(
        config: &ZalletConfig,
        db: Database,
        chain: C,
    ) -> Result<(TaskHandle, TaskHandle, TaskHandle, TaskHandle), Error> {
        let params = config.consensus.network();
        let recover_batch_size = config.sync.recover_batch_size();

        // The batch decryptor's built-in defaults (queue size 1000, batch-size threshold
        // 200, batch start delay 500ms) are appropriate for Zallet, so use them as-is.
        let (decryptor, decryptor_engine) = decryptor::new().build();

        // Spawn the processing tasks.
        let batch_decryptor_task = {
            let mut db_data = db.handle().await?;
            crate::spawn!("Batch decryptor", async move {
                batch_decryptor(params, db_data.as_mut(), decryptor_engine).await?;
                Ok(())
            })
        };

        // Ensure the wallet is in a state that the sync tasks can work with.
        let mut db_data = db.handle().await?;
        let (starting_tip, starting_boundary) =
            initialize(&chain, &params, db_data.as_mut(), decryptor.clone()).await?;

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
            crate::spawn!("Steady state sync", async move {
                steady_state(
                    chain,
                    &params,
                    db_data.as_mut(),
                    starting_tip,
                    lower_boundary,
                    tip_change_signal_source,
                    decryptor,
                )
                .await?;
                Ok(())
            })
        };

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
                )
                .await?;
                Ok(())
            })
        };

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

/// Prepares the wallet state for syncing.
///
/// Returns the boundary block between [`steady_state`] and [`recover_history`] syncing.
#[tracing::instrument(skip_all)]
async fn initialize<C: Chain>(
    chain: &C,
    params: &Network,
    db_data: &mut DbConnection,
    decryptor: decryptor::Handle<AccountUuid, (AccountUuid, Scope)>,
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
        info!("Latest block height is {}", current_tip.height);
        db_data.update_chain_tip(current_tip.height)?;

        // Set the starting boundary between the `steady_state` and `recover_history` tasks.
        let starting_boundary = update_boundary(BlockHeight::from_u32(0), current_tip.height);

        let scan_range = match db_data
            .suggest_scan_ranges()?
            .into_iter()
            .filter_map(|r| {
                if r.priority() == ScanPriority::Verify {
                    Some(r)
                } else if r.priority() >= ScanPriority::Historic {
                    r.truncate_start(starting_boundary)
                } else {
                    None
                }
            })
            .next()
        {
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
                if current_tip.height > BlockHeight::from_u32(0)
                    && db_data.block_metadata(current_tip.height)?.is_none()
                {
                    let attempt = async {
                        let tip_block = chain_view
                            .get_block(current_tip.height)
                            .await
                            .map_err(SyncError::Chain)?
                            .ok_or_else(|| {
                                SyncError::Chain(ChainError::backend(format!(
                                    "chain view did not return its own tip \
                                     block at height {}",
                                    current_tip.height
                                )))
                            })?;
                        steps::scan_block(&chain_view, db_data, params, tip_block, &decryptor).await
                    };
                    if let Err(e) = attempt.await {
                        warn!(
                            "Best-effort tip scan during initialize failed; \
                             steady_state will populate metadata once the indexer \
                             catches up: {e}"
                        );
                    }
                }
                break (current_tip, starting_boundary);
            }
        };

        steps::scan_blocks(chain_view, db_data, params, &scan_range, &decryptor).await?;
    };

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
    let locator = locator::build_block_locator(db_data, prev_tip.height)?;
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
        prev_tip.hash, prev_tip.height,
    );
    step_back_to_best_chain(chain_view, prev_tip, birthday, |height| {
        Ok(db_data.get_block_hash(height)?)
    })
    .await
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
    let mut height = prev_tip.height;
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
                return Ok(ChainBlock { height, hash: wh });
            }
        }
        if reached_birthday {
            return Err(SyncError::WalletDivergedBelowBirthday { birthday });
        }
    }
}

/// Keeps the wallet state up-to-date with the chain tip, and handles the mempool.
#[tracing::instrument(skip_all)]
async fn steady_state<C: Chain>(
    chain: C,
    params: &Network,
    db_data: &mut DbConnection,
    mut prev_tip: ChainBlock,
    lower_boundary: Arc<AtomicU32>,
    tip_change_signal: Arc<Notify>,
    decryptor: decryptor::Handle<AccountUuid, (AccountUuid, Scope)>,
) -> Result<(), SyncError> {
    info!("Steady-state sync task started");

    // Wake up any tasks waiting on the tip-change signal, so they can service work that
    // accumulated while the wallet was offline.
    tip_change_signal.notify_one();

    loop {
        if let Err(error) = steady_state_iteration(
            &chain,
            params,
            db_data,
            &mut prev_tip,
            &lower_boundary,
            &tip_change_signal,
            &decryptor,
        )
        .await
        {
            // A stale-view error means the captured snapshot referenced a non-finalized
            // block that was reorged away mid-read. Discard the view, pause briefly, and
            // loop to re-pin to the current tip. Progress already committed to the wallet
            // (and recorded in `prev_tip`) is preserved across the retry.
            if is_retryable(&error) {
                warn!("Chain view became stale, re-pinning to the current tip: {error}");
                time::sleep(REORG_RETRY_BACKOFF).await;
                continue;
            }
            return Err(error);
        }
    }
}

/// Performs one pass of [`steady_state`]: captures a fresh chain view, applies any new or
/// reorged blocks to the wallet (advancing `prev_tip`), then streams the mempool until the
/// view's tip changes.
async fn steady_state_iteration<C: Chain>(
    chain: &C,
    params: &Network,
    db_data: &mut DbConnection,
    prev_tip: &mut ChainBlock,
    lower_boundary: &AtomicU32,
    tip_change_signal: &Notify,
    decryptor: &decryptor::Handle<AccountUuid, (AccountUuid, Scope)>,
) -> Result<(), SyncError> {
    let chain_view = chain.snapshot().await.map_err(SyncError::Chain)?;
    let current_tip = chain_view.tip().await.map_err(SyncError::Chain)?;
    let tip_changed = current_tip != *prev_tip;

    if tip_changed {
        info!("New chain tip: {} {}", current_tip.height, current_tip.hash);
        lower_boundary
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current_boundary| {
                Some(
                    update_boundary(BlockHeight::from_u32(current_boundary), current_tip.height)
                        .into(),
                )
            })
            .expect("closure always returns Some");
        tip_change_signal.notify_one();

        // Find where the wallet's history rejoins the backend's best chain.
        let fork_point = locate_fork_point(&chain_view, db_data, *prev_tip).await?;
        assert!(fork_point.height <= current_tip.height);

        // Fetch blocks that need to be applied to the wallet.
        let blocks_to_apply = chain_view.stream_blocks_to_tip(fork_point.height + 1);
        tokio::pin!(blocks_to_apply);

        // If the fork point is equal to `prev_tip` then no reorg has occurred.
        if fork_point != *prev_tip {
            // Ensured by `find_fork_point`.
            assert!(fork_point.height < prev_tip.height);

            // Rewind the wallet to the fork point. `truncate_to_height` fully resets
            // the wallet state to that height, so the blocks in the old fork need no
            // further handling.
            info!(
                "Chain reorg detected, rewinding to {} {}",
                fork_point.height, fork_point.hash
            );
            db_data.truncate_to_height(fork_point.height)?;
            *prev_tip = fork_point;
        };

        // Notify the wallet of block connections.
        while let Some(block) = blocks_to_apply.try_next().await.map_err(SyncError::Chain)? {
            let height = block.claimed_height();
            assert_eq!(height, prev_tip.height + 1);
            let current_block = ChainBlock {
                height,
                hash: block.header().hash(),
            };
            db_data.update_chain_tip(height)?;

            steps::scan_block(&chain_view, db_data, params, block, decryptor).await?;

            // Now that we're done applying the block, update our chain pointer.
            *prev_tip = current_block;
        }
    }

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
                // See zcash/wallet#477.
                decrypt_and_store_transaction(params, db_data, &tx, None)?;
            }

            // Mempool stream ended, signalling that the chain tip has changed.
        }
        // The chain tip already changed since this view was captured; loop around
        // immediately to observe it.
        None if tip_changed => (),
        // The chain tip has not changed, and no mempool stream is available (e.g.
        // because the chain indexer is still syncing its finalized state). Pause
        // briefly to avoid spinning.
        None => time::sleep(Duration::from_millis(500)).await,
    }

    Ok(())
}

/// Recovers historic wallet state.
///
/// This function only operates on finalized chain state, and does not handle reorgs.
#[tracing::instrument(skip_all)]
async fn recover_history<C: Chain>(
    chain: C,
    params: &Network,
    db_data: &mut DbConnection,
    upper_boundary: Arc<AtomicU32>,
    decryptor: decryptor::Handle<AccountUuid, (AccountUuid, Scope)>,
    batch_size: u32,
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
            let chain_view = chain.snapshot().await.map_err(SyncError::Chain)?;
            steps::scan_blocks(chain_view, db_data, params, &scan_range, &decryptor).await?;

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
                decrypt_and_store_transaction(params, db_data, &tx.inner, tx.mined_height)?;
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

        let view_tip = chain_view.tip().await.map_err(SyncError::Chain)?.height;
        info!("{} transaction data requests to service", requests.len());
        for request in requests {
            match request {
                TransactionDataRequest::GetStatus(txid) => {
                    if txid.is_null() {
                        continue;
                    }

                    info!("Getting status of {txid}");
                    let status = chain_view
                        .get_transaction_status(txid)
                        .await
                        .map_err(SyncError::Chain)?;

                    db_data.set_transaction_status(txid, status)?;
                }
                TransactionDataRequest::Enhancement(txid) => {
                    if txid.is_null() {
                        continue;
                    }

                    info!("Enhancing {txid}");
                    if let Some(tx) = chain_view
                        .get_transaction(txid)
                        .await
                        .map_err(SyncError::Chain)?
                    {
                        // TODO: Route individual-transaction scanning through the batch
                        // decryptor (`Handle::queue_tx`) once a single-tx store path
                        // exists. See zcash/wallet#477.
                        decrypt_and_store_transaction(params, db_data, &tx.inner, tx.mined_height)?;
                    } else {
                        db_data
                            .set_transaction_status(txid, TransactionStatus::TxidNotRecognized)?;
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
                                    &tx.inner,
                                    tx.mined_height,
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
    use super::{ChainError, SyncError, is_retryable, rewind_step};
    use zcash_protocol::consensus::BlockHeight;

    fn h(height: u32) -> BlockHeight {
        BlockHeight::from_u32(height)
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

        let prev_tip = ChainBlock {
            height: h(100),
            hash: header(200).hash(),
        };
        let resume = step_back_to_best_chain(&view, prev_tip, h(0), |height| {
            Ok(wallet.get(&height).copied())
        })
        .await
        .unwrap();

        assert_eq!(
            resume,
            ChainBlock {
                height: h(70),
                hash: header(70).hash(),
            }
        );
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

        let prev_tip = ChainBlock {
            height: h(100),
            hash: header(200).hash(),
        };
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
