use std::collections::HashMap;
use std::convert::Infallible;
use std::ops::{ControlFlow, Range};

use futures::TryStreamExt as _;
use jsonrpsee::tracing::info;
use transparent::{address::TransparentAddress, keys::TransparentKeyScope};
use zcash_client_backend::{
    data_api::{
        BlockMetadata, WalletCommitmentTrees, WalletRead, WalletWrite, scanning::ScanRange,
    },
    scanning::{
        Nullifiers,
        full::{self, ScanBlockError},
    },
};
use zcash_client_sqlite::AccountUuid;
use zcash_primitives::block::Block;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    components::{
        chain::{Chain, ChainError, ChainView},
        database::DbConnection,
    },
    network::Network,
};

use super::{SyncError, WalletDecryptorHandle};

pub(super) async fn update_subtree_roots<C: Chain>(
    chain: &C,
    db_data: &mut DbConnection,
) -> Result<(), SyncError> {
    // TODO: Query and insert only the subtree roots added since our last query (via the
    // `start_index` parameter of `get_*_subtree_roots`), instead of re-fetching and
    // re-inserting all historical roots on every call. Not urgent: the cost is small and
    // grows very slowly.
    let sapling_roots = chain
        .get_sapling_subtree_roots()
        .await
        .map_err(SyncError::Chain)?;

    info!("Sapling tree has {} subtrees", sapling_roots.len());
    db_data.put_sapling_subtree_roots(0, &sapling_roots)?;

    let orchard_roots = chain
        .get_orchard_subtree_roots()
        .await
        .map_err(SyncError::Chain)?;

    info!("Orchard tree has {} subtrees", orchard_roots.len());
    db_data.put_orchard_subtree_roots(0, &orchard_roots)?;

    // Ironwood (NU6.3) shares the Orchard tree shape. Inserting its subtree roots is what
    // lets received Ironwood notes become spendable; without them the tree never
    // stabilizes and the notes stay pending.
    let ironwood_roots = chain
        .get_ironwood_subtree_roots()
        .await
        .map_err(SyncError::Chain)?;

    info!("Ironwood tree has {} subtrees", ironwood_roots.len());
    db_data.put_ironwood_subtree_roots(0, &ironwood_roots)?;

    Ok(())
}

/// An index from transparent address to the wallet account that controls it.
type TransparentAddressIndex =
    HashMap<TransparentAddress, (AccountUuid, Option<TransparentKeyScope>)>;

/// Collects the wallet's transparent receivers, for detecting transparent outputs while
/// scanning full blocks.
fn transparent_address_index(db_data: &DbConnection) -> Result<TransparentAddressIndex, SyncError> {
    let mut index = HashMap::new();
    for account in db_data.get_account_ids()? {
        for (address, metadata) in db_data.get_transparent_receivers(account, true, true)? {
            index.insert(address, (account, metadata.scope()));
        }
    }
    Ok(index)
}

/// Maps the error type produced by [`full::scan_block`] into a [`SyncError`].
fn scan_block_error(e: ScanBlockError<Infallible>) -> SyncError {
    match e {
        ScanBlockError::Scan(e) => SyncError::Scan(e),
        // The address lookup is infallible, and `ScanBlockError` is non-exhaustive, so
        // map any future variants to a generic error rather than panicking.
        other => SyncError::Chain(ChainError::backend(other.to_string())),
    }
}

/// Clamps a scan `range` so it stops before a known consensus-divergence height: scanning at
/// or beyond that height would interpret the chain under rules this build does not follow.
///
/// The result distinguishes the three ways a range relates to the boundary:
///
/// * `Break(height)` — the whole range lies at or beyond the boundary; scan nothing and stop
///   at `height`.
/// * `Continue(Some(height))` — the range straddles the boundary; scan `range.start..height`,
///   then stop at `height`.
/// * `Continue(None)` — the range lies entirely below the boundary (or there is no boundary);
///   scan it in full and carry on.
///
/// A range whose exclusive end is exactly the boundary is *not* trimmed: its last block is
/// `boundary - 1`, which is still below the divergence height.
fn clamp_to_boundary(
    range: &Range<BlockHeight>,
    shutdown_height: Option<BlockHeight>,
) -> ControlFlow<BlockHeight, Option<BlockHeight>> {
    let end = shutdown_height.map_or(range.end, |h| h.min(range.end));
    if end <= range.start {
        ControlFlow::Break(end)
    } else if end < range.end {
        ControlFlow::Continue(Some(end))
    } else {
        ControlFlow::Continue(None)
    }
}

/// Scans a contiguous sequence of blocks in the main chain.
pub(super) async fn scan_blocks<V: ChainView>(
    chain_view: V,
    db_data: &mut DbConnection,
    params: &Network,
    scan_range: &ScanRange,
    decryptor: &WalletDecryptorHandle,
    shutdown_height: Option<BlockHeight>,
) -> Result<ControlFlow<BlockHeight>, SyncError> {
    // Clamp the range to stop before any known consensus-divergence height (see
    // [`clamp_to_boundary`]). If the whole range is at or beyond the boundary there is nothing
    // left to scan; otherwise `boundary` is `Some(height)` when we trimmed, which we report
    // after scanning so the caller can shut down.
    let boundary = match clamp_to_boundary(scan_range.block_range(), shutdown_height) {
        ControlFlow::Break(end) => return Ok(ControlFlow::Break(end)),
        ControlFlow::Continue(boundary) => boundary,
    };
    let clamped;
    let scan_range = if let Some(end) = boundary {
        clamped = ScanRange::from_parts(scan_range.block_range().start..end, scan_range.priority());
        &clamped
    } else {
        scan_range
    };

    // Ignore scan ranges beyond the end of the current chain tip (which indicates a race
    // with a chain reorg).
    if let Some(from_state) = chain_view
        .tree_state_as_of(scan_range.block_range().start - 1)
        .await
        .map_err(SyncError::Chain)?
    {
        info!("Scanning blocks {}", scan_range);
        let blocks_to_apply = chain_view.stream_blocks(scan_range.block_range());
        tokio::pin!(blocks_to_apply);

        // Queue the blocks for batch decryption.
        let mut batch = Vec::with_capacity(scan_range.len());
        while let Some(block) = blocks_to_apply.try_next().await.map_err(SyncError::Chain)? {
            let height = block.claimed_height();
            let result = decryptor
                .queue_block(block)
                .await
                .ok_or(SyncError::BatchDecryptorUnavailable)?;
            batch.push((height, result));
        }

        let mut prior_block_metadata = Some(BlockMetadata::from_parts(
            from_state.block_height(),
            from_state.block_hash(),
            Some(from_state.final_sapling_tree().tree_size() as u32),
            Some(from_state.final_orchard_tree().tree_size() as u32),
            Some(from_state.final_ironwood_tree().tree_size() as u32),
        ));

        // Get the nullifiers for the unspent notes we are tracking, and the transparent
        // addresses we control.
        let mut nullifiers = Nullifiers::unspent(db_data)?;
        let addresses = transparent_address_index(db_data)?;

        // Now wait on the batch and scan each block as it becomes available.
        let mut scanned_blocks = Vec::with_capacity(scan_range.len());
        for (height, result) in batch {
            let (scanning_keys, header, vtx) = result
                .await
                .map_err(|_| SyncError::BatchDecryptorUnavailable)?;

            let scanned_block = full::scan_block(
                params,
                height,
                &header,
                vtx,
                &scanning_keys,
                &nullifiers,
                prior_block_metadata.as_ref(),
                |address| Ok::<_, Infallible>(addresses.get(address).copied()),
            )
            .map_err(scan_block_error)?;

            nullifiers.update_with(&scanned_block);
            prior_block_metadata = Some(scanned_block.to_block_metadata());
            scanned_blocks.push(scanned_block);
        }

        tokio::task::block_in_place(|| db_data.put_blocks(&from_state, scanned_blocks))?;
    } else {
        info!(
            "{} is greater than chain view's tip ({}), skipping",
            scan_range.block_range().start - 1,
            chain_view.tip().await.map_err(SyncError::Chain)?.height(),
        );
        // The range starts beyond the chain view's tip (a reorg race), so we scanned nothing
        // and have not reached the divergence boundary; let the caller retry.
        return Ok(ControlFlow::Continue(()));
    }

    Ok(match boundary {
        Some(end) => ControlFlow::Break(end),
        None => ControlFlow::Continue(()),
    })
}

/// Scans a block in the main chain.
pub(super) async fn scan_block<V: ChainView>(
    chain_view: &V,
    db_data: &mut DbConnection,
    params: &Network,
    block: Block,
    decryptor: &WalletDecryptorHandle,
    shutdown_height: Option<BlockHeight>,
) -> Result<ControlFlow<BlockHeight>, SyncError> {
    let height = block.claimed_height();

    // Refuse to scan at or beyond a known consensus-divergence height: from here on the
    // backing node follows rules this build cannot interpret, so scanning would corrupt the
    // wallet's view. Signal the boundary so the caller can shut down gracefully.
    if shutdown_height.is_some_and(|h| height >= h) {
        return Ok(ControlFlow::Break(height));
    }

    let from_state = chain_view
        .tree_state_as_of(height - 1)
        .await
        .map_err(SyncError::Chain)?
        .ok_or_else(|| {
            SyncError::Chain(ChainError::backend(
                "Programming error: tried to scan block ahead of the chain view's tip",
            ))
        })?;

    info!("Scanning block {} ({})", height, block.header().hash());
    let result = decryptor
        .queue_block(block)
        .await
        .ok_or(SyncError::BatchDecryptorUnavailable)?;

    let prior_block_metadata = Some(BlockMetadata::from_parts(
        from_state.block_height(),
        from_state.block_hash(),
        Some(from_state.final_sapling_tree().tree_size() as u32),
        Some(from_state.final_orchard_tree().tree_size() as u32),
        Some(from_state.final_ironwood_tree().tree_size() as u32),
    ));

    // Get the nullifiers for the unspent notes we are tracking, and the transparent
    // addresses we control.
    let nullifiers = Nullifiers::unspent(db_data)?;
    let addresses = transparent_address_index(db_data)?;

    let (scanning_keys, header, vtx) = result
        .await
        .map_err(|_| SyncError::BatchDecryptorUnavailable)?;

    let scanned = full::scan_block(
        params,
        height,
        &header,
        vtx,
        &scanning_keys,
        &nullifiers,
        prior_block_metadata.as_ref(),
        |address| Ok::<_, Infallible>(addresses.get(address).copied()),
    )
    .map_err(scan_block_error)?;

    tokio::task::block_in_place(|| db_data.put_blocks(&from_state, vec![scanned]))?;

    Ok(ControlFlow::Continue(()))
}

#[cfg(test)]
mod tests {
    use std::ops::ControlFlow;

    use zcash_protocol::consensus::BlockHeight;

    use super::clamp_to_boundary;

    fn h(height: u32) -> BlockHeight {
        BlockHeight::from_u32(height)
    }

    #[test]
    fn clamp_without_boundary_scans_whole_range() {
        // No known divergence height: never clamp, never signal a stop.
        assert_eq!(
            clamp_to_boundary(&(h(50)..h(80)), None),
            ControlFlow::Continue(None),
        );
    }

    #[test]
    fn clamp_range_entirely_below_boundary_scans_whole_range() {
        assert_eq!(
            clamp_to_boundary(&(h(50)..h(80)), Some(h(100))),
            ControlFlow::Continue(None),
        );
    }

    #[test]
    fn clamp_range_ending_at_boundary_is_not_trimmed() {
        // A half-open range ending exactly at the boundary scans up to `boundary - 1`, which
        // is still below the divergence height, so it is neither trimmed nor stopped early.
        assert_eq!(
            clamp_to_boundary(&(h(95)..h(100)), Some(h(100))),
            ControlFlow::Continue(None),
        );
    }

    #[test]
    fn clamp_range_straddling_boundary_trims_and_stops() {
        // Scan 90..100 (up to block 99); block 100, where the new rules take effect, is left
        // unscanned, and the boundary is reported so the caller shuts down.
        assert_eq!(
            clamp_to_boundary(&(h(90)..h(110)), Some(h(100))),
            ControlFlow::Continue(Some(h(100))),
        );
    }

    #[test]
    fn clamp_range_starting_at_boundary_scans_nothing() {
        assert_eq!(
            clamp_to_boundary(&(h(100)..h(110)), Some(h(100))),
            ControlFlow::Break(h(100)),
        );
    }

    #[test]
    fn clamp_range_entirely_above_boundary_scans_nothing() {
        assert_eq!(
            clamp_to_boundary(&(h(150)..h(200)), Some(h(100))),
            ControlFlow::Break(h(100)),
        );
    }
}
