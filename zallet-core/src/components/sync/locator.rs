//! Block locator construction for fork-point detection.
//!
//! A block locator is a list of the wallet's own block hashes at exponentially-spaced
//! heights, used to find where the wallet's chain diverges from a backend's best chain.

use zcash_client_backend::data_api::WalletRead as _;
use zcash_protocol::consensus::BlockHeight;

use super::SyncError;
use crate::components::chain::{BlockLocator, ChainBlock};
use crate::components::database::DbConnection;

/// The maximum depth below the tip that a locator spans, matching Zebra's
/// `MAX_BLOCK_REORG_HEIGHT` so the locator always covers the reorg window.
const MAX_LOCATOR_DEPTH: u32 = 1000;

/// Returns the heights to sample for a block locator, from `tip` down to
/// `tip - MAX_LOCATOR_DEPTH`: the tip, then exponentially-increasing gaps
/// (tip−1, tip−2, tip−4, …), ending at the depth floor.
///
/// Mirrors `zebra_state`'s `block_locator_heights`.
pub(super) fn locator_block_heights(tip: BlockHeight) -> Vec<BlockHeight> {
    let tip = u32::from(tip);
    let min = tip.saturating_sub(MAX_LOCATOR_DEPTH);

    let exponential = std::iter::successors(Some(1u32), |step| step.checked_mul(2))
        .flat_map(move |step| tip.checked_sub(step));

    std::iter::once(tip)
        .chain(exponential)
        .take_while(move |&height| height > min)
        .chain(std::iter::once(min))
        .map(BlockHeight::from_u32)
        .collect()
}

/// Builds a [`BlockLocator`] from the wallet's own chain history, for fork-point detection.
///
/// Returns the wallet's blocks at [`locator_block_heights`], highest height first, skipping
/// any heights the wallet does not have a hash for. Those heights are strictly decreasing,
/// so the resulting locator satisfies [`BlockLocator`]'s construction invariant.
pub(super) fn build_block_locator(
    db_data: &DbConnection,
    tip: BlockHeight,
) -> Result<BlockLocator, SyncError> {
    let mut blocks = Vec::new();
    for height in locator_block_heights(tip) {
        if let Some(hash) = db_data.get_block_hash(height)? {
            blocks.push(ChainBlock { height, hash });
        }
    }
    Ok(BlockLocator::from_blocks(blocks))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_heights_are_exponentially_spaced() {
        let heights: Vec<u32> = locator_block_heights(BlockHeight::from_u32(10))
            .into_iter()
            .map(u32::from)
            .collect();
        // tip, tip-1, tip-2, tip-4, tip-8, then the floor (tip-1000 saturates to 0).
        assert_eq!(heights, vec![10, 9, 8, 6, 2, 0]);
    }
}
