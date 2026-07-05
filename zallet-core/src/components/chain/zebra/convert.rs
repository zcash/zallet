//! Conversions between `zebra-chain` types and `zcash_primitives`/`zcash_protocol` types.

use zcash_primitives::block::{Block, BlockHash};
use zcash_protocol::{
    TxId,
    consensus::{BlockHeight, BranchId},
};
use zebra_chain::serialization::ZcashSerialize as _;

use super::super::ChainError;
use crate::network::Network;

/// `zebra-chain` block hash → wallet block hash (same byte order).
pub(super) fn block_hash(h: zebra_chain::block::Hash) -> BlockHash {
    BlockHash(h.0)
}

/// Wallet block hash → `zebra-chain` block hash.
pub(super) fn to_zebra_hash(h: &BlockHash) -> zebra_chain::block::Hash {
    zebra_chain::block::Hash(h.0)
}

/// Wallet txid → `zebra-chain` transaction hash (same internal byte order).
pub(super) fn to_zebra_txid(txid: TxId) -> zebra_chain::transaction::Hash {
    zebra_chain::transaction::Hash(*txid.as_ref())
}

/// `zebra-chain` transaction hash → wallet txid (same internal byte order).
#[cfg(feature = "spend-index")]
pub(super) fn from_zebra_tx_hash(h: zebra_chain::transaction::Hash) -> TxId {
    TxId::from_bytes(h.0)
}

/// Wallet transparent outpoint → `zebra-chain` transparent outpoint.
#[cfg(feature = "spend-index")]
pub(super) fn to_zebra_outpoint(
    outpoint: &transparent::bundle::OutPoint,
) -> zebra_chain::transparent::OutPoint {
    zebra_chain::transparent::OutPoint::from_usize(
        zebra_chain::transaction::Hash(*outpoint.hash()),
        outpoint.n() as usize,
    )
}

/// `zebra-chain` height → wallet height.
pub(super) fn height(h: zebra_chain::block::Height) -> BlockHeight {
    BlockHeight::from_u32(h.0)
}

/// Wallet height → `zebra-chain` height.
pub(super) fn to_zebra_height(h: BlockHeight) -> zebra_chain::block::Height {
    zebra_chain::block::Height(u32::from(h))
}

/// Deserializes raw block bytes (the canonical encoding produced by `zebra-chain`) into a
/// wallet block.
pub(super) fn block(bytes: &[u8], params: &Network) -> Result<Block, ChainError> {
    Block::read(bytes, params).map_err(ChainError::invalid_data)
}

/// Re-serializes a `zebra-chain` block to its canonical encoding.
pub(super) fn block_to_bytes(block: &zebra_chain::block::Block) -> Result<Vec<u8>, ChainError> {
    block.zcash_serialize_to_vec().map_err(ChainError::backend)
}

/// Re-serializes a `zebra-chain` transaction to its canonical encoding.
pub(super) fn tx_to_bytes(
    tx: &zebra_chain::transaction::Transaction,
) -> Result<Vec<u8>, ChainError> {
    tx.zcash_serialize_to_vec().map_err(ChainError::backend)
}

/// Deserializes raw transaction bytes, parsing at `parse_height` to select the consensus
/// branch.
pub(super) fn transaction(
    bytes: &[u8],
    params: &Network,
    parse_height: BlockHeight,
) -> Result<zcash_primitives::transaction::Transaction, ChainError> {
    let branch_id = BranchId::for_height(params, parse_height);
    zcash_primitives::transaction::Transaction::read(bytes, branch_id)
        .map_err(ChainError::invalid_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_height_roundtrip() {
        let bh = BlockHash([3u8; 32]);
        assert_eq!(block_hash(to_zebra_hash(&bh)), bh);

        let h = BlockHeight::from_u32(123_456);
        assert_eq!(height(to_zebra_height(h)), h);
    }
}
