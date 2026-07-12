//! Wire conversions between the Zinder `WalletQuery` contract and wallet types.
//!
//! Zinder speaks RPC byte order (reversed) hex for hashes and transaction ids;
//! the wallet's [`BlockHash`] and [`TxId`] hold internal byte order. Every hash
//! that crosses this boundary is byte-flipped here, in one place.

use transparent::bundle::OutPoint;
use zcash_primitives::block::BlockHash;
use zcash_protocol::{TxId, consensus::BlockHeight};

use super::proto;
use zallet_core::components::chain::{ChainBlock, ChainError};

/// Encodes 32 internal-order bytes as an RPC-byte-order (reversed) lowercase
/// hex string.
pub(super) fn rpc_hex(internal: &[u8; 32]) -> String {
    let mut bytes = *internal;
    bytes.reverse();
    hex::encode(bytes)
}

/// Decodes an RPC-byte-order (reversed) hex string into 32 internal-order bytes.
pub(super) fn internal_bytes(rpc_hex: &str) -> Result<[u8; 32], ChainError> {
    let mut bytes = hex::decode(rpc_hex).map_err(ChainError::invalid_data)?;
    if bytes.len() != 32 {
        return Err(ChainError::invalid_data(format!(
            "expected a 32-byte hash, got {} bytes",
            bytes.len()
        )));
    }
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// RPC-order hex of a block hash.
pub(super) fn rpc_hex_block_hash(hash: &BlockHash) -> String {
    rpc_hex(&hash.0)
}

/// RPC-order hex of a transaction id.
pub(super) fn rpc_hex_txid(txid: &TxId) -> String {
    rpc_hex(txid.as_ref())
}

/// Parses an RPC-order hex string into a [`BlockHash`].
pub(super) fn block_hash(rpc_hex: &str) -> Result<BlockHash, ChainError> {
    Ok(BlockHash(internal_bytes(rpc_hex)?))
}

/// Parses an RPC-order hex string into a [`TxId`].
pub(super) fn txid(rpc_hex: &str) -> Result<TxId, ChainError> {
    Ok(TxId::from_bytes(internal_bytes(rpc_hex)?))
}

/// Narrows a wire block time (`int64` Unix seconds) into the `u32` the wallet
/// block header carries, rejecting out-of-range values as invalid data.
pub(super) fn block_time(block_time: i64) -> Result<u32, ChainError> {
    u32::try_from(block_time).map_err(ChainError::invalid_data)
}

/// Builds a [`ChainBlock`] from wire block metadata.
pub(super) fn chain_block(
    metadata: &proto::wallet::BlockMetadata,
) -> Result<ChainBlock, ChainError> {
    Ok(ChainBlock::new(
        BlockHeight::from_u32(metadata.height),
        block_hash(&metadata.block_hash)?,
    ))
}

/// Builds a wire [`OutPoint`](proto::wallet::OutPoint) from a wallet outpoint.
pub(super) fn wire_outpoint(outpoint: &OutPoint) -> proto::wallet::OutPoint {
    proto::wallet::OutPoint {
        transaction_id: rpc_hex(outpoint.hash()),
        output_index: outpoint.n(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_hex_round_trips_through_internal_bytes() {
        let internal: [u8; 32] = std::array::from_fn(|i| i as u8);
        let hex = rpc_hex(&internal);
        // RPC order is the byte reversal of internal order.
        assert!(hex.starts_with("1f1e1d"));
        assert!(hex.ends_with("020100"));
        assert_eq!(internal_bytes(&hex).unwrap(), internal);
    }

    #[test]
    fn internal_bytes_rejects_wrong_length() {
        assert!(matches!(
            internal_bytes("00112233"),
            Err(ChainError::InvalidData(_))
        ));
    }

    #[test]
    fn internal_bytes_rejects_non_hex() {
        assert!(matches!(
            internal_bytes(&"z".repeat(64)),
            Err(ChainError::InvalidData(_))
        ));
    }

    #[test]
    fn block_time_narrows_and_guards() {
        assert_eq!(block_time(1_700_000_000).unwrap(), 1_700_000_000);
        assert!(matches!(block_time(-1), Err(ChainError::InvalidData(_))));
        assert!(matches!(
            block_time(i64::from(u32::MAX) + 1),
            Err(ChainError::InvalidData(_))
        ));
    }
}
