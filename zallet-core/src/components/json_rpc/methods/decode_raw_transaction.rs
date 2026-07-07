use jsonrpsee::core::RpcResult;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus;

use super::get_raw_transaction::{TransactionDetails, tx_to_json};
use crate::{components::json_rpc::server::LegacyCode, network::Network};

/// Response to a `decoderawtransaction` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The result type for OpenRPC schema generation.
pub(crate) type ResultType = TransactionDetails;

/// Parameter description for OpenRPC schema generation.
pub(super) const PARAM_HEXSTRING_DESC: &str = "The transaction hex string";

/// Decodes a hex-encoded transaction.
pub(crate) fn call(params: &Network, hexstring: &str) -> Response {
    let tx_bytes = hex::decode(hexstring)
        .map_err(|_| LegacyCode::Deserialization.with_static("TX decode failed"))?;

    // The branch ID parameter doesn't affect parsing - tx bytes are self-describing.
    // TODO: Consider proposing Option<BranchId> upstream for decode-only use cases.
    let tx = Transaction::read(tx_bytes.as_slice(), consensus::BranchId::Nu6)
        .map_err(|_| LegacyCode::Deserialization.with_static("TX decode failed"))?;

    let size = tx_bytes.len() as u64;

    Ok(tx_to_json(params, tx, size))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from zcashd `src/test/rpc_tests.cpp:26-70`
    const MAINNET: &Network = &Network::Consensus(consensus::Network::MainNetwork);

    /// Tests that "DEADBEEF" (valid hex but invalid transaction) returns an error.
    #[test]
    fn decode_deadbeef_returns_error() {
        let result = call(MAINNET, "DEADBEEF");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.message(), "TX decode failed");
    }

    /// Tests that "null" (invalid hex) returns an error.
    #[test]
    fn decode_null_returns_error() {
        let result = call(MAINNET, "null");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.message(), "TX decode failed");
    }

    /// Tests that an empty string returns an error.
    #[test]
    fn decode_empty_returns_error() {
        let result = call(MAINNET, "");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.message(), "TX decode failed");
    }

    /// Tests that the error code is RPC_DESERIALIZATION_ERROR (value -22) for decode failures.
    #[test]
    fn decode_error_has_correct_code() {
        let result = call(MAINNET, "DEADBEEF");
        let err = result.unwrap_err();
        assert_eq!(err.code(), LegacyCode::Deserialization as i32);
    }
}
