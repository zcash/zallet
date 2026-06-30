//! Shared helpers for the PCZT RPC methods.

use base64ct::{Base64, Encoding};
use jsonrpsee::types::ErrorObjectOwned;
use pczt::Pczt;

use crate::components::json_rpc::server::LegacyCode;

/// Maximum size, in bytes, accepted for a base64-encoded PCZT.
///
/// PCZTs grow with the number of inputs and outputs (and their proofs), but a
/// 10 MiB ceiling comfortably exceeds any realistic transaction while bounding
/// the work an unauthenticated decode can be made to do.
pub(super) const MAX_PCZT_BASE64_LEN: usize = 10 * 1024 * 1024;

/// Maximum number of PCZTs accepted by `pczt_combine` in a single call.
pub(super) const MAX_PCZTS_TO_COMBINE: usize = 20;

/// Decodes a base64-encoded PCZT, rejecting oversized inputs before allocating.
pub(super) fn decode_pczt_base64(s: &str) -> Result<Pczt, ErrorObjectOwned> {
    if s.len() > MAX_PCZT_BASE64_LEN {
        return Err(LegacyCode::InvalidParameter.with_static("PCZT exceeds maximum size limit"));
    }
    let pczt_bytes = Base64::decode_vec(s).map_err(|e| {
        LegacyCode::Deserialization.with_message(format!("Invalid base64 encoding: {e}"))
    })?;
    // The parse error describes the malformed bytes; we surface a generic
    // message rather than its internals.
    Pczt::parse(&pczt_bytes).map_err(|_| LegacyCode::Deserialization.with_static("Invalid PCZT"))
}

/// Serializes a PCZT and base64-encodes it for a JSON-RPC response.
///
/// `Pczt::serialize` consumes the PCZT and can fail if it holds values that
/// exceed the wire format's bounds; that would be an internal inconsistency
/// rather than bad user input, so we surface it as a generic error.
pub(super) fn encode_pczt_base64(pczt: Pczt) -> Result<String, ErrorObjectOwned> {
    let bytes = pczt
        .serialize()
        .map_err(|_| LegacyCode::Misc.with_static("Failed to serialize PCZT"))?;
    Ok(Base64::encode_string(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_input() {
        let oversized = "A".repeat(MAX_PCZT_BASE64_LEN + 1);
        let err = decode_pczt_base64(&oversized).unwrap_err();
        assert!(err.message().contains("maximum size limit"));
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = decode_pczt_base64("not valid base64 !!!").unwrap_err();
        assert!(err.message().contains("base64"));
    }

    #[test]
    fn rejects_valid_base64_that_is_not_a_pczt() {
        // Valid base64, but not the PCZT magic/format.
        assert!(decode_pczt_base64("AAAAAAAA").is_err());
    }
}
