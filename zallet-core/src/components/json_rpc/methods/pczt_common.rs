//! Shared helpers for the PCZT RPC methods.

use base64ct::{Base64, Encoding};
use jsonrpsee::types::ErrorObjectOwned;
use pczt::Pczt;
use transparent::keys::TransparentKeyScope;

use super::pczt_error::PcztError;
use crate::components::json_rpc::server::LegacyCode;

/// Maximum size, in bytes, accepted for a base64-encoded PCZT.
///
/// PCZTs grow with the number of inputs and outputs (and their proofs), but a
/// 10 MiB ceiling comfortably exceeds any realistic transaction while bounding
/// the work an unauthenticated decode can be made to do.
pub(super) const MAX_PCZT_BASE64_LEN: usize = 10 * 1024 * 1024;

/// Maximum number of PCZTs accepted by `pczt_combine` in a single call.
pub(super) const MAX_PCZTS_TO_COMBINE: usize = 20;

// Proprietary-field keys carrying Zallet's signing hints inside a PCZT.
//
// `pczt_create` writes these and `pczt_sign` reads them back — a private
// contract between the two methods. A PCZT does carry native ZIP 32 / BIP 32
// derivation metadata, but as of pczt 0.8.0-rc.1 it cannot be read back out:
// `Zip32Derivation` is crate-private, and the only public API touching the
// metadata is the Redactor, which clears it. So we stash our own copy.
// Defining these in one place keeps the writer and reader from drifting; the
// `v1` prefix leaves room for the format to evolve.

/// Global: the wallet seed fingerprint (32 bytes).
pub(super) const PROP_SEED_FINGERPRINT: &str = "zallet.v1.seed_fingerprint";

/// Global: the ZIP 32 account index (`u32`, little-endian).
pub(super) const PROP_ACCOUNT_INDEX: &str = "zallet.v1.account_index";

/// Per transparent input: the key scope (`u32`, little-endian; see [`encode_key_scope`]).
pub(super) const PROP_SCOPE: &str = "zallet.v1.scope";

/// Per transparent input: the non-hardened address index (`u32`, little-endian).
pub(super) const PROP_ADDRESS_INDEX: &str = "zallet.v1.address_index";

/// Encodes a transparent key scope as the `u32` stored in the [`PROP_SCOPE`] hint.
///
/// Inverse of [`decode_key_scope`]. Any scope that is neither external nor
/// internal (e.g. ephemeral) maps to `2`.
pub(super) fn encode_key_scope(scope: TransparentKeyScope) -> u32 {
    if scope == TransparentKeyScope::EXTERNAL {
        0
    } else if scope == TransparentKeyScope::INTERNAL {
        1
    } else {
        2
    }
}

/// Decodes a [`PROP_SCOPE`] `u32` back into a key scope, or `None` if the value
/// is not one this Zallet version writes.
pub(super) fn decode_key_scope(value: u32) -> Option<TransparentKeyScope> {
    match value {
        0 => Some(TransparentKeyScope::EXTERNAL),
        1 => Some(TransparentKeyScope::INTERNAL),
        2 => Some(TransparentKeyScope::EPHEMERAL),
        _ => None,
    }
}

/// Decodes a base64-encoded PCZT, rejecting oversized inputs before allocating.
pub(super) fn decode_pczt_base64(s: &str) -> Result<Pczt, ErrorObjectOwned> {
    if s.len() > MAX_PCZT_BASE64_LEN {
        return Err(LegacyCode::InvalidParameter.with_static("PCZT exceeds maximum size limit"));
    }
    let pczt_bytes = Base64::decode_vec(s).map_err(|e| {
        LegacyCode::Deserialization.with_message(format!("Invalid base64 encoding: {e}"))
    })?;
    // The parse error names which part of the encoding was malformed, which is
    // what a caller debugging a rejected PCZT needs.
    Ok(Pczt::parse(&pczt_bytes).map_err(PcztError::Parse)?)
}

/// Serializes a PCZT and base64-encodes it for a JSON-RPC response.
///
/// `Pczt::serialize` consumes the PCZT and can fail if it holds values that
/// exceed the wire format's bounds; that would be an internal inconsistency
/// rather than bad user input, so it maps to a generic error code, with the
/// cause carried in the message.
pub(super) fn encode_pczt_base64(pczt: Pczt) -> Result<String, ErrorObjectOwned> {
    let bytes = pczt.serialize().map_err(PcztError::Serialize)?;
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
        let err = decode_pczt_base64("AAAAAAAA").unwrap_err();
        let message = err.message();

        // The parse failure must name its cause, not just report that the PCZT
        // was invalid; this is the regression guard for surfacing the error
        // rather than discarding it.
        let prefix = "Invalid PCZT: ";
        let cause = message.strip_prefix(prefix).unwrap_or_else(|| {
            panic!("expected message to start with {prefix:?}, got {message:?}")
        });
        assert!(!cause.is_empty(), "expected a cause after {prefix:?}");
    }
}
