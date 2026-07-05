use base64ct::{Base64, Encoding};
use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use secp256k1::{
    Message, Secp256k1,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use serde::Serialize;
use std::io::Write;
use transparent::address::TransparentAddress;
use transparent::util::sha256d::HashWriter;
use zcash_encoding::CompactSize;
use zcash_keys::encoding::AddressCodec;

use crate::{components::json_rpc::server::LegacyCode, network::Network};

const MESSAGE_MAGIC: &str = "Zcash Signed Message:\n";

pub(crate) type Response = RpcResult<ResultType>;

/// The result of verifying a message signature.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(bool);

pub(super) const PARAM_ZCASHADDRESS_DESC: &str =
    "The zcash transparent address to use for the signature.";
pub(super) const PARAM_SIGNATURE_DESC: &str =
    "The signature provided by the signer in base64 encoding.";
pub(super) const PARAM_MESSAGE_DESC: &str = "The message that was signed.";

/// Creates the message hash for signature verification.
///
/// This matches zcashd's `src/rpc/misc.cpp:493-495`.
///
/// Each string is prefixed with CompactSize length, then the result is double SHA-256 hashed.
fn message_hash(message: &str) -> [u8; 32] {
    let mut writer = HashWriter::default();

    CompactSize::write(&mut writer, MESSAGE_MAGIC.len()).expect("write to HashWriter");
    writer
        .write_all(MESSAGE_MAGIC.as_bytes())
        .expect("write to HashWriter");

    CompactSize::write(&mut writer, message.len()).expect("write to HashWriter");
    writer
        .write_all(message.as_bytes())
        .expect("write to HashWriter");

    writer.into_hash().into()
}

/// Verifies a message signed with a transparent Zcash address.
///
/// # Arguments
/// - `params`: Network parameters for address encoding/decoding.
/// - `zcashaddress`: The zcash transparent address to use for the signature.
/// - `signature`: The signature provided by the signer in base64 encoding.
/// - `message`: The message that was signed.
pub(crate) fn call(
    params: &Network,
    zcashaddress: &str,
    signature: &str,
    message: &str,
) -> Response {
    let transparent_addr = TransparentAddress::decode(params, zcashaddress)
        .map_err(|_| LegacyCode::Type.with_static("Invalid address"))?;

    if matches!(transparent_addr, TransparentAddress::ScriptHash(_)) {
        return Err(LegacyCode::Type.with_static("Address does not refer to key"));
    }

    let sig_bytes = Base64::decode_vec(signature)
        .map_err(|_| LegacyCode::InvalidAddressOrKey.with_static("Malformed base64 encoding"))?;

    if sig_bytes.len() != 65 {
        return Ok(ResultType(false));
    }

    // Parse signature header byte (zcashd pubkey.cpp:47-48)
    // Header 27-30 = uncompressed pubkey, 31-34 = compressed pubkey.
    let header = sig_bytes[0];
    if (27..=30).contains(&header) {
        return Err(LegacyCode::Type.with_static("Uncompressed key signatures are not supported."));
    }
    if !(31..=34).contains(&header) {
        return Ok(ResultType(false));
    }

    let recovery_id = ((header - 27) & 3) as i32;

    let hash = message_hash(message);

    // Attempt to recover the public key from the signature
    let secp = Secp256k1::new();

    let recid = match RecoveryId::from_i32(recovery_id) {
        Ok(id) => id,
        Err(_) => return Ok(ResultType(false)),
    };

    let recoverable_sig = match RecoverableSignature::from_compact(&sig_bytes[1..65], recid) {
        Ok(sig) => sig,
        Err(_) => return Ok(ResultType(false)),
    };

    let msg = match Message::from_digest_slice(&hash) {
        Ok(m) => m,
        Err(_) => return Ok(ResultType(false)),
    };

    let recovered_pubkey = match secp.recover_ecdsa(&msg, &recoverable_sig) {
        Ok(pk) => pk,
        Err(_) => return Ok(ResultType(false)),
    };

    let recovered_addr = TransparentAddress::from_pubkey(&recovered_pubkey);
    Ok(ResultType(recovered_addr == transparent_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus;

    // A real signed message found on the Zcash Community Forum
    const TEST_ADDRESS: &str = "t1VydNnkjBzfL1iAMyUbwGKJAF7PgvuCfMY";
    const TEST_SIGNATURE: &str =
        "H3RY+6ZfWUbzaaXxK8I42thf+f3tOrwKP2elphxAxq8tKypwJG4+V7EGR+sTWMZ5MFyvTQW8ZIV0yGU+93JTioA=";
    const TEST_MESSAGE: &str =
        "20251117: 1 Yay; 2 Yay; 3 Yay; 4 Yay; 5 Nay; 6 Nay; 7 Yay; 8 Yay; 9 Nay";

    fn mainnet() -> Network {
        Network::Consensus(consensus::Network::MainNetwork)
    }

    #[test]
    fn verify_valid_signature() {
        let result = call(&mainnet(), TEST_ADDRESS, TEST_SIGNATURE, TEST_MESSAGE);
        assert!(result.is_ok());
        let ResultType(verified) = result.unwrap();
        assert!(verified, "Valid signature should verify successfully");
    }

    #[test]
    fn verify_wrong_message_fails() {
        let result = call(&mainnet(), TEST_ADDRESS, TEST_SIGNATURE, "wrongmessage");
        assert!(result.is_ok());
        let ResultType(verified) = result.unwrap();
        assert!(!verified, "Wrong message should fail verification");
    }

    #[test]
    fn verify_wrong_address_fails() {
        let result = call(
            &mainnet(),
            "t1VtArtnn1dGPiD2WFfMXYXW5mHM3q1GpgV",
            TEST_SIGNATURE,
            TEST_MESSAGE,
        );
        assert!(result.is_ok());
        let ResultType(verified) = result.unwrap();
        assert!(!verified, "Wrong address should fail verification");
    }

    #[test]
    fn verify_invalid_address_returns_error() {
        let result = call(
            &mainnet(),
            "t1VtArtnn1dGPiD2WFfMXYXW5mHM3q1Gpg",
            TEST_SIGNATURE,
            TEST_MESSAGE,
        );
        let err = result.unwrap_err();
        assert_eq!(err.code(), LegacyCode::Type as i32);
        assert_eq!(err.message(), "Invalid address");
    }

    #[test]
    fn verify_malformed_base64_returns_error() {
        let result = call(&mainnet(), TEST_ADDRESS, "not_base64!!!", TEST_MESSAGE);
        let err = result.unwrap_err();
        assert_eq!(err.code(), LegacyCode::InvalidAddressOrKey as i32);
        assert_eq!(err.message(), "Malformed base64 encoding");
    }

    #[test]
    fn verify_script_address_returns_error() {
        let result = call(
            &mainnet(),
            "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd",
            TEST_SIGNATURE,
            TEST_MESSAGE,
        );
        let err = result.unwrap_err();
        assert_eq!(err.code(), LegacyCode::Type as i32);
        assert_eq!(err.message(), "Address does not refer to key");
    }

    #[test]
    fn verify_uncompressed_key_returns_error() {
        let mut sig_bytes = Base64::decode_vec(TEST_SIGNATURE).unwrap();
        sig_bytes[0] = 27;
        let uncompressed_sig = Base64::encode_string(&sig_bytes);

        let result = call(&mainnet(), TEST_ADDRESS, &uncompressed_sig, TEST_MESSAGE);
        let err = result.unwrap_err();
        assert_eq!(err.code(), LegacyCode::Type as i32);
        assert_eq!(
            err.message(),
            "Uncompressed key signatures are not supported."
        );
    }

    #[test]
    fn verify_wrong_signature_length_returns_false() {
        // Valid base64 but wrong length (too short)
        let result = call(&mainnet(), TEST_ADDRESS, "AAAA", TEST_MESSAGE);
        assert!(result.is_ok());
        let ResultType(verified) = result.unwrap();
        assert!(!verified, "Wrong signature length should return false");
    }
}
