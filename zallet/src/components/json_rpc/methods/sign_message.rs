use base64ct::{Base64, Encoding};
use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use secp256k1::{Message, Secp256k1};
use secrecy::ExposeSecret;
use serde::Serialize;
use transparent::address::TransparentAddress;
use zcash_client_backend::{
    data_api::{Account as _, WalletRead},
    keys::UnifiedSpendingKey,
};
use zcash_keys::encoding::AddressCodec;

use super::verify_message;
use crate::components::{database::DbConnection, json_rpc::server::LegacyCode, keystore::KeyStore};

/// Response to a `signmessage` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The result of signing a message.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(String);

// Re-export parameter descriptions from verify_message for OpenRPC generation.
pub(super) use super::verify_message::PARAM_MESSAGE_DESC;

pub(super) const PARAM_T_ADDR_DESC: &str = "The transparent address to use to look up the private key that will be used to sign the message.";

/// Signs a message with the private key of a transparent address.
pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    t_addr: &str,
    message: &str,
) -> Response {
    let transparent_addr = TransparentAddress::decode(wallet.params(), t_addr).map_err(|_| {
        LegacyCode::InvalidAddressOrKey.with_static("Invalid Zcash transparent address")
    })?;

    if matches!(transparent_addr, TransparentAddress::ScriptHash(_)) {
        return Err(LegacyCode::Type.with_static("Address does not refer to key"));
    }

    let secret_key = get_transparent_secret_key(wallet, keystore, &transparent_addr).await?;

    let signature_b64 = sign_message_with_key(&secret_key, message);
    Ok(ResultType(signature_b64))
}

/// Retrieves the private key for a transparent address known to the wallet.
async fn get_transparent_secret_key(
    wallet: &DbConnection,
    keystore: &KeyStore,
    address: &TransparentAddress,
) -> RpcResult<secp256k1::SecretKey> {
    // Find the account for this transparent address.
    let (account, metadata) = {
        let mut found = None;
        for account_id in wallet
            .get_account_ids()
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        {
            if let Some(meta) = wallet
                .get_transparent_address_metadata(account_id, address)
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            {
                let account = wallet
                    .get_account(account_id)
                    .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
                    .ok_or_else(|| LegacyCode::Database.with_static("Account not found"))?;
                found = Some((account, meta));
                break;
            }
        }
        found.ok_or_else(|| LegacyCode::Wallet.with_static("Unknown address"))?
    };

    // Derive/decrypt based on address source.
    match (metadata.source().scope(), metadata.source().address_index()) {
        // HD: derive from seed.
        (Some(scope), Some(address_index)) => {
            let derivation = account
                .source()
                .key_derivation()
                .ok_or_else(|| LegacyCode::Wallet.with_static("Private key not available"))?;

            let seed = keystore
                .decrypt_seed(derivation.seed_fingerprint())
                .await
                .map_err(map_wallet_locked_error)?;

            let usk = UnifiedSpendingKey::from_seed(
                wallet.params(),
                seed.expose_secret(),
                derivation.account_index(),
            )
            .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

            usk.transparent()
                .derive_secret_key(scope, address_index)
                .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))
        }
        // Standalone imported key.
        #[cfg(feature = "transparent-key-import")]
        (None, None) => keystore
            .decrypt_standalone_transparent_key(address)
            .await
            .map_err(map_wallet_locked_error),
        #[cfg(not(feature = "transparent-key-import"))]
        (None, None) => Err(LegacyCode::Wallet.with_static("Private key not available")),
        // Invalid state: scope and address_index should both be Some or both be None.
        _ => Err(LegacyCode::Wallet.with_static("Private key not available")),
    }
}

/// Maps keystore errors, converting "Wallet is locked" to the appropriate RPC error.
// TODO: Improve internal error types to not rely on string matching (#256)
fn map_wallet_locked_error(e: crate::error::Error) -> jsonrpsee::types::ErrorObject<'static> {
    if e.to_string() == "Wallet is locked" {
        LegacyCode::WalletUnlockNeeded
            .with_static("Error: Please enter the wallet passphrase with walletpassphrase first.")
    } else {
        LegacyCode::Wallet.with_message(e.to_string())
    }
}

/// Signs a message with a secret key, returning the base64-encoded signature.
fn sign_message_with_key(secret_key: &secp256k1::SecretKey, message: &str) -> String {
    let hash = verify_message::message_hash(message);
    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(&hash).expect("message_hash always returns 32 bytes");

    let recoverable_sig = secp.sign_ecdsa_recoverable(&msg, secret_key);
    let (recovery_id, sig_bytes) = recoverable_sig.serialize_compact();

    // Header byte is 31 + recovery_id for compressed pubkey signatures.
    // <https://github.com/zcash/zcash/blob/v6.11.0/src/pubkey.cpp#L227>
    let header = 31 + recovery_id.to_i32() as u8;
    let mut signature = [0u8; 65];
    signature[0] = header;
    signature[1..65].copy_from_slice(&sig_bytes);

    Base64::encode_string(&signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Network;
    use zcash_protocol::consensus;

    fn mainnet() -> Network {
        Network::Consensus(consensus::Network::MainNetwork)
    }

    /// Helper to create a random keypair for testing.
    fn test_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey) {
        use rand::RngCore;
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let secret_key = secp256k1::SecretKey::from_slice(&secret_bytes)
            .expect("32 random bytes should be a valid secret key");
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        (secret_key, public_key)
    }

    /// Test the signing logic by signing a message and verifying it.
    /// This tests correctness without needing a full wallet.
    // TODO: Add integration tests for sign_message::call() once a full wallet testing framework exists
    #[test]
    fn sign_and_verify_roundtrip() {
        let (secret_key, public_key) = test_keypair();

        // Derive the transparent address from the public key.
        let address = TransparentAddress::from_pubkey(&public_key);
        let address_str = address.encode(&mainnet());

        let message = "Test message for signing";
        let signature_b64 = sign_message_with_key(&secret_key, message);

        // Verify using the verify_message implementation.
        let result = verify_message::call(&mainnet(), &address_str, &signature_b64, message);
        let verify_message::ResultType(verified) = result.expect("Verification should succeed");
        assert!(verified, "Signature should verify as valid");
    }

    /// Test that signatures don't verify with wrong message.
    #[test]
    fn sign_verify_wrong_message_fails() {
        let (secret_key, public_key) = test_keypair();
        let address = TransparentAddress::from_pubkey(&public_key);
        let address_str = address.encode(&mainnet());

        let message = "Original message";
        let wrong_message = "Different message";

        let signature_b64 = sign_message_with_key(&secret_key, message);

        // Verify with wrong message should return false.
        let result = verify_message::call(&mainnet(), &address_str, &signature_b64, wrong_message);
        let verify_message::ResultType(verified) =
            result.expect("Verification call should succeed");
        assert!(!verified, "Signature should not verify with wrong message");
    }

    /// Test that signatures don't verify with wrong address.
    #[test]
    fn sign_verify_wrong_address_fails() {
        let (secret_key, _public_key) = test_keypair();
        let (_other_secret, other_public) = test_keypair();

        // Use a different address than the one that signed.
        let wrong_address = TransparentAddress::from_pubkey(&other_public);
        let wrong_address_str = wrong_address.encode(&mainnet());

        let message = "Test message";
        let signature_b64 = sign_message_with_key(&secret_key, message);

        // Verify with wrong address should return false.
        let result = verify_message::call(&mainnet(), &wrong_address_str, &signature_b64, message);
        let verify_message::ResultType(verified) =
            result.expect("Verification call should succeed");
        assert!(!verified, "Signature should not verify with wrong address");
    }
}
