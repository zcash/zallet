use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Serialize;
use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_keys::{
    address::Address, encoding::encode_extended_full_viewing_key, keys::UnifiedSpendingKey,
};
use zcash_protocol::consensus::NetworkConstants;

use crate::components::{
    database::DbConnection,
    json_rpc::{
        payments::get_account_for_address, server::LegacyCode, utils::ensure_wallet_is_unlocked,
    },
    keystore::KeyStore,
};

/// Response to a `z_exportviewingkey` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The exported viewing key, as a bech32- or bech32m-encoded string.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(String);

pub(super) const PARAM_ZADDR_DESC: &str = "The Sapling payment address or unified address.";
pub(super) const PARAM_IVK_DESC: &str = "Whether to export the unified incoming viewing key (UIVK) instead of the full viewing key. Default is false.";

pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    zaddr: &str,
    ivk: Option<bool>,
) -> Response {
    ensure_wallet_is_unlocked(keystore).await?;

    let address = Address::decode(wallet.params(), zaddr)
        .ok_or(LegacyCode::InvalidAddressOrKey.with_static("Invalid zaddr"))?;

    let export_ivk = ivk.unwrap_or(false);

    match &address {
        Address::Unified(_) => {
            let account = get_account_for_address(wallet, &address).map_err(|e| {
                // Align the "address not held" error with the Sapling path below;
                // `get_account_for_address` reports it with a payment-oriented message.
                if e.code() == LegacyCode::InvalidAddressOrKey as i32 {
                    LegacyCode::Wallet.with_static(
                        "Wallet does not hold private key or viewing key for this zaddr",
                    )
                } else {
                    e
                }
            })?;
            let ufvk = account.ufvk().ok_or(
                LegacyCode::Wallet.with_static("Account does not have a unified full viewing key"),
            )?;

            Ok(ResultType(if export_ivk {
                ufvk.to_unified_incoming_viewing_key()
                    .encode(wallet.params())
            } else {
                ufvk.encode(wallet.params())
            }))
        }
        Address::Sapling(sapling_addr) => {
            // Look up the account by matching the Sapling address against each UFVK's
            // Sapling component. `get_account_for_address` doesn't find bare Sapling
            // receivers derived from unified accounts.
            let ufvks = wallet
                .get_unified_full_viewing_keys()
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

            let (account_id, ufvk) = ufvks
                .iter()
                .find_map(|(id, ufvk)| {
                    ufvk.sapling()
                        .and_then(|dfvk| dfvk.decrypt_diversifier(sapling_addr))
                        .map(|_| (*id, ufvk))
                })
                .ok_or_else(|| {
                    LegacyCode::Wallet.with_static(
                        "Wallet does not hold private key or viewing key for this zaddr",
                    )
                })?;

            // The UIVK is derivable from the UFVK alone, so this also works for
            // imported view-only accounts.
            if export_ivk {
                return Ok(ResultType(
                    ufvk.to_unified_incoming_viewing_key()
                        .encode(wallet.params()),
                ));
            }

            let account = wallet
                .get_account(account_id)
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
                .ok_or(LegacyCode::Wallet.with_static(
                    "Wallet does not hold private key or viewing key for this zaddr",
                ))?;

            let derivation = account.source().key_derivation().ok_or_else(|| {
                LegacyCode::Wallet
                    .with_static("Cannot export viewing key for an imported view-only account")
            })?;

            let seed = keystore
                .decrypt_seed(derivation.seed_fingerprint())
                .await
                .map_err(|e| match e.kind() {
                    // TODO: Improve internal error types.
                    //       https://github.com/zcash/zallet/issues/256
                    crate::error::ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                        LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
                    }
                    _ => LegacyCode::Database.with_message(e.to_string()),
                })?;

            let usk = UnifiedSpendingKey::from_seed(
                wallet.params(),
                seed.expose_secret(),
                derivation.account_index(),
            )
            .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

            // The account was selected by matching the address against the stored
            // UFVK, but the exported key is re-derived from the seed. Ensure the two
            // agree, so we never export a key that does not view the queried address.
            let derived_dfvk = usk.sapling().to_diversifiable_full_viewing_key();
            if ufvk
                .sapling()
                .is_none_or(|dfvk| dfvk.to_bytes() != derived_dfvk.to_bytes())
            {
                return Err(LegacyCode::Wallet
                    .with_static("Wallet key derivation does not match the stored viewing key"));
            }

            // Only ExtendedFullViewingKey carries the chain code needed for bech32 encoding;
            // DiversifiableFullViewingKey can't be used here.
            #[allow(deprecated)]
            let extfvk = usk.sapling().to_extended_full_viewing_key();

            let hrp = wallet.params().hrp_sapling_extended_full_viewing_key();
            Ok(ResultType(encode_extended_full_viewing_key(hrp, &extfvk)))
        }
        _ => Err(LegacyCode::InvalidAddressOrKey
            .with_static("z_exportviewingkey only supports Sapling and unified addresses")),
    }
}

#[cfg(test)]
mod tests {
    use zcash_keys::{
        encoding::{
            decode_extended_full_viewing_key, encode_extended_full_viewing_key,
            encode_payment_address,
        },
        keys::UnifiedFullViewingKey,
    };
    use zcash_protocol::{
        consensus::{MAIN_NETWORK, TEST_NETWORK},
        constants,
    };

    /// Constructs a UFVK (with only a Sapling component) from seed `[0; 32]`.
    fn test_ufvk() -> UnifiedFullViewingKey {
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&[0; 32]);
        #[allow(deprecated)]
        let extfvk = extsk.to_extended_full_viewing_key();
        UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
            .expect("valid UFVK parts")
    }

    /// Derives a Sapling extended spending key from seed [0; 32] and returns
    /// the encoded EFVK and the default payment address.
    fn test_efvk_and_address(hrp_fvk: &str, hrp_addr: &str) -> (String, String) {
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&[0; 32]);
        #[allow(deprecated)]
        let extfvk = extsk.to_extended_full_viewing_key();
        let encoded_fvk = encode_extended_full_viewing_key(hrp_fvk, &extfvk);
        let (_, payment_address) = extfvk.default_address();
        let encoded_addr = encode_payment_address(hrp_addr, &payment_address);
        (encoded_fvk, encoded_addr)
    }

    #[test]
    fn encoded_efvk_is_valid_bech32() {
        let (encoded, _) = test_efvk_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
        );
        assert!(encoded.starts_with("zxviews"));
    }

    #[test]
    fn encoded_efvk_round_trips() {
        let hrp = constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY;
        let (encoded, _) =
            test_efvk_and_address(hrp, constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS);
        let decoded = decode_extended_full_viewing_key(hrp, &encoded).unwrap();
        let re_encoded = encode_extended_full_viewing_key(hrp, &decoded);
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn efvk_produces_consistent_default_address() {
        let hrp_fvk = constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY;
        let hrp_addr = constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS;

        let (_, addr1) = test_efvk_and_address(hrp_fvk, hrp_addr);
        let (_, addr2) = test_efvk_and_address(hrp_fvk, hrp_addr);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn mainnet_address_starts_with_zs() {
        let (_, addr) = test_efvk_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
        );
        assert!(addr.starts_with("zs"));
    }

    #[test]
    fn testnet_efvk_has_correct_hrp() {
        let (encoded, _) = test_efvk_and_address(
            constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
        );
        assert!(encoded.starts_with("zxviewtestsapling"));
    }

    #[test]
    fn testnet_efvk_round_trips() {
        let hrp = constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY;
        let (encoded, _) =
            test_efvk_and_address(hrp, constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS);
        let decoded = decode_extended_full_viewing_key(hrp, &encoded).unwrap();
        let re_encoded = encode_extended_full_viewing_key(hrp, &decoded);
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn different_seeds_produce_different_efvks() {
        let hrp = constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY;

        let extsk_a = sapling::zip32::ExtendedSpendingKey::master(&[0; 32]);
        #[allow(deprecated)]
        let efvk_a = encode_extended_full_viewing_key(hrp, &extsk_a.to_extended_full_viewing_key());

        let extsk_b = sapling::zip32::ExtendedSpendingKey::master(&[1; 32]);
        #[allow(deprecated)]
        let efvk_b = encode_extended_full_viewing_key(hrp, &extsk_b.to_extended_full_viewing_key());

        assert_ne!(efvk_a, efvk_b);
    }

    #[test]
    fn ufvk_encodes_with_uview_hrp() {
        let ufvk = test_ufvk();
        assert!(ufvk.encode(&MAIN_NETWORK).starts_with("uview1"));
        assert!(ufvk.encode(&TEST_NETWORK).starts_with("uviewtest1"));
    }

    #[test]
    fn ufvk_encoding_round_trips() {
        let ufvk = test_ufvk();
        let encoded = ufvk.encode(&MAIN_NETWORK);
        let decoded = UnifiedFullViewingKey::decode(&MAIN_NETWORK, &encoded).unwrap();
        assert_eq!(encoded, decoded.encode(&MAIN_NETWORK));
    }

    #[test]
    fn uivk_encodes_with_uivk_hrp() {
        let uivk = test_ufvk().to_unified_incoming_viewing_key();
        assert!(uivk.encode(&MAIN_NETWORK).starts_with("uivk1"));
        assert!(uivk.encode(&TEST_NETWORK).starts_with("uivktest1"));
    }

    #[test]
    fn uivk_is_deterministic_for_a_ufvk() {
        let ufvk = test_ufvk();
        let uivk_a = ufvk.to_unified_incoming_viewing_key().encode(&MAIN_NETWORK);
        let uivk_b = ufvk.to_unified_incoming_viewing_key().encode(&MAIN_NETWORK);
        assert_eq!(uivk_a, uivk_b);
    }

    #[test]
    fn efvk_default_address_matches_import_flow() {
        // Exported EFVK, decoded back, should produce the same default address.
        let hrp_fvk = constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY;
        let hrp_addr = constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS;

        let (encoded_fvk, original_addr) = test_efvk_and_address(hrp_fvk, hrp_addr);

        let decoded = decode_extended_full_viewing_key(hrp_fvk, &encoded_fvk).unwrap();
        let (_, reimported_payment_addr) = decoded.default_address();
        let reimported_addr = encode_payment_address(hrp_addr, &reimported_payment_addr);

        assert_eq!(original_addr, reimported_addr);
    }
}
