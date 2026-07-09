use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{AccountPurpose, WalletRead, WalletWrite};
use zcash_keys::{encoding::decode_extended_spending_key, keys::UnifiedFullViewingKey};
use zcash_protocol::consensus::{BlockHeight, NetworkConstants};

use crate::components::{
    chain::Chain,
    database::DbConnection,
    json_rpc::{server::LegacyCode, utils::fetch_account_birthday},
    keystore::KeyStore,
    sync::WalletDecryptorHandle,
};

/// Response to a `z_importkey` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// Result of importing a spending key.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// The type of the imported address (always "sapling").
    address_type: String,

    /// The Sapling payment address corresponding to the imported key.
    address: String,
}

pub(super) const PARAM_KEY_DESC: &str =
    "The spending key (only Sapling extended spending keys are supported).";
pub(super) const PARAM_RESCAN_DESC: &str = "Whether to rescan the blockchain for transactions (\"yes\", \"no\", or \"whenkeyisnew\"; default is \"whenkeyisnew\"). When rescan is enabled, the wallet's background sync engine will scan for historical transactions from the given start height.";
pub(super) const PARAM_START_HEIGHT_DESC: &str = "Block height from which to begin the rescan (default is 0). Only used when rescan is \"yes\" or \"whenkeyisnew\" (for a new key).";

/// Validates the `rescan` parameter.
///
/// Returns the validated rescan value, or an RPC error if the value is invalid.
fn validate_rescan(rescan: Option<&str>) -> RpcResult<&str> {
    match rescan {
        None | Some("whenkeyisnew") => Ok("whenkeyisnew"),
        Some("yes") => Ok("yes"),
        Some("no") => Ok("no"),
        Some(_) => Err(LegacyCode::InvalidParameter
            .with_static("Invalid rescan value. Must be \"yes\", \"no\", or \"whenkeyisnew\".")),
    }
}

/// Decodes a Sapling extended spending key and derives the default payment address.
///
/// Returns the decoded key and the encoded payment address string.
fn decode_key_and_address(
    hrp_spending_key: &str,
    hrp_payment_address: &str,
    key: &str,
) -> RpcResult<(sapling::zip32::ExtendedSpendingKey, String)> {
    let extsk = decode_extended_spending_key(hrp_spending_key, key).map_err(|e| {
        LegacyCode::InvalidAddressOrKey.with_message(format!("Invalid spending key: {e}"))
    })?;

    let (_, payment_address) = extsk.default_address();

    let address =
        zcash_keys::encoding::encode_payment_address(hrp_payment_address, &payment_address);

    Ok((extsk, address))
}

pub(crate) async fn call<C: Chain>(
    wallet: &mut DbConnection,
    keystore: &KeyStore,
    chain: C,
    decryptor: &WalletDecryptorHandle,
    key: &str,
    rescan: Option<&str>,
    start_height: Option<u64>,
) -> Response {
    let rescan = validate_rescan(rescan)?;

    // Resolve and validate start_height, defaulting to 0 (genesis).
    let start_height = BlockHeight::from_u32(
        u32::try_from(start_height.unwrap_or(0))
            .map_err(|_| LegacyCode::InvalidParameter.with_static("Block height out of range."))?,
    );

    let chain_tip = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    // `start_height` is only used as the rescan start when rescanning; for rescan="no"
    // it is ignored entirely, so there is no point validating it against the chain tip.
    if rescan != "no"
        && let Some(tip) = chain_tip
        && start_height > tip
    {
        return Err(LegacyCode::InvalidParameter.with_static("Block height out of range."));
    }

    let hrp = wallet.params().hrp_sapling_extended_spending_key();
    let hrp_addr = wallet.params().hrp_sapling_payment_address();
    let (extsk, address) = decode_key_and_address(hrp, hrp_addr, key)?;

    // Store the encrypted spending key in the keystore.
    keystore
        .encrypt_and_store_standalone_sapling_key(&extsk)
        .await
        .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

    // Import the UFVK derived from the spending key into the wallet database so the
    // wallet can track transactions to/from this key's addresses.
    #[allow(deprecated)]
    let extfvk = extsk.to_extended_full_viewing_key();
    let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
        .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

    // Check if the key is already known to the wallet.
    let is_new_key = wallet
        .get_account_for_ufvk(&ufvk)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .is_none();

    if is_new_key {
        // Determine the birthday height based on the rescan parameter:
        // - "yes" or "whenkeyisnew" → use start_height so the sync engine scans
        //   historical blocks from that point.
        // - "no" → use the current chain tip so the sync engine only tracks new
        //   transactions going forward.
        //
        // TODO: When rescan is "yes" and the key already exists, zcashd would force a
        // rescan from start_height. `WalletWrite::rewind_to_height` could now drive this,
        // but it rewinds the *entire* wallet (every account) rather than just this key, so
        // we defer wiring it up until that global side effect is the desired behaviour.
        let effective_height = match rescan {
            "yes" | "whenkeyisnew" => start_height,
            "no" => chain_tip.unwrap_or_else(|| {
                tracing::warn!(
                    "z_importkey with rescan=\"no\" but no chain tip is known yet; \
                     using genesis (height 0) as the imported key's birthday"
                );
                BlockHeight::from_u32(0)
            }),
            _ => unreachable!(),
        };

        let birthday = fetch_account_birthday(&chain, effective_height).await?;

        wallet
            .import_account_ufvk(
                &format!("Imported Sapling key {}", &address[..16]),
                &ufvk,
                &birthday,
                AccountPurpose::Spending { derivation: None },
                None,
            )
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

        // Reload viewing keys so the imported key is scanned without a restart. Don't wait
        // for the reload to be processed: the marker is queued behind any blocks already in
        // the decryptor, so awaiting it could block this call for a long time during sync.
        if decryptor.reload_keys().await.is_none() {
            tracing::warn!(
                "sync engine has shut down; imported key won't be scanned until restart"
            );
        }
    }

    Ok(ResultType {
        address_type: "sapling".to_string(),
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_keys::encoding::encode_extended_spending_key;
    use zcash_protocol::constants;

    // Test vector: ExtendedSpendingKey derived from master key with seed [0; 32].
    // From zcash_keys::encoding tests.
    const MAINNET_ENCODED_EXTSK: &str = "secret-extended-key-main1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r7h4st4kpsf6qysqws3xh6qmha7gna72fs2n4clnc9zgyd22s658f65pex4exe56qjk5pqj9vfdq7dfdhjc2rs9jdwq0zl99uwycyrxzp86705rk687spn44e2uhm7h0hsagfvkk4n7n6nfer6u57v9cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efchyxwysrvjs87qvlj";
    const TESTNET_ENCODED_EXTSK: &str = "secret-extended-key-test1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r7h4st4kpsf6qysqws3xh6qmha7gna72fs2n4clnc9zgyd22s658f65pex4exe56qjk5pqj9vfdq7dfdhjc2rs9jdwq0zl99uwycyrxzp86705rk687spn44e2uhm7h0hsagfvkk4n7n6nfer6u57v9cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efchyxwysrvjsvzyw8j";

    // -- validate_rescan tests --

    #[test]
    fn rescan_none_defaults_to_whenkeyisnew() {
        assert_eq!(validate_rescan(None).unwrap(), "whenkeyisnew");
    }

    #[test]
    fn rescan_whenkeyisnew() {
        assert_eq!(
            validate_rescan(Some("whenkeyisnew")).unwrap(),
            "whenkeyisnew"
        );
    }

    #[test]
    fn rescan_yes() {
        assert_eq!(validate_rescan(Some("yes")).unwrap(), "yes");
    }

    #[test]
    fn rescan_no() {
        assert_eq!(validate_rescan(Some("no")).unwrap(), "no");
    }

    #[test]
    fn rescan_invalid_value() {
        assert!(validate_rescan(Some("always")).is_err());
        assert!(validate_rescan(Some("")).is_err());
        assert!(validate_rescan(Some("true")).is_err());
    }

    // -- decode_key_and_address tests --

    #[test]
    fn decode_valid_mainnet_key() {
        let (_, address) = decode_key_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            MAINNET_ENCODED_EXTSK,
        )
        .unwrap();

        // The address should be a valid Sapling address starting with "zs1".
        assert!(address.starts_with("zs1"));
    }

    #[test]
    fn decode_valid_testnet_key() {
        let (_, address) = decode_key_and_address(
            constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
            TESTNET_ENCODED_EXTSK,
        )
        .unwrap();

        // Testnet Sapling addresses start with "ztestsapling1".
        assert!(address.starts_with("ztestsapling1"));
    }

    #[test]
    fn decode_same_key_produces_same_address_across_calls() {
        let (_, addr1) = decode_key_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            MAINNET_ENCODED_EXTSK,
        )
        .unwrap();

        let (_, addr2) = decode_key_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            MAINNET_ENCODED_EXTSK,
        )
        .unwrap();

        assert_eq!(addr1, addr2);
    }

    #[test]
    fn decode_roundtrip_mainnet() {
        let (extsk, _) = decode_key_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            MAINNET_ENCODED_EXTSK,
        )
        .unwrap();

        let re_encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &extsk,
        );
        assert_eq!(re_encoded, MAINNET_ENCODED_EXTSK);
    }

    #[test]
    fn decode_invalid_key() {
        let result = decode_key_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "not-a-valid-key",
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_wrong_network_key() {
        // Try to decode a testnet key with mainnet HRP — should fail.
        let result = decode_key_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            TESTNET_ENCODED_EXTSK,
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_empty_key() {
        let result = decode_key_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "",
        );
        assert!(result.is_err());
    }
}
