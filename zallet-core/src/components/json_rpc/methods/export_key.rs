use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_keys::encoding::{decode_payment_address, encode_extended_spending_key};
use zcash_protocol::consensus::NetworkConstants;

use crate::components::{
    database::DbConnection,
    json_rpc::{server::LegacyCode, utils::ensure_wallet_is_unlocked},
    keystore::KeyStore,
};

/// Response to a `z_exportkey` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The exported Sapling extended spending key, encoded as a Bech32 string.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(String);

pub(super) const PARAM_ADDRESS_DESC: &str =
    "The Sapling payment address corresponding to the spending key to export.";

pub(crate) async fn call(wallet: &DbConnection, keystore: &KeyStore, address: &str) -> Response {
    ensure_wallet_is_unlocked(keystore).await?;

    // Decode the Sapling payment address.
    let payment_address = decode_payment_address(
        wallet.params().hrp_sapling_payment_address(),
        address,
    )
    .map_err(|e| {
        LegacyCode::InvalidAddressOrKey.with_message(format!("Invalid Sapling address: {e}"))
    })?;

    // Look up and decrypt the standalone spending key for this address.
    let extsk = keystore
        .decrypt_standalone_sapling_key(&payment_address)
        .await
        .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?
        .ok_or_else(|| {
            LegacyCode::InvalidAddressOrKey
                .with_static("Wallet does not hold the spending key for this Sapling address")
        })?;

    let encoded =
        encode_extended_spending_key(wallet.params().hrp_sapling_extended_spending_key(), &extsk);

    Ok(ResultType(encoded))
}

#[cfg(test)]
mod tests {
    use zcash_keys::encoding::{decode_payment_address, encode_payment_address};
    use zcash_protocol::constants;

    #[test]
    fn decode_valid_mainnet_sapling_address() {
        // From zcash_keys::encoding tests — address derived from seed [0; 32].
        let addr = decode_payment_address(
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "zs1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75c8v35z",
        );
        assert!(addr.is_ok());
    }

    #[test]
    fn decode_valid_testnet_sapling_address() {
        let addr = decode_payment_address(
            constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "ztestsapling1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75ss7jnk",
        );
        assert!(addr.is_ok());
    }

    #[test]
    fn decode_invalid_address() {
        let addr = decode_payment_address(
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "not-a-valid-address",
        );
        assert!(addr.is_err());
    }

    #[test]
    fn decode_wrong_network_address() {
        // Testnet address decoded with mainnet HRP should fail.
        let addr = decode_payment_address(
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "ztestsapling1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75ss7jnk",
        );
        assert!(addr.is_err());
    }

    #[test]
    fn address_encode_decode_roundtrip() {
        let addr = decode_payment_address(
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "zs1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75c8v35z",
        )
        .unwrap();

        let re_encoded =
            encode_payment_address(constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS, &addr);
        assert_eq!(
            re_encoded,
            "zs1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75c8v35z"
        );
    }
}
