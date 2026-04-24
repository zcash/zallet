use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{Account, AccountPurpose, WalletRead, WalletWrite};
use zcash_keys::{
    encoding::{decode_extended_full_viewing_key, encode_payment_address},
    keys::UnifiedFullViewingKey,
};
use zcash_protocol::consensus::{BlockHeight, NetworkConstants};

use crate::components::{
    chain::Chain,
    database::DbConnection,
    json_rpc::{server::LegacyCode, utils::fetch_account_birthday},
};

/// Response to a `z_importviewingkey` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// Result of importing a viewing key.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// The type of the imported address (always "sapling").
    address_type: String,

    /// The Sapling payment address corresponding to the imported viewing key
    /// (the default address).
    address: String,
}

pub(super) const PARAM_VKEY_DESC: &str =
    "The viewing key (only Sapling extended full viewing keys are supported).";
pub(super) const PARAM_RESCAN_DESC: &str = "Whether to rescan the blockchain for transactions (\"yes\", \"no\", or \"whenkeyisnew\"; default is \"whenkeyisnew\"). When rescan is enabled, the wallet's background sync engine will scan for historical transactions from the given start height.";
pub(super) const PARAM_START_HEIGHT_DESC: &str = "Block height from which to begin the rescan (default is 0). Only used when rescan is \"yes\" or \"whenkeyisnew\" (for a new key).";

/// Parsed `rescan` parameter for key-import RPCs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RescanPolicy {
    Yes,
    No,
    WhenKeyIsNew,
}

impl RescanPolicy {
    /// Parses the `rescan` parameter string.
    ///
    /// Returns the parsed policy, or an RPC error if the value is invalid.
    fn parse(rescan: Option<&str>) -> RpcResult<Self> {
        match rescan {
            None | Some("whenkeyisnew") => Ok(Self::WhenKeyIsNew),
            Some("yes") => Ok(Self::Yes),
            Some("no") => Ok(Self::No),
            Some(_) => Err(LegacyCode::InvalidParameter.with_static(
                "Invalid rescan value. Must be \"yes\", \"no\", or \"whenkeyisnew\".",
            )),
        }
    }
}

/// Decodes a Sapling extended full viewing key and derives the default payment address.
///
/// Returns the decoded extended full viewing key and the encoded payment address string.
fn decode_vkey_and_address(
    hrp_fvk: &str,
    hrp_payment_address: &str,
    vkey: &str,
) -> RpcResult<(sapling::zip32::ExtendedFullViewingKey, String)> {
    let extfvk = decode_extended_full_viewing_key(hrp_fvk, vkey).map_err(|e| {
        LegacyCode::InvalidAddressOrKey.with_message(format!("Invalid viewing key: {e}"))
    })?;

    let (_, payment_address) = extfvk.default_address();

    let address = encode_payment_address(hrp_payment_address, &payment_address);

    Ok((extfvk, address))
}

pub(crate) async fn call<C: Chain>(
    wallet: &mut DbConnection,
    chain: C,
    vkey: &str,
    rescan: Option<&str>,
    start_height: Option<u64>,
) -> Response {
    let rescan = RescanPolicy::parse(rescan)?;

    // Parse start_height if provided, keeping it as Option so we can
    // distinguish "not supplied" from "explicitly set to 0" below.
    let start_height = start_height
        .map(|h| {
            u32::try_from(h)
                .map(BlockHeight::from_u32)
                .map_err(|_| LegacyCode::InvalidParameter.with_static("Block height out of range."))
        })
        .transpose()?;

    let chain_tip = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    if let (Some(height), Some(tip)) = (start_height, chain_tip) {
        if height > tip {
            return Err(LegacyCode::InvalidParameter.with_static("Block height out of range."));
        }
    }

    let hrp_fvk = wallet.params().hrp_sapling_extended_full_viewing_key();
    let hrp_addr = wallet.params().hrp_sapling_payment_address();
    let (extfvk, address) = decode_vkey_and_address(hrp_fvk, hrp_addr, vkey)?;

    // Construct a UFVK from the Sapling extended full viewing key so the wallet can
    // track transactions to/from this key's addresses.
    let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
        .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

    // Check if the key is already known to the wallet.
    let existing_account = wallet
        .get_account_for_ufvk(&ufvk)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
    match existing_account {
        Some(account) => {
            if matches!(account.purpose(), AccountPurpose::Spending { .. }) {
                return Err(LegacyCode::Wallet.with_message(format!(
                    "The wallet already contains the private key for this viewing key (address: {address})",
                )));
            }
            // ViewOnly — key already exists, return result.
            //
            // TODO: When rescan is "yes" and the key already exists, zcashd would force a
            // rescan from start_height. We could use `WalletWrite::rewind_to_chain_state`
            // for this (see `z_import_address` for an example).
        }
        None => {
            // new key
            let effective_height = match rescan {
                RescanPolicy::Yes | RescanPolicy::WhenKeyIsNew => {
                    start_height.unwrap_or(BlockHeight::from_u32(0))
                }
                RescanPolicy::No => {
                    start_height.unwrap_or_else(|| chain_tip.unwrap_or(BlockHeight::from_u32(0)))
                }
            };

            let birthday = fetch_account_birthday(&chain, effective_height).await?;

            wallet
                .import_account_ufvk(
                    &format!("Imported Sapling viewing key {address}"),
                    &ufvk,
                    &birthday,
                    AccountPurpose::ViewOnly,
                    None,
                )
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
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
    use zcash_keys::encoding::encode_extended_full_viewing_key;
    use zcash_protocol::constants;

    /// Derives a test extended full viewing key from seed [0; 32] and encodes it.
    fn encoded_mainnet_extfvk() -> String {
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&[0; 32]);
        #[allow(deprecated)]
        let extfvk = extsk.to_extended_full_viewing_key();
        encode_extended_full_viewing_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            &extfvk,
        )
    }

    /// Derives a test extended full viewing key from seed [0; 32] and encodes it for testnet.
    fn encoded_testnet_extfvk() -> String {
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&[0; 32]);
        #[allow(deprecated)]
        let extfvk = extsk.to_extended_full_viewing_key();
        encode_extended_full_viewing_key(
            constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            &extfvk,
        )
    }

    // -- RescanPolicy::parse tests --

    #[test]
    fn rescan_none_defaults_to_whenkeyisnew() {
        assert_eq!(
            RescanPolicy::parse(None).unwrap(),
            RescanPolicy::WhenKeyIsNew
        );
    }

    #[test]
    fn rescan_whenkeyisnew() {
        assert_eq!(
            RescanPolicy::parse(Some("whenkeyisnew")).unwrap(),
            RescanPolicy::WhenKeyIsNew
        );
    }

    #[test]
    fn rescan_yes() {
        assert_eq!(RescanPolicy::parse(Some("yes")).unwrap(), RescanPolicy::Yes);
    }

    #[test]
    fn rescan_no() {
        assert_eq!(RescanPolicy::parse(Some("no")).unwrap(), RescanPolicy::No);
    }

    #[test]
    fn rescan_invalid_value() {
        assert!(RescanPolicy::parse(Some("always")).is_err());
        assert!(RescanPolicy::parse(Some("")).is_err());
        assert!(RescanPolicy::parse(Some("true")).is_err());
    }

    // -- decode_vkey_and_address tests --

    #[test]
    fn decode_valid_mainnet_vkey() {
        let encoded = encoded_mainnet_extfvk();
        let (_, address) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        // Mainnet Sapling addresses start with "zs1".
        assert!(address.starts_with("zs1"));
    }

    #[test]
    fn decode_valid_testnet_vkey() {
        let encoded = encoded_testnet_extfvk();
        let (_, address) = decode_vkey_and_address(
            constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        // Testnet Sapling addresses start with "ztestsapling1".
        assert!(address.starts_with("ztestsapling1"));
    }

    #[test]
    fn decode_same_key_produces_same_address_across_calls() {
        let encoded = encoded_mainnet_extfvk();

        let (_, addr1) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        let (_, addr2) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        assert_eq!(addr1, addr2);
    }

    #[test]
    fn decode_roundtrip() {
        let encoded = encoded_mainnet_extfvk();
        let (extfvk, _) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        let re_encoded = encode_extended_full_viewing_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            &extfvk,
        );
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn decode_invalid_vkey() {
        let result = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "not-a-valid-key",
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_wrong_network_vkey() {
        // Testnet viewing key decoded with mainnet HRP should fail.
        let testnet_encoded = encoded_testnet_extfvk();
        let result = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &testnet_encoded,
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_empty_vkey() {
        let result = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "",
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_spending_key_rejected_as_viewing_key() {
        // A spending key string should be rejected when decoded as a viewing key,
        // since the HRP will not match.
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&[0; 32]);
        let spending_key_encoded = zcash_keys::encoding::encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &extsk,
        );

        let result = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &spending_key_encoded,
        );
        assert!(result.is_err());
    }
}
