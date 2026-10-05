use documented::Documented;
use jsonrpsee::{
    core::{JsonValue, RpcResult},
    types::{ErrorCode as RpcErrorCode, ErrorObjectOwned},
};
use schemars::JsonSchema;
use serde::Serialize;
use zcash_address::unified;
#[cfg(zallet_build = "wallet")]
use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_backend::{
    data_api::WalletWrite,
    keys::{AddressGenerationError, ReceiverRequirement, UnifiedAddressRequest},
};
use zcash_client_sqlite::error::SqliteClientError;

use crate::components::{
    database::DbConnection,
    json_rpc::{
        server::LegacyCode,
        utils::{parse_account_parameter, parse_diversifier_index},
    },
};

#[cfg(zallet_build = "wallet")]
use crate::components::{json_rpc::utils::ensure_seed_is_backed_up, keystore::KeyStore};

/// Response to a `z_getaddressforaccount` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = Address;

/// Information about a derived Unified Address.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct Address {
    /// The account's UUID within this Zallet instance.
    account_uuid: String,

    /// The ZIP 32 account ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<u64>,

    /// The diversifier index specified or chosen.
    diversifier_index: u128,

    /// The receiver types that the UA contains (valid values are "p2pkh", "sapling", "orchard").
    receiver_types: Vec<String>,

    /// The unified address corresponding to the diversifier.
    address: String,
}

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "Either the UUID or ZIP 32 account index of the account to derive from.";
pub(super) const PARAM_RECEIVER_TYPES_DESC: &str =
    "Receiver types to include in the derived address.";
pub(super) const PARAM_DIVERSIFIER_INDEX_DESC: &str = "A specific diversifier index to derive at.";

pub(crate) async fn call(
    wallet: &mut DbConnection,
    #[cfg(zallet_build = "wallet")] keystore: KeyStore,
    account: JsonValue,
    receiver_types: Option<Vec<String>>,
    diversifier_index: Option<u128>,
) -> Response {
    let account_id = parse_account_parameter(
        #[cfg(zallet_build = "wallet")]
        wallet,
        #[cfg(zallet_build = "wallet")]
        &keystore,
        &account,
    )
    .await?;

    // Deriving a fresh address invites new funds into the account, so it is gated on the
    // account's seed having a confirmed backup just as account creation is.
    //
    // Since accounts can no longer be created from an unconfirmed seed at all, in practice
    // this catches new usage of accounts that already existed before that gate was added:
    // a wallet whose phrase Zallet generated, and whose operator never recorded it.
    // Accounts with no key derivation (an imported viewing key, say) are not covered by
    // any mnemonic, so there is nothing to have backed up and nothing to check.
    #[cfg(zallet_build = "wallet")]
    if let Some(seed_fp) = wallet
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .and_then(|account| {
            account
                .source()
                .key_derivation()
                .map(|derivation| *derivation.seed_fingerprint())
        })
    {
        ensure_seed_is_backed_up(&keystore, &seed_fp).await?;
    }

    let (receiver_types, request) = match receiver_types {
        Some(receiver_types) if !receiver_types.is_empty() => {
            let mut orchard = ReceiverRequirement::Omit;
            let mut sapling = ReceiverRequirement::Omit;
            let mut p2pkh = ReceiverRequirement::Omit;
            let mut invalid_receivers = vec![];
            for receiver_type in &receiver_types {
                match receiver_type.as_str() {
                    "orchard" => orchard = ReceiverRequirement::Require,
                    "sapling" => sapling = ReceiverRequirement::Require,
                    "p2sh" => {
                        return Err(LegacyCode::Wallet.with_static(
                            "Error: P2SH addresses can not be created using this RPC method.",
                        ));
                    }
                    "p2pkh" => p2pkh = ReceiverRequirement::Require,
                    _ => invalid_receivers.push(receiver_type),
                }
            }

            if invalid_receivers.is_empty() {
                UnifiedAddressRequest::custom(orchard, sapling, p2pkh)
                    .map(|request| (receiver_types, request))
                    .map_err(|_| {
                        LegacyCode::InvalidParameter.with_static(
                            "Error: cannot generate an address containing no shielded receivers.",
                        )
                    })
            } else {
                Err(LegacyCode::InvalidParameter.with_message(format!(
                    "{:?} {}. Arguments must be “p2pkh”, “sapling”, or “orchard”",
                    // TODO: Format nicely (matching zcashd).
                    invalid_receivers,
                    if invalid_receivers.len() == 1 {
                        "is an invalid receiver type"
                    } else {
                        "are invalid receiver types"
                    }
                )))
            }
        }
        _ => {
            // zcashd default is the best and second-best shielded receiver types, and the
            // transparent (P2PKH) receiver type. That currently corresponds to all possible
            // receiver types.
            let request = UnifiedAddressRequest::unsafe_custom(
                ReceiverRequirement::Require,
                ReceiverRequirement::Require,
                ReceiverRequirement::Require,
            );
            Ok((
                vec!["orchard".into(), "sapling".into(), "p2pkh".into()],
                request,
            ))
        }
    }?;

    let diversifier_index = diversifier_index.map(parse_diversifier_index).transpose()?;

    let (address, diversifier_index) = if let Some(diversifier_index) = diversifier_index {
        match wallet
            .get_address_for_index(account_id, diversifier_index, request)
            .map_err(|e| map_sqlite_error(e, &account))?
        {
            Some(address) => Ok((address, diversifier_index)),
            // zcash_client_sqlite only returns `Ok(None)` if the diversifier index is
            // invalid for one of the requested receiver types.
            None => Err(LegacyCode::Wallet.with_message(format!(
                "Error: diversifier index {} cannot generate an address with the requested receivers.",
                u128::from(diversifier_index),
            ))),
        }
    } else {
        wallet
            .get_next_available_address(account_id, request)
            .map_err(|e| map_sqlite_error(e, &account))?
            // This would be a race condition between this and account deletion.
            .ok_or(RpcErrorCode::InternalError.into())
    }?;

    // Only include `account` in the response if it was provided in the request. We rely
    // on the checks performed in `parse_account_parameter`.
    let account = match account {
        JsonValue::Number(n) => n.as_u64(),
        _ => None,
    };

    Ok(Address {
        account_uuid: account_id.expose_uuid().to_string(),
        account,
        diversifier_index: diversifier_index.into(),
        receiver_types,
        // Keep every receiver reported in `receiver_types`: the default encoding of a
        // ZIP 316 Revision 2 address strips the transparent receiver.
        address: address.encode_receiver_preserving(wallet.params()),
    })
}

fn map_address_generation_error(
    e: AddressGenerationError,
    account: &JsonValue,
) -> ErrorObjectOwned {
    match e {
        AddressGenerationError::InvalidTransparentChildIndex(diversifier_index) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: diversifier index {} cannot generate an address with a transparent receiver.",
                u128::from(diversifier_index),
            ))
        }
        AddressGenerationError::InvalidSaplingDiversifierIndex(diversifier_index) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: diversifier index {} cannot generate an address with a Sapling receiver.",
                u128::from(diversifier_index),
            ))
        }
        AddressGenerationError::DiversifierSpaceExhausted => LegacyCode::Wallet.with_static(
            "Error: ran out of diversifier indices. Generate a new account with z_getnewaccount"
        ),
        AddressGenerationError::ReceiverTypeNotSupported(typecode) => match typecode {
            unified::Typecode::P2SH =>  LegacyCode::Wallet.with_static(
                "Error: P2SH addresses can not be created using this RPC method.",
            ),
            _ => LegacyCode::Wallet.with_message(format!(
                "Error: receiver type {typecode:?} is not supported.",
            ))
        }
        AddressGenerationError::KeyNotAvailable(typecode) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: account {account} cannot generate a receiver component with type {typecode:?}.",
            ))
        }
        AddressGenerationError::NoSatisfiableReceiver => {
            LegacyCode::Wallet.with_static(
                "Error: cannot generate an address containing no shielded receivers."
            )
        }
        AddressGenerationError::UnsupportedTransparentKeyScope(s) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: Address generation is not supported for transparent key scope {s:?}", 
            ))
        }
        AddressGenerationError::Bip32DerivationError(e) => {
            LegacyCode::Wallet.with_message(format!(
                "An error occurred in BIP 32 address derivation: {e}"
            ))
        }
    }
}

fn map_sqlite_error(e: SqliteClientError, account: &JsonValue) -> ErrorObjectOwned {
    match e {
        SqliteClientError::TransparentDerivation(error) => LegacyCode::Wallet.with_message(format!(
            "Error: failed to derive a transparent component: {error}",
        )),
        SqliteClientError::AddressGeneration(e) => map_address_generation_error(e, account),
        SqliteClientError::AccountUnknown => LegacyCode::Wallet.with_message(format!(
            "Error: account {account} has not been generated by z_getnewaccount."
        )),
        SqliteClientError::ChainHeightUnknown => LegacyCode::Wallet.with_static(
            "Error: chain height is unknown. Wait for syncing to progress and then try again."
        ),
        SqliteClientError::ReachedGapLimit(_, index) => LegacyCode::Wallet.with_message(format!(
            "Error: reached the transparent gap limit while attempting to generate a new address at index {index}.",
        )),
        SqliteClientError::DiversifierIndexReuse(diversifier_index, _) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: address at diversifier index {} was already generated with different receiver types.",
                u128::from(diversifier_index),
            ))
        }
        _ => LegacyCode::Database.with_message(e.to_string()),
    }
}
