//! `addmultisigaddress` — create an m-of-n multisig address and track it in the wallet.
//!
//! The script and address are exactly those `createmultisig` reports, because both
//! come from the same [`build_multisig`]; the difference is that the redeem script is
//! recorded against an account, so the wallet detects funds sent to the address.
//!
//! [`build_multisig`]: super::create_multisig::build_multisig

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use crate::components::{database::DbConnection, json_rpc::server::LegacyCode};

#[cfg(feature = "transparent-key-import")]
use {
    super::create_multisig::build_multisig,
    crate::components::json_rpc::payments::get_legacy_pool_account,
    zcash_client_backend::data_api::{Account as _, WalletWrite},
    zcash_client_sqlite::AccountUuid,
};

pub(crate) type Response = RpcResult<ResultType>;

/// The P2SH address of the multisig redeem script, now tracked by the wallet.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(String);

pub(super) const PARAM_NREQUIRED_DESC: &str =
    "The number of the supplied keys that must sign to spend.";
pub(super) const PARAM_KEYS_DESC: &str = "The keys the multisig address is composed of, each either a hex-encoded public key \
     or a transparent address this wallet holds the public key for.";
pub(super) const PARAM_KEYS_REQUIRED: bool = true;
pub(super) const PARAM_ACCOUNT_DESC: &str = "The UUID of the account to track the address in. Defaults to the legacy `zcashd` \
     pool of funds, which requires `features.legacy_pool_seed_fingerprint` to be set in \
     the Zallet config file.";

/// Creates a multisig address and records its redeem script in the wallet.
#[cfg(feature = "transparent-key-import")]
pub(crate) fn call(
    wallet: &mut DbConnection,
    nrequired: u8,
    keys: &[String],
    account: Option<&str>,
) -> Response {
    // Everything that only reads the wallet happens before the write, so a bad
    // argument is rejected without having recorded anything.
    let multisig = build_multisig(wallet, nrequired, keys)?;

    let account_id = match account {
        Some(account) => account.parse().map(AccountUuid::from_uuid).map_err(|_| {
            LegacyCode::InvalidParameter.with_message(format!("Invalid account UUID: {account}"))
        })?,
        // `zcashd` had one pool of transparent funds per wallet and put the address
        // there. Zallet holds that pool in the legacy account, which the operator names
        // via `features.legacy_pool_seed_fingerprint`; this reports an actionable error
        // when they have not.
        None => get_legacy_pool_account(wallet)?.id(),
    };

    wallet
        .import_standalone_transparent_script(account_id, multisig.redeem)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    Ok(ResultType(multisig.address))
}

#[cfg(not(feature = "transparent-key-import"))]
pub(crate) fn call(
    _wallet: &mut DbConnection,
    _nrequired: u8,
    _keys: &[String],
    _account: Option<&str>,
) -> Response {
    Err(LegacyCode::Misc
        .with_static("addmultisigaddress requires the transparent-key-import feature"))
}
