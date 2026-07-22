//! `z_clearlockedoutputs`: release every note lock held for an account.

use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::WalletWrite;

use crate::components::{
    database::DbConnection,
    json_rpc::{server::LegacyCode, utils::parse_account_parameter},
    keystore::KeyStore,
};

/// Response to a `z_clearlockedoutputs` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = ClearLockedOutputs;

/// The result of releasing an account's note locks.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ClearLockedOutputs {
    /// The UUID of the account whose locks were released.
    account_uuid: String,

    /// The number of outputs that were unlocked.
    cleared: u64,
}

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "Either the UUID or ZIP 32 account index of the account whose locks to release.";

pub(crate) async fn call(
    wallet: &mut DbConnection,
    keystore: &KeyStore,
    account: JsonValue,
) -> Response {
    let account_id = parse_account_parameter(wallet, keystore, &account).await?;

    let cleared = wallet
        .clear_locked_outputs(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    Ok(ClearLockedOutputs {
        account_uuid: account_id.expose_uuid().to_string(),
        cleared: cleared as u64,
    })
}
