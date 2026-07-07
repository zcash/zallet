use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_sqlite::AccountUuid;

use crate::components::{
    database::DbConnection,
    json_rpc::{
        methods::list_accounts::{Address, account_details},
        server::LegacyCode,
    },
};

/// Response to a `z_getaccount` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = Account;

/// Information about an account.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct Account {
    /// The account's UUID within this Zallet instance.
    account_uuid: String,

    /// The account name.
    ///
    /// Omitted if the account has no configured name.
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    /// The account's seed fingerprint.
    ///
    /// Omitted if the account has no known derivation information.
    #[serde(skip_serializing_if = "Option::is_none")]
    seedfp: Option<String>,

    /// The account's ZIP 32 account index.
    ///
    /// Omitted if the account has no known derivation information.
    #[serde(skip_serializing_if = "Option::is_none")]
    zip32_account_index: Option<u32>,

    /// The addresses known to the wallet for this account.
    addresses: Vec<Address>,
}

pub(super) const PARAM_ACCOUNT_UUID_DESC: &str = "The UUID of the account.";

pub(crate) fn call(wallet: &DbConnection, account_uuid: String) -> Response {
    let account_id = account_uuid
        .parse()
        .map(AccountUuid::from_uuid)
        .map_err(|_| {
            LegacyCode::InvalidParameter.with_message(format!("not a valid UUID: {account_uuid}"))
        })?;

    account_details(
        wallet,
        account_id,
        true,
        |name, seedfp, zip32_account_index, addresses| Account {
            account_uuid: account_id.expose_uuid().to_string(),
            name,
            seedfp,
            zip32_account_index,
            addresses: addresses.expect("include_addresses is true"),
        },
    )
}
