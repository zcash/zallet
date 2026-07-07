use documented::Documented;
use jsonrpsee::{core::RpcResult, types::ErrorCode as RpcErrorCode};
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{Account as _, AddressSource, WalletRead};
use zcash_client_sqlite::AccountUuid;

use crate::components::{database::DbConnection, json_rpc::server::LegacyCode};

/// Response to a `z_listaccounts` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// A list of accounts.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(Vec<Account>);

#[derive(Clone, Debug, Serialize, JsonSchema)]
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

    /// The account's ZIP 32 account index.
    ///
    /// Omitted if the account has no known derivation information.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<u32>,

    /// The addresses known to the wallet for this account.
    ///
    /// Omitted if `include_addresses` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    addresses: Option<Vec<Address>>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct Address {
    /// A diversifier index used in the account to derive this address.
    #[serde(skip_serializing_if = "Option::is_none")]
    diversifier_index: Option<u128>,

    /// The unified address.
    ///
    /// Omitted if this is not a unified address.
    #[serde(skip_serializing_if = "Option::is_none")]
    ua: Option<String>,

    /// The Sapling address.
    ///
    /// Omitted if this is not a Sapling address.
    #[serde(skip_serializing_if = "Option::is_none")]
    sapling: Option<String>,

    /// The transparent address.
    ///
    /// Omitted if this is not a transparent address.
    #[serde(skip_serializing_if = "Option::is_none")]
    transparent: Option<String>,
}

pub(super) const PARAM_INCLUDE_ADDRESSES_DESC: &str =
    "Also include the addresses known to the wallet for this account.";

pub(crate) fn call(wallet: &DbConnection, include_addresses: Option<bool>) -> Response {
    let include_addresses = include_addresses.unwrap_or(true);

    let accounts = wallet
        .get_account_ids()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .into_iter()
        .map(|account_id| {
            account_details(
                wallet,
                account_id,
                include_addresses,
                |name, seedfp, zip32_account_index, addresses| Account {
                    account_uuid: account_id.expose_uuid().to_string(),
                    name,
                    seedfp,
                    zip32_account_index,
                    account: zip32_account_index,
                    addresses,
                },
            )
        })
        .collect::<Result<_, _>>()?;

    Ok(ResultType(accounts))
}

pub(super) fn account_details<T>(
    wallet: &DbConnection,
    account_id: AccountUuid,
    include_addresses: bool,
    f: impl FnOnce(Option<String>, Option<String>, Option<u32>, Option<Vec<Address>>) -> T,
) -> RpcResult<T> {
    let account = wallet
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        // This would be a race condition between this and account deletion.
        .ok_or(RpcErrorCode::InternalError)?;

    let name = account.name().map(String::from);

    let derivation = account.source().key_derivation();
    let seedfp = derivation.map(|derivation| derivation.seed_fingerprint().to_string());
    let account = derivation.map(|derivation| u32::from(derivation.account_index()));

    let addresses = wallet
        .list_addresses(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let addresses = include_addresses.then(|| {
        addresses
            .into_iter()
            .map(|a| {
                let diversifier_index = match a.source() {
                    AddressSource::Derived {
                        diversifier_index, ..
                    } => Some(diversifier_index.into()),
                    #[cfg(feature = "transparent-key-import")]
                    AddressSource::Standalone => None,
                };
                let enc = a.address().to_zcash_address(wallet.params()).to_string();
                let (ua, sapling, transparent) = match a.address() {
                    zcash_keys::address::Address::Sapling(_) => (None, Some(enc), None),
                    zcash_keys::address::Address::Transparent(_) => (None, None, Some(enc)),
                    zcash_keys::address::Address::Unified(_) => (Some(enc), None, None),
                    zcash_keys::address::Address::Tex(_) => {
                        unreachable!("zcash_client_sqlite never stores these")
                    }
                };
                Address {
                    diversifier_index,
                    ua,
                    sapling,
                    transparent,
                }
            })
            .collect()
    });

    Ok(f(name, seedfp, account, addresses))
}
