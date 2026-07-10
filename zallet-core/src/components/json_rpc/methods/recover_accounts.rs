use std::collections::HashMap;

use documented::Documented;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zcash_client_backend::data_api::{Account as _, AccountBirthday, WalletRead, WalletWrite};
use zcash_protocol::consensus::BlockHeight;

use crate::components::{
    chain::{Chain, ChainView},
    database::DbConnection,
    json_rpc::{
        server::LegacyCode,
        utils::{ensure_wallet_is_unlocked, parse_seedfp_parameter},
    },
    keystore::KeyStore,
    sync::WalletDecryptorHandle,
};

/// Response to a `z_recoveraccounts` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = Accounts;

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub(crate) struct AccountParameter<'a> {
    name: &'a str,
    seedfp: &'a str,
    zip32_account_index: u32,
    birthday_height: u32,
}

/// The list of recovered accounts.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct Accounts {
    accounts: Vec<Account>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct Account {
    /// The account's UUID within this Zallet instance.
    account_uuid: String,

    seedfp: String,

    /// The account's ZIP 32 account index.
    zip32_account_index: u32,
}

pub(super) const PARAM_ACCOUNTS_DESC: &str =
    "An array of JSON objects representing the accounts to recover.";
pub(super) const PARAM_ACCOUNTS_REQUIRED: bool = true;

pub(crate) async fn call<C: Chain>(
    wallet: &mut DbConnection,
    keystore: &KeyStore,
    chain: C,
    decryptor: &WalletDecryptorHandle,
    accounts: Vec<AccountParameter<'_>>,
) -> Response {
    ensure_wallet_is_unlocked(keystore).await?;
    // TODO: Ensure wallet is backed up.
    //       https://github.com/zcash/zallet/issues/201

    let chain_view = chain
        .snapshot()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let recover_until = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or(LegacyCode::InWarmup.with_static("Wallet sync required"))?;

    // Prepare arguments for the wallet.
    let mut account_args = vec![];
    for account in accounts {
        let seed_fp = parse_seedfp_parameter(account.seedfp)?;

        let account_index =
            zip32::AccountId::try_from(account.zip32_account_index).map_err(|e| {
                LegacyCode::InvalidParameter
                    .with_message(format!("Invalid ZIP 32 account index: {e}"))
            })?;

        let birthday_height = BlockHeight::from_u32(account.birthday_height);
        let treestate_height = birthday_height.saturating_sub(1);

        let chain_state = chain_view
            .tree_state_as_of(treestate_height)
            .await
            .map_err(|e| {
                LegacyCode::InvalidParameter.with_message(format!(
                    "Failed to get treestate at height {treestate_height}: {e}"
                ))
            })?
            .ok_or_else(|| {
                LegacyCode::InvalidParameter.with_message(format!(
                    "Account birthday height {birthday_height} does not exist in the chain"
                ))
            })?;

        let birthday = AccountBirthday::from_parts(chain_state, Some(recover_until));

        account_args.push((account.name, seed_fp, account_index, birthday));
    }

    // Fetch the seeds for the given seed fingerprints.
    let mut seeds = HashMap::new();
    for (_, seed_fp, _, _) in &account_args {
        if !seeds.contains_key(seed_fp) {
            let seed = keystore
                .decrypt_seed(seed_fp)
                .await
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

            seeds.insert(*seed_fp, seed);
        }
    }

    // Import the accounts.
    let accounts = account_args
        .into_iter()
        .map(|(account_name, seed_fp, account_index, birthday)| {
            let seed = seeds.get(&seed_fp).expect("present");

            let (account, _usk) = wallet
                .import_account_hd(account_name, seed, account_index, &birthday, None)
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

            Ok::<_, ErrorObjectOwned>(Account {
                account_uuid: account.id().expose_uuid().to_string(),
                seedfp: seed_fp.to_string(),
                zip32_account_index: account_index.into(),
            })
        })
        .collect::<Result<_, _>>()?;

    // Reload viewing keys so recovered accounts are scanned without a restart (see z_importkey).
    if decryptor.reload_keys().await.is_none() {
        tracing::warn!(
            "sync engine has shut down; recovered accounts won't be scanned until restart"
        );
    }

    Ok(Accounts { accounts })
}
