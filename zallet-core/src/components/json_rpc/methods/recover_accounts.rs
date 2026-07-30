use std::collections::HashMap;

use documented::Documented;
use jsonrpsee::{
    core::RpcResult,
    types::{ErrorCode as RpcErrorCode, ErrorObjectOwned},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zcash_client_backend::data_api::{Account as _, AccountBirthday, WalletRead, WalletWrite};
use zcash_protocol::consensus::BlockHeight;

use crate::components::{
    chain::{Chain, ChainView},
    database::Database,
    json_rpc::{
        server::LegacyCode,
        utils::{ensure_wallet_is_unlocked, parse_seedfp_parameter},
    },
    keystore::KeyStore,
    sync::WalletSyncReconfiguration,
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
    wallet: &Database,
    keystore: &KeyStore,
    chain: C,
    reconfiguration: &WalletSyncReconfiguration,
    accounts: Vec<AccountParameter<'_>>,
) -> Response {
    ensure_wallet_is_unlocked(keystore).await?;
    // TODO: Ensure wallet is backed up.
    //       https://github.com/zcash/zallet/issues/201

    let chain_view = chain
        .snapshot()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let wallet_handle = wallet
        .handle()
        .await
        .map_err(|_| RpcErrorCode::InternalError)?;
    let recover_until = wallet_handle
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or(LegacyCode::InWarmup.with_static("Wallet sync required"))?;
    // Keystore reads acquire their own pooled connection. Release this read handle before
    // decrypting seeds while sync retains its four long-lived connections.
    drop(wallet_handle);

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
    let mut wallet_handle = wallet
        .handle()
        .await
        .map_err(|_| RpcErrorCode::InternalError)?;
    // Reserve the mutation connection before waiting for exclusive sync admission so two
    // concurrent key mutations cannot acquire those resources in opposite orders.
    let admitted = reconfiguration.admit_reconfiguration().await;
    let accounts = account_args
        .into_iter()
        .map(|(account_name, seed_fp, account_index, birthday)| {
            let seed = seeds.get(&seed_fp).expect("present");

            let (account, _usk) = wallet_handle
                .import_account_hd(account_name, seed, account_index, &birthday, None)
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

            Ok::<_, ErrorObjectOwned>(Account {
                account_uuid: account.id().expose_uuid().to_string(),
                seedfp: seed_fp.to_string(),
                zip32_account_index: account_index.into(),
            })
        })
        .collect::<Result<_, _>>()?;
    drop(wallet_handle);

    // Reload viewing keys so recovered accounts are scanned without a restart (see z_importkey).
    if !admitted.reload_keys_and_wake_wallet_recovery().await {
        tracing::warn!(
            "sync engine has shut down; recovered accounts won't be scanned until restart"
        );
    }

    Ok(Accounts { accounts })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use age::secrecy::ExposeSecret as _;
    use bip0039::{English, Mnemonic};
    use secrecy::{ExposeSecret as _, SecretVec};
    use zcash_client_backend::data_api::{WalletRead as _, WalletWrite as _};
    use zcash_protocol::consensus::BlockHeight;
    use zip32::fingerprint::SeedFingerprint;

    use super::{
        super::{WalletRpcImpl, WalletRpcServer},
        AccountParameter,
    };
    use crate::{
        components::{
            chain::MockChain,
            database::Database,
            keystore::KeyStore,
            sync::{WalletSync, WalletSyncReconfiguration, status},
        },
        config::ZalletConfig,
    };

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const SYNC_CONNECTION_COUNT: usize = 4;
    const TIP_HEIGHT: u32 = 500_100;

    #[tokio::test(flavor = "multi_thread")]
    async fn rpc_recovers_account_while_sync_retains_database_connections() {
        crate::i18n::load_languages(&[]);
        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let identity = age::x25519::Identity::generate();
        std::fs::write(
            config.encryption_identity(),
            identity.to_string().expose_secret(),
        )
        .expect("writes unencrypted identity");

        let database = Database::open(&config)
            .await
            .expect("creates wallet database");
        let keystore = KeyStore::new(&config, database.clone()).expect("creates keystore");
        keystore
            .initialize_recipients(vec![identity.to_public().to_string()])
            .await
            .expect("initializes unencrypted keystore");
        let mnemonic =
            Mnemonic::<English>::from_phrase(TEST_MNEMONIC).expect("parses test mnemonic");
        let seed = SecretVec::new(mnemonic.to_seed("").to_vec());
        let seedfp = SeedFingerprint::from_seed(seed.expose_secret())
            .expect("derives seed fingerprint")
            .to_string();
        keystore
            .encrypt_and_store_mnemonic(mnemonic)
            .await
            .expect("stores test mnemonic");

        let mut setup_wallet = database.handle().await.expect("reserves setup database");
        setup_wallet
            .update_chain_tip(BlockHeight::from_u32(TIP_HEIGHT))
            .expect("records chain tip");
        drop(setup_wallet);

        let (decryptor, decryptor_engine) = WalletSync::build_decryptor();
        drop(decryptor_engine);
        let (_sync_status_writer, sync_status) = status::channel(config.sync.lock_threshold());
        let rpc = WalletRpcImpl::new(
            database.clone(),
            keystore,
            MockChain::reporting(Vec::new(), TIP_HEIGHT).with_empty_tree_states(),
            WalletSyncReconfiguration::new(decryptor),
            sync_status,
            config.rpc.async_operation_limit(),
        );
        let mut sync_wallets = Vec::with_capacity(SYNC_CONNECTION_COUNT);
        for _ in 0..SYNC_CONNECTION_COUNT {
            sync_wallets.push(database.handle().await.expect("reserves sync database"));
        }

        let recovered = tokio::time::timeout(
            Duration::from_secs(10),
            WalletRpcServer::recover_accounts(
                &rpc,
                vec![AccountParameter {
                    name: "saturation test",
                    seedfp: &seedfp,
                    zip32_account_index: 0,
                    birthday_height: TIP_HEIGHT,
                }],
            ),
        )
        .await
        .expect("account recovery completes while sync retains database connections")
        .expect("recovers account");

        let wallet = database.handle().await.expect("reopens wallet database");
        assert_eq!(recovered.accounts.len(), 1);
        assert_eq!(
            wallet
                .get_account_ids()
                .expect("lists recovered wallet accounts")
                .len(),
            1
        );
    }
}
