use documented::Documented;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorCode as RpcErrorCode;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{AccountBirthday, WalletRead, WalletWrite};

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

/// Response to a `z_getnewaccount` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = Account;

/// Information about the new account.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct Account {
    /// The new account's UUID within this Zallet instance.
    account_uuid: String,

    /// The new account's ZIP 32 account index.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<u64>,
}

pub(super) const PARAM_ACCOUNT_NAME_DESC: &str = "A human-readable name for the account.";
pub(super) const PARAM_SEEDFP_DESC: &str =
    "ZIP 32 seed fingerprint for the BIP 39 mnemonic phrase from which to derive the account.";

pub(crate) async fn call<C: Chain>(
    wallet: &Database,
    keystore: &KeyStore,
    chain: C,
    reconfiguration: &WalletSyncReconfiguration,
    account_name: &str,
    seedfp: Option<&str>,
) -> Response {
    ensure_wallet_is_unlocked(keystore).await?;
    // TODO: Ensure wallet is backed up.
    //       https://github.com/zcash/zallet/issues/201

    let seedfp = seedfp.map(parse_seedfp_parameter).transpose()?;

    let chain_view = chain
        .snapshot()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let chain_tip = chain_view
        .tip()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
    let wallet_handle = wallet
        .handle()
        .await
        .map_err(|_| RpcErrorCode::InternalError)?;
    let chain_height = wallet_handle
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or(LegacyCode::InWarmup.with_static("Wallet sync required"))?
        // Tolerate race conditions between this RPC and the sync engine.
        .min(chain_tip.height());
    // Keystore reads acquire their own pooled connection. Release this read handle before
    // entering the keystore while sync retains its four long-lived connections.
    drop(wallet_handle);
    let treestate_height = chain_height.saturating_sub(1);

    let chain_state = chain_view
        .tree_state_as_of(treestate_height)
        .await
        .map_err(|e| {
            LegacyCode::InvalidParameter.with_message(format!(
                "Failed to get treestate at height {treestate_height}: {e}"
            ))
        })?
        .expect("always in range");

    let birthday = AccountBirthday::from_parts(chain_state, None);

    let seed_fps = keystore
        .list_seed_fingerprints()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let seed_fp = match (seed_fps.len(), seedfp) {
        (0, _) => Err(LegacyCode::Wallet
            .with_static("Wallet does not contain any seeds to generate accounts with")),
        (1, None) => Ok(seed_fps.into_iter().next().expect("present")),
        (_, None) => Err(LegacyCode::InvalidParameter
            .with_static("Wallet has more than one seed; seedfp argument must be provided")),
        (_, Some(seedfp)) => seed_fps.contains(&seedfp).then_some(seedfp).ok_or_else(|| {
            LegacyCode::InvalidParameter.with_static("seedfp does not match any seed in the wallet")
        }),
    }?;

    let seed = keystore
        .decrypt_seed(&seed_fp)
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let mut wallet_handle = wallet
        .handle()
        .await
        .map_err(|_| RpcErrorCode::InternalError)?;
    // Reserve the mutation connection before waiting for exclusive sync admission so two
    // concurrent key mutations cannot acquire those resources in opposite orders.
    let admitted = reconfiguration.admit_reconfiguration().await;
    let (account_id, _usk) = wallet_handle
        .create_account(account_name, &seed, &birthday, None)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
    drop(wallet_handle);

    // Reload viewing keys so the new account is scanned without a restart (see z_importkey).
    if !admitted.reload_keys_and_wake_wallet_recovery().await {
        tracing::warn!("sync engine has shut down; new account won't be scanned until restart");
    }

    Ok(Account {
        account_uuid: account_id.expose_uuid().to_string(),
        // TODO: Should we ever set this in Zallet?
        account: None,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use age::secrecy::ExposeSecret;
    use bip0039::{English, Mnemonic};
    use secrecy::SecretVec;
    use zcash_client_backend::data_api::{
        AccountBirthday, WalletRead as _, WalletWrite as _, chain::ChainState,
    };
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::BlockHeight;

    use super::super::{WalletRpcImpl, WalletRpcServer};
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
    async fn rpc_creates_account_while_sync_retains_database_connections() {
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
        keystore
            .encrypt_and_store_mnemonic(mnemonic)
            .await
            .expect("stores test mnemonic");

        let mut setup_wallet = database.handle().await.expect("reserves setup database");
        setup_wallet
            .create_account(
                "existing account",
                &seed,
                &AccountBirthday::from_parts(
                    ChainState::empty(BlockHeight::from_u32(TIP_HEIGHT - 1), BlockHash([0u8; 32])),
                    None,
                ),
                None,
            )
            .expect("creates existing account");
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

        let account = tokio::time::timeout(
            Duration::from_secs(10),
            WalletRpcServer::get_new_account(&rpc, "saturation test", None),
        )
        .await
        .expect("account creation completes while sync retains database connections")
        .expect("creates account");

        let wallet = database.handle().await.expect("reopens wallet database");
        assert!(account.account_uuid.parse::<uuid::Uuid>().is_ok());
        assert_eq!(
            wallet
                .get_account_ids()
                .expect("lists created wallet accounts")
                .len(),
            2
        );
    }
}
