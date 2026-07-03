//! `start` subcommand

use abscissa_core::{FrameworkError, Runnable, config};
use tokio::{pin, select};

use crate::{
    cli::StartCmd,
    commands::AsyncRunnable,
    components::{chain::ChainBackend, database::Database, json_rpc::JsonRpc, sync::WalletSync},
    config::ZalletConfig,
    error::Error,
    fl,
    prelude::*,
};

#[cfg(zallet_build = "wallet")]
use crate::components::keystore::KeyStore;

impl AsyncRunnable for StartCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        // ALPHA: Warn when currently-unused config options are set.
        let warn_unused =
            |option: &str| warn!("{}", fl!("warn-config-unused", option = option.to_string()));
        // TODO: https://github.com/zcash/zallet/issues/199
        if config.builder.spend_zeroconf_change.is_some() {
            warn_unused("builder.spend_zeroconf_change");
        }
        // TODO: https://github.com/zcash/zallet/issues/200
        if config.builder.tx_expiry_delta.is_some() {
            warn_unused("builder.tx_expiry_delta");
        }
        // TODO: https://github.com/zcash/zallet/issues/138
        #[cfg(zallet_build = "wallet")]
        if config.features.legacy_pool_seed_fingerprint.is_some() {
            warn_unused("features.legacy_pool_seed_fingerprint");
        }
        // TODO: https://github.com/zcash/zallet/issues/201
        #[cfg(zallet_build = "wallet")]
        if config.keystore.require_backup.is_some() {
            warn_unused("keystore.require_backup");
        }

        let db = Database::open(&config).await?;
        #[cfg(zallet_build = "wallet")]
        let keystore = KeyStore::new(&config, db.clone())?;

        // Start monitoring the chain.
        let (chain, chain_indexer_task_handle) = ChainBackend::new(&config).await?;

        // Launch RPC server.
        let rpc_task_handle = JsonRpc::spawn(
            &config,
            db.clone(),
            #[cfg(zallet_build = "wallet")]
            keystore,
            chain.clone(),
        )
        .await?;

        // Start the wallet sync process.
        let (
            wallet_sync_steady_state_task_handle,
            wallet_sync_recover_history_task_handle,
            wallet_sync_batch_decryptor_task_handle,
            wallet_sync_data_requests_task_handle,
        ) = WalletSync::spawn(&config, db, chain).await?;

        info!("Spawned Zallet tasks");

        // ongoing tasks.
        pin!(chain_indexer_task_handle);
        pin!(rpc_task_handle);
        pin!(wallet_sync_steady_state_task_handle);
        pin!(wallet_sync_recover_history_task_handle);
        pin!(wallet_sync_batch_decryptor_task_handle);
        pin!(wallet_sync_data_requests_task_handle);

        // Wait for tasks to finish.
        let res = loop {
            let exit_when_task_finishes = true;

            let result = select! {
                chain_indexer_join_result = &mut chain_indexer_task_handle => {
                    let chain_indexer_result = chain_indexer_join_result
                        .expect("unexpected panic in the chain indexer task");
                    info!(?chain_indexer_result, "Chain indexer task exited");
                    Ok(())
                }

                rpc_join_result = &mut rpc_task_handle => {
                    let rpc_server_result = rpc_join_result
                        .expect("unexpected panic in the RPC task");
                    info!(?rpc_server_result, "RPC task exited");
                    Ok(())
                }

                wallet_sync_join_result = &mut wallet_sync_steady_state_task_handle => {
                    let wallet_sync_result = wallet_sync_join_result
                        .expect("unexpected panic in the wallet steady-state sync task");
                    info!(?wallet_sync_result, "Wallet steady-state sync task exited");
                    Ok(())
                }

                wallet_sync_join_result = &mut wallet_sync_recover_history_task_handle => {
                    let wallet_sync_result = wallet_sync_join_result
                        .expect("unexpected panic in the wallet recover-history sync task");
                    info!(?wallet_sync_result, "Wallet recover-history sync task exited");
                    Ok(())
                }

                wallet_sync_join_result = &mut wallet_sync_batch_decryptor_task_handle => {
                    let wallet_sync_result = wallet_sync_join_result
                        .expect("unexpected panic in the wallet batch decryptor task");
                    info!(?wallet_sync_result, "Wallet batch decryptor task exited");
                    Ok(())
                }

                wallet_sync_join_result = &mut wallet_sync_data_requests_task_handle => {
                    let wallet_sync_result = wallet_sync_join_result
                        .expect("unexpected panic in the wallet data-requests sync task");
                    info!(?wallet_sync_result, "Wallet data-requests sync task exited");
                    Ok(())
                }
            };

            // Stop Zallet if a task finished and returned an error, or if an ongoing task
            // exited.
            match result {
                Err(_) => break result,
                Ok(()) if exit_when_task_finishes => break result,
                Ok(()) => (),
            }
        };

        info!("Exiting Zallet because an ongoing task exited; asking other tasks to stop");

        // ongoing tasks
        chain_indexer_task_handle.abort();
        rpc_task_handle.abort();
        wallet_sync_steady_state_task_handle.abort();
        wallet_sync_recover_history_task_handle.abort();
        wallet_sync_batch_decryptor_task_handle.abort();
        wallet_sync_data_requests_task_handle.abort();

        info!("All tasks have been asked to stop, waiting for remaining tasks to finish");

        res
    }
}

impl Runnable for StartCmd {
    fn run(&self) {
        self.run_on_runtime();
        info!("Shutting down Zallet");
    }
}

impl config::Override<ZalletConfig> for StartCmd {
    fn override_config(&self, config: ZalletConfig) -> Result<ZalletConfig, FrameworkError> {
        Ok(config)
    }
}
