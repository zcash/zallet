//! `start` subcommand

use abscissa_core::{FrameworkError, Runnable, config};
use tokio::{pin, select};

use crate::{
    cli::StartCmd,
    commands::AsyncRunnable,
    components::{
        chain::{ChainFactory, check_consensus_compatibility},
        database::Database,
        json_rpc::JsonRpc,
        sync::WalletSync,
    },
    config::ZalletConfig,
    error::Error,
    fl,
    prelude::*,
};

#[cfg(zallet_build = "wallet")]
use crate::components::keystore::KeyStore;

impl StartCmd {
    /// Runs `zallet start` against the chain backend produced by `factory`.
    pub(crate) async fn run_with<F: ChainFactory>(factory: &F) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        Self::run_with_config(&config, factory).await
    }

    async fn run_with_config<F: ChainFactory>(
        config: &ZalletConfig,
        factory: &F,
    ) -> Result<(), Error> {
        // BETA: Warn when currently-unused config options are set.
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
        // TODO: https://github.com/zcash/zallet/issues/201
        #[cfg(zallet_build = "wallet")]
        if config.keystore.require_backup.is_some() {
            warn_unused("keystore.require_backup");
        }

        // Connect to and validate the chain backend before opening the wallet database.
        let (chain, chain_indexer_task_handle) = factory.build(config).await?;

        // Refuse to start if the backing full node already follows consensus rules we
        // cannot interpret. If the only incompatibilities are still in the future, this
        // returns the height at which to shut down before reaching them.
        let shutdown_height = check_consensus_compatibility(&chain).await?;

        let db = match Database::open(config).await {
            Ok(db) => db,
            Err(error) => {
                // Database failures occurred before this task existed under the previous
                // startup order, so retain that cleanup behavior after moving construction.
                chain_indexer_task_handle.abort();
                return Err(error);
            }
        };
        #[cfg(zallet_build = "wallet")]
        let keystore = match KeyStore::new(config, db.clone()) {
            Ok(keystore) => keystore,
            Err(error) => {
                chain_indexer_task_handle.abort();
                return Err(error);
            }
        };

        // Build the decryptor up front so the RPC server has its handle before the initial scan.
        let (decryptor_handle, decryptor_engine) = WalletSync::build_decryptor();

        // Launch RPC server.
        let rpc_task_handle = JsonRpc::spawn(
            config,
            db.clone(),
            #[cfg(zallet_build = "wallet")]
            keystore,
            chain.clone(),
            #[cfg(zallet_build = "wallet")]
            decryptor_handle.clone(),
        )
        .await?;

        // Start the wallet sync process.
        let (
            wallet_sync_steady_state_task_handle,
            wallet_sync_recover_history_task_handle,
            wallet_sync_batch_decryptor_task_handle,
            wallet_sync_data_requests_task_handle,
        ) = WalletSync::spawn(
            config,
            db,
            chain,
            shutdown_height,
            decryptor_handle,
            decryptor_engine,
        )
        .await?;

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

impl AsyncRunnable for StartCmd {
    async fn run(&self) -> Result<(), Error> {
        crate::application::chain_runtime().run_start().await
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use rusqlite::Connection;

    use super::StartCmd;
    use crate::{
        components::{
            TaskHandle,
            chain::{ChainFactory, MockChain},
        },
        config::ZalletConfig,
        error::{Error, ErrorKind},
    };

    /// The error returned by the fake backend's capability preflight.
    const CAPABILITY_PREFLIGHT_FAILURE: &str = "required scan capabilities are missing";
    /// A compatible prior version that makes a database reopen observably record this build.
    const PRIOR_ZALLET_VERSION: &str = "0.1.0-beta.0";

    struct RejectingBackend {
        build_was_attempted: Arc<AtomicBool>,
    }

    impl ChainFactory for RejectingBackend {
        type Chain = MockChain;

        const NAME: &'static str = "rejecting";

        async fn build(&self, _config: &ZalletConfig) -> Result<(Self::Chain, TaskHandle), Error> {
            self.build_was_attempted.store(true, Ordering::SeqCst);
            Err(ErrorKind::Init.context(CAPABILITY_PREFLIGHT_FAILURE).into())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejected_backend_preflight_does_not_create_wallet_database() {
        crate::i18n::load_languages(&[]);

        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let wallet_db_path = config.wallet_db_path();
        let build_was_attempted = Arc::new(AtomicBool::new(false));
        let factory = RejectingBackend {
            build_was_attempted: build_was_attempted.clone(),
        };

        let error = StartCmd::run_with_config(&config, &factory)
            .await
            .expect_err("capability preflight rejects startup");

        assert!(
            build_was_attempted.load(Ordering::SeqCst),
            "backend construction must run before wallet initialization",
        );
        assert!(
            error.to_string().contains(CAPABILITY_PREFLIGHT_FAILURE),
            "unexpected startup error: {error}",
        );
        assert!(
            !wallet_db_path.exists(),
            "backend preflight failure must not create or migrate the wallet database",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejected_backend_preflight_does_not_migrate_existing_wallet_database() {
        crate::i18n::load_languages(&[]);

        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let wallet_db_path = config.wallet_db_path();

        let database = super::Database::open(&config)
            .await
            .expect("creates a current wallet database");
        drop(database);

        let connection = Connection::open(&wallet_db_path).expect("opens wallet database");
        let updated = connection
            .execute(
                "UPDATE ext_zallet_db_version_metadata
                 SET version = ?1
                 WHERE rowid = (
                    SELECT MAX(rowid) FROM ext_zallet_db_version_metadata
                 )",
                [PRIOR_ZALLET_VERSION],
            )
            .expect("marks the database as last opened by the prior version");
        assert_eq!(updated, 1, "setup updates exactly one version record");
        drop(connection);

        let build_was_attempted = Arc::new(AtomicBool::new(false));
        let factory = RejectingBackend {
            build_was_attempted: build_was_attempted.clone(),
        };

        let error = StartCmd::run_with_config(&config, &factory)
            .await
            .expect_err("capability preflight rejects startup");

        assert!(build_was_attempted.load(Ordering::SeqCst));
        assert!(
            error.to_string().contains(CAPABILITY_PREFLIGHT_FAILURE),
            "unexpected startup error: {error}",
        );

        let connection = Connection::open(&wallet_db_path).expect("reopens wallet database");
        let latest_version: String = connection
            .query_row(
                "SELECT version
                 FROM ext_zallet_db_version_metadata
                 ORDER BY rowid DESC
                 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("reads latest recorded Zallet version");
        assert_eq!(
            latest_version, PRIOR_ZALLET_VERSION,
            "backend preflight failure must not run migrations or record this Zallet version",
        );
    }
}
