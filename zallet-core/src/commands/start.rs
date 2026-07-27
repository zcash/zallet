//! `start` subcommand

use abscissa_core::{FrameworkError, Runnable, config};
use tokio::{pin, select, task::AbortHandle};

use crate::{
    cli::StartCmd,
    commands::AsyncRunnable,
    components::{
        TaskHandle,
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

/// Cancels the chain indexer if startup exits before task supervision begins.
struct ChainIndexerStartupGuard {
    abort_handle: Option<AbortHandle>,
}

impl ChainIndexerStartupGuard {
    fn new(task: &TaskHandle) -> Self {
        Self {
            abort_handle: Some(task.abort_handle()),
        }
    }

    fn transfer_to_supervisor(mut self) {
        self.abort_handle = None;
    }
}

impl Drop for ChainIndexerStartupGuard {
    fn drop(&mut self) {
        if let Some(abort_handle) = &self.abort_handle {
            abort_handle.abort();
        }
    }
}

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

        // Construct a structurally admitted chain backend before opening the wallet database.
        let (chain, chain_indexer_task_handle) = factory.build(config).await?;
        let chain_indexer_startup_guard = ChainIndexerStartupGuard::new(&chain_indexer_task_handle);

        // Refuse to start if the backing full node already follows consensus rules we
        // cannot interpret. If the only incompatibilities are still in the future, this
        // returns the height at which to shut down before reaching them.
        let shutdown_height = check_consensus_compatibility(&chain).await?;

        let db = Database::open(config).await?;
        #[cfg(zallet_build = "wallet")]
        let keystore = KeyStore::new(config, db.clone())?;

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

        chain_indexer_startup_guard.transfer_to_supervisor();
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
        mpsc,
    };
    use std::time::Duration;

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

    /// The error returned when the fake factory cannot admit its backend.
    const BACKEND_ADMISSION_FAILURE: &str = "required chain backend service is unavailable";
    /// A compatible prior version that makes a database reopen observably record this build.
    const PRIOR_ZALLET_VERSION: &str = "0.1.0-beta.0";

    struct AdmissionRejectingFactory {
        build_was_attempted: Arc<AtomicBool>,
    }

    struct TaskCancellationProbe(mpsc::Sender<()>);

    impl Drop for TaskCancellationProbe {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    struct ConsensusIncompatibleFactory {
        task_cancelled: mpsc::Sender<()>,
    }

    impl ChainFactory for ConsensusIncompatibleFactory {
        type Chain = MockChain;

        const NAME: &'static str = "consensus-incompatible";

        async fn build(&self, _config: &ZalletConfig) -> Result<(Self::Chain, TaskHandle), Error> {
            let cancellation_probe = TaskCancellationProbe(self.task_cancelled.clone());
            let (task_started, task_started_receiver) = futures::channel::oneshot::channel();
            let task = tokio::spawn(async move {
                let _cancellation_probe = cancellation_probe;
                let _ = task_started.send(());
                std::future::pending::<Result<(), Error>>().await
            });
            task_started_receiver.await.map_err(|_| {
                Error::from(ErrorKind::Init.context("fake chain indexer did not start"))
            })?;

            Ok((MockChain::reporting(Vec::new(), u32::MAX), task))
        }
    }

    impl ChainFactory for AdmissionRejectingFactory {
        type Chain = MockChain;

        const NAME: &'static str = "admission-rejecting";

        async fn build(&self, _config: &ZalletConfig) -> Result<(Self::Chain, TaskHandle), Error> {
            self.build_was_attempted.store(true, Ordering::SeqCst);
            Err(ErrorKind::Init.context(BACKEND_ADMISSION_FAILURE).into())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backend_admission_failure_does_not_create_wallet_database() {
        crate::i18n::load_languages(&[]);

        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let wallet_db_path = config.wallet_db_path();
        let build_was_attempted = Arc::new(AtomicBool::new(false));
        let factory = AdmissionRejectingFactory {
            build_was_attempted: build_was_attempted.clone(),
        };

        let error = StartCmd::run_with_config(&config, &factory)
            .await
            .expect_err("backend admission rejects startup");

        assert!(
            build_was_attempted.load(Ordering::SeqCst),
            "backend construction must run before wallet initialization",
        );
        assert!(
            error.to_string().contains(BACKEND_ADMISSION_FAILURE),
            "unexpected startup error: {error}",
        );
        assert!(
            !wallet_db_path.exists(),
            "backend admission failure must not create or migrate the wallet database",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn backend_admission_failure_does_not_migrate_existing_wallet_database() {
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
        let factory = AdmissionRejectingFactory {
            build_was_attempted: build_was_attempted.clone(),
        };

        let error = StartCmd::run_with_config(&config, &factory)
            .await
            .expect_err("backend admission rejects startup");

        assert!(build_was_attempted.load(Ordering::SeqCst));
        assert!(
            error.to_string().contains(BACKEND_ADMISSION_FAILURE),
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
            "backend admission failure must not run migrations or record this Zallet version",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn consensus_rejection_cancels_admitted_backend_task_before_wallet_initialization() {
        crate::i18n::load_languages(&[]);

        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let (task_cancelled, task_cancelled_receiver) = mpsc::channel();
        let factory = ConsensusIncompatibleFactory { task_cancelled };

        StartCmd::run_with_config(&config, &factory)
            .await
            .expect_err("consensus incompatibility rejects startup");

        tokio::task::spawn_blocking(move || {
            task_cancelled_receiver.recv_timeout(Duration::from_secs(1))
        })
        .await
        .expect("cancellation observer does not panic")
        .expect("an admitted backend task is cancelled before startup returns");
        assert!(
            !config.wallet_db_path().exists(),
            "consensus rejection must happen before wallet initialization",
        );
    }
}
