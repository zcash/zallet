//! Shared construction of a read-only Zebra [`ReadStateService`] over a local zebrad.
//!
//! Both the `zebra-state` backend and the (optional) read-state-service variant of the
//! `zaino` backend read finalized chain state directly from a co-located zebrad's state
//! database (opened read-only as a RocksDB secondary) and follow the non-finalized tip
//! over zebrad's gRPC indexer interface. This module is the single place that wiring lives.

use tokio::net::lookup_host;
use tokio::task::JoinHandle;
use tracing::info;
use zebra_rpc::sync::init_read_state_with_syncer;
use zebra_state::ReadStateService;

use crate::{
    commands::resolve_datadir_path,
    config::{ReadStateServiceSection, ZalletConfig},
    error::{Error, ErrorKind},
    network::Network,
};

/// Aborts the wrapped syncer task when the last owner is dropped, so the non-finalized
/// syncer never outlives the chain data source it feeds.
pub(super) struct AbortOnDrop(pub(super) JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Opens zebrad's on-disk state read-only (a secondary) and starts a syncer that follows
/// the non-finalized tip over zebrad's gRPC indexer interface.
///
/// Returns the [`ReadStateService`] plus the syncer task handle; wrap the handle in an
/// [`AbortOnDrop`] held for the lifetime of the data source so the syncer is torn down
/// with it.
pub(super) async fn init_read_state_service(
    config: &ZalletConfig,
    params: &Network,
    rss: &ReadStateServiceSection,
) -> Result<(ReadStateService, JoinHandle<()>), Error> {
    // Resolve the gRPC indexer address used by the non-finalized syncer.
    let grpc_addr = lookup_host(&rss.grpc_address)
        .await
        .map_err(|e| {
            ErrorKind::Init.context(format!(
                "failed to resolve indexer.read_state_service.grpc_address '{}': {e}",
                rss.grpc_address,
            ))
        })?
        .next()
        .ok_or_else(|| {
            ErrorKind::Init.context(format!(
                "indexer.read_state_service.grpc_address '{}' resolved to no IP addresses",
                rss.grpc_address,
            ))
        })?;

    let zebra_network = params.to_zebra().map_err(|e| ErrorKind::Init.context(e))?;
    let zebra_state_path = resolve_datadir_path(config.datadir(), &rss.zebra_state_path);
    let zebra_config = zebra_state::Config {
        cache_dir: zebra_state_path,
        // The standalone read state service cannot use ephemeral state; it reads
        // zebrad's on-disk database in place.
        ephemeral: false,
        // We are a read-only secondary; never delete or back up zebrad's database.
        delete_old_database: false,
        should_backup_non_finalized_state: false,
        ..Default::default()
    };

    // Fail fast with an actionable error if there is no compatible zebra-state database at
    // the configured path, rather than letting zebra-state silently create a new (empty)
    // database there.
    match zebra_state::state_database_format_version_on_disk(&zebra_config, &zebra_network)
        .map_err(|e| {
            ErrorKind::Init.context(format!(
                "failed to read the zebra-state database version at '{}': {e}",
                zebra_config.cache_dir.display(),
            ))
        })? {
        Some(_) => {}
        None => {
            return Err(ErrorKind::Init
                .context(format!(
                    "no zebra-state v{} database found under '{}'; check that \
                     indexer.read_state_service.zebra_state_path points at zebrad's \
                     state cache directory, and that zebrad's on-disk state format \
                     matches Zallet's zebra-state version",
                    zebra_state::state_database_format_version_in_code().major,
                    zebra_config.cache_dir.display(),
                ))
                .into());
        }
    }

    info!("Initializing read-only Zebra state service");
    let (read_state_service, _latest_tip, _tip_change, sync_task) =
        init_read_state_with_syncer(zebra_config, &zebra_network, grpc_addr)
            .await
            // Outer JoinError from the spawned init task.
            .map_err(|e| ErrorKind::Init.context(e))?
            // Inner BoxError from read-state initialization.
            .map_err(|e| ErrorKind::Init.context(e))?;

    Ok((read_state_service, sync_task))
}
