//! Shared construction of a read-only Zebra [`ReadStateService`] over a local zebrad.
//!
//! Both the `zebra-state` backend and the (optional) read-state-service variant of the
//! `zaino` backend read finalized chain state directly from a co-located zebrad's state
//! database (opened read-only as a RocksDB secondary) and follow the non-finalized tip
//! over zebrad's gRPC indexer interface. This crate is the single place that wiring
//! lives; it is compiled into each backend's own dependency graph.

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

use std::fmt;
use std::path::PathBuf;

use tokio::net::lookup_host;
use tokio::task::JoinHandle;
use tracing::info;
use zcash_protocol::consensus::NetworkType;
use zebra_rpc::sync::init_read_state_with_syncer;
use zebra_state::ReadStateService;

/// A boxed error from the zebra crates.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors that can occur while initializing the read state service.
#[derive(Debug)]
pub enum ReadStateError {
    /// The configured gRPC indexer address could not be resolved to an IP address.
    ResolveGrpcAddress {
        /// The configured `host:port` address.
        address: String,
        /// The resolution failure, if resolution itself errored (rather than
        /// returning no addresses).
        source: Option<std::io::Error>,
    },
    /// The requested network has no zebra equivalent.
    UnsupportedNetwork(&'static str),
    /// The version of the on-disk zebra-state database could not be read.
    DatabaseVersion {
        /// The configured state cache directory.
        path: PathBuf,
        /// The underlying failure.
        source: BoxError,
    },
    /// No compatible zebra-state database was found at the configured path.
    DatabaseMissing {
        /// The database format major version this build requires.
        major: u64,
        /// The configured state cache directory.
        path: PathBuf,
    },
    /// Read-state initialization failed.
    Init(BoxError),
}

impl fmt::Display for ReadStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadStateError::ResolveGrpcAddress { address, source } => match source {
                Some(e) => write!(
                    f,
                    "failed to resolve indexer.read_state_service.grpc_address '{address}': {e}",
                ),
                None => write!(
                    f,
                    "indexer.read_state_service.grpc_address '{address}' resolved to no IP addresses",
                ),
            },
            ReadStateError::UnsupportedNetwork(msg) => write!(f, "{msg}"),
            ReadStateError::DatabaseVersion { path, source } => write!(
                f,
                "failed to read the zebra-state database version at '{}': {source}",
                path.display(),
            ),
            ReadStateError::DatabaseMissing { major, path } => write!(
                f,
                "no zebra-state v{major} database found under '{}'; check that \
                 indexer.read_state_service.zebra_state_path points at zebrad's \
                 state cache directory, and that zebrad's on-disk state format \
                 matches Zallet's zebra-state version",
                path.display(),
            ),
            ReadStateError::Init(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReadStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReadStateError::ResolveGrpcAddress { source, .. } => source
                .as_ref()
                .map(|e| e as &(dyn std::error::Error + 'static)),
            ReadStateError::UnsupportedNetwork(_) => None,
            ReadStateError::DatabaseVersion { source, .. } | ReadStateError::Init(source) => {
                Some(source.as_ref())
            }
            ReadStateError::DatabaseMissing { .. } => None,
        }
    }
}

/// Converts a network type into the corresponding `zebra-chain` network.
///
/// Returns an error for regtest, which the read-state-service backend does not
/// support.
pub fn network_to_zebra(
    network: NetworkType,
) -> Result<zebra_chain::parameters::Network, ReadStateError> {
    use zebra_chain::parameters::Network as ZebraNetwork;
    match network {
        NetworkType::Main => Ok(ZebraNetwork::Mainnet),
        NetworkType::Test => Ok(ZebraNetwork::new_default_testnet()),
        NetworkType::Regtest => Err(ReadStateError::UnsupportedNetwork(
            "the read-state-service indexer backend does not support regtest",
        )),
    }
}

/// Aborts the wrapped syncer task when the last owner is dropped, so the non-finalized
/// syncer never outlives the chain data source it feeds.
pub struct AbortOnDrop(JoinHandle<()>);

impl AbortOnDrop {
    /// Wraps a task handle so the task is aborted when the last owner is dropped.
    pub fn new(handle: JoinHandle<()>) -> Self {
        Self(handle)
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Opens zebrad's on-disk state read-only (a secondary) and starts a syncer that follows
/// the non-finalized tip over zebrad's gRPC indexer interface.
///
/// `zebra_state_path` must already be resolved (relative to the Zallet datadir if the
/// configured path was relative). Returns the [`ReadStateService`] plus the syncer task
/// handle; wrap the handle in an [`AbortOnDrop`] held for the lifetime of the data
/// source so the syncer is torn down with it.
pub async fn init_read_state_service(
    zebra_network: &zebra_chain::parameters::Network,
    grpc_address: &str,
    zebra_state_path: PathBuf,
) -> Result<(ReadStateService, JoinHandle<()>), ReadStateError> {
    // Resolve the gRPC indexer address used by the non-finalized syncer.
    let grpc_addr = lookup_host(grpc_address)
        .await
        .map_err(|e| ReadStateError::ResolveGrpcAddress {
            address: grpc_address.into(),
            source: Some(e),
        })?
        .next()
        .ok_or_else(|| ReadStateError::ResolveGrpcAddress {
            address: grpc_address.into(),
            source: None,
        })?;

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
    match zebra_state::state_database_format_version_on_disk(&zebra_config, zebra_network).map_err(
        |e| ReadStateError::DatabaseVersion {
            path: zebra_config.cache_dir.clone(),
            source: e.into(),
        },
    )? {
        Some(_) => {}
        None => {
            return Err(ReadStateError::DatabaseMissing {
                major: zebra_state::state_database_format_version_in_code().major,
                path: zebra_config.cache_dir.clone(),
            });
        }
    }

    info!("Initializing read-only Zebra state service");
    let (read_state_service, _latest_tip, _tip_change, sync_task) =
        init_read_state_with_syncer(zebra_config, zebra_network, grpc_addr)
            .await
            // Outer JoinError from the spawned init task.
            .map_err(|e| ReadStateError::Init(e.into()))?
            // Inner BoxError from read-state initialization.
            .map_err(ReadStateError::Init)?;

    Ok((read_state_service, sync_task))
}
