//! `z_getpoolmigrationstatus`: report the status of a pool migration.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use zcash_client_backend::data_api::WalletRead;

use super::pool_migration::{
    MIGRATION_ENABLING_UPGRADE, MIGRATION_FROM_POOL, MIGRATION_ID, MIGRATION_TO_POOL,
    MigrationPhase, MigrationProgress, MigrationTransactionStatus, Pool, migration_progress,
    migration_transactions, no_such_migration, validate_migration_id,
};
use crate::components::database::DbConnection;
use crate::components::json_rpc::server::LegacyCode;
use crate::migrate::load_migration;

/// Response to a `z_getpoolmigrationstatus` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = PoolMigrationStatus;

pub(super) const PARAM_MIGRATION_ID_DESC: &str = "The identifier returned by z_startpoolmigration.";

/// The status of a pool migration.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct PoolMigrationStatus {
    /// Opaque identifier for the migration.
    migration_id: String,
    /// The value pool funds are being migrated from.
    from_pool: Pool,
    /// The value pool funds are being migrated to.
    to_pool: Pool,
    /// The network upgrade that enables this migration (for example `"Nu6.3"`).
    enabling_upgrade: String,
    /// The migration's current lifecycle phase.
    phase: MigrationPhase,
    /// The migration's progress so far.
    progress: MigrationProgress,
    /// Every transaction the migration comprises, with its lifecycle state and, for a transaction a
    /// wallet can act on now, the next action (or what it is waiting on). This lets a wallet render
    /// progress and drive signing/broadcasting deterministically from persisted state, which a
    /// multi-layer migration on a mobile wallet requires.
    transactions: Vec<MigrationTransactionStatus>,
}

pub(crate) fn call(wallet: &DbConnection, migration_id: &str) -> Response {
    validate_migration_id(migration_id)?;
    if migration_id != MIGRATION_ID {
        return Err(no_such_migration());
    }
    // The height the next transaction would build at (tip + 1), used to decide which scheduled
    // transactions are due. Before the wallet has synced a chain tip, treat nothing as due.
    let target_height = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .map(|h| u32::from(h) + 1)
        .unwrap_or(0);
    let state = wallet
        .with_raw_mut(|conn, _| load_migration(conn))
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(no_such_migration)?;
    Ok(PoolMigrationStatus {
        migration_id: MIGRATION_ID.to_string(),
        from_pool: MIGRATION_FROM_POOL,
        to_pool: MIGRATION_TO_POOL,
        enabling_upgrade: MIGRATION_ENABLING_UPGRADE.to_string(),
        phase: MigrationPhase::from_status(state.status),
        progress: migration_progress(&state),
        transactions: migration_transactions(&state, target_height),
    })
}
