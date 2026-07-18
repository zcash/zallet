//! `z_listpoolmigrations`: list the migrations known to the wallet.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use super::pool_migration::{
    MIGRATION_FROM_POOL, MIGRATION_ID, MIGRATION_TO_POOL, MigrationPhase, Pool,
};
use crate::components::database::DbConnection;
use crate::components::json_rpc::server::LegacyCode;
use crate::migrate::load_migration;

/// Response to a `z_listpoolmigrations` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = PoolMigrationList;

/// A single entry in the list of known migrations.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct PoolMigrationSummary {
    /// Opaque identifier for the migration.
    migration_id: String,
    /// The value pool funds are being migrated from.
    from_pool: Pool,
    /// The value pool funds are being migrated to.
    to_pool: Pool,
    /// The migration's current lifecycle phase.
    phase: MigrationPhase,
}

/// The list of migrations known to the wallet.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct PoolMigrationList {
    /// Every migration the wallet is tracking (at most one at a time).
    migrations: Vec<PoolMigrationSummary>,
}

pub(crate) fn call(wallet: &DbConnection) -> Response {
    let migrations = wallet
        .with_raw_mut(|conn, _| load_migration(conn))
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .map(|state| {
            vec![PoolMigrationSummary {
                migration_id: MIGRATION_ID.to_string(),
                from_pool: MIGRATION_FROM_POOL,
                to_pool: MIGRATION_TO_POOL,
                phase: MigrationPhase::from_status(state.status),
            }]
        })
        .unwrap_or_default();
    Ok(PoolMigrationList { migrations })
}
