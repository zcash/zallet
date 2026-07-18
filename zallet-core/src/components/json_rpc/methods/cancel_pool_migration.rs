//! `z_cancelpoolmigration`: cancel a pool migration.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_pool_migration_backend::engine::MigrationStatus;

use super::pool_migration::{
    MIGRATION_ID, MigrationPhase, no_such_migration, validate_migration_id,
};
use crate::components::database::DbConnection;
use crate::components::json_rpc::server::LegacyCode;
use crate::migrate::{load_migration, persist_migration};

/// Response to a `z_cancelpoolmigration` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = CancelPoolMigration;

pub(super) const PARAM_MIGRATION_ID_DESC: &str = "The identifier returned by z_startpoolmigration.";

/// The result of cancelling a pool migration.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct CancelPoolMigration {
    /// Opaque identifier for the cancelled migration.
    migration_id: String,
    /// The migration's lifecycle phase after cancellation.
    phase: MigrationPhase,
}

pub(crate) fn call(wallet: &DbConnection, migration_id: &str) -> Response {
    validate_migration_id(migration_id)?;
    if migration_id != MIGRATION_ID {
        return Err(no_such_migration());
    }
    // Mark the stored migration as failed, which reports as the cancelled phase. Any preparation
    // transactions already broadcast cannot be undone on chain; cancelling stops the migration from
    // building or broadcasting anything further.
    let phase = wallet
        .with_raw_mut(
            |conn, _| -> Result<Option<MigrationPhase>, zcash_pool_migration_sqlite::Error> {
                let Some(mut state) = load_migration(conn)? else {
                    return Ok(None);
                };
                state.status = MigrationStatus::Failed;
                persist_migration(conn, &state)?;
                Ok(Some(MigrationPhase::from_status(state.status)))
            },
        )
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(no_such_migration)?;
    Ok(CancelPoolMigration {
        migration_id: MIGRATION_ID.to_string(),
        phase,
    })
}
