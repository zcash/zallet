//! `z_advancepoolmigration`: advance a pool migration by one step.
//!
//! Advancing drives a committed migration forward: proving and broadcasting the next due pre-signed
//! transaction, and (once its preparation is mined) building the phase-2 transfers. Proving and
//! broadcasting is not yet wired into Zallet (it needs the `pczt` prover and an Orchard proving
//! key), so for a migration that still has work to do this reports that it is committed and awaiting
//! that step; a finished or cancelled migration reports its terminal phase.

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
use crate::migrate::load_migration;

/// Response to a `z_advancepoolmigration` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = AdvancePoolMigration;

pub(super) const PARAM_MIGRATION_ID_DESC: &str = "The identifier returned by z_startpoolmigration.";

/// The result of advancing a pool migration by one step.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct AdvancePoolMigration {
    /// Opaque identifier for the migration.
    migration_id: String,
    /// The migration's lifecycle phase after advancing.
    phase: MigrationPhase,
}

pub(crate) fn call(wallet: &DbConnection, migration_id: &str) -> Response {
    validate_migration_id(migration_id)?;
    if migration_id != MIGRATION_ID {
        return Err(no_such_migration());
    }
    let state = wallet
        .with_raw_mut(|conn, _| load_migration(conn))
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(no_such_migration)?;

    match state.status {
        // A finished or cancelled migration has nothing left to advance.
        MigrationStatus::Complete | MigrationStatus::Failed => Ok(AdvancePoolMigration {
            migration_id: MIGRATION_ID.to_string(),
            phase: MigrationPhase::from_status(state.status),
        }),
        // Making on-chain progress requires proving and broadcasting the pre-signed transactions,
        // which is not yet wired into Zallet (it needs the pczt prover and an Orchard proving key).
        _ => Err(LegacyCode::Misc.with_message(format!(
            "advancing a pool migration (proving and broadcasting its pre-signed transactions) is \
             not yet wired; the migration is committed with {} transactions ready",
            state.transactions.len(),
        ))),
    }
}
