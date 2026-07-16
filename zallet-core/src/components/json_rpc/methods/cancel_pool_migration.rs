//! `z_cancelpoolmigration`: cancel a pool migration (scaffold).

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use super::pool_migration::{MigrationPhase, not_implemented, validate_migration_id};

/// Response to a `z_cancelpoolmigration` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = CancelPoolMigration;

pub(super) const PARAM_MIGRATION_ID_DESC: &str = "The identifier returned by z_startpoolmigration.";

/// The result of cancelling a pool migration.
///
/// Describes the response shape for when the migration engine is wired in; the scaffold
/// validates inputs and then returns a not-implemented error rather than constructing
/// this value.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct CancelPoolMigration {
    /// Opaque identifier for the cancelled migration.
    migration_id: String,
    /// The migration's lifecycle phase after cancellation.
    phase: MigrationPhase,
}

pub(crate) fn call(migration_id: &str) -> Response {
    validate_migration_id(migration_id)?;
    not_implemented("z_cancelpoolmigration")
}
