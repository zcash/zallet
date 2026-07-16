//! `z_getpoolmigrationstatus`: report the status of a pool migration (scaffold).

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use super::pool_migration::{
    MigrationPhase, MigrationProgress, Pool, not_implemented, validate_migration_id,
};

/// Response to a `z_getpoolmigrationstatus` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = PoolMigrationStatus;

pub(super) const PARAM_MIGRATION_ID_DESC: &str = "The identifier returned by z_startpoolmigration.";

/// The status of a pool migration.
///
/// Describes the response shape for when the migration engine is wired in; the scaffold
/// validates inputs and then returns a not-implemented error rather than constructing
/// this value.
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
}

pub(crate) fn call(migration_id: &str) -> Response {
    validate_migration_id(migration_id)?;
    not_implemented("z_getpoolmigrationstatus")
}
