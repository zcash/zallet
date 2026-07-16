//! `z_listpoolmigrations`: list the migrations known to the wallet (scaffold).

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use super::pool_migration::{MigrationPhase, Pool, not_implemented};

/// Response to a `z_listpoolmigrations` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = PoolMigrationList;

/// A single entry in the list of known migrations.
///
/// Describes the response shape for when the migration engine is wired in.
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
///
/// Describes the response shape for when the migration engine is wired in; the scaffold
/// returns a not-implemented error rather than constructing this value.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct PoolMigrationList {
    /// Every migration the wallet is tracking.
    migrations: Vec<PoolMigrationSummary>,
}

pub(crate) fn call() -> Response {
    not_implemented("z_listpoolmigrations")
}
