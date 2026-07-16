//! `z_startpoolmigration`: schedule a generic pool-to-pool migration (scaffold).

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use super::pool_migration::{MigrationPlan, Pool, not_implemented, validate_pool_pair};
use crate::components::database::DbConnection;

/// Response to a `z_startpoolmigration` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = StartPoolMigration;

pub(super) const PARAM_FROM_POOL_DESC: &str =
    "The value pool to migrate funds from (\"sapling\", \"orchard\", or \"ironwood\").";
pub(super) const PARAM_TO_POOL_DESC: &str =
    "The value pool to migrate funds to (\"sapling\", \"orchard\", or \"ironwood\").";

/// The result of scheduling a pool migration.
///
/// Describes the response shape for when the migration engine is wired in; the scaffold
/// validates inputs and then returns a not-implemented error rather than constructing
/// this value.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct StartPoolMigration {
    /// Opaque identifier for the scheduled migration, used with the status, advance,
    /// and cancel methods.
    migration_id: String,
    /// The value pool funds are being migrated from.
    from_pool: Pool,
    /// The value pool funds are being migrated to.
    to_pool: Pool,
    /// The network upgrade that enables this migration (for example `"Nu6.3"`).
    enabling_upgrade: String,
    /// The plan describing how the migration will be carried out.
    plan: MigrationPlan,
}

pub(crate) fn call(wallet: &DbConnection, from_pool: &str, to_pool: &str) -> Response {
    let (_from_pool, _to_pool, _enabling_upgrade) = validate_pool_pair(wallet, from_pool, to_pool)?;
    not_implemented("z_startpoolmigration")
}
