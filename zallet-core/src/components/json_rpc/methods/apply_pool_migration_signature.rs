//! `z_applypoolmigrationsignature`: apply an externally-signed PCZT to a migration transaction.
//!
//! Stores the signed PCZT an external (hardware or offline) signer returned against the migration
//! transaction it was built for, moving that transaction from `AwaitingSignature` to `Signed` so
//! `z_advancepoolmigration` can prove and broadcast it. The PCZT is matched to its transaction by the
//! id that `z_startpoolmigration` (with `external_signer`) or `z_buildpoolmigrationtransfers` returned
//! alongside the unsigned PCZT.

use base64ct::{Base64, Encoding};
use documented::Documented;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_pool_migration_backend::engine::MigrationTxId;

use super::pool_migration::{
    MIGRATION_ID, MigrationPhase, MigrationProgress, migration_progress, no_such_migration,
    validate_migration_id,
};
use crate::components::database::DbConnection;
use crate::components::json_rpc::server::LegacyCode;
use crate::migrate::{load_migration, persist_migration};

/// Response to a `z_applypoolmigrationsignature` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = ApplyPoolMigrationSignature;

pub(super) const PARAM_MIGRATION_ID_DESC: &str = "The identifier returned by z_startpoolmigration.";
pub(super) const PARAM_TRANSACTION_ID_DESC: &str = "The id of the migration transaction the signed PCZT is for, from the unsigned_transactions list.";
pub(super) const PARAM_PCZT_DESC: &str = "The signed migration PCZT, base64 encoded (from an external signer or z_signpoolmigrationpczt).";

/// The result of applying an external signature to a migration transaction.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ApplyPoolMigrationSignature {
    /// Opaque identifier for the migration.
    migration_id: String,
    /// The migration's lifecycle phase after applying the signature.
    phase: MigrationPhase,
    /// The migration's progress after applying the signature.
    progress: MigrationProgress,
    /// A short description of what this step did.
    status: String,
}

pub(crate) async fn call(
    wallet: &DbConnection,
    migration_id: &str,
    transaction_id: u32,
    pczt: &str,
) -> Response {
    validate_migration_id(migration_id)?;
    if migration_id != MIGRATION_ID {
        return Err(no_such_migration());
    }
    let bytes = Base64::decode_vec(pczt)
        .map_err(|_| LegacyCode::InvalidParameter.with_static("Malformed base64 PCZT"))?;

    // Load the migration, apply the signed PCZT to its transaction, and persist. The load and the
    // store write run on one connection, sequentially.
    let state = wallet.with_raw_mut(|conn, _| -> Result<_, ErrorObjectOwned> {
        let mut state = load_migration(conn)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            .ok_or_else(no_such_migration)?;
        if !state.apply_signature(MigrationTxId(transaction_id), bytes) {
            return Err(LegacyCode::InvalidParameter
                .with_static("no migration transaction with that id is awaiting a signature"));
        }
        persist_migration(conn, &state)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
        Ok(state)
    })?;

    Ok(ApplyPoolMigrationSignature {
        migration_id: MIGRATION_ID.to_string(),
        phase: MigrationPhase::from_status(state.status),
        progress: migration_progress(&state),
        status: "applied the external signature".to_string(),
    })
}
