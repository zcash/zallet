//! `z_buildpoolmigrationtransfers`: build a migration's phase-2 transfers UNSIGNED, for an external
//! signer.
//!
//! The external-signer counterpart of the in-process transfer building that `z_advancepoolmigration`
//! performs: it detects newly mined preparation transactions and, once the whole preparation is mined,
//! builds the transfer transactions but leaves them UNSIGNED, returning their PCZTs to sign on the
//! device (applied back with `z_applypoolmigrationsignature`). Nothing is proved or broadcast here. An
//! external migration uses this rather than `z_advancepoolmigration` for the preparation-to-transfers
//! step, so the wallet never signs the transfers in process.

use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::WalletRead;

use super::pool_migration::{
    MIGRATION_ID, MigrationPhase, MigrationProgress, UnsignedMigrationTransaction,
    decrypt_account_usk, encode_unsigned, map_advance_error, migration_progress, no_such_migration,
    validate_migration_id,
};
use crate::components::database::DbConnection;
use crate::components::json_rpc::server::LegacyCode;
use crate::components::json_rpc::utils::parse_account_parameter;
use crate::components::keystore::KeyStore;
use crate::migrate::build_transfers_unsigned_blocking;

/// Response to a `z_buildpoolmigrationtransfers` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = BuildPoolMigrationTransfers;

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "Either the UUID or ZIP 32 account index of the account whose migration transfers to build.";
pub(super) const PARAM_MIGRATION_ID_DESC: &str = "The identifier returned by z_startpoolmigration.";

/// The result of building a migration's transfers for an external signer.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct BuildPoolMigrationTransfers {
    /// Opaque identifier for the migration.
    migration_id: String,
    /// The migration's lifecycle phase after building.
    phase: MigrationPhase,
    /// The migration's progress after building.
    progress: MigrationProgress,
    /// The unsigned transfer PCZTs to sign externally. Empty until the whole preparation is mined; a
    /// non-empty list means the transfers were built and are awaiting signatures.
    unsigned_transactions: Vec<UnsignedMigrationTransaction>,
    /// A short description of what this step did.
    status: String,
}

pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account: JsonValue,
    migration_id: &str,
) -> Response {
    validate_migration_id(migration_id)?;
    if migration_id != MIGRATION_ID {
        return Err(no_such_migration());
    }
    let account_id = parse_account_parameter(wallet, keystore, &account).await?;
    // The key builds the transfer PCZTs (viewing key and witnesses); it does not sign them.
    let usk = decrypt_account_usk(wallet, keystore, account_id).await?;

    let chain_height = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;
    let tip = u32::from(chain_height);

    // Blocking: detect newly mined preparation transactions and, if the preparation is fully mined,
    // build the transfers unsigned and persist the migration.
    let (state, unsigned, message) = wallet
        .with_raw_mut(|conn, network| {
            build_transfers_unsigned_blocking(conn, network, account_id, usk, tip)
        })
        .map_err(map_advance_error)?;

    Ok(BuildPoolMigrationTransfers {
        migration_id: MIGRATION_ID.to_string(),
        phase: MigrationPhase::from_status(state.status),
        progress: migration_progress(&state),
        unsigned_transactions: encode_unsigned(unsigned),
        status: message,
    })
}
