//! `z_advancepoolmigration`: advance a pool migration by one step.
//!
//! Advancing drives a committed migration forward one step per call (so a caller polls it): it
//! detects newly mined transactions, proves and broadcasts the next due pre-signed transaction, and
//! once the preparation is mined builds the phase-2 transfers. Proving is done against the migration's
//! Orchard circuit; broadcasting sends the extracted transaction to the mempool.

use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::WalletRead;

use super::pool_migration::{
    MIGRATION_ID, MigrationPhase, MigrationProgress, decrypt_account_usk, map_advance_error,
    migration_progress, no_such_migration, validate_migration_id,
};
use crate::components::chain::Chain;
use crate::components::database::DbConnection;
use crate::components::json_rpc::server::LegacyCode;
use crate::components::json_rpc::utils::parse_account_parameter;
use crate::components::keystore::KeyStore;
use crate::migrate::{AdvanceOutcome, advance_blocking, record_broadcast, transaction_txid_bytes};

/// Response to a `z_advancepoolmigration` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = AdvancePoolMigration;

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "Either the UUID or ZIP 32 account index of the account whose migration to advance.";
pub(super) const PARAM_MIGRATION_ID_DESC: &str = "The identifier returned by z_startpoolmigration.";

/// The result of advancing a pool migration by one step.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct AdvancePoolMigration {
    /// Opaque identifier for the migration.
    migration_id: String,
    /// The migration's lifecycle phase after advancing.
    phase: MigrationPhase,
    /// The migration's progress after advancing.
    progress: MigrationProgress,
    /// A short description of what this step did.
    status: String,
}

pub(crate) async fn call<C: Chain>(
    wallet: &DbConnection,
    keystore: &KeyStore,
    chain: C,
    account: JsonValue,
    migration_id: &str,
) -> Response {
    validate_migration_id(migration_id)?;
    if migration_id != MIGRATION_ID {
        return Err(no_such_migration());
    }
    let account_id = parse_account_parameter(wallet, keystore, &account).await?;
    // Decrypt the spending key before the blocking section (the phase-2 transfers are signed there).
    let usk = decrypt_account_usk(wallet, keystore, account_id).await?;

    let chain_height = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;
    let tip = u32::from(chain_height);

    // Blocking: load the migration, detect newly mined transactions, and decide + build the next
    // transaction to broadcast (or build the transfers, or report what it is waiting for).
    let AdvanceOutcome {
        mut state,
        to_broadcast,
        message,
    } = wallet
        .with_raw_mut(|conn, network| advance_blocking(conn, network, account_id, usk, tip))
        .map_err(map_advance_error)?;

    // Broadcast the built transaction (async), then record its broadcast and persist.
    if let Some((tx, tx_id)) = to_broadcast {
        chain.broadcast_transaction(&tx).await.map_err(|e| {
            LegacyCode::Misc.with_message(format!("broadcasting the transaction failed: {e}"))
        })?;
        let txid = transaction_txid_bytes(&tx);
        wallet
            .with_raw_mut(|conn, _| record_broadcast(conn, &mut state, tx_id, txid))
            .map_err(map_advance_error)?;
    }

    Ok(AdvancePoolMigration {
        migration_id: MIGRATION_ID.to_string(),
        phase: MigrationPhase::from_status(state.status),
        progress: migration_progress(&state),
        status: message,
    })
}
