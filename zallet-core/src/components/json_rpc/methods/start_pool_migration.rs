//! `z_startpoolmigration`: start a generic pool-to-pool migration.
//!
//! Builds and pre-signs the note-preparation transactions that split the account's source-pool
//! balance into the self-funding notes that cross the turnstile, records the transfer schedule, and
//! persists the whole committed migration (as pre-signed PCZTs plus metadata) so it can be advanced
//! and broadcast later. Nothing is proved or broadcast here.

use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::WalletRead;

use super::pool_migration::{
    MIGRATION_ID, MigrationPlan, Pool, UnsignedMigrationTransaction, decrypt_account_usk,
    encode_unsigned, map_commit_failure, migration_plan, validate_pool_pair,
};
use crate::components::database::DbConnection;
use crate::components::json_rpc::server::LegacyCode;
use crate::components::json_rpc::utils::parse_account_parameter;
use crate::components::keystore::KeyStore;
use crate::migrate::{
    CommitFailure, build_preparation_unsigned_over_wallet, commit_preparation_over_wallet,
    load_migration, persist_migration,
};

/// Response to a `z_startpoolmigration` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = StartPoolMigration;

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "Either the UUID or ZIP 32 account index of the account whose balance to migrate.";
pub(super) const PARAM_FROM_POOL_DESC: &str =
    "The value pool to migrate funds from (\"sapling\", \"orchard\", or \"ironwood\").";
pub(super) const PARAM_TO_POOL_DESC: &str =
    "The value pool to migrate funds to (\"sapling\", \"orchard\", or \"ironwood\").";
pub(super) const PARAM_EXTERNAL_SIGNER_DESC: &str = "When true, build the preparation transactions unsigned for an external (hardware or offline) \
     signer and return their PCZTs to sign on the device; when false (default) pre-sign in process.";

/// The result of starting a pool migration.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct StartPoolMigration {
    /// Opaque identifier for the migration, used with the status, advance, and cancel methods.
    migration_id: String,
    /// The value pool funds are being migrated from.
    from_pool: Pool,
    /// The value pool funds are being migrated to.
    to_pool: Pool,
    /// The network upgrade that enables this migration (for example `"Nu6.3"`).
    enabling_upgrade: String,
    /// The plan describing how the migration will be carried out.
    plan: MigrationPlan,
    /// When the migration was started for an EXTERNAL signer (`external_signer=true`), the unsigned
    /// preparation PCZTs to sign on the device; each is applied back with
    /// `z_applypoolmigrationsignature`. Absent for the default in-process-signing path (where the
    /// preparation is already pre-signed).
    #[serde(skip_serializing_if = "Option::is_none")]
    unsigned_transactions: Option<Vec<UnsignedMigrationTransaction>>,
}

pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account: JsonValue,
    from_pool: &str,
    to_pool: &str,
    external_signer: Option<bool>,
) -> Response {
    let (from_pool, to_pool, enabling_upgrade) = validate_pool_pair(wallet, from_pool, to_pool)?;
    let account_id = parse_account_parameter(wallet, keystore, &account).await?;
    let external_signer = external_signer.unwrap_or(false);

    // The transactions build at the height after the current chain tip.
    let chain_height = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;
    let target_height = u32::from(chain_height) + 1;

    // Decrypt the account's spending key. This is the only async step, and it happens BEFORE the
    // blocking build section (no `.await` may occur inside `with_raw_mut`). For an external signer,
    // the key still builds the PCZTs (it derives the account's viewing key and witnesses); it just
    // does not sign them, leaving that to the device.
    let usk = decrypt_account_usk(wallet, keystore, account_id).await?;

    // Build the preparation over the wallet, then persist the resulting migration. Both the engine's
    // wallet access and the store write run on one connection, sequentially. In the default path the
    // transactions are pre-signed; for an external signer they are left unsigned (in
    // `AwaitingSignature`) and their PCZTs are returned for the device to sign.
    let (state, unsigned_transactions) = wallet
        .with_raw_mut(|conn, network| -> Result<_, CommitFailure> {
            // Refuse to overwrite an in-progress migration: its transactions would be lost. A
            // terminal (complete or failed) migration may be replaced.
            if let Some(existing) =
                load_migration(conn).map_err(|e| CommitFailure::Other(e.to_string()))?
            {
                if !existing.is_terminal() {
                    return Err(CommitFailure::AlreadyInProgress);
                }
            }
            let (state, unsigned) = if external_signer {
                let (state, unsigned) = build_preparation_unsigned_over_wallet(
                    conn,
                    network,
                    account_id,
                    usk,
                    target_height,
                )?;
                (state, Some(encode_unsigned(unsigned)))
            } else {
                let state =
                    commit_preparation_over_wallet(conn, network, account_id, usk, target_height)?;
                (state, None)
            };
            persist_migration(conn, &state).map_err(|e| CommitFailure::Other(e.to_string()))?;
            Ok((state, unsigned))
        })
        .map_err(map_commit_failure)?;

    Ok(StartPoolMigration {
        migration_id: MIGRATION_ID.to_string(),
        from_pool,
        to_pool,
        enabling_upgrade: enabling_upgrade.to_string(),
        plan: migration_plan(state.transactions.len() as u32),
        unsigned_transactions,
    })
}
