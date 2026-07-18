//! `z_startpoolmigration`: start a generic pool-to-pool migration.
//!
//! Builds and pre-signs the note-preparation transactions that split the account's source-pool
//! balance into the self-funding notes that cross the turnstile, records the transfer schedule, and
//! persists the whole committed migration (as pre-signed PCZTs plus metadata) so it can be advanced
//! and broadcast later. Nothing is proved or broadcast here.

use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Serialize;
use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_keys::keys::UnifiedSpendingKey;

use super::pool_migration::{
    MIGRATION_ID, MigrationPlan, Pool, map_commit_failure, migration_plan, validate_pool_pair,
};
use crate::components::database::DbConnection;
use crate::components::json_rpc::server::LegacyCode;
use crate::components::json_rpc::utils::parse_account_parameter;
use crate::components::keystore::KeyStore;
use crate::migrate::{
    CommitFailure, commit_preparation_over_wallet, is_terminal, load_migration, persist_migration,
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
}

pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account: JsonValue,
    from_pool: &str,
    to_pool: &str,
) -> Response {
    let (from_pool, to_pool, enabling_upgrade) = validate_pool_pair(wallet, from_pool, to_pool)?;
    let account_id = parse_account_parameter(wallet, keystore, &account).await?;

    // The transactions build at the height after the current chain tip.
    let chain_height = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;
    let target_height = u32::from(chain_height) + 1;

    // Decrypt the account's spending key. This is the only async step, and it happens BEFORE the
    // blocking build section (no `.await` may occur inside `with_raw_mut`).
    let acct = wallet
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InvalidParameter.with_static("no such account"))?;
    let derivation = acct.source().key_derivation().ok_or_else(|| {
        LegacyCode::InvalidAddressOrKey
            .with_static("the account has no spending key to migrate with")
    })?;
    let seed = keystore
        .decrypt_seed(derivation.seed_fingerprint())
        .await
        .map_err(|e| match e.kind() {
            crate::error::ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
            }
            _ => LegacyCode::Database.with_message(e.to_string()),
        })?;
    let usk = UnifiedSpendingKey::from_seed(
        wallet.params(),
        seed.expose_secret(),
        derivation.account_index(),
    )
    .map_err(|e| LegacyCode::InvalidAddressOrKey.with_message(e.to_string()))?;

    // Build + pre-sign the preparation over the wallet, then persist the resulting migration. Both
    // the engine's wallet access and the store write run on one connection, sequentially.
    let state = wallet
        .with_raw_mut(|conn, network| -> Result<_, CommitFailure> {
            // Refuse to overwrite an in-progress migration: its pre-signed transactions would be
            // lost. A terminal (complete or failed) migration may be replaced.
            if let Some(existing) =
                load_migration(conn).map_err(|e| CommitFailure::Other(e.to_string()))?
            {
                if !is_terminal(&existing) {
                    return Err(CommitFailure::AlreadyInProgress);
                }
            }
            let state =
                commit_preparation_over_wallet(conn, network, account_id, usk, target_height)?;
            persist_migration(conn, &state).map_err(|e| CommitFailure::Other(e.to_string()))?;
            Ok(state)
        })
        .map_err(map_commit_failure)?;

    Ok(StartPoolMigration {
        migration_id: MIGRATION_ID.to_string(),
        from_pool,
        to_pool,
        enabling_upgrade: enabling_upgrade.to_string(),
        plan: migration_plan(state.transactions.len() as u32),
    })
}
