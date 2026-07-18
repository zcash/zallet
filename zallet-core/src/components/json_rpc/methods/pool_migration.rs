//! Shared types and validation for the generic value-pool migration RPC surface.
//!
//! The migration surface is a pool-to-pool workflow (`z_startpoolmigration` and the
//! companion status, advance, cancel, and list methods) spread across sibling method
//! modules. This module holds what they share: the pool-agnostic [`Pool`] type, the
//! [`SUPPORTED_MIGRATIONS`] table that is the single extension point for new pool
//! pairs, the fixed migration identifier and pools, the plan/progress/phase response
//! shapes and their mapping from the engine's state, and the input validation.
//!
//! `z_startpoolmigration` builds, pre-signs, and persists the migration; the status
//! and list methods read the persisted state; cancel marks it cancelled. Proving and
//! broadcasting the pre-signed transactions (`z_advancepoolmigration`) is the one step
//! not yet wired into Zallet, because it needs the `pczt` prover and an Orchard proving
//! key; until then a committed migration cannot make on-chain progress.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Serialize;
use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration_backend::engine::{MigrationState, MigrationStatus, MigrationTxState};
use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

use crate::components::keystore::KeyStore;
use crate::components::{database::DbConnection, json_rpc::server::LegacyCode};
use crate::migrate::CommitFailure;

/// The identifier of the wallet's pool migration. The store holds at most one migration at a time,
/// so a single fixed identifier names it: `z_startpoolmigration` returns this, and the status,
/// advance, and cancel methods accept it.
pub(crate) const MIGRATION_ID: &str = "orchard-to-ironwood";

/// The only supported migration is Orchard -> Ironwood, so a stored migration's pools and enabling
/// upgrade are fixed rather than recorded per migration.
pub(crate) const MIGRATION_FROM_POOL: Pool = Pool::Orchard;
pub(crate) const MIGRATION_TO_POOL: Pool = Pool::Ironwood;
pub(crate) const MIGRATION_ENABLING_UPGRADE: NetworkUpgrade = NetworkUpgrade::Nu6_3;

/// Wire name of the Sapling value pool.
const POOL_NAME_SAPLING: &str = "sapling";
/// Wire name of the Orchard value pool.
const POOL_NAME_ORCHARD: &str = "orchard";
/// Wire name of the Ironwood value pool.
const POOL_NAME_IRONWOOD: &str = "ironwood";

/// A Zcash shielded value pool that can take part in a pool-to-pool migration.
///
/// Serialized as its lowercase wire name (`"sapling"`, `"orchard"`, `"ironwood"`). New
/// pools are added here and, if they can be migrated, wired into
/// [`SUPPORTED_MIGRATIONS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Pool {
    /// The Sapling shielded value pool.
    Sapling,
    /// The Orchard shielded value pool.
    Orchard,
    /// The Ironwood shielded value pool (NU6.3, ZIP 2005).
    Ironwood,
}

impl Pool {
    /// Returns the lowercase wire name of this pool.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Pool::Sapling => POOL_NAME_SAPLING,
            Pool::Orchard => POOL_NAME_ORCHARD,
            Pool::Ironwood => POOL_NAME_IRONWOOD,
        }
    }

    /// Parses a pool from its wire name, returning an `InvalidParameter` RPC error for
    /// any unrecognized value.
    pub(crate) fn parse(label: &str, value: &str) -> RpcResult<Self> {
        match value {
            POOL_NAME_SAPLING => Ok(Pool::Sapling),
            POOL_NAME_ORCHARD => Ok(Pool::Orchard),
            POOL_NAME_IRONWOOD => Ok(Pool::Ironwood),
            other => Err(LegacyCode::InvalidParameter.with_message(format!(
                "{label}: unknown value pool {other:?}; expected one of \
                 {POOL_NAME_SAPLING:?}, {POOL_NAME_ORCHARD:?}, {POOL_NAME_IRONWOOD:?}",
            ))),
        }
    }
}

/// One supported pool-to-pool migration and the network upgrade that enables it.
struct SupportedMigration {
    /// The value pool funds are migrated from.
    from: Pool,
    /// The value pool funds are migrated to.
    to: Pool,
    /// The network upgrade that must be active for this migration to run.
    enabling_upgrade: NetworkUpgrade,
}

/// The single source of truth for which pool-to-pool migrations exist and which
/// network upgrade each one requires.
///
/// This is the one extension point for supporting new migrations: adding a pool pair
/// here makes it selectable through the whole RPC surface. Migrating from the Orchard
/// pool to the Ironwood pool requires NU6.3 (ZIP 2005).
const SUPPORTED_MIGRATIONS: &[SupportedMigration] = &[SupportedMigration {
    from: Pool::Orchard,
    to: Pool::Ironwood,
    enabling_upgrade: NetworkUpgrade::Nu6_3,
}];

/// Looks up a supported migration by its ordered pool pair.
fn supported_migration(from: Pool, to: Pool) -> Option<&'static SupportedMigration> {
    SUPPORTED_MIGRATIONS
        .iter()
        .find(|m| m.from == from && m.to == to)
}

/// Parses and validates a pool pair, returning the parsed pools and the network
/// upgrade that enables the migration.
///
/// Validates that the pair is present in [`SUPPORTED_MIGRATIONS`] and that its enabling
/// upgrade is active at the wallet's current chain height, returning an
/// `InvalidParameter` RPC error otherwise.
pub(crate) fn validate_pool_pair(
    wallet: &DbConnection,
    from_pool: &str,
    to_pool: &str,
) -> RpcResult<(Pool, Pool, NetworkUpgrade)> {
    let from_pool = Pool::parse("from_pool", from_pool)?;
    let to_pool = Pool::parse("to_pool", to_pool)?;

    if from_pool == to_pool {
        return Err(LegacyCode::InvalidParameter.with_message(format!(
            "from_pool and to_pool must differ; both were {:?}",
            from_pool.name(),
        )));
    }

    let migration = supported_migration(from_pool, to_pool).ok_or_else(|| {
        LegacyCode::InvalidParameter.with_message(format!(
            "migrating from the {:?} pool to the {:?} pool is not supported",
            from_pool.name(),
            to_pool.name(),
        ))
    })?;

    let params = wallet.params();
    let activation = params.activation_height(migration.enabling_upgrade);

    let chain_height = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;

    match activation {
        Some(height) if chain_height >= height => {
            Ok((from_pool, to_pool, migration.enabling_upgrade))
        }
        _ => Err(LegacyCode::InvalidParameter.with_message(format!(
            "migrating from the {:?} pool to the {:?} pool requires network upgrade {} \
             to be active",
            from_pool.name(),
            to_pool.name(),
            migration.enabling_upgrade,
        ))),
    }
}

/// Decrypts the account's unified spending key. This is the async step that must run BEFORE the
/// blocking build/prove section (no `.await` may occur while the database write lock is held).
/// Mirrors the send path: find the account's ZIP-32 derivation, decrypt its seed, and derive the
/// spending key.
pub(crate) async fn decrypt_account_usk(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account_id: AccountUuid,
) -> RpcResult<UnifiedSpendingKey> {
    let account = wallet
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InvalidParameter.with_static("no such account"))?;
    let derivation = account.source().key_derivation().ok_or_else(|| {
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
    UnifiedSpendingKey::from_seed(
        wallet.params(),
        seed.expose_secret(),
        derivation.account_index(),
    )
    .map_err(|e| LegacyCode::InvalidAddressOrKey.with_message(e.to_string()))
}

/// Validates that a migration identifier is well-formed (currently just non-empty).
pub(crate) fn validate_migration_id(migration_id: &str) -> RpcResult<()> {
    if migration_id.trim().is_empty() {
        return Err(LegacyCode::InvalidParameter.with_static("migration_id must not be empty"));
    }
    Ok(())
}

/// The lifecycle phase of a pool migration.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MigrationPhase {
    /// The migration has been scheduled but no transactions have been created.
    Scheduled,
    /// The migration is creating and broadcasting transactions.
    InProgress,
    /// Every planned transaction has been mined.
    Completed,
    /// The migration was cancelled before completing.
    Cancelled,
}

impl MigrationPhase {
    /// The lifecycle phase corresponding to a stored migration's overall status.
    pub(crate) fn from_status(status: MigrationStatus) -> Self {
        match status {
            MigrationStatus::Planning | MigrationStatus::Committed => MigrationPhase::Scheduled,
            MigrationStatus::InProgress => MigrationPhase::InProgress,
            MigrationStatus::Complete => MigrationPhase::Completed,
            MigrationStatus::Failed => MigrationPhase::Cancelled,
        }
    }
}

/// Builds the response plan summary from the number of transactions a migration comprises.
pub(crate) fn migration_plan(transaction_count: u32) -> MigrationPlan {
    MigrationPlan { transaction_count }
}

/// Summarizes a migration's progress: how many of its transactions have been mined, out of the
/// total the migration comprises.
pub(crate) fn migration_progress(state: &MigrationState) -> MigrationProgress {
    let total_transactions = state.transactions.len() as u32;
    let completed_transactions = state
        .transactions
        .iter()
        .filter(|t| matches!(t.state, MigrationTxState::Mined { .. }))
        .count() as u32;
    MigrationProgress {
        completed_transactions,
        total_transactions,
    }
}

/// The RPC error for a migration id that does not name the wallet's migration, or when no migration
/// is stored.
pub(crate) fn no_such_migration() -> ErrorObjectOwned {
    LegacyCode::InvalidParameter.with_static("no such migration")
}

/// Maps a migration build/commit failure to an RPC error.
pub(crate) fn map_commit_failure(failure: CommitFailure) -> ErrorObjectOwned {
    match failure {
        CommitFailure::NothingToMigrate => LegacyCode::InvalidParameter
            .with_static("the account has no spendable source-pool balance to migrate"),
        CommitFailure::UnsupportedMultiLayer => LegacyCode::InvalidParameter
            .with_static("this balance needs multi-layer preparation, which is not yet supported"),
        CommitFailure::NoMigrationInProgress => {
            LegacyCode::InvalidParameter.with_static("no migration is in progress")
        }
        CommitFailure::AlreadyInProgress => LegacyCode::InvalidParameter
            .with_static("a migration is already in progress; cancel it before starting another"),
        CommitFailure::Other(message) => LegacyCode::Misc.with_message(message),
    }
}

/// The plan produced when a migration is scheduled.
///
/// Stubbed in the current scaffold; the fields describe the intended shape only.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct MigrationPlan {
    /// The number of transactions the migration is expected to require.
    transaction_count: u32,
}

/// Progress of an in-flight migration.
///
/// Stubbed in the current scaffold; the fields describe the intended shape only.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct MigrationProgress {
    /// The number of planned transactions that have been mined so far.
    completed_transactions: u32,
    /// The total number of transactions the migration requires.
    total_transactions: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_round_trips_through_its_wire_name() {
        for pool in [Pool::Sapling, Pool::Orchard, Pool::Ironwood] {
            assert_eq!(Pool::parse("pool", pool.name()).unwrap(), pool);
        }
    }

    #[test]
    fn unknown_pool_is_rejected() {
        assert!(Pool::parse("pool", "transparent").is_err());
        assert!(Pool::parse("pool", "").is_err());
    }

    #[test]
    fn every_supported_migration_has_distinct_pools() {
        for migration in SUPPORTED_MIGRATIONS {
            assert_ne!(migration.from, migration.to);
        }
    }

    #[test]
    fn orchard_to_ironwood_is_supported_and_requires_nu6_3() {
        let migration = supported_migration(Pool::Orchard, Pool::Ironwood)
            .expect("Orchard to Ironwood must be supported");
        assert!(matches!(migration.enabling_upgrade, NetworkUpgrade::Nu6_3));
    }

    #[test]
    fn unsupported_pairs_are_absent_from_the_table() {
        assert!(supported_migration(Pool::Ironwood, Pool::Orchard).is_none());
        assert!(supported_migration(Pool::Sapling, Pool::Orchard).is_none());
    }

    #[test]
    fn blank_migration_id_is_rejected() {
        assert!(validate_migration_id("   ").is_err());
        assert!(validate_migration_id("m-1").is_ok());
    }
}
