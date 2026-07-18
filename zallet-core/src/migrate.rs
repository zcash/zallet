//! Scaffolding for the Orchard-to-Ironwood value-pool migration.
//!
//! This module wires the backend-agnostic pool-migration engine into Zallet. The
//! engine crate is still evolving upstream (it lives on a librustzcash feature
//! branch and is not yet released to crates.io), so this module keeps the
//! integration seam small: the rest of Zallet reaches the engine through the
//! [`engine`] re-export rather than depending on the external crate name
//! directly.
//!
//! It also provides [`SpendableSnapshot`], Zallet's implementation of the
//! engine's `MigrationBackend` trait for the PLANNING slice. The engine's
//! `plan_migration` needs only the account's spendable source-pool note values
//! and the chain-tip height, so the snapshot captures both from the wallet up
//! front and serves them back to the engine. Capturing a snapshot (rather than
//! querying the wallet from inside the trait methods) keeps all wallet I/O and its
//! error handling in the RPC layer, and lets the pure planner run synchronously
//! after the last `.await`.
//!
//! Persistence is a separate concern: the engine's `PoolMigrationRead` /
//! `PoolMigrationWrite` store traits (implemented over the wallet database by
//! `zcash_pool_migration_sqlite`) hold a committed migration, and the
//! `MigrationBackend` trait this snapshot implements is now just the planning
//! inputs. Committing a migration uses the `WalletMigration` adapter over the
//! wallet, not this snapshot.

use core::convert::Infallible;

use rand::rngs::OsRng;
use rusqlite::Connection;
use zcash_client_sqlite::{AccountUuid, WalletDb, util::SystemClock};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration_backend::engine::{
    CommitError, MigrationBackend, MigrationError, MigrationState, MigrationStatus, MigrationTxId,
    MigrationTxState, PoolMigrationRead, PoolMigrationWrite, commit_preparation, commit_transfers,
    plan_migration,
};
use zcash_pool_migration_backend::note_splitting::{FeePolicy, Zip317FeePolicy};
use zcash_pool_migration_backend::preparation::PREP_TX_ACTIONS;
use zcash_pool_migration_backend::wallet::WalletMigration;
use zcash_pool_migration_sqlite::PoolMigrations;

use crate::network::Network;

/// The backend-agnostic value-pool migration engine.
///
/// Re-exported from the `zcash_pool_migration_backend` crate (formerly
/// `zcash_ironwood_migration_backend`, renamed upstream to a pool-agnostic name).
/// Its API is not yet stable; treat this re-export as the integration seam and
/// avoid coupling Zallet code to specific items until the engine is released.
pub use zcash_pool_migration_backend as engine;

/// A point-in-time snapshot of the inputs the migration engine needs to PLAN a
/// migration for one account: the values of the account's spendable source-pool
/// (Orchard) notes, and the chain-tip height.
///
/// This is Zallet's `MigrationBackend` for planning. The caller gathers both
/// values from the wallet (mapping any wallet error to an RPC error), then hands
/// the snapshot to `engine::plan_migration`. It holds only already-read values,
/// so it is infallible; committing a migration uses the `WalletMigration`
/// adapter over the wallet, not this snapshot.
pub struct SpendableSnapshot {
    orchard_note_values: Vec<u64>,
    chain_tip_height: u32,
}

impl SpendableSnapshot {
    /// Builds a snapshot from the spendable source-pool note values and the
    /// chain-tip height the caller has already read from the wallet.
    pub fn new(orchard_note_values: Vec<u64>, chain_tip_height: u32) -> Self {
        Self {
            orchard_note_values,
            chain_tip_height,
        }
    }
}

impl MigrationBackend for SpendableSnapshot {
    type Error = Infallible;

    fn spendable_orchard_note_values(&self) -> Result<Vec<u64>, Self::Error> {
        Ok(self.orchard_note_values.clone())
    }

    fn chain_tip_height(&self) -> Result<u32, Self::Error> {
        Ok(self.chain_tip_height)
    }
}

/// Why committing (building/pre-signing) a migration failed, in terms the RPC layer maps to
/// user-facing errors without depending on the engine's error shapes.
pub enum CommitFailure {
    /// The account has no spendable source-pool balance to migrate.
    NothingToMigrate,
    /// The plan needs multi-layer preparation, which the two-phase commit path does not yet
    /// support.
    UnsupportedMultiLayer,
    /// There is no committed migration to act on (nothing was loaded from the store).
    NoMigrationInProgress,
    /// A migration is already in progress; starting another would overwrite its pre-signed
    /// transactions. The caller must cancel the current migration first.
    AlreadyInProgress,
    /// Any other build/backend failure, rendered to a string.
    Other(String),
}

/// Whether a stored migration has reached a terminal status (complete or failed), so a new migration
/// may replace it. A non-terminal migration is still in progress and must not be overwritten.
pub fn is_terminal(state: &MigrationState) -> bool {
    matches!(
        state.status,
        MigrationStatus::Complete | MigrationStatus::Failed
    )
}

fn map_plan_error<E: core::fmt::Display>(err: MigrationError<E>) -> CommitFailure {
    match err {
        MigrationError::NothingToMigrate => CommitFailure::NothingToMigrate,
        MigrationError::Preparation(e) => CommitFailure::Other(format!(
            "the spendable notes cannot fund the migration: {e}"
        )),
        MigrationError::Backend(e) => CommitFailure::Other(e.to_string()),
    }
}

fn map_commit_error<E: core::fmt::Display>(err: CommitError<E>) -> CommitFailure {
    match err {
        CommitError::UnsupportedMultiLayer => CommitFailure::UnsupportedMultiLayer,
        CommitError::NoMigrationInProgress => CommitFailure::NoMigrationInProgress,
        CommitError::Backend(e) => CommitFailure::Other(e.to_string()),
        CommitError::Build(m) => CommitFailure::Other(m),
    }
}

/// An in-memory migration store used to run the engine's commit functions WITHOUT letting them
/// write to SQLite. `commit_preparation` / `commit_transfers` return the resulting
/// [`MigrationState`], so the caller runs the engine against this store, then persists the returned
/// state to the real SQLite store separately. This keeps the engine's wallet access and the store's
/// database access on ONE connection, used sequentially (never two live borrows at once).
#[derive(Default)]
pub struct InMemoryStore {
    state: Option<MigrationState>,
}

impl InMemoryStore {
    /// An in-memory store pre-seeded with a loaded migration (for `commit_transfers`, which reads
    /// the in-progress migration before filling in the transfers).
    pub fn seeded(state: Option<MigrationState>) -> Self {
        Self { state }
    }
}

impl PoolMigrationRead for InMemoryStore {
    type Error = Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }
}

impl PoolMigrationWrite for InMemoryStore {
    fn put_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.state = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        tx_state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        if let Some(state) = &mut self.state {
            if let Some(tx) = state.transactions.iter_mut().find(|t| t.id == id) {
                tx.state = tx_state;
            }
        }
        Ok(())
    }
}

/// The ZIP-317 fee reserved per note-preparation transaction (the fixed padded action count times
/// the marginal fee), as the engine's planning and preparation both compute it.
fn prep_fee_zatoshi() -> u64 {
    PREP_TX_ACTIONS as u64 * Zip317FeePolicy.marginal_fee_zatoshi()
}

/// Loads the persisted migration from the SQLite store over `conn`.
pub fn load_migration(
    conn: &mut Connection,
) -> Result<Option<MigrationState>, zcash_pool_migration_sqlite::Error> {
    PoolMigrations::new(&mut *conn).get_migration()
}

/// Persists a migration to the SQLite store over `conn`, replacing any existing one.
pub fn persist_migration(
    conn: &mut Connection,
    state: &MigrationState,
) -> Result<(), zcash_pool_migration_sqlite::Error> {
    PoolMigrations::new(&mut *conn).put_migration(state)
}

/// Plans and commits the PREPARATION of a migration over the wallet: builds and pre-signs every
/// preparation transaction and records the transfer placeholders, returning the resulting state
/// (NOT persisted; the caller persists it). Runs the engine synchronously; call inside the blocking
/// database section, after the spending key has been decrypted.
pub fn commit_preparation_over_wallet(
    conn: &mut Connection,
    network: &Network,
    account: AccountUuid,
    usk: UnifiedSpendingKey,
    target_height: u32,
) -> Result<MigrationState, CommitFailure> {
    let mut wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
    let mut migration = WalletMigration::new(&mut wallet, account, usk, InMemoryStore::default());
    let mut rng = OsRng;
    let plan = plan_migration(&migration, prep_fee_zatoshi(), &mut rng).map_err(map_plan_error)?;
    commit_preparation(network, target_height, &mut migration, &plan, &mut rng)
        .map_err(map_commit_error)
}

/// Commits the TRANSFERS of an in-progress migration over the wallet: builds and pre-signs the
/// phase-2 transfer transactions (whose funding notes the mined preparation created), returning the
/// updated state (NOT persisted; the caller persists it). `loaded` is the migration read from the
/// store. Runs the engine synchronously; call inside the blocking database section.
pub fn commit_transfers_over_wallet(
    conn: &mut Connection,
    network: &Network,
    account: AccountUuid,
    usk: UnifiedSpendingKey,
    target_height: u32,
    loaded: MigrationState,
) -> Result<MigrationState, CommitFailure> {
    let mut wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
    let store = InMemoryStore::seeded(Some(loaded));
    let mut migration = WalletMigration::new(&mut wallet, account, usk, store);
    let mut rng = OsRng;
    commit_transfers(network, target_height, &mut migration, &mut rng).map_err(map_commit_error)
}
