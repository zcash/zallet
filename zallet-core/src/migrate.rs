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

use zcash_pool_migration_backend::engine::MigrationBackend;

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
    type Error = core::convert::Infallible;

    fn spendable_orchard_note_values(&self) -> Result<Vec<u64>, Self::Error> {
        Ok(self.orchard_note_values.clone())
    }

    fn chain_tip_height(&self) -> Result<u32, Self::Error> {
        Ok(self.chain_tip_height)
    }
}
