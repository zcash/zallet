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
//! The trait also declares persistence methods (store/load/update) used by the
//! still-unreleased commit and reconcile slices. This planning-only snapshot does
//! not persist anything: `load_migration` reports "no migration in progress" and
//! the mutating methods return [`SnapshotError::PersistenceUnsupported`]. A
//! persistence-capable backend over the wallet database replaces it once those
//! slices land.

use std::fmt;

use zcash_pool_migration_backend::engine::{
    MigrationBackend, MigrationState, MigrationTxId, MigrationTxState,
};

/// The backend-agnostic value-pool migration engine.
///
/// Re-exported from the `zcash_pool_migration_backend` crate (formerly
/// `zcash_ironwood_migration_backend`, renamed upstream to a pool-agnostic name).
/// Its API is not yet stable; treat this re-export as the integration seam and
/// avoid coupling Zallet code to specific items until the engine is released.
pub use zcash_pool_migration_backend as engine;

/// The error type of the planning-only [`SpendableSnapshot`] backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// The planning snapshot cannot persist migration state. Committing a
    /// migration (building, pre-signing, and storing the PCZTs) needs a
    /// persistence-capable backend, which a later engine slice provides.
    PersistenceUnsupported,
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::PersistenceUnsupported => f.write_str(
                "the migration preview backend does not persist migration state; \
                 committing a migration is not yet available",
            ),
        }
    }
}

impl std::error::Error for SnapshotError {}

/// A point-in-time snapshot of the inputs the migration engine needs to PLAN a
/// migration for one account: the values of the account's spendable source-pool
/// (Orchard) notes, and the chain-tip height.
///
/// This is Zallet's `MigrationBackend` for planning. The caller gathers both
/// values from the wallet (mapping any wallet error to an RPC error), then hands
/// the snapshot to `engine::plan_migration`. The persistence methods are not
/// supported (see the module docs): planning never calls them, and committing
/// needs a different, persistence-capable backend.
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
    type Error = SnapshotError;

    fn spendable_orchard_note_values(&self) -> Result<Vec<u64>, Self::Error> {
        Ok(self.orchard_note_values.clone())
    }

    fn chain_tip_height(&self) -> Result<u32, Self::Error> {
        Ok(self.chain_tip_height)
    }

    fn store_migration(&mut self, _state: &MigrationState) -> Result<(), Self::Error> {
        Err(SnapshotError::PersistenceUnsupported)
    }

    fn load_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        // A planning snapshot never persists, so no migration is ever in progress through it.
        Ok(None)
    }

    fn update_transaction(
        &mut self,
        _id: MigrationTxId,
        _state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        Err(SnapshotError::PersistenceUnsupported)
    }
}
