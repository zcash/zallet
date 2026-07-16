//! Scaffolding for the Orchard-to-Ironwood value-pool migration.
//!
//! This module wires the backend-agnostic Orchard-to-Ironwood migration engine
//! into Zallet. It is currently only an integration point: the engine crate is
//! still evolving upstream (it lives on a librustzcash feature branch and is not
//! yet released to crates.io), so nothing here is written against the shape of
//! its final API.
//!
//! The engine is re-exported so that, as the integration grows, the rest of
//! Zallet has a single stable path to reach it rather than depending on the
//! external crate name directly.

/// The backend-agnostic Orchard-to-Ironwood value-pool migration engine.
///
/// Re-exported from the `zcash_ironwood_migration_backend` crate. Its API is not
/// yet stable; treat this re-export as the integration seam and avoid coupling
/// Zallet code to specific items until the engine is released.
pub use zcash_ironwood_migration_backend as engine;
