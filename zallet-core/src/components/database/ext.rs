//! Documentation about top-level extensions to the database structure.
//!
//! The database structure is managed by [`Database::open`], which applies migrations
//! (defined in [`migrations`]) that produce the current structure.
//!
//! The SQL code in this module's constants encodes the current database structure, as
//! represented internally by SQLite. We do not use these constants at runtime; instead we
//! check the output of the migrations in a test, to pin the expected database structure.
//!
//! [`Database::open`]: super::Database::open

// The constants in this module are only used in tests, but `#[cfg(test)]` prevents them
// from showing up in `cargo doc --document-private-items`.
#![allow(dead_code)]

pub(in crate::components) mod migrations;

/// Stores metadata about the Zallet wallet.
///
/// This table is a pseudo-key-value store, and should only ever contain at most one row.
///
/// ### Columns
///
/// - `network`: The network type that the wallet was created with.
pub(crate) const TABLE_WALLET_METADATA: &str = r#"
CREATE TABLE ext_zallet_db_wallet_metadata (
    network_type STRING NOT NULL
)
"#;

/// Stores metadata about the Zallet versions that the user has run with this database.
///
/// ### Columns
///
/// - `version`: The string encoding of a Zallet version.
/// - `git_revision`: The specific revision that the Zallet version was built from, or
///   `NULL` if Zallet was built from a source tarball without Git information.
/// - `clean`: A boolean indicating whether the Git working tree was clean at the time of
///   project build, or `NULL` if `git_revision IS NULL`.
/// - `migrated`: The time at which the Zallet version completed applying any missing
///   migrations to the wallet, as a string in the format `yyyy-MM-dd HH:mm:ss.fffffffzzz`.
pub(crate) const TABLE_VERSION_METADATA: &str = r#"
CREATE TABLE ext_zallet_db_version_metadata (
    version STRING NOT NULL,
    git_revision STRING,
    clean INTEGER,
    migrated TEXT NOT NULL
)
"#;
