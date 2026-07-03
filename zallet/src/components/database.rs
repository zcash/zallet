use std::fmt;

use abscissa_core::tracing::info;
use rusqlite::{OptionalExtension, named_params};
use schemerz_rusqlite::RusqliteMigration;
use semver::Version;
use tokio::fs;

use zcash_client_sqlite::wallet::init::{WalletMigrationError, WalletMigrator};
use zcash_protocol::consensus::{NetworkType, Parameters};

use crate::{
    config::ZalletConfig,
    error::{Error, ErrorKind},
    fl,
};

#[cfg(zallet_build = "wallet")]
use super::keystore;

mod connection;
pub(crate) use connection::DbConnection;

mod ext;

#[cfg(test)]
mod tests;

pub(crate) type DbHandle = deadpool::managed::Object<connection::WalletManager>;

// Old databases are accepted only if the last recorded Zallet version is at
// least the oldest release whose wallet database this binary accepts.
//
// Bumped to 0.1.0-alpha.4 because the embedded Zaino chain indexer made a
// backwards-incompatible change to its database format (zingolabs/zaino#914),
// pulled in by this release. Wallet databases last touched by 0.1.0-alpha.3 or
// earlier must be recreated from scratch. See zcash/zallet#394.
const MIN_COMPATIBLE_ZALLET_VERSION: &str = "0.1.0-alpha.4";

/// Returns the full list of migrations defined in Zallet, to be applied alongside the
/// migrations internal to `zcash_client_sqlite`.
fn all_external_migrations(
    network_type: NetworkType,
) -> Vec<Box<dyn RusqliteMigration<Error = WalletMigrationError>>> {
    let migrations = ext::migrations::all(network_type);

    #[cfg(zallet_build = "wallet")]
    let migrations = migrations.chain(keystore::db::migrations::all());

    migrations.collect()
}

#[derive(Clone)]
pub(crate) struct Database {
    db_data_pool: connection::WalletPool,
}

impl fmt::Debug for Database {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Database").finish_non_exhaustive()
    }
}

impl Database {
    pub(crate) async fn open(config: &ZalletConfig) -> Result<Self, Error> {
        let path = config.wallet_db_path();

        let db_exists = fs::try_exists(&path)
            .await
            .map_err(|e| ErrorKind::Init.context(e))?;

        let db_data_pool = connection::pool(&path, config.consensus.network())?;

        let database = Self { db_data_pool };

        let handle = database.handle().await?;

        if db_exists {
            // Verify that the database matches the configured network type and was
            // last opened by a compatible alpha before we make any changes (including
            // migrations, some of which make use of the network params), to avoid
            // leaving the database in an inconsistent state. We can assume the network
            // metadata table is present, as it's added by the initial migrations.
            handle.with_raw(|conn, _| verify_existing_database(conn, config, &path))?;

            info!("Applying latest database migrations");
        } else {
            info!("Creating empty database");
        }

        // Initialize the database before we go any further.
        handle.with_mut(|mut db_data| {
            match WalletMigrator::new()
                .with_external_migrations(all_external_migrations(db_data.params().network_type()))
                .init_or_migrate(&mut db_data)
            {
                Ok(()) => Ok(()),
                // TODO: KeyStore depends on Database, but we haven't finished
                // initializing both yet. We might need to write logic to either
                // defer initialization until later, or expose enough of the
                // keystore read logic to let us parse the keystore database here
                // before the KeyStore component is initialized.
                //       https://github.com/zcash/zallet/issues/18
                // TODO: Support multi-seed or seed-absent migrations.
                //       https://github.com/zcash/librustzcash/issues/1284
                Err(schemerz::MigratorError::Migration {
                    error: WalletMigrationError::SeedRequired,
                    ..
                }) => Err(ErrorKind::Init.context("TODO: Support seed-required migrations")),
                Err(e) => Err(ErrorKind::Init.context(e)),
            }?;

            Ok::<(), Error>(())
        })?;

        let now = ::time::OffsetDateTime::now_utc();

        // Record that we migrated the database using this Zallet version. We don't have
        // an easy way to detect whether any migrations actually ran, so we check whether
        // the most recent entry matches the current version tuple, and only record an
        // entry if it doesn't.
        handle.with_raw_mut(|conn, _| {
            #[allow(clippy::const_is_empty)]
            let (git_revision, clean) = (!crate::build::COMMIT_HASH.is_empty())
                .then_some((crate::build::COMMIT_HASH, crate::build::GIT_CLEAN))
                .unzip();

            match conn
                .query_row(
                    "SELECT version, git_revision, clean
                    FROM ext_zallet_db_version_metadata
                    ORDER BY rowid DESC
                    LIMIT 1",
                    [],
                    |row| {
                        Ok(
                            row.get::<_, String>("version")? == crate::build::PKG_VERSION
                                && row.get::<_, Option<String>>("git_revision")?.as_deref()
                                    == git_revision
                                && row.get::<_, Option<bool>>("clean")? == clean,
                        )
                    },
                )
                .optional()
                .map_err(|e| ErrorKind::Init.context(e))?
            {
                Some(true) => (),
                None | Some(false) => {
                    conn.execute(
                        "INSERT INTO ext_zallet_db_version_metadata
                        VALUES (:version, :git_revision, :clean, :migrated)",
                        named_params! {
                            ":version": crate::build::PKG_VERSION,
                            ":git_revision": git_revision,
                            ":clean": clean,
                            ":migrated": now,
                        },
                    )
                    .map_err(|e| ErrorKind::Init.context(e))?;
                }
            }

            Ok::<(), Error>(())
        })?;

        Ok(database)
    }

    pub(crate) async fn handle(&self) -> Result<DbHandle, Error> {
        self.db_data_pool
            .get()
            .await
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }
}

fn verify_existing_database(
    conn: &rusqlite::Connection,
    config: &ZalletConfig,
    db_path: &std::path::Path,
) -> Result<(), Error> {
    verify_alpha_db_compatibility(conn)?;
    verify_wallet_network_type(conn, config, db_path)
}

fn verify_wallet_network_type(
    conn: &rusqlite::Connection,
    config: &ZalletConfig,
    db_path: &std::path::Path,
) -> Result<(), Error> {
    let wallet_network_type = conn
        .query_row(
            "SELECT network_type FROM ext_zallet_db_wallet_metadata",
            [],
            |row| row.get::<_, crate::network::kind::Sql>("network_type"),
        )
        .map_err(|e| ErrorKind::Init.context(e))?;

    if wallet_network_type.0 == config.consensus.network {
        Ok(())
    } else {
        Err(ErrorKind::Init
            .context(fl!(
                "err-init-config-db-mismatch",
                db_path = db_path.display().to_string(),
                db_network_type = crate::network::kind::type_to_str(&wallet_network_type.0),
                config_network_type = crate::network::kind::type_to_str(&config.consensus.network),
            ))
            .into())
    }
}

fn verify_alpha_db_compatibility(conn: &rusqlite::Connection) -> Result<(), Error> {
    let latest_version = latest_recorded_zallet_version(conn)?;
    let latest_version = Version::parse(&latest_version)
        .map_err(|e| invalid_zallet_version_error(&latest_version, e))?;
    let minimum_version = Version::parse(MIN_COMPATIBLE_ZALLET_VERSION)
        .expect("minimum compatible Zallet version is valid SemVer");

    if latest_version >= minimum_version {
        Ok(())
    } else {
        Err(incompatible_alpha_database_error())
    }
}

fn latest_recorded_zallet_version(conn: &rusqlite::Connection) -> Result<String, Error> {
    conn.query_row(
        "SELECT version
         FROM ext_zallet_db_version_metadata
         ORDER BY rowid DESC
         LIMIT 1",
        [],
        |row| row.get("version"),
    )
    .optional()
    .map_err(|_| incompatible_alpha_database_error())?
    .ok_or_else(incompatible_alpha_database_error)
}

fn incompatible_alpha_database_error() -> Error {
    ErrorKind::Init
        .context(fl!("err-init-db-incompatible-alpha"))
        .into()
}

fn invalid_zallet_version_error(version: &str, err: semver::Error) -> Error {
    ErrorKind::Init
        .context(fl!(
            "err-init-db-invalid-zallet-version",
            version = version,
            err = err.to_string(),
        ))
        .into()
}
