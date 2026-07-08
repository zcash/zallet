use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension, named_params};
use shardtree::error::ShardTreeError;
use tempfile::tempdir;
use zcash_client_backend::data_api::{NullifierQuery, WalletCommitmentTrees, WalletRead};
use zcash_client_sqlite::{WalletDb, util::SystemClock, wallet::init::WalletMigrator};
use zcash_protocol::consensus::{self, NetworkType, Parameters};

use crate::{components::database, config::ZalletConfig, network::Network};

#[cfg(zallet_build = "wallet")]
use crate::components::keystore;

#[test]
fn verify_schema() {
    let mut conn = Connection::open_in_memory().unwrap();
    let mut db_data = WalletDb::from_connection(
        &mut conn,
        Network::Consensus(consensus::Network::MainNetwork),
        SystemClock,
        OsRng,
    );

    WalletMigrator::new()
        .with_external_migrations(database::all_external_migrations(
            db_data.params().network_type(),
        ))
        .init_or_migrate(&mut db_data)
        .unwrap();

    use regex::Regex;
    let re = Regex::new(r"\s+").unwrap();

    let verify_consistency = |query: &str, expected: &[&str]| {
        let mut stmt = conn.prepare(query).unwrap();
        let mut rows = stmt.query([]).unwrap();
        let mut expected_idx = 0;
        while let Some(row) = rows.next().unwrap() {
            let sql: String = row.get(0).unwrap();
            assert_eq!(
                re.replace_all(&sql, " "),
                re.replace_all(expected[expected_idx], " ").trim(),
            );
            expected_idx += 1;
        }
        assert_eq!(expected_idx, expected.len());
    };

    verify_consistency(
        "SELECT sql
        FROM sqlite_schema
        WHERE type = 'table' AND tbl_name LIKE 'ext_zallet_%'
        ORDER BY tbl_name",
        &[
            database::ext::TABLE_VERSION_METADATA,
            database::ext::TABLE_WALLET_METADATA,
            #[cfg(zallet_build = "wallet")]
            keystore::db::TABLE_AGE_RECIPIENTS,
            #[cfg(zallet_build = "wallet")]
            keystore::db::TABLE_LEGACY_SEEDS,
            #[cfg(zallet_build = "wallet")]
            keystore::db::TABLE_MNEMONICS,
            #[cfg(zallet_build = "wallet")]
            keystore::db::TABLE_STANDALONE_SAPLING_KEYS,
            #[cfg(zallet_build = "wallet")]
            keystore::db::TABLE_STANDALONE_TRANSPARENT_KEYS,
        ],
    );

    verify_consistency(
        "SELECT sql
        FROM sqlite_master
        WHERE type = 'index' AND sql != '' AND name LIKE 'ext_zallet_%'
        ORDER BY tbl_name, name",
        &[],
    );

    verify_consistency(
        "SELECT sql
        FROM sqlite_schema
        WHERE type = 'view' AND tbl_name LIKE 'ext_zallet_%'
        ORDER BY tbl_name",
        &[],
    );
}

#[test]
fn legacy_alpha_2_database_is_rejected_before_recording_current_version() {
    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);
    create_wallet_db(config.wallet_db_path(), &["0.1.0-alpha.2"]);

    let err = open_database(&config).expect_err("legacy alpha.2 database must be rejected");
    assert!(
        err.to_string().contains("fresh Zallet wallet"),
        "unexpected error: {err}",
    );

    let conn = Connection::open(config.wallet_db_path()).unwrap();
    assert_eq!(
        latest_recorded_version(&conn),
        Some("0.1.0-alpha.2".to_string())
    );
    assert_eq!(
        count_recorded_versions(&conn, crate::build::PKG_VERSION),
        0,
        "the current Zallet version should not be recorded after rejecting the database",
    );
}

#[test]
fn legacy_alpha_3_database_is_rejected_before_recording_current_version() {
    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);
    create_wallet_db(config.wallet_db_path(), &["0.1.0-alpha.3"]);

    let err = open_database(&config).expect_err("legacy alpha.3 database must be rejected");
    assert!(
        err.to_string().contains("fresh Zallet wallet"),
        "unexpected error: {err}",
    );

    let conn = Connection::open(config.wallet_db_path()).unwrap();
    assert_eq!(
        latest_recorded_version(&conn),
        Some("0.1.0-alpha.3".to_string())
    );
    assert_eq!(
        count_recorded_versions(&conn, crate::build::PKG_VERSION),
        0,
        "the current Zallet version should not be recorded after rejecting the database",
    );
}

#[test]
fn latest_alpha_4_database_is_allowed() {
    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);
    create_wallet_db(config.wallet_db_path(), &["0.1.0-alpha.4"]);

    open_database(&config).unwrap();

    let conn = Connection::open(config.wallet_db_path()).unwrap();
    assert_eq!(
        latest_recorded_version(&conn),
        Some(crate::build::PKG_VERSION.to_string()),
    );
}

#[test]
fn compatibility_check_uses_latest_recorded_version() {
    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);
    create_wallet_db(config.wallet_db_path(), &["0.1.0-alpha.3", "0.1.0-alpha.4"]);

    open_database(&config).unwrap();
}

#[test]
fn latest_alpha_2_version_is_rejected_even_with_earlier_alpha_4_version() {
    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);
    create_wallet_db(config.wallet_db_path(), &["0.1.0-alpha.4", "0.1.0-alpha.2"]);

    let err = open_database(&config).expect_err("latest alpha.2 database must be rejected");
    assert!(
        err.to_string().contains("fresh Zallet wallet"),
        "unexpected error: {err}",
    );
}

#[test]
fn malformed_legacy_version_is_rejected() {
    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);
    create_wallet_db(config.wallet_db_path(), &["not-a-version"]);

    let err = open_database(&config).expect_err("malformed version must be rejected");
    assert!(
        err.to_string().contains("invalid zallet version"),
        "unexpected error: {err}",
    );

    let conn = Connection::open(config.wallet_db_path()).unwrap();
    assert_eq!(count_recorded_versions(&conn, crate::build::PKG_VERSION), 0);
}

#[test]
fn missing_legacy_version_is_rejected() {
    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);
    create_wallet_db(config.wallet_db_path(), &[]);

    let err = open_database(&config).expect_err("missing version must be rejected");
    assert!(
        err.to_string().contains("fresh Zallet wallet"),
        "unexpected error: {err}",
    );

    let conn = Connection::open(config.wallet_db_path()).unwrap();
    assert_eq!(count_recorded_versions(&conn, crate::build::PKG_VERSION), 0);
}

#[test]
fn network_mismatch_still_reports_network_error() {
    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);
    create_wallet_db_for_network(
        config.wallet_db_path(),
        Network::Consensus(consensus::Network::MainNetwork),
        &["0.1.0-alpha.4"],
    );

    let err = open_database(&config).expect_err("network mismatch must be rejected");
    assert!(
        err.to_string().contains("was created for network type"),
        "unexpected error: {err}",
    );
}

#[test]
fn incompatible_alpha_is_reported_before_network_mismatch() {
    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);
    create_wallet_db_for_network(
        config.wallet_db_path(),
        Network::Consensus(consensus::Network::MainNetwork),
        &["0.1.0-alpha.2"],
    );

    let err = open_database(&config).expect_err("incompatible alpha database must be rejected");
    assert!(
        err.to_string().contains("fresh Zallet wallet"),
        "unexpected error: {err}",
    );
}

#[test]
fn db_connection_forwards_ironwood_reads_and_tree_ops() {
    // DbConnection wraps WalletDb and must forward the Ironwood WalletRead /
    // WalletCommitmentTrees methods to it rather than fall back to the trait's no-op
    // defaults. On a freshly migrated wallet with no notes:
    //   * get_ironwood_nullifiers (required on the scan path) returns an empty set,
    //   * put_ironwood_subtree_roots accepts an empty batch, and
    //   * with_ironwood_tree_mut reaches WalletDb's real Ironwood tree (Some), proving it
    //     is not the WalletCommitmentTrees default (which returns None).
    crate::i18n::load_languages(&[]);

    let datadir = tempdir().unwrap();
    let config = test_config(datadir.path(), NetworkType::Test);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let db = database::Database::open(&config).await.unwrap();
            let mut handle = db.handle().await.unwrap();

            let nullifiers = handle.get_ironwood_nullifiers(NullifierQuery::All).unwrap();
            assert!(
                nullifiers.is_empty(),
                "a fresh wallet has no Ironwood nullifiers, got {nullifiers:?}",
            );

            handle
                .put_ironwood_subtree_roots(0, &[])
                .expect("an empty Ironwood subtree-root batch should be accepted");

            let reached_real_tree =
                handle
                    .with_ironwood_tree_mut(|_tree| {
                        Ok::<
                            (),
                            ShardTreeError<
                                <database::DbConnection as WalletCommitmentTrees>::Error,
                            >,
                        >(())
                    })
                    .expect("with_ironwood_tree_mut should succeed on a migrated wallet");
            assert!(
                reached_real_tree.is_some(),
                "with_ironwood_tree_mut must reach WalletDb's Ironwood tree, not the no-op default",
            );
        });
}

fn test_config(datadir: &std::path::Path, network_type: NetworkType) -> ZalletConfig {
    ZalletConfig {
        datadir: Some(datadir.to_path_buf()),
        consensus: crate::config::ConsensusSection {
            network: network_type,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn open_database(config: &ZalletConfig) -> Result<(), crate::error::Error> {
    crate::i18n::load_languages(&[]);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let database = database::Database::open(config).await?;
            drop(database);
            Ok(())
        })
}

fn create_wallet_db(path: impl AsRef<std::path::Path>, versions: &[&str]) {
    create_wallet_db_for_network(
        path,
        Network::Consensus(consensus::Network::TestNetwork),
        versions,
    );
}

fn create_wallet_db_for_network(
    path: impl AsRef<std::path::Path>,
    network: Network,
    versions: &[&str],
) {
    let mut conn = Connection::open(path).unwrap();
    let mut db_data = WalletDb::from_connection(&mut conn, network, SystemClock, OsRng);

    WalletMigrator::new()
        .with_external_migrations(database::all_external_migrations(
            db_data.params().network_type(),
        ))
        .init_or_migrate(&mut db_data)
        .unwrap();

    for version in versions {
        conn.execute(
            "INSERT INTO ext_zallet_db_version_metadata
             VALUES (:version, NULL, NULL, :migrated)",
            named_params! {
                ":version": version,
                ":migrated": "2026-01-01 00:00:00Z",
            },
        )
        .unwrap();
    }
}

fn latest_recorded_version(conn: &Connection) -> Option<String> {
    conn.query_row(
        "SELECT version
         FROM ext_zallet_db_version_metadata
         ORDER BY rowid DESC
         LIMIT 1",
        [],
        |row| row.get("version"),
    )
    .optional()
    .unwrap()
}

fn count_recorded_versions(conn: &Connection, version: &str) -> usize {
    conn.query_row(
        "SELECT COUNT(*)
         FROM ext_zallet_db_version_metadata
         WHERE version = :version",
        named_params! {
            ":version": version,
        },
        |row| row.get::<_, usize>(0),
    )
    .unwrap()
}
