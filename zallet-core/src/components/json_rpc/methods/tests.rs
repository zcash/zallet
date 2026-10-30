//! Saturated-pool regression tests for zcash/zallet#708.
//!
//! Wallet sync retains pooled database connections for the life of the process, so a
//! wallet RPC must never hold one pooled connection while acquiring another (directly,
//! or via a keystore method that takes its own; see `Database::handle`). These tests run
//! the affected methods against a pool of exactly one connection, where any
//! hold-while-acquire regression deadlocks immediately rather than only under production
//! load, and is reported as a test failure after a bounded wait rather than hanging CI.
//!
//! Methods whose keystore-and-database interleaving cannot be reached without a chain
//! and funds (`z_sendmany`, `z_shieldcoinbase`, the `pczt_*` flow, `z_viewtransaction`'s
//! legacy-OVK collection) follow the same staged-acquisition pattern but are exercised
//! end to end in zcash/integration-tests, not here.

use std::future::Future;
use std::num::NonZeroUsize;
use std::time::Duration;

use jsonrpsee::core::JsonValue;
use tempfile::TempDir;
use zcash_client_backend::data_api::{AccountBirthday, WalletRead, WalletWrite, chain::ChainState};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::encoding::{AddressCodec, encode_extended_spending_key, encode_payment_address};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, NetworkConstants, NetworkUpgrade, Parameters};

use super::{
    get_address_for_account, get_new_account, import_key, recover_accounts, sign_message,
    z_export_viewing_key, z_get_balance_for_account,
};
use crate::components::{
    chain::MockChain,
    database::Database,
    json_rpc::server::LegacyCode,
    keystore::{
        BackupStatus, KeyStore,
        testing::{keystore_and_database_with_config, phrase, run_async},
    },
    sync::WalletSync,
};

/// A connection pool of exactly one connection: the smallest pool on which a correctly
/// staged method can make progress at all, and the one on which holding a connection
/// while acquiring another deadlocks immediately.
const SINGLE_CONNECTION: NonZeroUsize = NonZeroUsize::MIN;

/// The chain height to record in the test wallet, standing in for the sync engine's
/// `update_chain_tip`: the network's Sapling activation height, below which
/// `update_chain_tip` records nothing at all for `chain_height` to report.
fn recorded_tip(params: &crate::network::Network) -> BlockHeight {
    params
        .activation_height(NetworkUpgrade::Sapling)
        .expect("Sapling activates on the test network")
}

/// Upper bound for a call against the single-connection pool to complete.
///
/// A staged-acquisition regression deadlocks forever (the pool's `get` has no wait
/// timeout), so any finite bound separates a deadlock from a slow test machine; this is
/// far above the cost of the handful of local SQLite statements each call performs.
const SATURATED_CALL_DEADLINE: Duration = Duration::from_secs(60);

/// Runs `fut` against the saturated pool, failing the test (rather than hanging it) if
/// the method deadlocks on a nested connection acquisition.
async fn completes<T>(fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(SATURATED_CALL_DEADLINE, fut)
        .await
        .expect("deadlocked: a pooled connection was held across another acquisition")
}

/// An [`AccountBirthday`] at genesis: the note commitment trees are empty before block
/// 0, and the conventional hash of genesis's nonexistent parent is all-zeros (see
/// `fetch_account_birthday`).
fn genesis_birthday() -> AccountBirthday {
    AccountBirthday::from_parts(
        ChainState::empty(BlockHeight::from_u32(0), BlockHash([0; 32])),
        None,
    )
}

/// Builds a wallet on a single-connection pool, holding one account derived from a
/// backed-up mnemonic.
async fn wallet_with_account(datadir: &TempDir) -> (KeyStore, Database, AccountUuid) {
    let (keystore, db) =
        keystore_and_database_with_config(datadir, Some(SINGLE_CONNECTION), |_| {}).await;

    let seed_fp = keystore
        .encrypt_and_store_mnemonic(phrase([7; 32]), BackupStatus::Confirmed)
        .await
        .expect("stores the mnemonic");
    let seed = keystore
        .decrypt_seed(&seed_fp)
        .await
        .expect("the identity file is unencrypted, so the keystore is never locked");

    let (account_id, _usk) = db
        .handle()
        .await
        .expect("acquires the pool's only connection")
        .as_mut()
        .create_account("test", &seed, &genesis_birthday(), None)
        .expect("creates the account");

    // Record a chain height, as the sync engine would: address derivation refuses to
    // run while the chain height is unknown.
    db.handle()
        .await
        .expect("acquires the pool's only connection")
        .as_mut()
        .update_chain_tip(recorded_tip(db.params()))
        .expect("records the chain tip");

    (keystore, db, account_id)
}

/// The bootstrapping case from zcash/zallet#708: on a fresh wallet, `z_getnewaccount` is
/// the very call that would let sync progress, so it must complete even when no pooled
/// connection is ever free while one is held. It reads the chain height, selects and
/// decrypts the seed via the keystore, and creates the account: three acquisitions that
/// all come from a pool of size one here.
#[test]
fn z_getnewaccount_completes_on_a_fresh_wallet_with_a_saturated_pool() {
    let datadir = tempfile::tempdir().unwrap();

    run_async(|| async {
        let (keystore, db) =
            keystore_and_database_with_config(&datadir, Some(SINGLE_CONNECTION), |_| {}).await;
        keystore
            .encrypt_and_store_mnemonic(phrase([1; 32]), BackupStatus::Confirmed)
            .await
            .expect("stores the mnemonic");

        // Record a chain height, as the sync engine would have; `z_getnewaccount`
        // refuses to pick a birthday without one.
        db.handle()
            .await
            .expect("acquires the pool's only connection")
            .as_mut()
            .update_chain_tip(recorded_tip(db.params()))
            .expect("records the chain tip");

        // A chain view whose tip is at genesis: the birthday is clamped to the view's
        // tip, and a genesis birthday needs no treestate (which `MockChainView` does
        // not serve).
        let chain = MockChain::reporting(Vec::new(), 0);
        let (decryptor, _engine) = WalletSync::build_decryptor();

        completes(get_new_account::call(
            &db, &keystore, chain, &decryptor, "default", None,
        ))
        .await
        .expect("creates the account");

        // The account exists in the wallet: exactly one, the one just created.
        let account_ids = db
            .handle()
            .await
            .expect("acquires the pool's only connection")
            .as_ref()
            .get_account_ids()
            .expect("lists accounts");
        assert_eq!(account_ids.len(), 1);
    });
}

/// `z_getaddressforaccount` with a ZIP 32 account index resolves the account through
/// both the keystore (legacy-seed fingerprints) and the wallet database, checks the
/// backup gate through the keystore again, and then derives through the database: the
/// full interleaving that previously held one connection across the keystore accesses.
#[test]
fn z_getaddressforaccount_completes_on_a_saturated_pool() {
    let datadir = tempfile::tempdir().unwrap();

    run_async(|| async {
        let (keystore, db, _account_id) = wallet_with_account(&datadir).await;

        completes(get_address_for_account::call(
            &db,
            keystore,
            JsonValue::Number(0u32.into()),
            None,
            None,
        ))
        .await
        .expect("derives an address for the account");
    });
}

/// `signmessage` looks the address's account up in the wallet database and then
/// decrypts the seed via the keystore; with one pooled connection those must not
/// overlap.
#[test]
fn signmessage_completes_on_a_saturated_pool() {
    let datadir = tempfile::tempdir().unwrap();

    run_async(|| async {
        let (keystore, db, account_id) = wallet_with_account(&datadir).await;

        let address = db
            .handle()
            .await
            .expect("acquires the pool's only connection")
            .as_ref()
            .get_transparent_receivers(account_id, true, true)
            .expect("lists the account's transparent receivers")
            .into_keys()
            .next()
            .expect("the account's default unified address has a transparent receiver")
            .encode(db.params());

        completes(sign_message::call(&db, &keystore, &address, "zallet#708"))
            .await
            .expect("signs with the address's key");
    });
}

/// `z_exportviewingkey` for a bare Sapling address reads the account through the wallet
/// database, decrypts the seed via the keystore, and re-derives the key; with one
/// pooled connection those must not overlap.
#[test]
fn z_exportviewingkey_completes_on_a_saturated_pool() {
    let datadir = tempfile::tempdir().unwrap();

    run_async(|| async {
        let (keystore, db, account_id) = wallet_with_account(&datadir).await;

        let sapling_addr = db
            .handle()
            .await
            .expect("acquires the pool's only connection")
            .as_ref()
            .get_unified_full_viewing_keys()
            .expect("lists the wallet's UFVKs")
            .remove(&account_id)
            .expect("the account has a UFVK")
            .sapling()
            .expect("the account's UFVK has a Sapling component")
            .default_address()
            .1;
        let zaddr =
            encode_payment_address(db.params().hrp_sapling_payment_address(), &sapling_addr);

        completes(z_export_viewing_key::call(
            &db,
            &keystore,
            &zaddr,
            Some(false),
        ))
        .await
        .expect("exports the viewing key");
    });
}

/// `z_getbalanceforaccount` with a ZIP 32 account index resolves the account through
/// the keystore and the wallet database before reading the summary; completing (here
/// with the in-warmup refusal, since nothing has been synced) is the regression
/// property.
#[test]
fn z_getbalanceforaccount_completes_on_a_saturated_pool() {
    let datadir = tempfile::tempdir().unwrap();

    run_async(|| async {
        let (keystore, db, _account_id) = wallet_with_account(&datadir).await;

        let result = completes(z_get_balance_for_account::call(
            &db,
            &keystore,
            JsonValue::Number(0u32.into()),
            None,
        ))
        .await;

        // Whether the unsynced wallet yields a summary is `zcash_client_sqlite`'s
        // decision, not this method's; the account must at least have resolved, so
        // anything but success or the in-warmup refusal (asserted by code, so a
        // reworded or localised message cannot widen this into accepting any error)
        // would be a regression in the staging.
        if let Err(e) = result {
            assert_equal_warmup_code(&e);
        }
    });
}

/// Asserts that an error is the in-warmup refusal, `zcashd`'s `RPC_IN_WARMUP`.
fn assert_equal_warmup_code(e: &jsonrpsee::types::ErrorObjectOwned) {
    assert_eq!(
        e.code(),
        LegacyCode::InWarmup as i32,
        "expected the in-warmup refusal, got: {e}",
    );
}

/// `z_recoveraccounts` reads the wallet's chain height, decrypts the named seed via the
/// keystore, and imports the accounts; with one pooled connection those must not
/// overlap.
#[test]
fn z_recoveraccounts_completes_on_a_saturated_pool() {
    let datadir = tempfile::tempdir().unwrap();

    run_async(|| async {
        let (keystore, db) =
            keystore_and_database_with_config(&datadir, Some(SINGLE_CONNECTION), |_| {}).await;
        let seed_fp = keystore
            .encrypt_and_store_mnemonic(phrase([3; 32]), BackupStatus::Confirmed)
            .await
            .expect("stores the mnemonic");

        // Record a chain height, as the sync engine would; `z_recoveraccounts` refuses
        // to pick a recovery window without one.
        db.handle()
            .await
            .expect("acquires the pool's only connection")
            .as_mut()
            .update_chain_tip(recorded_tip(db.params()))
            .expect("records the chain tip");

        // A birthday at genesis needs no treestate (which `MockChainView` does not
        // serve). The parameters go through serde because `AccountParameter`'s fields
        // are private to its module, exactly as they arrive over the RPC interface.
        let params_json = format!(
            r#"[{{"name": "recovered", "seedfp": "{seed_fp}", "zip32_account_index": 0, "birthday_height": 0}}]"#,
        );
        let accounts: Vec<recover_accounts::AccountParameter<'_>> =
            serde_json::from_str(&params_json).expect("well-formed account parameters");

        let chain = MockChain::reporting(Vec::new(), 0);
        let (decryptor, _engine) = WalletSync::build_decryptor();

        completes(recover_accounts::call(
            &db, &keystore, chain, &decryptor, accounts,
        ))
        .await
        .expect("recovers the account");

        // The account exists in the wallet: exactly one, the one just recovered.
        let account_ids = db
            .handle()
            .await
            .expect("acquires the pool's only connection")
            .as_ref()
            .get_account_ids()
            .expect("lists accounts");
        assert_eq!(account_ids.len(), 1);
    });
}

/// `z_importkey` interleaves wallet reads with keystore encryption of the imported key;
/// with one pooled connection those must not overlap.
#[test]
fn z_importkey_completes_on_a_saturated_pool() {
    let datadir = tempfile::tempdir().unwrap();

    run_async(|| async {
        let (keystore, db) =
            keystore_and_database_with_config(&datadir, Some(SINGLE_CONNECTION), |_| {}).await;

        // Record a chain height, as the sync engine would; `z_importkey` validates the
        // rescan start height against it.
        db.handle()
            .await
            .expect("acquires the pool's only connection")
            .as_mut()
            .update_chain_tip(recorded_tip(db.params()))
            .expect("records the chain tip");

        // A standalone Sapling spending key for the wallet's network, derived rather
        // than hardcoded so it tracks the canonical encoding. Rescanning from the
        // default start height (genesis) keeps the birthday off the treestate path
        // (which `MockChainView` does not serve).
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&[9; 32]);
        let encoded =
            encode_extended_spending_key(db.params().hrp_sapling_extended_spending_key(), &extsk);

        let chain = MockChain::reporting(Vec::new(), 0);
        let (decryptor, _engine) = WalletSync::build_decryptor();

        completes(import_key::call(
            &db,
            &keystore,
            chain,
            &decryptor,
            &encoded,
            Some("yes"),
            None,
        ))
        .await
        .expect("imports the key");

        // The imported key's account exists in the wallet: exactly one.
        let account_ids = db
            .handle()
            .await
            .expect("acquires the pool's only connection")
            .as_ref()
            .get_account_ids()
            .expect("lists accounts");
        assert_eq!(account_ids.len(), 1);
    });
}
