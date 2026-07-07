use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_sqlite::wallet::init::{WalletMigrationError, migrations::V_0_15_0};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xadfd5ac7_927f_4288_9cca_55520c4b45d1);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        V_0_15_0.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Initializes the Zallet keystore database."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "CREATE TABLE ext_zallet_keystore_age_recipients (
                recipient STRING NOT NULL,
                added TEXT NOT NULL
            );
            CREATE TABLE ext_zallet_keystore_mnemonics (
                hd_seed_fingerprint BLOB NOT NULL UNIQUE,
                encrypted_mnemonic BLOB NOT NULL
            );
            CREATE TABLE ext_zallet_keystore_legacy_seeds (
                hd_seed_fingerprint BLOB NOT NULL UNIQUE,
                encrypted_legacy_seed BLOB NOT NULL
            );
            CREATE TABLE ext_zallet_keystore_standalone_sapling_keys (
                dfvk BLOB NOT NULL UNIQUE,
                encrypted_sapling_extsk BLOB NOT NULL
            );
            CREATE TABLE ext_zallet_keystore_standalone_transparent_keys (
                pubkey BLOB NOT NULL UNIQUE,
                encrypted_transparent_privkey BLOB NOT NULL
            );",
        )?;
        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}
