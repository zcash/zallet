use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_sqlite::wallet::init::WalletMigrationError;

use super::initial_setup;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xf22680bc_a601_466f_b0d2_9328fe7c7298);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [initial_setup::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Tracks whether each mnemonic phrase's backup has been confirmed."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        // Mnemonics that predate this migration default to unconfirmed. We cannot know
        // whether their operator ever recorded them, and the safe assumption is the one
        // that asks: `zallet confirm-backup` clears it.
        transaction.execute_batch(
            "ALTER TABLE ext_zallet_keystore_mnemonics
            ADD COLUMN backup_confirmed INTEGER NOT NULL DEFAULT FALSE",
        )?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        // Reverting discards which phrases had been confirmed. Nothing else records it,
        // so re-applying this migration starts everything unconfirmed again, and each
        // phrase needs `zallet confirm-backup` run against it a second time.
        transaction.execute_batch(
            "ALTER TABLE ext_zallet_keystore_mnemonics
            DROP COLUMN backup_confirmed",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use schemerz_rusqlite::RusqliteMigration;

    use super::Migration;

    /// The table as this migration finds it.
    const TABLE_BEFORE: &str = "CREATE TABLE ext_zallet_keystore_mnemonics (
        hd_seed_fingerprint BLOB NOT NULL UNIQUE,
        encrypted_mnemonic BLOB NOT NULL
    )";

    fn columns(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM pragma_table_info('ext_zallet_keystore_mnemonics')")
            .unwrap();
        let names = stmt.query_map([], |row| row.get(0)).unwrap();
        names.collect::<Result<_, _>>().unwrap()
    }

    fn stored_fingerprints(conn: &Connection) -> Vec<Vec<u8>> {
        let mut stmt = conn
            .prepare("SELECT hd_seed_fingerprint FROM ext_zallet_keystore_mnemonics")
            .unwrap();
        let rows = stmt.query_map([], |row| row.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    }

    /// `DROP COLUMN` needs SQLite 3.35, so the revert is worth exercising rather than
    /// assuming: a version without it would fail only when someone reverted.
    #[test]
    fn the_column_is_added_and_removed_again() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(TABLE_BEFORE).unwrap();
        conn.execute(
            "INSERT INTO ext_zallet_keystore_mnemonics VALUES (:fp, :mnemonic)",
            rusqlite::named_params! {":fp": vec![7u8; 32], ":mnemonic": vec![1u8, 2, 3]},
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        Migration.up(&tx).unwrap();
        tx.commit().unwrap();
        assert!(columns(&conn).iter().any(|c| c == "backup_confirmed"));

        let tx = conn.transaction().unwrap();
        Migration.down(&tx).unwrap();
        tx.commit().unwrap();
        assert!(!columns(&conn).iter().any(|c| c == "backup_confirmed"));

        // Reverting discards the confirmations, but must not disturb the phrases they
        // were recorded against.
        assert_eq!(stored_fingerprints(&conn), vec![vec![7u8; 32]]);
    }
}
