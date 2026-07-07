use schemerz_rusqlite::RusqliteMigration;
use zcash_client_sqlite::wallet::init::WalletMigrationError;

mod initial_setup;

pub(in crate::components) fn all()
-> impl Iterator<Item = Box<dyn RusqliteMigration<Error = WalletMigrationError>>> {
    [
        // initial_setup
        Box::new(initial_setup::Migration {}) as _,
    ]
    .into_iter()
}
