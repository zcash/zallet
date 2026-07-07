use schemerz_rusqlite::RusqliteMigration;

use zcash_client_sqlite::wallet::init::WalletMigrationError;
use zcash_protocol::consensus::NetworkType;

mod initial_setup;

pub(in crate::components) fn all(
    network_type: NetworkType,
) -> impl Iterator<Item = Box<dyn RusqliteMigration<Error = WalletMigrationError>>> {
    [
        // initial_setup
        Box::new(initial_setup::Migration { network_type }) as _,
    ]
    .into_iter()
}
