use abscissa_core::Runnable;
use tokio::io::{self, AsyncWriteExt};
use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::AccountUuid;

use crate::{
    cli::ExportMnemonicCmd,
    commands::AsyncRunnable,
    components::{database::Database, keystore::KeyStore},
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

impl AsyncRunnable for ExportMnemonicCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let db = Database::open(&config).await?;
        let wallet = db.handle().await?;
        let keystore = KeyStore::new(&config, db)?;

        let account = wallet
            .get_account(AccountUuid::from_uuid(self.account_uuid))
            .map_err(|e| ErrorKind::Generic.context(e))?
            .ok_or_else(|| ErrorKind::Generic.context(fl!("err-account-not-found")))?;

        let derivation = account
            .source()
            .key_derivation()
            .ok_or_else(|| ErrorKind::Generic.context(fl!("err-account-no-payment-source")))?;

        let encrypted_mnemonic = keystore
            .export_mnemonic(derivation.seed_fingerprint(), self.armor)
            .await?;

        let mut stdout = io::stdout();
        stdout
            .write_all(&encrypted_mnemonic)
            .await
            .map_err(|e| ErrorKind::Generic.context(e))?;
        stdout
            .flush()
            .await
            .map_err(|e| ErrorKind::Generic.context(e))?;

        Ok(())
    }
}

impl Runnable for ExportMnemonicCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
