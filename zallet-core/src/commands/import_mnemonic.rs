use abscissa_core::Runnable;
use bip0039::{English, Mnemonic};
use secrecy::{ExposeSecret, SecretString};

use crate::{
    cli::ImportMnemonicCmd,
    commands::AsyncRunnable,
    components::{database::Database, keystore::KeyStore},
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

impl AsyncRunnable for ImportMnemonicCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let db = Database::open(&config).await?;
        let keystore = KeyStore::new(&config, db)?;

        let phrase = SecretString::new(
            rpassword::prompt_password(fl!("cmd-import-mnemonic-prompt"))
                .map_err(|e| ErrorKind::Generic.context(e))?,
        );

        let mnemonic = Mnemonic::<English>::from_phrase(phrase.expose_secret())
            .map_err(|e| ErrorKind::Generic.context(e))?;

        let seedfp = keystore.encrypt_and_store_mnemonic(mnemonic).await?;

        println!(
            "{}",
            fl!("cmd-seed-fingerprint", seedfp = seedfp.to_string())
        );

        Ok(())
    }
}

impl Runnable for ImportMnemonicCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
