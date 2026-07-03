use abscissa_core::Runnable;

use crate::{
    cli::InitWalletEncryptionCmd,
    commands::AsyncRunnable,
    components::{database::Database, keystore::KeyStore},
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

impl AsyncRunnable for InitWalletEncryptionCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let db = Database::open(&config).await?;
        let keystore = KeyStore::new(&config, db)?;

        // TODO: The following logic does not support plugin recipients, which can only be
        //       derived from identities by the plugins themselves.
        //       https://github.com/zcash/zallet/issues/252

        // If we have encrypted identities, it means the operator configured Zallet with
        // an encrypted identity file; obtain the recipients from it.
        let identity_file = match keystore
            .decrypt_identity_file(age::cli_common::UiCallbacks)
            .await?
        {
            Some(identity_file) => Ok(identity_file),
            _ => {
                // Re-read the identity file from disk.
                age::IdentityFile::from_file(
                    config
                        .encryption_identity()
                        .to_str()
                        .ok_or_else(|| {
                            ErrorKind::Init.context(fl!(
                                "err-init-path-not-utf8",
                                path = config.encryption_identity().display().to_string(),
                            ))
                        })?
                        .to_string(),
                )
            }
        }
        .map_err(|e| ErrorKind::Generic.context(e))?;

        // Write out a recipients file, then parse it back into recipient strings.
        let mut recipients = vec![];
        identity_file
            .write_recipients_file(&mut recipients)
            .map_err(|e| ErrorKind::Generic.context(e))?;
        let recipient_strings = String::from_utf8(recipients)
            .map_err(|e| ErrorKind::Generic.context(e))?
            .lines()
            .map(String::from)
            .collect();

        // Store the recipients in the keystore.
        keystore.initialize_recipients(recipient_strings).await
    }
}

impl Runnable for InitWalletEncryptionCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
