use abscissa_core::Runnable;
use tokio::io::{self, AsyncWriteExt};
use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_sqlite::AccountUuid;

use crate::{
    cli::ExportMnemonicCmd,
    commands::{AsyncRunnable, seed_selection::resolve_seed_fingerprint},
    components::{database::Database, keystore::KeyStore},
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

impl AsyncRunnable for ExportMnemonicCmd {
    #[expect(
        clippy::await_holding_invalid_type,
        reason = "one-shot CLI command: the only task on an otherwise idle pool, so a \
                  nested acquisition cannot exhaust it (see `Database::handle`)"
    )]
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let db = Database::open(&config).await?;
        let wallet = db.handle().await?;
        let keystore = KeyStore::new(&config, db)?;

        let seed_fp = match self.account_uuid {
            Some(account_uuid) => {
                let account = wallet
                    .get_account(AccountUuid::from_uuid(account_uuid))
                    .map_err(|e| ErrorKind::Generic.context(e))?
                    .ok_or_else(|| ErrorKind::Generic.context(fl!("err-account-not-found")))?;

                let derivation = account.source().key_derivation().ok_or_else(|| {
                    ErrorKind::Generic.context(fl!("err-account-no-payment-source"))
                })?;

                *derivation.seed_fingerprint()
            }
            // A phrase with no accounts derived from it yet cannot be named by account
            // UUID, which is the state every phrase starts in.
            None => resolve_seed_fingerprint(&keystore, self.seedfp.as_deref()).await?,
        };

        // Exporting decrypts the stored phrase in order to check that the fingerprint actually
        // matches the one used for lookup.
        //
        // Deliberately after the seed has been resolved, so that naming a seed the wallet
        // does not hold fails without asking for a passphrase first.
        keystore.unlock_on_terminal().await?;

        let encrypted_mnemonic = keystore.export_mnemonic(&seed_fp, self.armor).await?;

        let mut stdout = io::stdout();
        stdout
            .write_all(&encrypted_mnemonic)
            .await
            .map_err(|e| ErrorKind::Generic.context(e))?;
        stdout
            .flush()
            .await
            .map_err(|e| ErrorKind::Generic.context(e))?;

        eprintln!();
        eprintln!("WARNING: the output above is NOT your mnemonic in plain text. It is encrypted");
        eprintln!("to the wallet's age identity, and decrypting it requires that identity file");
        eprintln!("(and its passphrase, if it is passphrase-encrypted).");
        eprintln!();
        eprintln!("This mnemonic may also not be a complete backup of your wallet. It backs up");
        eprintln!("only funds derived from this seed; this wallet may also hold spending keys");
        eprintln!("that no mnemonic covers (Sapling keys imported with z_importkey, and other");
        eprintln!("standalone key material), which are NOT included here. To back those up you");
        eprintln!("must ALSO keep a secure copy of BOTH:");
        eprintln!("  - your Zallet wallet database (wallet.db in your datadir), and");
        eprintln!("  - the age encryption identity file (the file named by the");
        eprintln!("    keystore.encryption_identity config option); wallet.db needs it too.");
        eprintln!();
        eprintln!("If you lose the identity file, or forget its passphrase, neither this exported");
        eprintln!("mnemonic nor the spending keys in wallet.db can be decrypted, and those funds");
        eprintln!("are unrecoverable. (wallet.db itself is not encrypted: it holds your");
        eprintln!("transaction history and viewing keys in the clear, so store backups securely.)");
        eprintln!("There is currently no complete backup RPC or command.");

        Ok(())
    }
}

impl Runnable for ExportMnemonicCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
