use abscissa_core::Runnable;
use bip0039::{Count, English, Mnemonic};
use rand::{RngCore, rngs::OsRng};

use crate::{
    cli::GenerateMnemonicCmd,
    commands::AsyncRunnable,
    components::{database::Database, keystore::KeyStore},
    error::Error,
    fl,
    prelude::*,
};

impl AsyncRunnable for GenerateMnemonicCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let db = Database::open(&config).await?;
        let keystore = KeyStore::new(&config, db)?;

        // Adapted from `Mnemonic::generate` so we can use `OsRng` directly.
        const BITS_PER_BYTE: usize = 8;
        const MAX_ENTROPY_BITS: usize = Count::Words24.entropy_bits();
        const ENTROPY_BYTES: usize = MAX_ENTROPY_BITS / BITS_PER_BYTE;

        let mut entropy = [0u8; ENTROPY_BYTES];
        OsRng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::<English>::from_entropy(entropy)
            .expect("valid entropy length won't fail to generate the mnemonic");

        let seedfp = keystore.encrypt_and_store_mnemonic(mnemonic).await?;

        println!(
            "{}",
            fl!("cmd-seed-fingerprint", seedfp = seedfp.to_string())
        );

        Ok(())
    }
}

impl Runnable for GenerateMnemonicCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
