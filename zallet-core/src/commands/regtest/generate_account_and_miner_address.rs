use abscissa_core::Runnable;
use transparent::keys::IncomingViewingKey;
use zcash_client_backend::data_api::{AccountBirthday, WalletRead, WalletWrite, chain::ChainState};
use zcash_keys::encoding::AddressCodec;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    cli::GenerateAccountAndMinerAddressCmd,
    commands::AsyncRunnable,
    components::{database::Database, keystore::KeyStore},
    error::{Error, ErrorKind},
    network::Network,
    prelude::*,
};

impl AsyncRunnable for GenerateAccountAndMinerAddressCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let params = config.consensus.network();
        if !matches!(params, Network::RegTest(_)) {
            return Err(ErrorKind::Init
                .context("Command only works on a regtest wallet")
                .into());
        }

        let db = Database::open(&config).await?;
        let keystore = KeyStore::new(&config, db.clone())?;
        let mut wallet = db.handle().await?;

        match wallet.chain_height() {
            Ok(None) => Ok(()),
            Ok(Some(_)) | Err(_) => {
                Err(ErrorKind::Init.context("Command only works on a fresh wallet"))
            }
        }?;

        let seed_fps = keystore.list_seed_fingerprints().await?;
        let mut seed_fps = seed_fps.into_iter();
        match (seed_fps.next(), seed_fps.next()) {
            (None, _) => Err(ErrorKind::Init
                .context("Need to call generate-mnemonic or import-mnemonic first")
                .into()),
            (_, Some(_)) => Err(ErrorKind::Init
                .context("This regtest API is not supported with multiple seeds")
                .into()),
            (Some(seed_fp), None) => {
                let seed = keystore.decrypt_seed(&seed_fp).await?;

                // We should use the regtest block hash here, but we also know that the
                // `zcash_client_sqlite` implementation of `WalletWrite::create_account`
                // does not use the prior chain state's block hash anywhere, so we can
                // get away with faking it.
                let birthday = AccountBirthday::from_parts(
                    ChainState::empty(BlockHeight::from_u32(0), BlockHash([0; 32])),
                    None,
                );

                let (_, usk) = wallet
                    .create_account("Default account", &seed, &birthday, None)
                    .map_err(|e| {
                        ErrorKind::Generic.context(format!("Failed to generate miner address: {e}"))
                    })?;

                let (addr, _) = usk
                    .transparent()
                    .to_account_pubkey()
                    .derive_internal_ivk()
                    .map_err(|e| {
                        ErrorKind::Generic.context(format!("Failed to generate miner address: {e}"))
                    })?
                    .default_address();

                print!("{}", addr.encode(&params));

                Ok(())
            }
        }
    }
}

impl Runnable for GenerateAccountAndMinerAddressCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
