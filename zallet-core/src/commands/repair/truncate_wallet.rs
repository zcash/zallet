use abscissa_core::Runnable;
use zcash_client_backend::data_api::WalletWrite;
use zcash_protocol::consensus::BlockHeight;

use crate::{
    cli::TruncateWalletCmd,
    commands::AsyncRunnable,
    components::database::Database,
    error::{Error, ErrorKind},
    prelude::*,
};

impl AsyncRunnable for TruncateWalletCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let db = Database::open(&config).await?;
        let mut wallet = db.handle().await?;

        let new_max_height = wallet
            .truncate_to_height(BlockHeight::from_u32(self.max_height))
            .map_err(|e| ErrorKind::Generic.context(e))?;
        info!("Wallet truncated to a maximum height of {new_max_height}");

        println!("{new_max_height}");

        Ok(())
    }
}

impl Runnable for TruncateWalletCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
