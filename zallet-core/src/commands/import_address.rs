use std::collections::HashSet;

use abscissa_core::Runnable;
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::{Account as _, WalletRead, WalletWrite};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::encoding::AddressCodec as _;

use crate::{
    cli::ImportAddressCmd,
    commands::AsyncRunnable,
    components::{
        chain::{Chain, ChainFactory, ChainView},
        database::Database,
        json_rpc::{
            methods::z_import_address::{ParseImportError, ParsedImport, ResultType, parse_import},
            payments::{LegacyPoolError, legacy_pool_account},
        },
    },
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

impl ImportAddressCmd {
    /// Runs the address import against the chain backend produced by `factory`.
    #[expect(
        clippy::await_holding_invalid_type,
        reason = "one-shot CLI command: the only task on an otherwise idle pool, so a \
                  nested acquisition cannot exhaust it (see `Database::handle`)"
    )]
    pub(crate) async fn run_with<F: ChainFactory>(&self, factory: &F) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let db = Database::open(&config).await?;
        let mut wallet = db.handle().await?;

        let account_id = match self.account {
            Some(uuid) => {
                let account_id = AccountUuid::from_uuid(uuid);
                wallet
                    .get_account(account_id)
                    .map_err(|e| ErrorKind::Generic.context(e))?
                    .ok_or_else(|| ErrorKind::Generic.context(fl!("err-account-not-found")))?;
                account_id
            }
            None => legacy_pool_account(&wallet)
                .map_err(|e| {
                    ErrorKind::Generic.context(match e {
                        LegacyPoolError::Disabled => fl!("err-import-address-legacy-disabled"),
                        LegacyPoolError::NotFound(seed_fp) => fl!(
                            "err-import-address-legacy-not-found",
                            seed_fp = seed_fp.to_string(),
                        ),
                        LegacyPoolError::Db(msg) => msg,
                    })
                })?
                .id(),
        };

        // A bare transparent address is imported as watch-only without key material; hex
        // data is classified as a public key or redeem script, as in `z_importaddress`.
        enum ImportData {
            Address(TransparentAddress),
            KeyMaterial(ParsedImport),
        }
        let parsed = match TransparentAddress::decode(wallet.params(), &self.data) {
            Ok(addr) => ImportData::Address(addr),
            Err(_) => {
                ImportData::KeyMaterial(parse_import(wallet.params(), &self.data).map_err(|e| {
                    ErrorKind::Generic.context(match e {
                        ParseImportError::InvalidHex => fl!("err-import-address-unrecognized"),
                        ParseImportError::NotKeyOrScript => {
                            fl!("err-import-address-not-key-or-script")
                        }
                    })
                })?)
            }
        };

        // Connect to the chain before modifying the wallet, so that an unreachable
        // chain backend fails the command without a partial effect.
        let chain = if self.no_rescan {
            None
        } else {
            Some(factory.build(&config).await?)
        };

        let result = match parsed {
            ImportData::Address(addr) => {
                wallet
                    .import_standalone_transparent_address(account_id, addr)
                    .map_err(|e| ErrorKind::Generic.context(e))?;
                ResultType {
                    kind: match addr {
                        TransparentAddress::PublicKeyHash(_) => "p2pkh",
                        TransparentAddress::ScriptHash(_) => "p2sh",
                    },
                    address: addr.encode(wallet.params()),
                }
            }
            ImportData::KeyMaterial(ParsedImport::P2pkh { pubkey, result }) => {
                wallet
                    .import_standalone_transparent_pubkey(account_id, pubkey)
                    .map_err(|e| ErrorKind::Generic.context(e))?;
                result
            }
            ImportData::KeyMaterial(ParsedImport::P2sh { script, result }) => {
                wallet
                    .import_standalone_transparent_script(account_id, script)
                    .map_err(|e| ErrorKind::Generic.context(e))?;
                result
            }
        };
        info!(
            "Imported watch-only {} address {}",
            result.kind, result.address,
        );

        if let Some((chain, _chain_indexer_task_handle)) = chain {
            // Rewind the scan queue to the block before the account's birthday, so
            // that the next `zallet start` re-scans the already-synced range with
            // the newly imported address tracked. This mirrors `z_importaddress`;
            // see its rationale for why no account birthday is reset.
            let birthday = wallet
                .get_account_birthday(account_id)
                .map_err(|e| ErrorKind::Generic.context(e))?;
            let chain_view = chain
                .snapshot()
                .await
                .map_err(|e| ErrorKind::Chain.context(e))?;
            let prior_chain_state = chain_view
                .tree_state_as_of(birthday - 1)
                .await
                .map_err(|e| ErrorKind::Chain.context(e))?
                .ok_or_else(|| {
                    ErrorKind::Chain.context(fl!("err-import-address-no-chain-state"))
                })?;
            wallet
                .rewind_to_chain_state(prior_chain_state, HashSet::new())
                .map_err(|e| ErrorKind::Generic.context(e))?;
            info!("Rescan queued from height {birthday}");
        }

        println!("{}", result.address);

        Ok(())
    }
}

impl AsyncRunnable for ImportAddressCmd {
    async fn run(&self) -> Result<(), Error> {
        crate::application::chain_runtime()
            .run_import_address(self)
            .await
    }
}

impl Runnable for ImportAddressCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
