use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::path::PathBuf;

use abscissa_core::Runnable;

use bip0039::{Count, English, Mnemonic};
use rand::{RngCore, rngs::OsRng};
use secp256k1::{
    PublicKey,
    constants::{PUBLIC_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE},
};
use secrecy::{SecretVec, Zeroize};
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::{
    Account as _, AccountSource, WalletRead, WalletWrite as _, chain::ChainState,
};
use zcash_client_backend::wallet::{
    Exposure, TransparentAddressMetadata, TransparentAddressSource,
};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::zewif::{
    AccountSkipReason, DiscardSecrets, SecretSink, SkippedAccount, SkippedTransparentKey,
    TransparentKeySkipReason, ZewifImportError, ZewifImportReport,
};
use zcash_keys::encoding::AddressCodec;
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};
use zewif_zcashd::{
    BDBDump, EncryptedKeyPolicy, ParseOptions, ZcashdDump, ZcashdParser, ZcashdWallet,
};
use zip32::fingerprint::SeedFingerprint;

use crate::{
    cli::MigrateZcashdWalletCmd,
    components::{
        chain::{Chain, ChainError, ChainFactory, ChainView},
        database::{Database, DbHandle},
        keystore::{
            KeyStore,
            zewif::{KeyStoreSecretSink, SecretSinkError, decode_seed_fingerprint},
        },
    },
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

use super::{AsyncRunnable, migrate_zcash_conf};

/// The ZIP 32 account identifier of the zcashd account used for maintaining legacy
/// `getnewaddress` and `z_getnewaddress` semantics after the zcashd v4.7.0 upgrade to
/// support using mnemonic-sourced HD derivation for all addresses in the wallet.
pub const ZCASHD_LEGACY_ACCOUNT_INDEX: u32 = 0x7FFFFFFF;
/// The key-source string with which `zewif-zcashd` labels the synthesized legacy
/// account, and with which the previous migration implementation labeled accounts
/// containing imported key material.
pub const ZCASHD_LEGACY_SOURCE: &str = "zcashd_legacy";
/// The key-source string with which `zewif-zcashd` labels accounts derived from the
/// mnemonic HD seed used for key derivation after the zcashd v4.7.0 upgrade.
pub const ZCASHD_MNEMONIC_SOURCE: &str = "zcashd_mnemonic";

impl MigrateZcashdWalletCmd {
    /// Runs the zcashd-wallet migration against the chain backend produced by
    /// `factory`.
    pub(crate) async fn run_with<F: ChainFactory>(&self, factory: &F) -> Result<(), Error> {
        let config = APP.config();

        // Hold the data directory lock for the whole migration. This command writes
        // accounts, transparent key material and exposure information into the same
        // wallet database that `zallet start` uses, so running the two concurrently
        // would interleave writes into a wallet neither had exclusive use of.
        let _lock = config.lock_datadir()?;

        if !self.this_is_beta_code_and_you_will_need_to_redo_the_migration_later {
            return Err(ErrorKind::Generic.context(fl!("migrate-beta-code")).into());
        }

        // Start monitoring the chain (skip if --no-scan).
        let (chain, _chain_indexer_task_handle) = if self.no_scan {
            (None, None)
        } else {
            let (c, h) = factory.build(&config).await?;
            (Some(c), Some(h))
        };
        let db = Database::open(&config).await?;
        let keystore = KeyStore::new(&config, db.clone())?;

        info!("Dumping zcashd wallet");
        let wallet = self.dump_wallet(config.consensus.network)?;
        info!("Wallet dumped");

        Self::migrate_zcashd_wallet(
            db,
            keystore,
            chain,
            wallet,
            self.allow_multiple_wallet_imports,
            self.allow_partial_import,
        )
        .await?;

        Ok(())
    }
}

impl AsyncRunnable for MigrateZcashdWalletCmd {
    async fn run(&self) -> Result<(), Error> {
        crate::application::chain_runtime()
            .run_migrate_zcashd_wallet(self)
            .await
    }
}

impl MigrateZcashdWalletCmd {
    fn dump_wallet(&self, network_type: NetworkType) -> Result<ZcashdWallet, MigrateError> {
        let wallet_path = if self.path.is_relative() {
            if let Some(datadir) = self.zcashd_datadir.as_ref() {
                datadir.join(&self.path)
            } else {
                migrate_zcash_conf::zcashd_default_data_dir()
                    .ok_or(MigrateError::Wrapped(ErrorKind::Generic.into()))?
                    .join(&self.path)
            }
        } else {
            self.path.to_path_buf()
        };

        // Resolve the `db_dump` utility. An explicit `--zcashd-install-dir` uses that
        // installation's binary; otherwise prefer the BDB 6.2 `db_dump` vendored by
        // `zewif-zcashd` (via `BDBDump::from_file`), which falls back to one on the `PATH`.
        let db_dump_unavailable = || {
            MigrateError::Wrapped(
                ErrorKind::Generic
                    .context(fl!("err-migrate-wallet-db-dump-not-found"))
                    .into(),
            )
        };
        let db_dump = match &self.zcashd_install_dir {
            Some(path) => {
                let db_dump_path = path.join("zcutil").join("bin").join("db_dump");
                if !db_dump_path.is_file() {
                    return Err(db_dump_unavailable());
                }
                BDBDump::from_file_with_path(db_dump_path.as_path(), wallet_path.as_path())
            }
            None => {
                // `from_file` tries the vendored `db_dump` and then one on the `PATH`. If
                // it fails and there is no `db_dump` on the `PATH` either, report it as
                // unavailable rather than surfacing a raw execution error.
                let dumped = BDBDump::from_file(wallet_path.as_path());
                if dumped.is_err() && which::which("db_dump").is_err() {
                    return Err(db_dump_unavailable());
                }
                dumped
            }
        }
        .map_err(|e| MigrateError::Zewif {
            error_type: ZewifError::BdbDump,
            wallet_path: wallet_path.to_path_buf(),
            error: e.into(),
        })?;

        let zcashd_dump =
            ZcashdDump::from_bdb_dump(&db_dump, self.allow_warnings).map_err(|e| {
                MigrateError::Zewif {
                    error_type: ZewifError::ZcashdDump,
                    wallet_path: wallet_path.clone(),
                    error: e.into(),
                }
            })?;

        // A pre-Sapling wallet (zcashd < 5.0.0) has no `networkinfo` record;
        // the parser requires a fallback network to identify its chain. For
        // regtest, supply the wallet database's configured network. Mainnet
        // and testnet wallets carry `networkinfo` from zcashd 2.0.0 onwards,
        // so no fallback is needed for them, but supplying one is harmless
        // (the wallet's own `networkinfo` record is authoritative when present).
        let fallback_network = match network_type {
            NetworkType::Regtest => Some(zewif::Network::Regtest(zewif::RegtestParams::default())),
            NetworkType::Main | NetworkType::Test => None,
        };

        let base_options = ParseOptions::new().strict(!self.allow_warnings);
        let base_options = if let Some(net) = fallback_network.clone() {
            base_options.fallback_network(net)
        } else {
            base_options
        };

        let parse_result = match ZcashdParser::parse_dump_with_options(&zcashd_dump, base_options) {
            // The wallet's key material is encrypted; interactively request the wallet
            // passphrase and retry.
            Err(zewif_zcashd::Error::EncryptedWalletRequiresPassphrase) => {
                let mut attempts = 0;
                loop {
                    let passphrase =
                        rpassword::prompt_password(fl!("cmd-migrate-wallet-passphrase-prompt"))
                            .map_err(|e| ErrorKind::Generic.context(e))?;
                    attempts += 1;
                    let mut options = ParseOptions::new()
                        .strict(!self.allow_warnings)
                        .encrypted_key_policy(EncryptedKeyPolicy::Decrypt(SecretVec::new(
                            passphrase.into_bytes(),
                        )));
                    if let Some(net) = fallback_network.clone() {
                        options = options.fallback_network(net);
                    }
                    match ZcashdParser::parse_dump_with_options(&zcashd_dump, options) {
                        Err(zewif_zcashd::Error::WrongWalletPassphrase) if attempts < 3 => {
                            eprintln!("{}", fl!("cmd-migrate-wallet-passphrase-wrong"));
                        }
                        result => break result,
                    }
                }
            }
            result => result,
        };
        let (zcashd_wallet, _unparsed_keys) = parse_result.map_err(|e| MigrateError::Zewif {
            error_type: ZewifError::ZcashdDump,
            wallet_path,
            error: e.into(),
        })?;

        Ok(zcashd_wallet)
    }

    fn check_network(
        zewif_network: &zewif::Network,
        network_type: NetworkType,
    ) -> Result<(), MigrateError> {
        match (zewif_network, network_type) {
            (zewif::Network::Mainnet, NetworkType::Main) => Ok(()),
            (zewif::Network::Testnet, NetworkType::Test) => Ok(()),
            // The ZeWIF export derives the document's regtest activation schedule
            // from the wallet database's configured parameters (see
            // `derive_regtest_activations`), so the two agree by construction.
            (zewif::Network::Regtest(_), NetworkType::Regtest) => Ok(()),
            (wallet_network, db_network) => Err(MigrateError::NetworkMismatch {
                wallet_network: wallet_network.clone(),
                db_network,
            }),
        }
    }

    async fn migrate_zcashd_wallet<C: Chain>(
        db: Database,
        keystore: KeyStore,
        chain: Option<C>,
        wallet: ZcashdWallet,
        allow_multiple_wallet_imports: bool,
        allow_partial_import: bool,
    ) -> Result<(), MigrateError> {
        let mut db_data = db.handle().await?;
        let network_params = *db_data.params();
        Self::check_network(wallet.network(), network_params.network_type())?;

        // Obtain information about the current state of the chain, so that we can set
        // the recovery height properly.
        let (chain_view, chain_tip) = if let Some(chain) = &chain {
            let chain_view = chain.snapshot().await?;
            let tip = chain_view.tip().await?;
            // A chain tip at height zero means the chain consists of only the genesis
            // block, and contains no usable tree state.
            let tip_height = (tip.height() > BlockHeight::from_u32(0)).then_some(tip.height());
            (Some(chain_view), tip_height)
        } else {
            info!("No-scan mode: skipping chain scanning");
            (None, None)
        };
        let sapling_activation = network_params
            .activation_height(NetworkUpgrade::Sapling)
            .expect("Sapling activation height is defined.");

        // The export height records the chain tip at export time. Without a chain
        // backend, approximate it with the wallet's maximum transaction expiry height
        // (expiry heights are near the height at which a transaction was created).
        let export_height = chain_tip
            .or_else(|| {
                wallet
                    .transactions()
                    .values()
                    .map(|tx| u32::from(tx.transaction().expiry_height()))
                    .filter(|&h| h > 0)
                    .max()
                    .map(BlockHeight::from_u32)
            })
            .unwrap_or(sapling_activation);

        // Export the parsed wallet to a ZeWIF document. Everything below operates on
        // the document alone.
        info!("Exporting the zcashd wallet to a ZeWIF document");
        // Mainnet and testnet activation schedules are fixed by the protocol, so
        // only a regtest export needs one supplied.
        let regtest_activations = match network_params.network_type() {
            NetworkType::Regtest => Some(derive_regtest_activations(&network_params)),
            NetworkType::Main | NetworkType::Test => None,
        };
        let mut document = zewif_zcashd::migrate_to_zewif(
            &wallet,
            zewif::BlockHeight::from_u32(u32::from(export_height)),
            regtest_activations,
        )
        .map_err(MigrateError::Export)?;
        drop(wallet);

        info!(
            "Wallet document contains {} transactions",
            document.transactions().len(),
        );

        // Normalize the secret store and the legacy account's derivation to zcashd's
        // post-v4.7.0 semantics: zcashd derives legacy-account (0x7FFFFFFF) keys from
        // the seed of its BIP 39 mnemonic, deriving that mnemonic from the pre-v4.7.0
        // legacy seed where one exists. A pre-v4.7.0 wallet's document carries only the
        // raw legacy seed, so reconstruct the mnemonic exactly as zcashd would have on
        // upgrade, and re-point the legacy account's key source at it.
        let secret_store = match document.secrets() {
            Some(zewif::Secrets::Plain(store)) => Some(store.clone()),
            Some(zewif::Secrets::Encrypted(_)) => return Err(MigrateError::EncryptedSecrets),
            None => None,
        };
        let (secret_store, mnemonic_fp) = match secret_store {
            Some(mut store) => {
                let mnemonic_fp = store.seeds().iter().find_map(|entry| {
                    matches!(entry.material(), zewif::SeedMaterial::Bip39Mnemonic(_))
                        .then(|| entry.fingerprint().clone())
                });
                let legacy_seed = store
                    .seeds()
                    .iter()
                    .find_map(|entry| match entry.material() {
                        zewif::SeedMaterial::LegacySeed(seed) => Some(*seed.as_bytes()),
                        _ => None,
                    });
                let mnemonic_fp = match (mnemonic_fp, legacy_seed) {
                    (Some(fp), _) => Some(fp),
                    (None, Some(seed_bytes)) => {
                        let seed = SecretVec::new(seed_bytes.to_vec());
                        let mnemonic = zcash_keys::keys::zcashd::derive_mnemonic(&seed).ok_or(
                            ErrorKind::Generic.context(fl!("err-failed-seed-fingerprinting")),
                        )?;
                        let fp = SeedFingerprint::from_seed(&mnemonic.to_seed(""))
                            .expect("BIP 39 seeds have a valid length");
                        let fp =
                            zewif_zcashd::zcashd_wallet::encode_seed_fingerprint(&fp.to_bytes());
                        store.add_seed(zewif::SeedEntry::new(
                            fp.clone(),
                            zewif::SeedMaterial::Bip39Mnemonic(zewif::Bip39Mnemonic::new(
                                mnemonic.phrase(),
                                Some(zewif::MnemonicLanguage::English),
                            )),
                        ));
                        Some(fp)
                    }
                    (None, None) => None,
                };
                (Some(store), mnemonic_fp)
            }
            None => (None, None),
        };
        // A wallet with no HD seed material at all (created before zcashd had HD
        // support, holding only standalone keys and watch-only addresses) gives its
        // legacy account no derivation root; the importer would then skip that
        // account and drop every standalone transparent key as unowned. Mint a fresh
        // mnemonic to serve as the account's derivation root, creating a secret
        // store to hold it if the wallet had no secrets at all.
        let minted_seed = mnemonic_fp.is_none() && has_seedless_legacy_account(&document);
        let (secret_store, mnemonic_fp) = if minted_seed {
            let mut store = secret_store.unwrap_or_else(zewif::SecretStore::new);
            let fp = mint_legacy_mnemonic(&mut store);
            (Some(store), Some(fp))
        } else {
            (secret_store, mnemonic_fp)
        };

        // Check whether this wallet (identified by its mnemonic seed fingerprint) has
        // already been imported, and whether additional wallet imports are permitted.
        let existing_zcashd_sourced_accounts = db_data.get_account_ids()?.into_iter().try_fold(
            HashSet::new(),
            |mut found, account_id| {
                let account = db_data
                    .get_account(account_id)?
                    .expect("account exists for just-retrieved id");

                if let AccountSource::Derived {
                    derivation,
                    key_source,
                } = account.source()
                    && matches!(
                        key_source.as_deref(),
                        Some(ZCASHD_MNEMONIC_SOURCE) | Some(ZCASHD_LEGACY_SOURCE)
                    )
                {
                    found.insert(*derivation.seed_fingerprint());
                }

                Ok::<_, SqliteClientError>(found)
            },
        )?;
        if !existing_zcashd_sourced_accounts.is_empty() {
            if allow_multiple_wallet_imports {
                if let Some(fp) = mnemonic_fp.as_ref().and_then(decode_seed_fingerprint)
                    && existing_zcashd_sourced_accounts.contains(&fp)
                {
                    return Err(MigrateError::DuplicateImport(fp));
                }
            } else {
                return Err(MigrateError::MultiImportDisabled);
            }
        }

        // Determine the wallet's birthday. With a chain backend, resolve the block
        // hashes recorded on the document's transactions to main-chain heights, take
        // the earliest as the birthday, and fetch the chain state (including the note
        // commitment tree frontiers) as of the prior block; the importer then
        // constructs precise account birthdays with no further chain access. In
        // no-scan mode, estimate a conservative birthday from transaction expiry
        // heights; the importer will schedule a rescan from there.
        let (birthday_chain_state, recover_until) = if let Some(chain_view) = chain_view.as_ref() {
            let mut block_heights = HashMap::new();
            for tx in document.transactions().values() {
                if let Some(position) = tx.block_position() {
                    let block_hash = BlockHash(*position.block_hash().as_bytes());
                    if let Entry::Vacant(entry) = block_heights.entry(block_hash) {
                        // Ignore any blocks that are not in the main chain.
                        if let Some(height) = chain_view.block_height(&block_hash).await? {
                            entry.insert(height);
                        }
                    }
                }
            }
            backfill_mined_heights(&mut document, &block_heights);
            info!(
                "Wallet document references {} mined main-chain blocks",
                block_heights.len(),
            );

            let birthday_height = block_heights
                .values()
                .min()
                .copied()
                .or(chain_tip)
                .map_or(sapling_activation, |h| std::cmp::max(h, sapling_activation));

            // Fetch the tree state corresponding to the last block prior to the
            // wallet's birthday height.
            let treestate_height = birthday_height.saturating_sub(1);
            let chain_state = chain_view.tree_state_as_of(treestate_height).await?.ok_or(
                ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-invalid-chain-data",
                    err = format!("missing tree state for height {treestate_height}")
                )),
            )?;
            info!("Setting the wallet birthday to height {}", birthday_height);

            (Some(to_zewif_chain_state(&chain_state)), chain_tip)
        } else {
            (None, None)
        };
        let no_scan_birthday_estimate = if chain_view.is_none() {
            // Expiry heights are typically creation_height + 40 (the default
            // TX_EXPIRY_DELTA in zcashd). Subtracting 1000 gives a conservative lower
            // bound on the earliest mined height.
            Some(
                document
                    .transactions()
                    .values()
                    .filter_map(|tx| tx.expiry_height())
                    .map(u32::from)
                    .filter(|&h| h > 0)
                    .min()
                    .map(|h| BlockHeight::from_u32(h.saturating_sub(1000)))
                    .map(|h| std::cmp::max(h, sapling_activation))
                    .unwrap_or(sapling_activation),
            )
        } else {
            None
        };

        let document = enriched_document(
            &document,
            secret_store,
            mnemonic_fp.as_ref(),
            birthday_chain_state.as_ref(),
            recover_until,
            no_scan_birthday_estimate,
        );

        // Persist all spending material in the keystore before any wallet-database
        // write occurs. This runs outside the wallet database's write lock: the
        // keystore shares that lock, so diverting secrets from within `import_wallet`
        // (which holds the write lock for its whole run) would deadlock.
        let mut sink = KeyStoreSecretSink::new(&keystore, network_params).await?;
        let import_result = (|| -> Result<ZewifImportReport, MigrateError> {
            if let Some(zewif::Secrets::Plain(store)) = document.secrets() {
                info!(
                    "Storing {} seeds, {} transparent keys, and {} Sapling keys in the keystore",
                    store.seeds().len(),
                    store.transparent_keys().len(),
                    store.sapling_keys().len(),
                );
                for entry in store.seeds() {
                    sink.store_seed(entry).map_err(MigrateError::SecretSink)?;
                }
                for entry in store.transparent_keys() {
                    sink.store_transparent_key(entry)
                        .map_err(MigrateError::SecretSink)?;
                }
                for entry in store.sapling_keys() {
                    sink.store_sapling_key(entry)
                        .map_err(MigrateError::SecretSink)?;
                }
                for entry in store.sprout_keys() {
                    sink.store_sprout_key(entry)
                        .map_err(MigrateError::SecretSink)?;
                }
                for entry in store.unified_keys() {
                    sink.store_unified_key(entry)
                        .map_err(MigrateError::SecretSink)?;
                }
                if sink.sprout_keys_ignored() > 0 {
                    warn!(
                        "The wallet contains {} Sprout spending keys, which Zallet does not \
                         support; move any Sprout funds using zcashd before migrating.",
                        sink.sprout_keys_ignored(),
                    );
                }
                if sink.unified_keys_ignored() > 0 {
                    warn!(
                        "The wallet contains {} extracted unified spending keys, which \
                         Zallet does not support storing.",
                        sink.unified_keys_ignored(),
                    );
                }
            }
            // For a minted seed, defer this recommendation until the import has
            // succeeded: a failed import is retried with a freshly minted seed, so the
            // fingerprint is only meaningful once the account is actually imported.
            if !minted_seed && let Some(fp) = mnemonic_fp.as_ref() {
                println!(
                    "{}",
                    fl!("migrate-wallet-legacy-seed-fp", seed_fp = fp.encoding())
                );
            }

            // Import the document. All secret material was persisted above, so the
            // importer's sink discards its (repeated) deliveries.
            info!("Importing the ZeWIF document into the wallet database");
            db_data
                .with_mut(|mut wdb| {
                    zcash_client_sqlite::zewif::import_wallet(
                        &mut wdb,
                        &document,
                        &mut DiscardSecrets,
                    )
                })
                .map_err(MigrateError::Import)
        })();
        // A minted seed is provisional until the import commits the legacy account
        // that derives from it: if any step from keystore persistence through the
        // import fails, remove it so that a retried migration cannot accumulate
        // seeds in the keystore. Once the import has committed, the minted seed is
        // in use and must never be deleted, even if a later step fails.
        let report = match import_result {
            Ok(report) => report,
            Err(e) => {
                if minted_seed && let Some(fp) = mnemonic_fp.as_ref() {
                    remove_provisional_mnemonic(&db_data, &keystore, fp).await;
                }
                return Err(e);
            }
        };

        log_import_report(&report);

        if minted_seed {
            println!("{}", fl!("migrate-wallet-minted-seed"));
            if let Some(fp) = mnemonic_fp.as_ref() {
                println!(
                    "{}",
                    fl!("migrate-wallet-legacy-seed-fp", seed_fp = fp.encoding())
                );
            }
        }

        let exposure_height = birthday_chain_state
            .as_ref()
            .map(|cs| BlockHeight::from_u32(u32::from(cs.height()) + 1))
            .or(no_scan_birthday_estimate)
            .unwrap_or(sapling_activation);
        // The backup reminder is printed before propagating any error from the
        // post-import steps, as the minted-seed notice above refers to it.
        let post_import = finish_import(
            &mut db_data,
            &document,
            &report,
            exposure_height,
            allow_partial_import,
        );
        print_backup_reminder();
        post_import?;

        Ok(())
    }
}

/// Completes a committed import: registers the watch-only transparent material the
/// ZeWIF importer has no path for, exposes the addresses of the imported standalone
/// spending keys and redeem scripts, then evaluates the import report.
///
/// All of this must happen after the imported accounts are fully set up, so that a
/// failure here never leaves committed accounts half-configured. The steps run in
/// order because each reads back what the ones before it registered.
fn finish_import(
    db_data: &mut DbHandle,
    document: &zewif::Zewif,
    report: &ZewifImportReport,
    exposure_height: BlockHeight,
    allow_partial_import: bool,
) -> Result<(), MigrateError> {
    let tracked = tracked_transparent_receivers(db_data)?;
    let derived = derived_transparent_receivers(db_data, report)?;
    register_watch_pubkeys(db_data, document, report, exposure_height, &tracked)?;
    expose_spending_key_addresses(db_data, document, report, exposure_height, &derived)?;
    register_watch_addresses(db_data, document, report, exposure_height)?;
    expose_registered_script_addresses(db_data, report, exposure_height)?;

    let document_account_count = document
        .wallets()
        .iter()
        .map(|wallet| wallet.accounts().len())
        .sum();
    check_import_report(report, document_account_count, allow_partial_import)
}

/// Derives the ZeWIF document's regtest activation schedule from the configured
/// network parameters.
///
/// A regtest chain's activation schedule lives in node configuration
/// (`regtest_nuparams`) rather than in the wallet, so it cannot be read out of
/// `wallet.dat`. Deriving it from the wallet database's own configured parameters
/// makes the document's schedule and the database's schedule agree by
/// construction, which the importer's `verify_regtest_activations` cross-check
/// then confirms.
///
/// The `LocalNetwork` carries every activation the wallet database's own
/// parameters define, up to NU6.3. `zewif-zcashd`'s activation schedule
/// currently maps only through NU6.2, so NU6.3 travels in the struct but
/// is not separately recorded in the document's activation map; the wallet
/// database keeps its full configured schedule regardless. NU7 is included
/// only when compiled with `--cfg zcash_unstable="nu7"`.
fn derive_regtest_activations(params: &impl Parameters) -> zewif_zcashd::RegtestActivations {
    let height = |nu: NetworkUpgrade| {
        params
            .activation_height(nu)
            .map(|h| BlockHeight::from_u32(u32::from(h)))
    };
    zewif_zcashd::RegtestActivations::Local(zcash_protocol::local_consensus::LocalNetwork {
        overwinter: height(NetworkUpgrade::Overwinter),
        sapling: height(NetworkUpgrade::Sapling),
        blossom: height(NetworkUpgrade::Blossom),
        heartwood: height(NetworkUpgrade::Heartwood),
        canopy: height(NetworkUpgrade::Canopy),
        nu5: height(NetworkUpgrade::Nu5),
        nu6: height(NetworkUpgrade::Nu6),
        nu6_1: height(NetworkUpgrade::Nu6_1),
        nu6_2: height(NetworkUpgrade::Nu6_2),
        nu6_3: height(NetworkUpgrade::Nu6_3),
        #[cfg(zcash_unstable = "nu7")]
        nu7: height(NetworkUpgrade::Nu7),
    })
}

/// Collects the derived transparent receivers of every imported account.
///
/// Exposure marking excludes these: derived receivers keep the importer's
/// gap-inferred exposure, and force-exposing one beyond the gap could hide
/// funded addresses from seed recovery.
fn derived_transparent_receivers(
    db_data: &mut DbHandle,
    report: &ZewifImportReport,
) -> Result<HashSet<TransparentAddress>, MigrateError> {
    collect_transparent_receivers(
        db_data,
        report.imported_accounts.iter().map(|a| a.account_uuid),
        false,
    )
}

/// Collects the transparent receivers of every account in the wallet, standalone
/// imports included.
///
/// Both watch-only registration steps check their candidates against this rather than
/// against the accounts this run imported. A migration can run against a wallet that
/// already holds accounts, and the wallet rejects an import of material another
/// account has already imported; an address that is a derived receiver of another
/// account must also keep the exposure its own derivation gives it, rather than be
/// force-exposed as an import.
///
/// Each step reads its own set, as the steps before it register material that belongs
/// in the sets after them.
fn tracked_transparent_receivers(
    db_data: &mut DbHandle,
) -> Result<HashSet<TransparentAddress>, MigrateError> {
    let accounts = db_data.get_account_ids().map_err(MigrateError::Database)?;
    collect_transparent_receivers(db_data, accounts, true)
}

/// Collects the transparent receivers of `accounts` into a set, change addresses
/// included.
///
/// `include_standalone` selects whether imported standalone addresses count as
/// receivers of the account that holds them; the two callers differ on that, and on
/// which accounts they ask about, but not otherwise.
fn collect_transparent_receivers(
    db_data: &mut DbHandle,
    accounts: impl IntoIterator<Item = zcash_client_sqlite::AccountUuid>,
    include_standalone: bool,
) -> Result<HashSet<TransparentAddress>, MigrateError> {
    let mut receivers = HashSet::new();
    for account_uuid in accounts {
        receivers.extend(
            db_data
                .get_transparent_receivers(account_uuid, true, include_standalone)
                .map_err(MigrateError::Database)?
                .into_keys(),
        );
    }
    Ok(receivers)
}

/// Marks `to_expose` as exposed, doing nothing when there is nothing to mark.
///
/// Every caller assembles its addresses conditionally and several can end up with
/// none, which `mark_transparent_addresses_exposed` should not be troubled with.
fn mark_addresses_exposed(
    db_data: &mut DbHandle,
    to_expose: &[(TransparentAddress, BlockHeight)],
) -> Result<(), MigrateError> {
    if to_expose.is_empty() {
        return Ok(());
    }
    db_data
        .mark_transparent_addresses_exposed(to_expose)
        .map_err(MigrateError::Database)
}

/// Selects the watch-only transparent pubkeys `account` records that the wallet does
/// not already track, with the number of them declined for their serialization:
/// uncompressed first, then unparsable.
///
/// zcashd recorded a watch-only pubkey (`importpubkey`) against the address it
/// controls and no spend authority. An entry carrying a spend authority is the
/// importer's to register, and one carrying neither is
/// [`watched_addresses_to_import`]'s.
fn account_watch_pubkeys(
    account: &zewif::Account,
    tracked: &HashSet<TransparentAddress>,
) -> (Vec<PublicKey>, usize, usize) {
    let mut to_import = Vec::new();
    let mut uncompressed = 0usize;
    let mut malformed = 0usize;
    for address in account.addresses() {
        if let zewif::ProtocolAddress::Transparent(t) = address.address()
            && t.spend_authority().is_none()
            && let Some(pubkey) = t.pubkey()
        {
            match pubkey.as_slice() {
                bytes if bytes.len() == PUBLIC_KEY_SIZE => match PublicKey::from_slice(bytes) {
                    Ok(pk) => to_import.push(pk),
                    Err(_) => malformed += 1,
                },
                // `import_standalone_transparent_pubkeys` derives the stored P2PKH
                // address from the compressed pubkey serialization, so an uncompressed
                // pubkey would be tracked under a different address than zcashd had
                // on-chain.
                bytes if bytes.len() == UNCOMPRESSED_PUBLIC_KEY_SIZE => uncompressed += 1,
                _ => malformed += 1,
            }
        }
    }
    to_import.retain(|pubkey| !tracked.contains(&TransparentAddress::from_pubkey(pubkey)));
    (to_import, uncompressed, malformed)
}

/// Registers watch-only transparent pubkeys (from zcashd's `importpubkey`) with the
/// accounts whose address lists carry them, exposing their addresses as of
/// `exposure_height`.
///
/// The ZeWIF importer registers spendable transparent keys from the secret store
/// and P2SH redeem scripts, but has no path for pubkey-only (watch) addresses.
///
/// A pubkey whose address `tracked` already names is left alone, as in
/// [`register_watch_addresses`]. The wallet rejects an import of a pubkey another
/// account holds, which would fail a migration that has already committed; one this
/// account holds is a no-op; and one held as a derived receiver — zcashd also stored
/// seed-derived keys as watch entries — must keep the importer's gap-inferred
/// exposure, as force-exposing it beyond the gap could hide funded addresses from
/// seed recovery. An address the wallet tracks is not this step's to expose either:
/// whatever exposure it carries was established by whatever registered it.
fn register_watch_pubkeys(
    db_data: &mut DbHandle,
    document: &zewif::Zewif,
    report: &ZewifImportReport,
    exposure_height: BlockHeight,
    tracked: &HashSet<TransparentAddress>,
) -> Result<(), MigrateError> {
    let mut skipped_uncompressed_watch_pubkeys = 0usize;
    let mut skipped_malformed_watch_pubkeys = 0usize;
    for (account_uuid, account) in imported_document_accounts(document, report) {
        let (watch_pubkeys, uncompressed, malformed) = account_watch_pubkeys(account, tracked);
        skipped_uncompressed_watch_pubkeys += uncompressed;
        skipped_malformed_watch_pubkeys += malformed;
        if watch_pubkeys.is_empty() {
            continue;
        }
        info!(
            "Registering {} watch-only transparent pubkeys with account '{}'",
            watch_pubkeys.len(),
            account.name(),
        );
        let to_expose: Vec<(TransparentAddress, BlockHeight)> = watch_pubkeys
            .iter()
            .map(TransparentAddress::from_pubkey)
            .map(|address| (address, exposure_height))
            .collect();
        db_data
            .import_standalone_transparent_pubkeys(account_uuid, watch_pubkeys.into_iter())
            .map_err(MigrateError::Database)?;
        mark_addresses_exposed(db_data, &to_expose)?;
    }
    if skipped_uncompressed_watch_pubkeys > 0 {
        warn!(
            "Skipped {} watch-only entries whose public keys zcashd stored in \
             uncompressed form; Zallet only supports compressed-form pubkey imports.",
            skipped_uncompressed_watch_pubkeys,
        );
    }
    if skipped_malformed_watch_pubkeys > 0 {
        warn!(
            "Skipped {} watch-only entries whose public keys could not be parsed.",
            skipped_malformed_watch_pubkeys,
        );
    }
    Ok(())
}

/// Pairs each of the document's accounts that the import created a wallet account
/// for with the UUID of that wallet account.
///
/// The document names accounts and the import report records the UUID each was
/// created as, so matching the two by name is what lets a step that reads the
/// document address the wallet rows it produced. An account the import did not
/// create — one it skipped — is left out, as there is nothing to register against.
fn imported_document_accounts<'a>(
    document: &'a zewif::Zewif,
    report: &ZewifImportReport,
) -> Vec<(zcash_client_sqlite::AccountUuid, &'a zewif::Account)> {
    let accounts_by_name: HashMap<&str, zcash_client_sqlite::AccountUuid> = report
        .imported_accounts
        .iter()
        .map(|a| (a.name.as_str(), a.account_uuid))
        .collect();
    document
        .wallets()
        .iter()
        .flat_map(|wallet| wallet.accounts())
        .filter_map(|account| {
            accounts_by_name
                .get(account.name())
                .map(|account_uuid| (*account_uuid, account))
        })
        .collect()
}

/// Computes the P2PKH addresses of the standalone transparent spending keys that
/// the ZeWIF importer registered as Foreign-scope (genuinely standalone) rows.
///
/// Keys the importer skipped are excluded: their addresses have no wallet rows,
/// which `mark_transparent_addresses_exposed` rejects. Addresses in
/// `derived_receivers` are excluded: zcashd also stored seed-derived keys as
/// standalone `key` records, and derived receivers keep the importer's
/// gap-inferred exposure — force-exposing one beyond the gap could hide funded
/// addresses from seed recovery.
fn registered_spending_key_addresses<P: Parameters>(
    store: &zewif::SecretStore,
    report: &ZewifImportReport,
    params: &P,
    derived_receivers: &HashSet<TransparentAddress>,
) -> Vec<TransparentAddress> {
    let skipped: HashSet<&str> = report
        .skipped_transparent_keys
        .iter()
        .filter_map(|k| k.address.as_deref())
        .collect();
    let mut seen = HashSet::new();
    let mut addresses = Vec::new();
    for entry in store.transparent_keys() {
        // The importer skips uncompressed pubkeys; mirror that rather than
        // derive an address zcashd never used.
        if !entry.pubkey().is_compressed() {
            continue;
        }
        // A malformed pubkey would have failed the import outright.
        let Ok(pubkey) = PublicKey::from_slice(entry.pubkey().as_slice()) else {
            continue;
        };
        let address = TransparentAddress::from_pubkey(&pubkey);
        if derived_receivers.contains(&address) {
            continue;
        }
        // Encoding is only needed to test against the report's skipped addresses,
        // which name theirs as strings.
        if seen.insert(address) && !skipped.contains(address.encode(params).as_str()) {
            addresses.push(address);
        }
    }
    addresses
}

/// Marks the P2PKH addresses of the imported standalone transparent spending keys
/// (from zcashd's `importprivkey`) as exposed as of `exposure_height`.
///
/// The ZeWIF importer registers these keys but only marks an address as exposed
/// if the document records an exposure for it, so an imported-but-never-used
/// key's address would remain unexposed and thus invisible to `listaddresses`,
/// which only surfaces exposed addresses. zcashd always listed such addresses.
fn expose_spending_key_addresses(
    db_data: &mut DbHandle,
    document: &zewif::Zewif,
    report: &ZewifImportReport,
    exposure_height: BlockHeight,
    derived_receivers: &HashSet<TransparentAddress>,
) -> Result<(), MigrateError> {
    let Some(zewif::Secrets::Plain(store)) = document.secrets() else {
        return Ok(());
    };
    let params = *db_data.params();
    let to_expose: Vec<(TransparentAddress, BlockHeight)> =
        registered_spending_key_addresses(store, report, &params, derived_receivers)
            .into_iter()
            .map(|address| (address, exposure_height))
            .collect();
    if to_expose.is_empty() {
        return Ok(());
    }
    info!(
        "Marking {} imported transparent spending-key addresses as exposed",
        to_expose.len(),
    );
    mark_addresses_exposed(db_data, &to_expose)
}

/// A transparent address that zcashd watched and that the document records without
/// key material Zallet can import, together with the account that records it and the
/// height at which it is known to have been disclosed.
struct WatchedAddress {
    account_uuid: zcash_client_sqlite::AccountUuid,
    address: TransparentAddress,
    exposure_height: BlockHeight,
}

/// Selects the watch-only transparent addresses of the imported accounts that the
/// wallet does not track after the import, and so must be registered as bare
/// addresses for the migration not to lose them.
///
/// A candidate is an address the document records with neither a spend authority nor
/// a public key: zcashd's `importaddress <address>` records exactly that, and so does
/// `importaddress <redeemscript>` for the script's P2SH address. Key material the
/// import deliberately declined keeps that treatment, because the address still
/// carries the material: an uncompressed public key is excluded here as it is in
/// [`register_watch_pubkeys`], which warns rather than track the address zcashd never
/// used.
///
/// `tracked` names the receivers the wallet holds once the import and the
/// registration steps before this one have run, and removing them is what leaves only
/// the addresses that need registering. Deciding that here instead — by mirroring the
/// rules the wallet applies to a redeem script — would let the two drift apart: a
/// script the wallet can represent is tracked under its P2SH address already, and one
/// it cannot (non-multisig, or beyond the 520-byte P2SH limit) is not tracked at all,
/// and is reached by this step precisely because the wallet dropped it.
///
/// An address the document records an exposure height for takes that height, as the
/// import would have done had it recognized the address; the rest take
/// `exposure_height`. The result is sorted, so that a migration run registers
/// addresses in a deterministic order, and an address recorded by more than one
/// account is registered once, under the first account that records it: the wallet
/// rejects an import of the same address into a second account.
///
/// Returns the selected addresses along with the number of address strings that could
/// not be decoded for this network, which the caller warns about.
fn watched_addresses_to_import<P: Parameters>(
    document: &zewif::Zewif,
    report: &ZewifImportReport,
    tracked: &HashSet<TransparentAddress>,
    params: &P,
    exposure_height: BlockHeight,
) -> (Vec<WatchedAddress>, usize) {
    let mut undecodable = 0usize;
    let mut seen = HashSet::new();
    let mut to_import = Vec::new();
    for (account_uuid, account) in imported_document_accounts(document, report) {
        for address in account.addresses() {
            let zewif::ProtocolAddress::Transparent(taddr) = address.address() else {
                continue;
            };
            if taddr.spend_authority().is_some() || taddr.pubkey().is_some() {
                continue;
            }
            let Ok(decoded) = TransparentAddress::decode(params, taddr.address()) else {
                undecodable += 1;
                continue;
            };
            if tracked.contains(&decoded) || !seen.insert(decoded) {
                continue;
            }
            to_import.push(WatchedAddress {
                account_uuid,
                address: decoded,
                exposure_height: address
                    .exposed_at_height()
                    .map_or(exposure_height, |h| BlockHeight::from(u32::from(h))),
            });
        }
    }
    to_import.sort_by_key(|watched| watched.address);
    (to_import, undecodable)
}

/// Registers the transparent addresses that zcashd watched but for which no key
/// material reached the wallet (from zcashd's `importaddress <address>`, and from the
/// redeem scripts the wallet cannot represent) as bare watch-only addresses, exposing
/// each as of the height at which it was disclosed.
///
/// zcashd watched such an address, so a migration that dropped it would stop
/// reporting funds the source wallet could see. The ZeWIF importer has no path for
/// one: it registers spendable transparent keys and representable P2SH redeem
/// scripts, and counts every other address the document records in
/// `addresses_not_recognized`. The Zallet wallet can hold a bare transparent address
/// — `zallet import-address` takes one — so the migration registers it here rather
/// than warning that it was skipped. Without key material such an address cannot be
/// spent from, which is what it was in zcashd as well.
///
/// This runs after the registration steps that precede it, so that the receivers read
/// back here account for everything they added.
fn register_watch_addresses(
    db_data: &mut DbHandle,
    document: &zewif::Zewif,
    report: &ZewifImportReport,
    exposure_height: BlockHeight,
) -> Result<(), MigrateError> {
    let tracked = tracked_transparent_receivers(db_data)?;
    let params = *db_data.params();
    let (to_import, undecodable) =
        watched_addresses_to_import(document, report, &tracked, &params, exposure_height);
    if undecodable > 0 {
        warn!(
            "Skipped {} watch-only transparent addresses that could not be decoded for \
             this network.",
            undecodable,
        );
    }
    if to_import.is_empty() {
        return Ok(());
    }
    info!(
        "Registering {} watch-only transparent addresses that carry no key material",
        to_import.len(),
    );
    let mut to_expose = Vec::with_capacity(to_import.len());
    for watched in to_import {
        db_data
            .import_standalone_transparent_address(watched.account_uuid, watched.address)
            .map_err(MigrateError::Database)?;
        to_expose.push((watched.address, watched.exposure_height));
    }
    mark_addresses_exposed(db_data, &to_expose)
}

/// Selects the P2SH addresses among `receivers` that the wallet does not already
/// consider exposed.
///
/// A P2SH address registered from a redeem script carries no derivation, so the
/// child-index inference that the ZeWIF importer uses to fill in the exposures the
/// document does not record directly cannot reach it. Any such address that the
/// document's transactions did not already reveal is therefore left unexposed by the
/// import, and needs marking here.
///
/// The result is sorted, so that a migration run marks exposures in a deterministic
/// order regardless of the iteration order of the wallet's receiver map.
fn unexposed_script_addresses(
    receivers: impl IntoIterator<Item = (TransparentAddress, TransparentAddressMetadata)>,
) -> Vec<TransparentAddress> {
    let mut addresses = receivers
        .into_iter()
        .filter(|(_, meta)| {
            matches!(meta.source(), TransparentAddressSource::StandaloneScript(_))
                && !matches!(meta.exposure(), Exposure::Exposed { .. })
        })
        .map(|(address, _)| address)
        .collect::<Vec<_>>();
    addresses.sort();
    addresses
}

/// Marks the P2SH addresses of the imported standalone redeem scripts (from zcashd's
/// `importaddress <redeemscript>` and `addmultisigaddress`) as exposed as of
/// `exposure_height`.
///
/// A redeem script reaches a zcashd wallet only because its P2SH address was already
/// in use outside that wallet, so the address has been disclosed by the time it is
/// migrated and the wallet's exposure metadata should say so. The ZeWIF importer
/// cannot establish that on its own: it marks an address exposed only where the
/// document accounts for an exposure of it, and the child-index inference that fills
/// in the derived receivers the document does not mention cannot reach an address with
/// no derivation. A P2SH address that never appeared in a migrated transaction is
/// therefore left with no exposure height at all.
///
/// One consequence today is that the address goes unreported: `listaddresses` is built
/// on `list_addresses`, which returns only exposed addresses, so an imported-but-never-
/// funded P2SH address is invisible where zcashd always listed it. zcash/zallet#782
/// proposes to report standalone imports from `get_transparent_receivers` instead,
/// which applies no exposure filter; the exposure record needs to be right either way.
///
/// The registered scripts are read back from the wallet rather than recomputed from
/// the document: the importer skips the redeem scripts the wallet cannot represent,
/// and the standalone-script receivers of the accounts this import created are exactly
/// the scripts it registered.
fn expose_registered_script_addresses(
    db_data: &mut DbHandle,
    report: &ZewifImportReport,
    exposure_height: BlockHeight,
) -> Result<(), MigrateError> {
    let mut to_expose = Vec::new();
    for account in &report.imported_accounts {
        let receivers = db_data
            .get_transparent_receivers(account.account_uuid, true, true)
            .map_err(MigrateError::Database)?;
        to_expose.extend(
            unexposed_script_addresses(receivers)
                .into_iter()
                .map(|address| (address, exposure_height)),
        );
    }
    if to_expose.is_empty() {
        return Ok(());
    }
    info!(
        "Marking {} imported P2SH redeem script addresses as exposed",
        to_expose.len(),
    );
    mark_addresses_exposed(db_data, &to_expose)
}

/// Best-effort removal of a provisionally stored mnemonic from the keystore, after
/// a failed wallet import.
///
/// A minted seed is provisional until an account has been imported under it; once
/// any account derives from it, it must never be removed. Callers must therefore
/// only pass the fingerprint of a mnemonic minted in this migration run, after the
/// import failed. Before deleting, the wallet database is checked to confirm that
/// the failed import committed no account deriving from the seed; if one exists (or
/// the check cannot be performed), the seed is left in place. If removal fails, a
/// warning names the fingerprint of the orphaned seed left in the keystore.
async fn remove_provisional_mnemonic(
    db_data: &DbHandle,
    keystore: &KeyStore,
    fp: &zewif::SeedFingerprint,
) {
    let orphaned_seed_warning = || {
        warn!(
            "The failed import left a provisional seed with fingerprint '{}' stored \
             in the keystore; no account references it.",
            fp.encoding(),
        );
    };
    let Some(decoded) = decode_seed_fingerprint(fp) else {
        orphaned_seed_warning();
        return;
    };
    match seed_is_referenced(db_data, &decoded) {
        Ok(false) => (),
        Ok(true) => {
            warn!(
                "The import failed after committing an account that derives from the \
                 seed with fingerprint '{}'; leaving the seed in the keystore.",
                fp.encoding(),
            );
            return;
        }
        Err(e) => {
            warn!("Failed to check the wallet database for accounts derived from the seed: {e}");
            orphaned_seed_warning();
            return;
        }
    }
    match keystore.delete_mnemonic(&decoded).await {
        Ok(true) => info!("Removed the provisional seed from the keystore"),
        // The mnemonic never reached the keystore, so there is nothing to remove.
        Ok(false) => (),
        Err(e) => {
            warn!("Failed to remove the provisional seed from the keystore: {e}");
            orphaned_seed_warning();
        }
    }
}

/// Returns whether any account in the wallet database derives from `seed_fp`.
fn seed_is_referenced(
    db_data: &DbHandle,
    seed_fp: &SeedFingerprint,
) -> Result<bool, SqliteClientError> {
    for account_id in db_data.get_account_ids()? {
        if let Some(account) = db_data.get_account(account_id)?
            && let AccountSource::Derived { derivation, .. } = account.source()
            && derivation.seed_fingerprint() == seed_fp
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn print_backup_reminder() {
    let bar = "*".repeat(72);
    println!("\n{bar}");
    println!("BACK UP YOUR WALLETS (there are two)");
    println!("{bar}");
    println!("1. Keep your original zcashd wallet.dat. Anything this migration could not");
    println!("   import (reported above) exists only there; if you lose wallet.dat, those");
    println!("   funds are unrecoverable. Keeping a secure backup of it is encouraged.");
    println!();
    println!("2. Back up your new Zallet wallet too. wallet.db can hold spending keys that a");
    println!("   mnemonic backup does NOT cover (keys imported with z_importkey, and other");
    println!("   standalone key material), so `zallet export-mnemonic` is not a complete");
    println!("   backup of it. There is currently no complete backup RPC or command: keep a");
    println!("   secure copy of BOTH the wallet.db file AND the age encryption identity file");
    println!("   (named by the keystore.encryption_identity config option). Those spending");
    println!("   keys are encrypted to that identity; if you lose it, or forget its");
    println!("   passphrase, they cannot be decrypted and those funds are unrecoverable.");
    println!("   Note that wallet.db itself is NOT encrypted (it also holds your transaction");
    println!("   history and viewing keys in the clear), so store the backup securely.");
    println!("{bar}\n");
}

/// Returns whether the document's synthesized legacy account lacks a seed-derivation
/// root, i.e. the source wallet contained neither a mnemonic nor a legacy HD seed.
fn has_seedless_legacy_account(document: &zewif::Zewif) -> bool {
    document
        .wallets()
        .iter()
        .flat_map(|wallet| wallet.accounts())
        .any(is_seedless_legacy_account)
}

/// Returns whether `account` is the synthesized zcashd legacy account and lacks a
/// seed-derivation root.
fn is_seedless_legacy_account(account: &zewif::Account) -> bool {
    account.provenance() == Some(ZCASHD_LEGACY_SOURCE)
        && !matches!(account.key_source(), Some(zewif::KeySource::Derived(_)))
}

/// Generates a fresh 24-word English BIP 39 mnemonic, adds it to `store`, and
/// returns its seed fingerprint.
///
/// This provides a derivation root for wallets that never had one, so that the
/// legacy account — and the standalone key material attached to it — can be
/// imported as a seed-derived account.
fn mint_legacy_mnemonic(store: &mut zewif::SecretStore) -> zewif::SeedFingerprint {
    // Matches the entropy handling of the `generate-mnemonic` command.
    const BITS_PER_BYTE: usize = 8;
    const ENTROPY_BYTES: usize = Count::Words24.entropy_bits() / BITS_PER_BYTE;

    let mut entropy = [0u8; ENTROPY_BYTES];
    OsRng.fill_bytes(&mut entropy);
    // The mnemonic itself zeroizes its phrase and entropy on drop.
    let mnemonic = Mnemonic::<English>::from_entropy(entropy)
        .expect("valid entropy length won't fail to generate the mnemonic");
    entropy.zeroize();

    let mut seed_bytes = mnemonic.to_seed("");
    let fp = SeedFingerprint::from_seed(&seed_bytes).expect("BIP 39 seeds have a valid length");
    seed_bytes.zeroize();
    let fp = zewif_zcashd::zcashd_wallet::encode_seed_fingerprint(&fp.to_bytes());
    store.add_seed(zewif::SeedEntry::new(
        fp.clone(),
        zewif::SeedMaterial::Bip39Mnemonic(zewif::Bip39Mnemonic::new(
            mnemonic.phrase(),
            Some(zewif::MnemonicLanguage::English),
        )),
    ));
    fp
}

/// Converts a chain-backend `ChainState` into its ZeWIF representation, preserving
/// the note commitment tree frontiers of every shielded pool.
fn to_zewif_chain_state(chain_state: &ChainState) -> zewif::ChainState {
    let mut out = zewif::ChainState::new(zewif::BlockHeight::from_u32(u32::from(
        chain_state.block_height(),
    )));
    out.set_block_hash(zewif::BlockHash::from_bytes(chain_state.block_hash().0));
    out.set_sapling_tree(to_zewif_frontier(
        chain_state.final_sapling_tree(),
        |node| node.to_bytes(),
    ));
    out.set_orchard_tree(to_zewif_frontier(
        chain_state.final_orchard_tree(),
        |node| node.to_bytes(),
    ));
    out.set_ironwood_tree(to_zewif_frontier(
        chain_state.final_ironwood_tree(),
        |node| node.to_bytes(),
    ));
    out
}

/// Converts an `incrementalmerkletree` frontier into its ZeWIF representation.
fn to_zewif_frontier<H, const DEPTH: u8>(
    frontier: &incrementalmerkletree::frontier::Frontier<H, DEPTH>,
    node_bytes: impl Fn(&H) -> [u8; 32],
) -> zewif::Frontier {
    match frontier.value() {
        None => zewif::Frontier::Empty,
        Some(frontier) => zewif::Frontier::NonEmpty(zewif::FrontierData::from_parts(
            u64::from(frontier.position()),
            zewif::MerkleNode::new(node_bytes(frontier.leaf())),
            frontier
                .ommers()
                .iter()
                .map(|ommer| zewif::MerkleNode::new(node_bytes(ommer)))
                .collect(),
        )),
    }
}

/// Backfills the mined height of every document transaction whose block hash
/// resolved to a main-chain height.
///
/// zcashd records a per-transaction mined height only for transactions that
/// added notes to the Orchard note commitment tree, so transactions touching
/// only the transparent or Sapling pools never carry one in the exported
/// document. The importer needs either a mined height or a nonzero expiry
/// height to determine a transaction's consensus branch ID; a pre-NU5 coinbase
/// transaction has neither, and would abort the import with "Consensus branch
/// ID not known". Transactions recorded against blocks absent from
/// `block_heights` (blocks not in the main chain) are left untouched.
fn backfill_mined_heights(
    document: &mut zewif::Zewif,
    block_heights: &HashMap<BlockHash, BlockHeight>,
) {
    let backfill: Vec<(zewif::TxId, BlockHeight)> = document
        .transactions()
        .iter()
        .filter(|(_, tx)| tx.mined_height().is_none())
        .filter_map(|(txid, tx)| {
            let block_hash = BlockHash(*tx.block_position()?.block_hash().as_bytes());
            block_heights
                .get(&block_hash)
                .map(|height| (*txid, *height))
        })
        .collect();
    for (txid, height) in backfill {
        let mut tx = document
            .get_transaction(txid)
            .expect("txid was iterated from this document")
            .clone();
        tx.set_mined_height(zewif::BlockHeight::from_u32(u32::from(height)));
        document.add_transaction(txid, tx);
    }
}

/// Rebuilds `document` with Zallet's enrichments applied.
///
/// The ZeWIF document model does not expose mutable access to the accounts of an
/// assembled document, so enrichment reassembles it:
///
/// * the (possibly normalized) secret store replaces the original;
/// * the legacy account's key source is re-pointed at the mnemonic seed, matching
///   zcashd's post-v4.7.0 derivation semantics (for a seedless wallet, this anchors
///   the legacy account to the freshly minted mnemonic);
/// * account birthdays are replaced with the chain-derived birthday state where one
///   was computed, and defaulted to the no-scan estimate where the document records
///   nothing.
///
/// All of the document's transactions are carried through unchanged, to be imported
/// directly rather than recovered by the post-import chain scan (which cannot recover
/// transactions that were never mined into a main-chain block).
fn enriched_document(
    document: &zewif::Zewif,
    secret_store: Option<zewif::SecretStore>,
    mnemonic_fp: Option<&zewif::SeedFingerprint>,
    birthday_chain_state: Option<&zewif::ChainState>,
    recover_until: Option<BlockHeight>,
    no_scan_birthday_estimate: Option<BlockHeight>,
) -> zewif::Zewif {
    let mut out = zewif::Zewif::new(
        document.export_height(),
        document.export_height_block_hash(),
    );

    for wallet in document.wallets() {
        let mut out_wallet = zewif::ZewifWallet::new(wallet.network().clone());
        for account in wallet.accounts() {
            let mut account = account.clone();

            // Normalize the legacy account's derivation to the mnemonic seed.
            if let (Some(mnemonic_fp), Some(zewif::KeySource::Derived(derived))) =
                (mnemonic_fp, account.key_source())
                && derived.account_index() == ZCASHD_LEGACY_ACCOUNT_INDEX
                && derived.seed_fingerprint() != mnemonic_fp
            {
                let legacy_address_index = derived.legacy_address_index();
                account.set_key_source(zewif::KeySource::Derived(zewif::DerivedKeySource::new(
                    mnemonic_fp.clone(),
                    ZCASHD_LEGACY_ACCOUNT_INDEX,
                    legacy_address_index,
                )));
            } else if let Some(mnemonic_fp) = mnemonic_fp
                && is_seedless_legacy_account(&account)
            {
                // A seedless wallet's legacy account arrives without a derivation
                // root; anchor it to the (minted) mnemonic so that it imports as a
                // seed-derived account and the standalone keys attached to it
                // retain an owning account.
                account.set_key_source(zewif::KeySource::Derived(zewif::DerivedKeySource::new(
                    mnemonic_fp.clone(),
                    ZCASHD_LEGACY_ACCOUNT_INDEX,
                    None,
                )));
            }

            if let Some(chain_state) = birthday_chain_state {
                account.set_birthday_chain_state(chain_state.clone());
                if let Some(height) = recover_until {
                    account
                        .set_recover_until_height(zewif::BlockHeight::from_u32(u32::from(height)));
                }
            } else if account.birthday_height().is_none()
                && account.birthday_chain_state().is_none()
                && let Some(estimate) = no_scan_birthday_estimate
            {
                account.set_birthday_height(zewif::BlockHeight::from_u32(u32::from(estimate)));
            }

            out_wallet.add_account(account);
        }
        for entry in wallet.address_book() {
            out_wallet.add_address_book_entry(entry.clone());
        }
        *out_wallet.extensions_mut() = wallet.extensions().clone();
        out.add_wallet(out_wallet);
    }

    // Carry every transaction through to be imported directly. The post-import chain
    // scan only re-derives transactions from the main-chain blocks it scans, so it
    // cannot recover a transaction that was never mined (a still-unmined send) or one
    // recorded only against a non-main-chain block (a conflicted or reorged
    // transaction). Importing them all here is what preserves that history.
    //
    // Transactions whose block hash resolved to a main-chain height carry that
    // height (see `backfill_mined_heights`) and are stored as mined; the rest are
    // stored as unmined, and for one that was in fact mined, the scan later
    // re-encounters it and fills in its true height and block.
    out.set_transactions(document.transactions().clone());

    if let Some(store) = secret_store {
        out.set_secrets(zewif::Secrets::Plain(store));
    }

    *out.extensions_mut() = document.extensions().clone();
    out
}

/// Logs the outcome of a ZeWIF document import.
fn log_import_report(report: &ZewifImportReport) {
    for account in &report.imported_accounts {
        info!(
            "Imported account '{}' as {:?} (birthday basis: {:?})",
            account.name, account.account_uuid, account.birthday_basis,
        );
    }
    for skipped in &report.skipped_accounts {
        warn!(
            "Account '{}' was not imported: {:?}",
            skipped.name, skipped.reason,
        );
    }
    info!(
        "Registered {} standalone transparent keys and {} P2SH redeem scripts",
        report.transparent_keys_registered, report.redeem_scripts_registered,
    );
    if !report.skipped_transparent_keys.is_empty() {
        warn!(
            "{} transparent spending keys could not be registered with any account",
            report.skipped_transparent_keys.len(),
        );
    }
    if report.redeem_scripts_not_representable > 0 {
        warn!(
            "Skipped {} watch-only redeem scripts that the wallet cannot represent; \
             their P2SH addresses are registered as watch-only addresses, so funds \
             they receive remain visible, but the scripts must be re-imported into a \
             wallet that can hold them to be spent from.",
            report.redeem_scripts_not_representable,
        );
    }
    // Counts only document-recorded exposures; exposures inferred from stored
    // transactions or imported spending keys are logged where they happen.
    info!(
        "Marked {} transparent addresses with document-recorded exposures as exposed",
        report.addresses_marked_exposed,
    );
    if report.transactions_stored > 0 || report.transactions_without_wallet_relevance > 0 {
        info!(
            "Stored {} wallet transactions ({} were not relevant to any imported account)",
            report.transactions_stored, report.transactions_without_wallet_relevance,
        );
    }
    if report.transactions_without_raw_data > 0 {
        warn!(
            "{} transactions carried no raw data and were not stored",
            report.transactions_without_raw_data,
        );
    }
    if report.address_book_entries_not_imported > 0 {
        warn!(
            "The wallet's address book ({} entries) was not migrated; Zallet does not \
             yet store address book entries.",
            report.address_book_entries_not_imported,
        );
    }
}

/// Evaluates a ZeWIF import report against the number of accounts in the source
/// document, failing the migration when accounts or spending material were left
/// behind.
///
/// An import that creates no accounts from a document that contains some is
/// always an error. Skipped accounts and unregistered transparent spending keys
/// are errors unless partial imports are explicitly permitted; they concern
/// spendable material that would otherwise silently remain only in the source
/// `wallet.dat`. Representability limits that do not involve spendable key
/// material (unrepresentable watch-only redeem scripts, transactions without
/// raw data) remain warnings.
fn check_import_report(
    report: &ZewifImportReport,
    document_account_count: usize,
    allow_partial_import: bool,
) -> Result<(), MigrateError> {
    if document_account_count > 0 && report.imported_accounts.is_empty() {
        return Err(MigrateError::NothingImported {
            document_account_count,
        });
    }
    let material_left_behind =
        !report.skipped_accounts.is_empty() || !report.skipped_transparent_keys.is_empty();
    if material_left_behind && !allow_partial_import {
        return Err(MigrateError::PartialImport {
            skipped_accounts: report.skipped_accounts.clone(),
            skipped_transparent_keys: report.skipped_transparent_keys.clone(),
        });
    }
    Ok(())
}

/// Renders the items a partial import left behind, one per line, for inclusion
/// in the [`MigrateError::PartialImport`] message.
fn describe_skipped_items(
    skipped_accounts: &[SkippedAccount],
    skipped_transparent_keys: &[SkippedTransparentKey],
) -> String {
    skipped_accounts
        .iter()
        .map(|skipped| match skipped.reason {
            AccountSkipReason::SproutViewingKey => fl!(
                "migrate-wallet-skipped-account-sprout",
                name = skipped.name.as_str()
            ),
            AccountSkipReason::TransparentAddressSetWithoutSeed => fl!(
                "migrate-wallet-skipped-account-no-seed",
                name = skipped.name.as_str()
            ),
        })
        .chain(
            skipped_transparent_keys
                .iter()
                .map(|skipped| match skipped.reason {
                    TransparentKeySkipReason::UncompressedPubKey => {
                        fl!("migrate-wallet-skipped-key-uncompressed")
                    }
                    TransparentKeySkipReason::NoOwningAccount => fl!(
                        "migrate-wallet-skipped-key-no-account",
                        address = skipped
                            .address
                            .clone()
                            .unwrap_or_else(|| fl!("migrate-wallet-unknown-address"))
                    ),
                }),
        )
        .map(|item| format!("  - {item}"))
        .collect::<Vec<_>>()
        .join("\n")
}

impl Runnable for MigrateZcashdWalletCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}

#[derive(Debug)]
pub(crate) enum ZewifError {
    BdbDump,
    ZcashdDump,
}

#[derive(Debug)]
pub(crate) enum MigrateError {
    Wrapped(Error),
    Zewif {
        error_type: ZewifError,
        wallet_path: PathBuf,
        error: Box<dyn std::error::Error + Send + Sync>,
    },
    Export(zewif_zcashd::migrate::MigrateError),
    Import(ZewifImportError<std::convert::Infallible>),
    SecretSink(SecretSinkError),
    EncryptedSecrets,
    NetworkMismatch {
        wallet_network: zewif::Network,
        db_network: NetworkType,
    },
    Database(SqliteClientError),
    MultiImportDisabled,
    DuplicateImport(SeedFingerprint),
    NothingImported {
        document_account_count: usize,
    },
    PartialImport {
        skipped_accounts: Vec<SkippedAccount>,
        skipped_transparent_keys: Vec<SkippedTransparentKey>,
    },
}

impl From<MigrateError> for Error {
    fn from(value: MigrateError) -> Self {
        match value {
            MigrateError::Wrapped(e) => e,
            MigrateError::Zewif {
                error_type,
                wallet_path,
                error,
            } => Error::from(match error_type {
                ZewifError::BdbDump => ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-bdb-parse",
                    path = wallet_path.to_str(),
                    err = error.to_string()
                )),
                ZewifError::ZcashdDump => ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-db-dump",
                    path = wallet_path.to_str(),
                    err = error.to_string()
                )),
            }),
            MigrateError::Export(e) => Error::from(
                ErrorKind::Generic.context(fl!("err-migrate-wallet-export", err = e.to_string())),
            ),
            MigrateError::Import(e) => Error::from(
                ErrorKind::Generic.context(fl!("err-migrate-wallet-import", err = e.to_string())),
            ),
            MigrateError::SecretSink(e) => Error::from(
                ErrorKind::Generic
                    .context(fl!("err-migrate-wallet-secret-store", err = e.to_string())),
            ),
            MigrateError::EncryptedSecrets => {
                Error::from(ErrorKind::Generic.context(fl!("err-migrate-wallet-encrypted-secrets")))
            }
            MigrateError::NetworkMismatch {
                wallet_network,
                db_network,
            } => Error::from(ErrorKind::Generic.context(fl!(
                "err-migrate-wallet-network-mismatch",
                wallet_network = match wallet_network {
                    zewif::Network::Mainnet => "main".to_string(),
                    zewif::Network::Testnet => "test".to_string(),
                    zewif::Network::Regtest(_) => "regtest".to_string(),
                },
                zallet_network = match db_network {
                    NetworkType::Main => "main",
                    NetworkType::Test => "test",
                    NetworkType::Regtest => "regtest",
                }
            ))),
            MigrateError::Database(sqlite_client_error) => {
                Error::from(ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-storage",
                    err = sqlite_client_error.to_string()
                )))
            }
            MigrateError::MultiImportDisabled => Error::from(
                ErrorKind::Generic.context(fl!("err-migrate-wallet-multi-import-disabled")),
            ),
            MigrateError::DuplicateImport(seed_fingerprint) => {
                Error::from(ErrorKind::Generic.context(fl!(
                    "err-migrate-wallet-duplicate-import",
                    seed_fp = format!("{}", seed_fingerprint)
                )))
            }
            MigrateError::NothingImported {
                document_account_count,
            } => Error::from(ErrorKind::Generic.context(fl!(
                "err-migrate-wallet-nothing-imported",
                account_count = document_account_count.to_string()
            ))),
            MigrateError::PartialImport {
                skipped_accounts,
                skipped_transparent_keys,
            } => Error::from(ErrorKind::Generic.context(fl!(
                "err-migrate-wallet-partial-import",
                skipped = describe_skipped_items(&skipped_accounts, &skipped_transparent_keys)
            ))),
        }
    }
}

impl From<SqliteClientError> for MigrateError {
    fn from(e: SqliteClientError) -> Self {
        Self::Database(e)
    }
}

impl From<Error> for MigrateError {
    fn from(value: Error) -> Self {
        MigrateError::Wrapped(value)
    }
}

impl From<abscissa_core::error::Context<ErrorKind>> for MigrateError {
    fn from(value: abscissa_core::error::Context<ErrorKind>) -> Self {
        MigrateError::Wrapped(value.into())
    }
}

impl From<ChainError> for MigrateError {
    fn from(value: ChainError) -> Self {
        MigrateError::Wrapped(value.into())
    }
}

#[cfg(test)]
mod tests {
    use incrementalmerkletree::{Position, frontier::Frontier};
    use orchard::tree::MerkleHashOrchard;
    use zcash_client_sqlite::{
        AccountUuid,
        zewif::{
            AccountSkipReason, BirthdayBasis, ImportedAccount, SkippedAccount,
            SkippedTransparentKey, TransparentKeySkipReason, ZewifImportReport,
        },
    };
    use zcash_protocol::consensus::{BlockHeight, NetworkType};

    use super::{
        BlockHash, HashMap, HashSet, MigrateError, MigrateZcashdWalletCmd,
        ZCASHD_LEGACY_ACCOUNT_INDEX, ZCASHD_LEGACY_SOURCE, backfill_mined_heights,
        check_import_report, derive_regtest_activations, describe_skipped_items, enriched_document,
        has_seedless_legacy_account, mint_legacy_mnemonic, to_zewif_frontier,
    };

    fn node(byte: u8) -> MerkleHashOrchard {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        MerkleHashOrchard::from_bytes(&bytes).expect("valid field element")
    }

    #[test]
    fn check_network_accepts_matching_networks() {
        assert!(
            MigrateZcashdWalletCmd::check_network(&zewif::Network::Mainnet, NetworkType::Main)
                .is_ok()
        );
        assert!(
            MigrateZcashdWalletCmd::check_network(&zewif::Network::Testnet, NetworkType::Test)
                .is_ok()
        );
        assert!(
            MigrateZcashdWalletCmd::check_network(
                &zewif::Network::Regtest(zewif::RegtestParams::default()),
                NetworkType::Regtest,
            )
            .is_ok()
        );
    }

    #[test]
    fn check_network_rejects_mismatch() {
        assert!(matches!(
            MigrateZcashdWalletCmd::check_network(&zewif::Network::Testnet, NetworkType::Main),
            Err(MigrateError::NetworkMismatch { .. })
        ));
        assert!(matches!(
            MigrateZcashdWalletCmd::check_network(
                &zewif::Network::Regtest(zewif::RegtestParams::default()),
                NetworkType::Main,
            ),
            Err(MigrateError::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn spending_key_addresses_follow_importer_registration() {
        use transparent::address::TransparentAddress;
        use zcash_client_sqlite::zewif::{
            SkippedTransparentKey, TransparentKeySkipReason, ZewifImportReport,
        };
        use zcash_keys::encoding::AddressCodec;
        use zcash_protocol::consensus::MAIN_NETWORK;

        let secp = secp256k1::Secp256k1::new();
        let pubkey = |byte: u8| {
            secp256k1::SecretKey::from_slice(&[byte; 32])
                .expect("valid secret key")
                .public_key(&secp)
        };
        let entry = |pubkey_bytes: Vec<u8>| {
            zewif::TransparentKeyEntry::new(
                zewif::transparent::TransparentPubKey::from_bytes(pubkey_bytes)
                    .expect("valid pubkey bytes"),
                zewif::transparent::TransparentSpendingKey::new("unused"),
            )
        };

        let registered = pubkey(0x01);
        let unowned = pubkey(0x02);
        let uncompressed = pubkey(0x03);
        let derived = pubkey(0x04);

        let mut store = zewif::SecretStore::new();
        store.add_transparent_key(entry(registered.serialize().to_vec()));
        // Registered keys may repeat in the store; the address must not.
        store.add_transparent_key(entry(registered.serialize().to_vec()));
        store.add_transparent_key(entry(unowned.serialize().to_vec()));
        store.add_transparent_key(entry(uncompressed.serialize_uncompressed().to_vec()));
        // zcashd stored seed-derived keys as `key` records too; these must keep
        // the importer's gap-inferred exposure.
        store.add_transparent_key(entry(derived.serialize().to_vec()));

        let mut report = ZewifImportReport::default();
        report.skipped_transparent_keys.push(SkippedTransparentKey {
            address: Some(TransparentAddress::from_pubkey(&unowned).encode(&MAIN_NETWORK)),
            reason: TransparentKeySkipReason::NoOwningAccount,
        });
        report.skipped_transparent_keys.push(SkippedTransparentKey {
            address: None,
            reason: TransparentKeySkipReason::UncompressedPubKey,
        });

        let derived_receivers = HashSet::from([TransparentAddress::from_pubkey(&derived)]);

        assert_eq!(
            super::registered_spending_key_addresses(
                &store,
                &report,
                &MAIN_NETWORK,
                &derived_receivers,
            ),
            vec![TransparentAddress::from_pubkey(&registered)],
        );
    }

    /// Exposure marking after a migration covers exactly the P2SH addresses the
    /// importer registered a redeem script for and did not already expose: a
    /// standalone pubkey, a bare imported address and a derived receiver each belong
    /// to another step, an address the import exposed keeps the height its
    /// transactions established, and one the wallet cannot judge is marked, because
    /// the migration knows what the wallet does not. The selection is returned in
    /// address order, so a run does not depend on the iteration order of the wallet's
    /// receiver map.
    #[test]
    fn unexposed_script_addresses_selects_only_unexposed_p2sh() {
        use transparent::{
            address::TransparentAddress,
            keys::{NonHardenedChildIndex, TransparentKeyScope},
        };
        use zcash_client_backend::wallet::{Exposure, GapMetadata, TransparentAddressMetadata};
        use zcash_script::script::{Code, Redeem};

        // A P2PKH-shaped redeem script, with its hash varied per address so that no
        // two registered scripts are identical.
        let redeem = |byte: u8| {
            let mut script = hex::decode("76a91411695b6cd891484c2d49ec5aa738ec2b2f89777788ac")
                .expect("valid hex");
            script[3] = byte;
            Redeem::parse(&Code(script)).expect("valid redeem script")
        };
        let exposed = Exposure::Exposed {
            at_height: BlockHeight::from_u32(100),
            gap_metadata: GapMetadata::DerivationUnknown,
        };
        let pubkey = secp256k1::SecretKey::from_slice(&[0x01; 32])
            .expect("valid secret key")
            .public_key(&secp256k1::Secp256k1::new());

        let unexposed_high = TransparentAddress::ScriptHash([0x0b; 20]);
        let unexposed_low = TransparentAddress::ScriptHash([0x0a; 20]);
        let unknowable = TransparentAddress::ScriptHash([0x0f; 20]);

        let receivers = vec![
            (
                unexposed_high,
                TransparentAddressMetadata::standalone_script(
                    redeem(0x0b),
                    Exposure::Unknown,
                    None,
                ),
            ),
            (
                unexposed_low,
                TransparentAddressMetadata::standalone_script(
                    redeem(0x0a),
                    Exposure::Unknown,
                    None,
                ),
            ),
            // Already exposed by the import, at the height its transactions revealed.
            (
                TransparentAddress::ScriptHash([0x0c; 20]),
                TransparentAddressMetadata::standalone_script(redeem(0x0c), exposed, None),
            ),
            // The wallet cannot tell whether this one was exposed; the migration can.
            // A redeem script reached the zcashd wallet only because its address was
            // already in use outside it.
            (
                unknowable,
                TransparentAddressMetadata::standalone_script(
                    redeem(0x0f),
                    Exposure::CannotKnow,
                    None,
                ),
            ),
            // Handled by `register_watch_pubkeys` / `expose_spending_key_addresses`.
            (
                TransparentAddress::from_pubkey(&pubkey),
                TransparentAddressMetadata::standalone_p2pkh(pubkey, Exposure::Unknown, None),
            ),
            // A P2SH address held without its redeem script belongs to
            // `register_watch_addresses`, which exposes what it registers.
            (
                TransparentAddress::ScriptHash([0x0d; 20]),
                TransparentAddressMetadata::standalone_address(Exposure::Unknown, None),
            ),
            // Derived receivers keep the importer's gap-inferred exposure.
            (
                TransparentAddress::PublicKeyHash([0x0e; 20]),
                TransparentAddressMetadata::derived(
                    TransparentKeyScope::EXTERNAL,
                    NonHardenedChildIndex::ZERO,
                    Exposure::Unknown,
                    None,
                ),
            ),
        ];

        assert_eq!(
            super::unexposed_script_addresses(receivers),
            vec![unexposed_low, unexposed_high, unknowable],
        );
    }

    /// A document address entry for `address`, as zcashd's `importaddress <address>`
    /// records one: watched, with no key material of any kind.
    fn watched_taddr(
        address: transparent::address::TransparentAddress,
    ) -> zewif::transparent::Address {
        use zcash_keys::encoding::AddressCodec;
        use zcash_protocol::consensus::MAIN_NETWORK;

        zewif::transparent::Address::new(address.encode(&MAIN_NETWORK))
    }

    /// Wraps a transparent address entry as the document records it on an account.
    fn document_address(taddr: zewif::transparent::Address) -> zewif::Address {
        zewif::Address::new(zewif::ProtocolAddress::Transparent(taddr))
    }

    /// A redeem script recorded on a document address. Its contents do not matter to
    /// the selection, only whether the address carries one and whether the wallet
    /// ended up tracking the address it hashes to.
    fn recorded_redeem_script() -> zewif::Script {
        zewif::Script::from(zewif::Data::from_vec(vec![0x51]))
    }

    /// A document account named `name`, recording `addresses`.
    fn account_with(name: &str, addresses: Vec<zewif::Address>) -> zewif::Account {
        let mut account = zewif::Account::new(zewif::AccountViewingKey::TransparentAddressSet);
        account.set_name(name);
        for address in addresses {
            account.add_address(address);
        }
        account
    }

    /// A single-wallet document holding `accounts`, in the order given.
    fn document_with(accounts: Vec<zewif::Account>) -> zewif::Zewif {
        let mut wallet = zewif::ZewifWallet::new(zewif::Network::Mainnet);
        for account in accounts {
            wallet.add_account(account);
        }
        let mut document = zewif::Zewif::new(
            zewif::BlockHeight::from_u32(2_000_000),
            zewif::BlockHash::from_bytes([9u8; 32]),
        );
        document.add_wallet(wallet);
        document
    }

    /// An import report naming the accounts a migration run created.
    fn report_with(accounts: &[(&str, AccountUuid)]) -> ZewifImportReport {
        let mut report = ZewifImportReport::default();
        for (name, account_uuid) in accounts {
            report.imported_accounts.push(ImportedAccount {
                name: (*name).into(),
                account_uuid: *account_uuid,
                birthday_basis: BirthdayBasis::ChainState,
            });
        }
        report
    }

    /// A watched pubkey whose address the wallet already tracks is not this step's to
    /// register: the wallet rejects an import of a pubkey another account holds, which
    /// would fail a migration that has already committed, and an address held as a
    /// derived receiver must keep the exposure its derivation gives it. An entry with a
    /// spend authority belongs to the importer and one with no key material at all to
    /// `register_watch_addresses`, while a pubkey zcashd stored uncompressed is counted
    /// rather than tracked under an address zcashd never used.
    #[test]
    fn watch_pubkeys_exclude_what_the_wallet_already_tracks() {
        use transparent::address::TransparentAddress;

        let secp = secp256k1::Secp256k1::new();
        let key = |byte: u8| {
            secp256k1::SecretKey::from_slice(&[byte; 32])
                .expect("valid secret key")
                .public_key(&secp)
        };
        let fresh = key(0x01);
        let already_tracked = key(0x02);
        let uncompressed = key(0x03);
        let spendable = key(0x04);

        let pubkey_entry = |pubkey: &secp256k1::PublicKey, bytes: Vec<u8>| {
            let mut entry = watched_taddr(TransparentAddress::from_pubkey(pubkey));
            entry.set_pubkey(
                zewif::transparent::TransparentPubKey::from_bytes(bytes)
                    .expect("valid pubkey bytes"),
            );
            entry
        };

        let mut spendable_entry = pubkey_entry(&spendable, spendable.serialize().to_vec());
        spendable_entry
            .set_spend_authority(zewif::transparent::TransparentSpendAuthority::Imported);

        let account = account_with(
            "Legacy",
            vec![
                document_address(pubkey_entry(&fresh, fresh.serialize().to_vec())),
                document_address(pubkey_entry(
                    &already_tracked,
                    already_tracked.serialize().to_vec(),
                )),
                document_address(pubkey_entry(
                    &uncompressed,
                    uncompressed.serialize_uncompressed().to_vec(),
                )),
                document_address(spendable_entry),
                document_address(watched_taddr(TransparentAddress::ScriptHash([0x05; 20]))),
            ],
        );

        assert_eq!(
            super::account_watch_pubkeys(
                &account,
                &HashSet::from([TransparentAddress::from_pubkey(&already_tracked)]),
            ),
            (vec![fresh], 1, 0),
        );
    }

    /// The addresses registered as bare watch-only imports are the ones the import
    /// left untracked: zcashd's `importaddress <address>` records no key material at
    /// all, and a redeem script the wallet cannot represent leaves its P2SH address
    /// with none the wallet could keep. Material the import did handle is tracked
    /// already, material it declined keeps that treatment, and an address recorded by
    /// an account this run did not import has no account to be registered against.
    #[test]
    fn watched_addresses_cover_only_what_the_import_left_untracked() {
        use transparent::address::TransparentAddress;
        use zcash_protocol::consensus::MAIN_NETWORK;

        let pubkey = secp256k1::SecretKey::from_slice(&[0x01; 32])
            .expect("valid secret key")
            .public_key(&secp256k1::Secp256k1::new());

        let bare_p2pkh = TransparentAddress::PublicKeyHash([0x01; 20]);
        let bare_p2sh = TransparentAddress::ScriptHash([0x02; 20]);
        let script_registered = TransparentAddress::ScriptHash([0x03; 20]);
        let script_dropped = TransparentAddress::ScriptHash([0x04; 20]);
        let spendable = TransparentAddress::PublicKeyHash([0x05; 20]);
        let unowned = TransparentAddress::ScriptHash([0x06; 20]);

        // A redeem script the wallet could represent: registered by the import, and
        // so tracked under its P2SH address by the time this step runs.
        let mut registered_entry = watched_taddr(script_registered);
        registered_entry.set_redeem_script(recorded_redeem_script());
        // One it could not (non-multisig, or beyond the P2SH size limit): dropped by
        // the import, leaving the address tracked by nothing.
        let mut dropped_entry = watched_taddr(script_dropped);
        dropped_entry.set_redeem_script(recorded_redeem_script());
        // A watched pubkey belongs to `register_watch_pubkeys`, which registers the
        // key itself and so tracks the address as spendable-shaped material.
        let mut pubkey_entry = watched_taddr(TransparentAddress::from_pubkey(&pubkey));
        pubkey_entry.set_pubkey(
            zewif::transparent::TransparentPubKey::from_bytes(pubkey.serialize().to_vec())
                .expect("valid pubkey bytes"),
        );
        // An address the wallet holds a spending key for belongs to the import and to
        // `expose_spending_key_addresses`.
        let mut spendable_entry = watched_taddr(spendable);
        spendable_entry
            .set_spend_authority(zewif::transparent::TransparentSpendAuthority::Imported);

        let document = document_with(vec![
            account_with(
                "Legacy",
                vec![
                    document_address(watched_taddr(bare_p2sh)),
                    document_address(watched_taddr(bare_p2pkh)),
                    document_address(registered_entry),
                    document_address(dropped_entry),
                    document_address(pubkey_entry),
                    document_address(spendable_entry),
                ],
            ),
            account_with(
                "Not imported",
                vec![document_address(watched_taddr(unowned))],
            ),
        ]);

        let account_uuid = AccountUuid::from_uuid(uuid::Uuid::from_bytes([0x0a; 16]));
        let tracked = HashSet::from([script_registered]);

        let (to_import, undecodable) = super::watched_addresses_to_import(
            &document,
            &report_with(&[("Legacy", account_uuid)]),
            &tracked,
            &MAIN_NETWORK,
            BlockHeight::from_u32(500),
        );

        assert_eq!(undecodable, 0);
        assert_eq!(
            to_import
                .into_iter()
                .map(|watched| (watched.account_uuid, watched.address))
                .collect::<Vec<_>>(),
            vec![
                (account_uuid, bare_p2pkh),
                (account_uuid, bare_p2sh),
                (account_uuid, script_dropped),
            ],
        );
    }

    /// An address the document records an exposure height for takes that height: it
    /// is the height at which the address was seen, and is what the import would have
    /// applied had it recognized the address. The rest take the migration's own
    /// exposure height; the disclosure that put such an address into a zcashd wallet
    /// happened before the migration either way.
    #[test]
    fn watched_addresses_take_the_documents_exposure_height_where_it_records_one() {
        use transparent::address::TransparentAddress;
        use zcash_protocol::consensus::MAIN_NETWORK;

        let recorded = TransparentAddress::ScriptHash([0x01; 20]);
        let unrecorded = TransparentAddress::ScriptHash([0x02; 20]);

        let mut recorded_entry = document_address(watched_taddr(recorded));
        recorded_entry.set_exposed_at_height(zewif::BlockHeight::from_u32(123));

        let document = document_with(vec![account_with(
            "Legacy",
            vec![recorded_entry, document_address(watched_taddr(unrecorded))],
        )]);
        let account_uuid = AccountUuid::from_uuid(uuid::Uuid::from_bytes([0x0a; 16]));

        let (to_import, _) = super::watched_addresses_to_import(
            &document,
            &report_with(&[("Legacy", account_uuid)]),
            &HashSet::new(),
            &MAIN_NETWORK,
            BlockHeight::from_u32(500),
        );

        assert_eq!(
            to_import
                .into_iter()
                .map(|watched| (watched.address, watched.exposure_height))
                .collect::<Vec<_>>(),
            vec![
                (recorded, BlockHeight::from_u32(123)),
                (unrecorded, BlockHeight::from_u32(500)),
            ],
        );
    }

    /// The wallet rejects an import of an address that another account already holds,
    /// so an address recorded by two accounts is registered once, under the first that
    /// records it. An address string the wallet cannot decode for its own network is
    /// counted for the caller to warn about: no account can hold it, and one such
    /// entry is not worth failing a migration that has already committed.
    #[test]
    fn watched_addresses_are_registered_once_and_undecodable_strings_counted() {
        use transparent::address::TransparentAddress;
        use zcash_keys::encoding::AddressCodec;
        use zcash_protocol::consensus::{MAIN_NETWORK, TEST_NETWORK};

        let shared = TransparentAddress::ScriptHash([0x01; 20]);
        let first = AccountUuid::from_uuid(uuid::Uuid::from_bytes([0x0a; 16]));
        let second = AccountUuid::from_uuid(uuid::Uuid::from_bytes([0x0b; 16]));

        let document = document_with(vec![
            account_with(
                "First",
                vec![
                    document_address(watched_taddr(shared)),
                    document_address(zewif::transparent::Address::new("not an address")),
                    document_address(zewif::transparent::Address::new(
                        TransparentAddress::ScriptHash([0x02; 20]).encode(&TEST_NETWORK),
                    )),
                ],
            ),
            account_with("Second", vec![document_address(watched_taddr(shared))]),
        ]);

        let (to_import, undecodable) = super::watched_addresses_to_import(
            &document,
            &report_with(&[("First", first), ("Second", second)]),
            &HashSet::new(),
            &MAIN_NETWORK,
            BlockHeight::from_u32(500),
        );

        assert_eq!(undecodable, 2);
        assert_eq!(
            to_import
                .into_iter()
                .map(|watched| (watched.account_uuid, watched.address))
                .collect::<Vec<_>>(),
            vec![(first, shared)],
        );
    }

    #[test]
    fn regtest_activations_mirror_configured_parameters() {
        // Distinct heights per upgrade, with NU6.1 and NU6.2 left unactivated, so
        // that each `LocalNetwork` field is checked against its own upgrade.
        let params = zcash_protocol::local_consensus::LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: None,
            nu6_2: None,
            nu6_3: None,
            #[cfg(zcash_unstable = "nu7")]
            nu7: None,
        };

        let expected = zcash_protocol::local_consensus::LocalNetwork {
            overwinter: Some(BlockHeight::from_u32(1)),
            sapling: Some(BlockHeight::from_u32(2)),
            blossom: Some(BlockHeight::from_u32(3)),
            heartwood: Some(BlockHeight::from_u32(4)),
            canopy: Some(BlockHeight::from_u32(5)),
            nu5: Some(BlockHeight::from_u32(6)),
            nu6: Some(BlockHeight::from_u32(7)),
            nu6_1: None,
            nu6_2: None,
            nu6_3: None,
            #[cfg(zcash_unstable = "nu7")]
            nu7: None,
        };
        match derive_regtest_activations(&params) {
            zewif_zcashd::RegtestActivations::Local(local) => assert_eq!(local, expected),
            _ => panic!("expected a local activation schedule"),
        }
    }

    #[test]
    fn frontier_conversion_preserves_structure() {
        let empty: Frontier<MerkleHashOrchard, 32> = Frontier::empty();
        assert!(matches!(
            to_zewif_frontier(&empty, |n| n.to_bytes()),
            zewif::Frontier::Empty
        ));

        let frontier: Frontier<MerkleHashOrchard, 32> =
            Frontier::from_parts(Position::from(1), node(2), vec![node(3)])
                .expect("valid frontier");
        match to_zewif_frontier(&frontier, |n| n.to_bytes()) {
            zewif::Frontier::NonEmpty(data) => {
                assert_eq!(data.position(), 1);
                assert_eq!(data.leaf().as_bytes(), &node(2).to_bytes());
                assert_eq!(data.ommers().len(), 1);
                assert_eq!(data.ommers()[0].as_bytes(), &node(3).to_bytes());
            }
            zewif::Frontier::Empty => panic!("frontier should be non-empty"),
        }
    }

    fn imported_account(name: &str) -> ImportedAccount {
        ImportedAccount {
            name: name.into(),
            account_uuid: AccountUuid::from_uuid(uuid::Uuid::nil()),
            birthday_basis: BirthdayBasis::ChainState,
        }
    }

    fn skipped_account(name: &str) -> SkippedAccount {
        SkippedAccount {
            name: name.into(),
            reason: AccountSkipReason::SproutViewingKey,
        }
    }

    fn skipped_transparent_key() -> SkippedTransparentKey {
        SkippedTransparentKey {
            address: Some("t1ExampleAddress".into()),
            reason: TransparentKeySkipReason::NoOwningAccount,
        }
    }

    #[test]
    fn empty_import_from_nonempty_document_is_a_hard_error() {
        let report = ZewifImportReport::default();
        for allow_partial_import in [false, true] {
            assert!(matches!(
                check_import_report(&report, 1, allow_partial_import),
                Err(MigrateError::NothingImported {
                    document_account_count: 1
                })
            ));
        }
    }

    #[test]
    fn empty_import_from_empty_document_is_not_an_error() {
        assert!(check_import_report(&ZewifImportReport::default(), 0, false).is_ok());
    }

    #[test]
    fn skipped_accounts_fail_without_allow_partial_import() {
        let report = ZewifImportReport {
            imported_accounts: vec![imported_account("imported")],
            skipped_accounts: vec![skipped_account("sprout")],
            ..Default::default()
        };
        assert!(matches!(
            check_import_report(&report, 2, false),
            Err(MigrateError::PartialImport { .. })
        ));
        assert!(check_import_report(&report, 2, true).is_ok());
    }

    #[test]
    fn skipped_transparent_keys_fail_without_allow_partial_import() {
        let report = ZewifImportReport {
            imported_accounts: vec![imported_account("imported")],
            skipped_transparent_keys: vec![skipped_transparent_key()],
            ..Default::default()
        };
        assert!(matches!(
            check_import_report(&report, 1, false),
            Err(MigrateError::PartialImport { .. })
        ));
        assert!(check_import_report(&report, 1, true).is_ok());
    }

    #[test]
    fn all_skipped_report_fails_hard_despite_allow_partial_import() {
        let report = ZewifImportReport {
            skipped_accounts: vec![skipped_account("sprout")],
            ..Default::default()
        };
        assert!(matches!(
            check_import_report(&report, 1, true),
            Err(MigrateError::NothingImported {
                document_account_count: 1
            })
        ));
    }

    #[test]
    fn describe_skipped_items_renders_accounts_and_keys() {
        crate::i18n::load_languages(&[]);
        let skipped_accounts = vec![
            SkippedAccount {
                name: "sprout account".into(),
                reason: AccountSkipReason::SproutViewingKey,
            },
            SkippedAccount {
                name: "bare taddrs".into(),
                reason: AccountSkipReason::TransparentAddressSetWithoutSeed,
            },
        ];
        let skipped_transparent_keys = vec![
            SkippedTransparentKey {
                address: None,
                reason: TransparentKeySkipReason::UncompressedPubKey,
            },
            SkippedTransparentKey {
                address: Some("t1ExampleAddress".into()),
                reason: TransparentKeySkipReason::NoOwningAccount,
            },
            SkippedTransparentKey {
                address: None,
                reason: TransparentKeySkipReason::NoOwningAccount,
            },
        ];
        let rendered = describe_skipped_items(&skipped_accounts, &skipped_transparent_keys);
        // One bulleted item per skipped account or key.
        assert_eq!(rendered.matches("  - ").count(), 5);
        assert!(rendered.starts_with("  - "));
        assert!(rendered.contains("'sprout account'"));
        assert!(rendered.contains("'bare taddrs'"));
        assert!(rendered.contains("'t1ExampleAddress'"));
        assert!(rendered.contains("unknown address"));
    }

    #[test]
    fn clean_report_passes() {
        let report = ZewifImportReport {
            imported_accounts: vec![imported_account("imported")],
            // Representability limits do not fail the migration.
            redeem_scripts_not_representable: 2,
            transactions_without_raw_data: 3,
            ..Default::default()
        };
        assert!(check_import_report(&report, 1, false).is_ok());
    }

    fn test_document() -> (zewif::Zewif, zewif::SeedFingerprint, zewif::SeedFingerprint) {
        let legacy_fp = zewif_zcashd::zcashd_wallet::encode_seed_fingerprint(&[1u8; 32]);
        let mnemonic_fp = zewif_zcashd::zcashd_wallet::encode_seed_fingerprint(&[2u8; 32]);

        let mut document = zewif::Zewif::new(
            zewif::BlockHeight::from_u32(2_000_000),
            zewif::BlockHash::from_bytes([9u8; 32]),
        );
        let mut wallet = zewif::ZewifWallet::new(zewif::Network::Testnet);

        let mut legacy = zewif::Account::new(zewif::AccountViewingKey::TransparentAddressSet);
        legacy.set_name("Legacy");
        legacy.set_key_source(zewif::KeySource::Derived(zewif::DerivedKeySource::new(
            legacy_fp.clone(),
            ZCASHD_LEGACY_ACCOUNT_INDEX,
            None,
        )));
        wallet.add_account(legacy);
        document.add_wallet(wallet);

        // A mined transaction: it carries a block position.
        let txid = zewif::TxId::from_bytes([4u8; 32]);
        let mut tx = zewif::Transaction::new(txid);
        tx.set_block_position(zewif::TxBlockPosition::new(
            zewif::BlockHash::from_bytes([7u8; 32]),
            0,
        ));
        document.add_transaction(txid, tx);

        (document, legacy_fp, mnemonic_fp)
    }

    #[test]
    fn enrichment_normalizes_legacy_derivation_and_retains_transactions() {
        let (mut document, _legacy_fp, mnemonic_fp) = test_document();

        // Add a never-mined transaction (no block position) alongside the mined one
        // from `test_document`; a chain scan cannot recover it, so enrichment must
        // keep it.
        let unmined_txid = zewif::TxId::from_bytes([5u8; 32]);
        document.add_transaction(unmined_txid, zewif::Transaction::new(unmined_txid));

        let enriched = enriched_document(
            &document,
            None,
            Some(&mnemonic_fp),
            None,
            None,
            Some(BlockHeight::from_u32(1_900_000)),
        );

        let account = &enriched.wallets()[0].accounts()[0];
        match account.key_source() {
            Some(zewif::KeySource::Derived(derived)) => {
                assert_eq!(derived.seed_fingerprint(), &mnemonic_fp);
                assert_eq!(derived.account_index(), ZCASHD_LEGACY_ACCOUNT_INDEX);
            }
            other => panic!("unexpected key source: {other:?}"),
        }
        // The no-scan estimate fills in the missing birthday.
        assert_eq!(
            account.birthday_height(),
            Some(zewif::BlockHeight::from_u32(1_900_000))
        );
        // Both the mined and the unmined transaction are retained for direct import.
        assert_eq!(enriched.transactions().len(), 2);
        assert!(enriched.transactions().contains_key(&unmined_txid));
    }

    #[test]
    fn enrichment_applies_chain_state_and_retains_transactions() {
        let (document, legacy_fp, _mnemonic_fp) = test_document();

        let mut chain_state = zewif::ChainState::new(zewif::BlockHeight::from_u32(1_500_000));
        chain_state.set_block_hash(zewif::BlockHash::from_bytes([8u8; 32]));

        let enriched = enriched_document(
            &document,
            None,
            None,
            Some(&chain_state),
            Some(BlockHeight::from_u32(2_000_000)),
            None,
        );

        let account = &enriched.wallets()[0].accounts()[0];
        // Without a mnemonic fingerprint the legacy derivation is untouched.
        match account.key_source() {
            Some(zewif::KeySource::Derived(derived)) => {
                assert_eq!(derived.seed_fingerprint(), &legacy_fp);
            }
            other => panic!("unexpected key source: {other:?}"),
        }
        assert_eq!(
            account
                .birthday_chain_state()
                .map(|cs| u32::from(cs.height())),
            Some(1_500_000)
        );
        assert_eq!(
            account.recover_until_height(),
            Some(zewif::BlockHeight::from_u32(2_000_000))
        );
        assert_eq!(enriched.transactions().len(), 1);
    }

    /// A document as produced from a wallet with no HD seed material: the legacy
    /// account arrives with `KeySource::Imported`, alongside an unrelated imported
    /// account.
    fn seedless_document() -> zewif::Zewif {
        let mut document = zewif::Zewif::new(
            zewif::BlockHeight::from_u32(2_000_000),
            zewif::BlockHash::from_bytes([9u8; 32]),
        );
        let mut wallet = zewif::ZewifWallet::new(zewif::Network::Testnet);

        let mut legacy = zewif::Account::new(zewif::AccountViewingKey::TransparentAddressSet);
        legacy.set_name("Legacy");
        legacy.set_key_source(zewif::KeySource::Imported);
        legacy.set_provenance(ZCASHD_LEGACY_SOURCE);
        wallet.add_account(legacy);

        let mut other = zewif::Account::new(zewif::AccountViewingKey::TransparentAddressSet);
        other.set_name("Other");
        other.set_key_source(zewif::KeySource::Imported);
        wallet.add_account(other);

        document.add_wallet(wallet);
        document
    }

    #[test]
    fn minted_mnemonic_is_stored_and_its_fingerprint_round_trips() {
        let mut store = zewif::SecretStore::new();
        let fp = mint_legacy_mnemonic(&mut store);

        let entry = store
            .seeds()
            .iter()
            .find(|entry| entry.fingerprint() == &fp)
            .expect("minted seed is stored under its fingerprint");
        let phrase = match entry.material() {
            zewif::SeedMaterial::Bip39Mnemonic(m) => m.mnemonic().clone(),
            _ => panic!("minted seed material should be a BIP 39 mnemonic"),
        };

        // The stored phrase is a valid 24-word English mnemonic whose seed
        // reproduces the stored fingerprint (the importer verifies exactly this).
        let mnemonic = bip0039::Mnemonic::<bip0039::English>::from_phrase(&phrase)
            .expect("stored phrase is a valid English mnemonic");
        assert_eq!(phrase.split_whitespace().count(), 24);
        let expected = zip32::fingerprint::SeedFingerprint::from_seed(&mnemonic.to_seed(""))
            .expect("BIP 39 seeds have a valid length");
        assert_eq!(
            fp,
            zewif_zcashd::zcashd_wallet::encode_seed_fingerprint(&expected.to_bytes())
        );
    }

    #[test]
    fn minting_twice_yields_distinct_mnemonics() {
        let mut store = zewif::SecretStore::new();
        let fp_a = mint_legacy_mnemonic(&mut store);
        let fp_b = mint_legacy_mnemonic(&mut store);

        assert_ne!(fp_a, fp_b);
        let phrases: Vec<_> = store
            .seeds()
            .iter()
            .map(|entry| match entry.material() {
                zewif::SeedMaterial::Bip39Mnemonic(m) => m.mnemonic().clone(),
                _ => panic!("minted seed material should be a BIP 39 mnemonic"),
            })
            .collect();
        assert_eq!(phrases.len(), 2);
        assert_ne!(phrases[0], phrases[1]);
    }

    #[test]
    fn has_seedless_legacy_account_requires_missing_derivation_root() {
        assert!(has_seedless_legacy_account(&seedless_document()));

        // A wallet whose legacy account already has a derivation root does not
        // trigger minting.
        let (derived_document, _, _) = test_document();
        assert!(!has_seedless_legacy_account(&derived_document));
    }

    #[test]
    fn enrichment_anchors_seedless_legacy_account_to_minted_mnemonic() {
        let document = seedless_document();
        let mut store = zewif::SecretStore::new();
        let minted_fp = mint_legacy_mnemonic(&mut store);

        let enriched =
            enriched_document(&document, Some(store), Some(&minted_fp), None, None, None);

        let accounts = enriched.wallets()[0].accounts();
        // The legacy account is anchored to the minted mnemonic.
        match accounts[0].key_source() {
            Some(zewif::KeySource::Derived(derived)) => {
                assert_eq!(derived.seed_fingerprint(), &minted_fp);
                assert_eq!(derived.account_index(), ZCASHD_LEGACY_ACCOUNT_INDEX);
                assert_eq!(derived.legacy_address_index(), None);
            }
            other => panic!("unexpected key source: {other:?}"),
        }
        // A non-legacy imported account is left untouched.
        assert_eq!(accounts[1].key_source(), Some(&zewif::KeySource::Imported));
        // The minted seed travels with the document for the importer to resolve.
        match enriched.secrets() {
            Some(zewif::Secrets::Plain(store)) => assert_eq!(store.seeds().len(), 1),
            other => panic!("unexpected secrets: {other:?}"),
        }
    }

    #[test]
    fn backfill_sets_mined_height_from_resolved_blocks_only() {
        let (mut document, _legacy_fp, _mnemonic_fp) = test_document();

        // A transaction with a zcashd-recorded (Orchard-derived) mined height;
        // backfill must not override it even though its block hash resolves to a
        // different height.
        let orchard_txid = zewif::TxId::from_bytes([5u8; 32]);
        let mut orchard_tx = zewif::Transaction::new(orchard_txid);
        orchard_tx.set_block_position(zewif::TxBlockPosition::new(
            zewif::BlockHash::from_bytes([7u8; 32]),
            1,
        ));
        orchard_tx.set_mined_height(zewif::BlockHeight::from_u32(1_600_000));
        document.add_transaction(orchard_txid, orchard_tx);

        // A transaction recorded against a block that did not resolve to a
        // main-chain height (e.g. an orphaned block).
        let orphan_txid = zewif::TxId::from_bytes([6u8; 32]);
        let mut orphan_tx = zewif::Transaction::new(orphan_txid);
        orphan_tx.set_block_position(zewif::TxBlockPosition::new(
            zewif::BlockHash::from_bytes([13u8; 32]),
            0,
        ));
        document.add_transaction(orphan_txid, orphan_tx);

        // A never-mined transaction (no block position).
        let unmined_txid = zewif::TxId::from_bytes([12u8; 32]);
        document.add_transaction(unmined_txid, zewif::Transaction::new(unmined_txid));

        let block_heights =
            HashMap::from([(BlockHash([7u8; 32]), BlockHeight::from_u32(1_700_000))]);
        backfill_mined_heights(&mut document, &block_heights);

        let txs = document.transactions();
        // The height-less transaction mined in the resolved block gains its height.
        assert_eq!(
            txs[&zewif::TxId::from_bytes([4u8; 32])].mined_height(),
            Some(zewif::BlockHeight::from_u32(1_700_000))
        );
        // The zcashd-recorded mined height is untouched.
        assert_eq!(
            txs[&orchard_txid].mined_height(),
            Some(zewif::BlockHeight::from_u32(1_600_000))
        );
        // Transactions in unresolved blocks or never mined stay height-less.
        assert_eq!(txs[&orphan_txid].mined_height(), None);
        assert_eq!(txs[&unmined_txid].mined_height(), None);
    }
}
