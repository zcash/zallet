use std::collections::{BTreeMap, HashMap, HashSet, hash_map::Entry};
use std::path::PathBuf;

use abscissa_core::Runnable;

use secp256k1::PublicKey;
use secrecy::SecretVec;
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::{
    Account as _, AccountSource, WalletRead, WalletWrite as _, chain::ChainState,
};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_client_sqlite::zewif::{DiscardSecrets, SecretSink, ZewifImportError, ZewifImportReport};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, NetworkType, NetworkUpgrade, Parameters};
use zewif_zcashd::{BDBDump, ZcashdDump, ZcashdParser, ZcashdWallet};
use zip32::fingerprint::SeedFingerprint;

use crate::{
    cli::MigrateZcashdWalletCmd,
    components::{
        chain::{Chain, ChainError, ChainFactory, ChainView},
        database::Database,
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

        if !self.this_is_alpha_code_and_you_will_need_to_redo_the_migration_later {
            return Err(ErrorKind::Generic.context(fl!("migrate-alpha-code")).into());
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
        let wallet = self.dump_wallet()?;
        info!("Wallet dumped");

        Self::migrate_zcashd_wallet(
            db,
            keystore,
            chain,
            wallet,
            self.buffer_wallet_transactions,
            self.allow_multiple_wallet_imports,
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
    fn dump_wallet(&self) -> Result<ZcashdWallet, MigrateError> {
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

        let (zcashd_wallet, _unparsed_keys) =
            ZcashdParser::parse_dump(&zcashd_dump, !self.allow_warnings).map_err(|e| {
                MigrateError::Zewif {
                    error_type: ZewifError::ZcashdDump,
                    wallet_path,
                    error: e.into(),
                }
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
            // The ZeWIF importer cannot verify the equivalence of regtest activation
            // schedules, so regtest migrations are not currently supported.
            (zewif::Network::Regtest(_), NetworkType::Regtest) => {
                Err(MigrateError::NetworkNotSupported)
            }
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
        buffer_wallet_transactions: bool,
        allow_multiple_wallet_imports: bool,
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
        let document = zewif_zcashd::migrate_to_zewif(
            &wallet,
            zewif::BlockHeight::from_u32(u32::from(export_height)),
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
            buffer_wallet_transactions,
        );

        // Persist all spending material in the keystore before any wallet-database
        // write occurs. This runs outside the wallet database's write lock: the
        // keystore shares that lock, so diverting secrets from within `import_wallet`
        // (which holds the write lock for its whole run) would deadlock.
        let mut sink = KeyStoreSecretSink::new(&keystore, network_params).await?;
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
        if let Some(fp) = mnemonic_fp.as_ref() {
            println!(
                "{}",
                fl!("migrate-wallet-legacy-seed-fp", seed_fp = fp.encoding())
            );
        }

        // Import the document. All secret material was persisted above, so the
        // importer's sink discards its (repeated) deliveries.
        info!("Importing the ZeWIF document into the wallet database");
        let report = db_data
            .with_mut(|mut wdb| {
                zcash_client_sqlite::zewif::import_wallet(&mut wdb, &document, &mut DiscardSecrets)
            })
            .map_err(MigrateError::Import)?;

        log_import_report(&report);

        // Register watch-only transparent pubkeys (from zcashd's `importpubkey`) with
        // the accounts whose address lists carry them. The ZeWIF importer registers
        // spendable transparent keys from the secret store and P2SH redeem scripts,
        // but has no path for pubkey-only (watch) addresses.
        let accounts_by_name: HashMap<&str, zcash_client_sqlite::AccountUuid> = report
            .imported_accounts
            .iter()
            .map(|a| (a.name.as_str(), a.account_uuid))
            .collect();
        let exposure_height = birthday_chain_state
            .as_ref()
            .map(|cs| BlockHeight::from_u32(u32::from(cs.height()) + 1))
            .or(no_scan_birthday_estimate)
            .unwrap_or(sapling_activation);
        let mut skipped_uncompressed_watch_pubkeys = 0usize;
        for wallet in document.wallets() {
            for account in wallet.accounts() {
                let Some(account_uuid) = accounts_by_name.get(account.name()) else {
                    continue;
                };
                let mut watch_pubkeys = Vec::new();
                for address in account.addresses() {
                    if let zewif::ProtocolAddress::Transparent(t) = address.address()
                        && t.spend_authority().is_none()
                        && let Some(pubkey) = t.pubkey()
                    {
                        // `import_standalone_transparent_pubkeys` derives the stored
                        // P2PKH address from the compressed pubkey serialization, so an
                        // uncompressed pubkey would be tracked under a different
                        // address than zcashd had on-chain.
                        match PublicKey::from_slice(pubkey.as_slice()) {
                            Ok(pk) if pubkey.as_slice().len() == 33 => watch_pubkeys.push(pk),
                            _ => skipped_uncompressed_watch_pubkeys += 1,
                        }
                    }
                }
                if !watch_pubkeys.is_empty() {
                    info!(
                        "Registering {} watch-only transparent pubkeys with account '{}'",
                        watch_pubkeys.len(),
                        account.name(),
                    );
                    let to_expose: Vec<(TransparentAddress, BlockHeight)> = watch_pubkeys
                        .iter()
                        .map(|pk| (TransparentAddress::from_pubkey(pk), exposure_height))
                        .collect();
                    db_data
                        .import_standalone_transparent_pubkeys(
                            *account_uuid,
                            watch_pubkeys.into_iter(),
                        )
                        .map_err(MigrateError::Database)?;
                    db_data
                        .mark_transparent_addresses_exposed(&to_expose)
                        .map_err(MigrateError::Database)?;
                }
            }
        }
        if skipped_uncompressed_watch_pubkeys > 0 {
            warn!(
                "Skipped {} watch-only entries with uncompressed or malformed public \
                 keys; Zallet only supports compressed-form pubkey imports.",
                skipped_uncompressed_watch_pubkeys,
            );
        }

        Ok(())
    }
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

/// Rebuilds `document` with Zallet's enrichments applied.
///
/// The ZeWIF document model does not expose mutable access to the accounts of an
/// assembled document, so enrichment reassembles it:
///
/// * the (possibly normalized) secret store replaces the original;
/// * the legacy account's key source is re-pointed at the mnemonic seed, matching
///   zcashd's post-v4.7.0 derivation semantics;
/// * account birthdays are replaced with the chain-derived birthday state where one
///   was computed, and defaulted to the no-scan estimate where the document records
///   nothing; and
/// * transactions are dropped unless `--buffer-wallet-transactions` was given.
fn enriched_document(
    document: &zewif::Zewif,
    secret_store: Option<zewif::SecretStore>,
    mnemonic_fp: Option<&zewif::SeedFingerprint>,
    birthday_chain_state: Option<&zewif::ChainState>,
    recover_until: Option<BlockHeight>,
    no_scan_birthday_estimate: Option<BlockHeight>,
    buffer_wallet_transactions: bool,
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

    if buffer_wallet_transactions {
        out.set_transactions(document.transactions().clone());
    } else {
        out.set_transactions(BTreeMap::new());
    }

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
            "Skipped {} watch-only redeem scripts that the wallet cannot represent",
            report.redeem_scripts_not_representable,
        );
    }
    info!(
        "Marked {} transparent addresses as exposed",
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
    NetworkNotSupported,
    Database(SqliteClientError),
    MultiImportDisabled,
    DuplicateImport(SeedFingerprint),
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
            MigrateError::NetworkNotSupported => {
                Error::from(ErrorKind::Generic.context(fl!("err-migrate-wallet-regtest")))
            }
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
