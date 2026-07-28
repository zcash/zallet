use std::collections::HashSet;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{Account, AccountPurpose, WalletRead, WalletWrite};
use zcash_keys::{
    encoding::{decode_extended_full_viewing_key, encode_payment_address},
    keys::UnifiedFullViewingKey,
};
use zcash_protocol::consensus::{BlockHeight, NetworkConstants};

use crate::components::{
    chain::Chain,
    database::DbHandle,
    json_rpc::{server::LegacyCode, utils::fetch_account_birthday},
    sync::WalletSyncReconfiguration,
};

/// Response to a `z_importviewingkey` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// Result of importing a viewing key.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// The type of the imported address (always "sapling").
    address_type: String,

    /// The Sapling payment address corresponding to the imported viewing key
    /// (the default address).
    address: String,
}

pub(super) const PARAM_VKEY_DESC: &str =
    "The viewing key (only Sapling extended full viewing keys are supported).";
pub(super) const PARAM_RESCAN_DESC: &str = "Whether to rescan the blockchain for transactions (\"yes\", \"no\", or \"whenkeyisnew\"; default is \"whenkeyisnew\"). When rescan is enabled, the wallet's background sync engine will scan for historical transactions from the given start height.";
pub(super) const PARAM_START_HEIGHT_DESC: &str = "Block height from which to begin the rescan (default is 0). Only used when rescan is \"yes\" or \"whenkeyisnew\" (for a new key).";

/// Parsed `rescan` parameter for key-import RPCs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RescanPolicy {
    Yes,
    No,
    WhenKeyIsNew,
}

impl RescanPolicy {
    /// Parses the `rescan` parameter string.
    ///
    /// Returns the parsed policy, or an RPC error if the value is invalid.
    fn parse(rescan: Option<&str>) -> RpcResult<Self> {
        match rescan {
            None | Some("whenkeyisnew") => Ok(Self::WhenKeyIsNew),
            Some("yes") => Ok(Self::Yes),
            Some("no") => Ok(Self::No),
            Some(_) => Err(LegacyCode::InvalidParameter.with_static(
                "Invalid rescan value. Must be \"yes\", \"no\", or \"whenkeyisnew\".",
            )),
        }
    }
}

/// Decodes a Sapling extended full viewing key and derives the default payment address.
///
/// Returns the decoded extended full viewing key and the encoded payment address string.
fn decode_vkey_and_address(
    hrp_fvk: &str,
    hrp_payment_address: &str,
    vkey: &str,
) -> RpcResult<(sapling::zip32::ExtendedFullViewingKey, String)> {
    let extfvk = decode_extended_full_viewing_key(hrp_fvk, vkey).map_err(|e| {
        LegacyCode::InvalidAddressOrKey.with_message(format!("Invalid viewing key: {e}"))
    })?;

    let (_, payment_address) = extfvk.default_address();

    let address = encode_payment_address(hrp_payment_address, &payment_address);

    Ok((extfvk, address))
}

pub(crate) async fn call<C: Chain>(
    mut wallet: DbHandle,
    chain: C,
    reconfiguration: &WalletSyncReconfiguration,
    vkey: &str,
    rescan: Option<&str>,
    start_height: Option<u64>,
) -> Response {
    enum ViewingKeyImportEffect {
        KeyImported,
        RescanScheduled,
        Unchanged,
    }

    let rescan = RescanPolicy::parse(rescan)?;

    // Parse start_height if provided, keeping it as Option so we can
    // distinguish "not supplied" from "explicitly set to 0" below.
    let start_height = start_height
        .map(|h| {
            u32::try_from(h)
                .map(BlockHeight::from_u32)
                .map_err(|_| LegacyCode::InvalidParameter.with_static("Block height out of range."))
        })
        .transpose()?;

    let chain_tip = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    if let (Some(height), Some(tip)) = (start_height, chain_tip)
        && height > tip
    {
        return Err(LegacyCode::InvalidParameter.with_static("Block height out of range."));
    }

    let hrp_fvk = wallet.params().hrp_sapling_extended_full_viewing_key();
    let hrp_addr = wallet.params().hrp_sapling_payment_address();
    let (extfvk, address) = decode_vkey_and_address(hrp_fvk, hrp_addr, vkey)?;

    // Construct a UFVK from the Sapling extended full viewing key so the wallet can
    // track transactions to/from this key's addresses.
    let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
        .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

    // Check if the key is already known to the wallet.
    let existing_account = wallet
        .get_account_for_ufvk(&ufvk)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
    let birthday = match existing_account {
        Some(account) => {
            if matches!(account.purpose(), AccountPurpose::Spending { .. }) {
                return Err(LegacyCode::Wallet.with_message(format!(
                    "The wallet already contains the private key for this viewing key (address: {address})",
                )));
            }
            match rescan {
                RescanPolicy::Yes => {
                    fetch_account_birthday(&chain, start_height.unwrap_or(BlockHeight::from_u32(0)))
                        .await?
                }
                RescanPolicy::No | RescanPolicy::WhenKeyIsNew => {
                    return Ok(ResultType {
                        address_type: "sapling".to_string(),
                        address,
                    });
                }
            }
        }
        None => {
            // new key
            let effective_height = match rescan {
                RescanPolicy::Yes | RescanPolicy::WhenKeyIsNew => {
                    start_height.unwrap_or(BlockHeight::from_u32(0))
                }
                RescanPolicy::No => {
                    start_height.unwrap_or_else(|| chain_tip.unwrap_or(BlockHeight::from_u32(0)))
                }
            };

            fetch_account_birthday(&chain, effective_height).await?
        }
    };

    let admitted = reconfiguration.admit_reconfiguration().await;
    let existing_account = wallet
        .get_account_for_ufvk(&ufvk)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
    let effect = match existing_account {
        Some(account) => {
            if matches!(account.purpose(), AccountPurpose::Spending { .. }) {
                return Err(LegacyCode::Wallet.with_message(format!(
                    "The wallet already contains the private key for this viewing key (address: {address})",
                )));
            }
            if rescan == RescanPolicy::Yes {
                wallet
                    .rewind_to_chain_state(
                        birthday.prior_chain_state().clone(),
                        HashSet::from([account.id()]),
                    )
                    .map_err(|e| LegacyCode::Misc.with_message(format!("Rescan failed: {e}")))?;
                ViewingKeyImportEffect::RescanScheduled
            } else {
                ViewingKeyImportEffect::Unchanged
            }
        }
        None => {
            wallet
                .import_account_ufvk(
                    &format!("Imported Sapling viewing key {address}"),
                    &ufvk,
                    &birthday,
                    AccountPurpose::ViewOnly,
                    None,
                )
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
            ViewingKeyImportEffect::KeyImported
        }
    };
    drop(wallet);

    match effect {
        ViewingKeyImportEffect::RescanScheduled => admitted.wake_history_recovery(),
        ViewingKeyImportEffect::KeyImported => {
            if !admitted.reload_keys_and_wake_history_recovery().await {
                tracing::warn!(
                    "sync engine has shut down; imported viewing key won't be scanned until restart"
                );
            }
        }
        ViewingKeyImportEffect::Unchanged => {}
    }

    Ok(ResultType {
        address_type: "sapling".to_string(),
        address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        components::{
            chain::MockChain,
            database::Database,
            sync::{WalletSync, WalletSyncReconfiguration},
        },
        config::ZalletConfig,
    };
    use zcash_client_backend::data_api::{
        AccountBirthday, ScannedBlock, WalletRead, WalletWrite,
        chain::ChainState,
        scanning::{ScanPriority, ScanRange},
    };
    use zcash_client_backend::{
        proto::compact_formats::{ChainMetadata, CompactBlock},
        scanning::{Nullifiers, ScanningKeys, scan_block},
    };
    use zcash_client_sqlite::AccountUuid;
    use zcash_keys::encoding::encode_extended_full_viewing_key;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::constants;

    /// Derives a test extended full viewing key from seed [0; 32] and encodes it.
    fn encoded_mainnet_extfvk() -> String {
        encoded_mainnet_extfvk_for_seed([0; 32])
    }

    fn encoded_mainnet_extfvk_for_seed(seed: [u8; 32]) -> String {
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&seed);
        #[allow(deprecated)]
        let extfvk = extsk.to_extended_full_viewing_key();
        encode_extended_full_viewing_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            &extfvk,
        )
    }

    /// Derives a test extended full viewing key from seed [0; 32] and encodes it for testnet.
    fn encoded_testnet_extfvk() -> String {
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&[0; 32]);
        #[allow(deprecated)]
        let extfvk = extsk.to_extended_full_viewing_key();
        encode_extended_full_viewing_key(
            constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            &extfvk,
        )
    }

    fn height(value: u32) -> BlockHeight {
        BlockHeight::from_u32(value)
    }

    fn empty_birthday(value: u32) -> AccountBirthday {
        AccountBirthday::from_parts(
            ChainState::empty(height(value - 1), BlockHash([0; 32])),
            None,
        )
    }

    fn seed_retained_scanned_blocks(wallet: &mut DbHandle) -> Vec<BlockHeight> {
        let scanning_keys = ScanningKeys::<AccountUuid, ()>::empty();
        let nullifiers = Nullifiers::<AccountUuid>::empty();
        let mut retained_blocks: Vec<ScannedBlock<AccountUuid>> = Vec::new();
        for value in 500_048_u32..=500_100 {
            let hash_byte =
                u8::try_from(value - 500_047).expect("retained block offset fits in hash byte");
            let predecessor_hash_byte = u8::try_from(value - 500_048)
                .expect("retained predecessor offset fits in hash byte");
            let scanned = scan_block(
                wallet.params(),
                CompactBlock {
                    height: u64::from(value),
                    hash: vec![hash_byte; 32],
                    prev_hash: vec![predecessor_hash_byte; 32],
                    chain_metadata: Some(ChainMetadata {
                        sapling_commitment_tree_size: 0,
                        orchard_commitment_tree_size: 0,
                        ironwood_commitment_tree_size: 0,
                    }),
                    ..Default::default()
                },
                &scanning_keys,
                &nullifiers,
                retained_blocks
                    .last()
                    .map(|block| block.to_block_metadata())
                    .as_ref(),
            )
            .expect("scans an empty retained block");
            retained_blocks.push(scanned);
        }
        wallet
            .put_blocks(
                &ChainState::empty(height(500_047), BlockHash([0; 32])),
                retained_blocks,
            )
            .expect("seeds retained scanned blocks");
        (500_048..=500_100).map(height).collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn existing_viewing_key_rescan_rewinds_wallet_wide_scan_queue() {
        crate::i18n::load_languages(&[]);
        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let database = Database::open(&config)
            .await
            .expect("creates wallet database");
        let mut wallet = database.handle().await.expect("reserves wallet database");
        let encoded = encoded_mainnet_extfvk();
        let (extfvk, _) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .expect("decodes viewing key");
        let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
            .expect("constructs unified viewing key");
        wallet
            .import_account_ufvk(
                "existing viewing-only account",
                &ufvk,
                &empty_birthday(500_050),
                AccountPurpose::ViewOnly,
                None,
            )
            .expect("imports viewing-only account");
        wallet
            .update_chain_tip(height(500_100))
            .expect("records chain tip");
        let (decryptor, engine) = WalletSync::build_decryptor();
        let reconfiguration = WalletSyncReconfiguration::new(decryptor);

        call(
            wallet,
            MockChain::reporting(Vec::new(), 500_100),
            &reconfiguration,
            &encoded,
            Some("yes"),
            Some(0),
        )
        .await
        .expect("existing viewing key rescan succeeds");

        let wallet = database.handle().await.expect("reopens wallet database");
        let account = wallet
            .get_account_for_ufvk(&ufvk)
            .expect("reads viewing-only account")
            .expect("viewing-only account remains present");
        assert_eq!(
            wallet
                .get_account_birthday(account.id())
                .expect("reads rescan birthday"),
            height(1)
        );
        assert_eq!(
            wallet.suggest_scan_ranges().expect("reads scan queue"),
            vec![ScanRange::from_parts(
                height(1)..height(500_101),
                ScanPriority::Historic,
            )],
        );
        drop(engine);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn existing_viewing_key_rescan_preserves_unrelated_account_birthdays() {
        crate::i18n::load_languages(&[]);
        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let database = Database::open(&config)
            .await
            .expect("creates wallet database");
        let mut wallet = database.handle().await.expect("reserves wallet database");
        let selected_encoded = encoded_mainnet_extfvk();
        let unrelated_encoded = encoded_mainnet_extfvk_for_seed([1; 32]);
        let mut account_ids = Vec::new();
        for (name, encoded, birthday) in [
            ("selected viewing-only account", &selected_encoded, 500_050),
            (
                "unrelated viewing-only account",
                &unrelated_encoded,
                500_070,
            ),
        ] {
            let (extfvk, _) = decode_vkey_and_address(
                constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
                constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
                encoded,
            )
            .expect("decodes viewing key");
            let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
                .expect("constructs unified viewing key");
            account_ids.push(
                wallet
                    .import_account_ufvk(
                        name,
                        &ufvk,
                        &empty_birthday(birthday),
                        AccountPurpose::ViewOnly,
                        None,
                    )
                    .expect("imports viewing-only account")
                    .id(),
            );
        }
        wallet
            .update_chain_tip(height(500_100))
            .expect("records chain tip");
        let (decryptor, engine) = WalletSync::build_decryptor();
        let reconfiguration = WalletSyncReconfiguration::new(decryptor);

        call(
            wallet,
            MockChain::reporting(Vec::new(), 500_100),
            &reconfiguration,
            &selected_encoded,
            Some("yes"),
            Some(0),
        )
        .await
        .expect("existing viewing key rescan succeeds");

        let wallet = database.handle().await.expect("reopens wallet database");
        assert_eq!(
            wallet
                .get_account_birthday(account_ids[0])
                .expect("reads selected birthday"),
            height(1)
        );
        assert_eq!(
            wallet
                .get_account_birthday(account_ids[1])
                .expect("reads unrelated birthday"),
            height(500_070)
        );
        drop(engine);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn existing_viewing_key_predecessor_failure_leaves_wallet_unchanged() {
        crate::i18n::load_languages(&[]);
        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let database = Database::open(&config)
            .await
            .expect("creates wallet database");
        let mut wallet = database.handle().await.expect("reserves wallet database");
        let encoded = encoded_mainnet_extfvk();
        let (extfvk, _) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .expect("decodes viewing key");
        let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
            .expect("constructs unified viewing key");
        let account_id = wallet
            .import_account_ufvk(
                "existing viewing-only account",
                &ufvk,
                &empty_birthday(500_050),
                AccountPurpose::ViewOnly,
                None,
            )
            .expect("imports viewing-only account")
            .id();
        wallet
            .update_chain_tip(height(500_100))
            .expect("records chain tip");
        let retained_heights = seed_retained_scanned_blocks(&mut wallet);
        let birthday_before = wallet
            .get_account_birthday(account_id)
            .expect("reads birthday before failed predecessor fetch");
        let ranges_before = wallet
            .suggest_scan_ranges()
            .expect("reads scan ranges before failed predecessor fetch");
        let hashes_before = retained_heights
            .iter()
            .map(|height| {
                wallet
                    .get_block_hash(*height)
                    .expect("snapshots retained block hash")
            })
            .collect::<Vec<_>>();
        let (decryptor, engine) = WalletSync::build_decryptor();
        let reconfiguration = WalletSyncReconfiguration::new(decryptor);

        let error = call(
            wallet,
            MockChain::reporting(Vec::new(), 500_100),
            &reconfiguration,
            &encoded,
            Some("yes"),
            Some(10),
        )
        .await
        .expect_err("missing predecessor state rejects the rescan");
        assert_eq!(
            error.code(),
            jsonrpsee::types::ErrorCode::InternalError.code()
        );
        assert_eq!(error.message(), "No treestate available at height 9");

        let wallet = database.handle().await.expect("reopens wallet database");
        assert_eq!(
            wallet
                .get_account_birthday(account_id)
                .expect("reads unchanged birthday"),
            birthday_before
        );
        assert_eq!(
            wallet
                .suggest_scan_ranges()
                .expect("reads unchanged scan ranges"),
            ranges_before
        );
        assert_eq!(
            retained_heights
                .iter()
                .map(|height| {
                    wallet
                        .get_block_hash(*height)
                        .expect("reads unchanged retained block hash")
                })
                .collect::<Vec<_>>(),
            hashes_before
        );
        drop(engine);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn existing_viewing_key_rescan_failure_rolls_back_birthdays_scan_ranges_and_blocks() {
        crate::i18n::load_languages(&[]);
        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let database = Database::open(&config)
            .await
            .expect("creates wallet database");
        let mut wallet = database.handle().await.expect("reserves wallet database");
        let encoded = encoded_mainnet_extfvk();
        let unrelated_encoded = encoded_mainnet_extfvk_for_seed([1; 32]);
        let mut account_ids = Vec::new();
        for (name, encoded, birthday) in [
            ("selected viewing-only account", &encoded, 500_050),
            (
                "unrelated viewing-only account",
                &unrelated_encoded,
                500_070,
            ),
        ] {
            let (extfvk, _) = decode_vkey_and_address(
                constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
                constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
                encoded,
            )
            .expect("decodes viewing key");
            let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
                .expect("constructs unified viewing key");
            account_ids.push(
                wallet
                    .import_account_ufvk(
                        name,
                        &ufvk,
                        &empty_birthday(birthday),
                        AccountPurpose::ViewOnly,
                        None,
                    )
                    .expect("imports viewing-only account")
                    .id(),
            );
        }
        let retained_heights = seed_retained_scanned_blocks(&mut wallet);
        wallet
            .update_chain_tip(height(500_100))
            .expect("records chain tip");
        let birthdays_before = account_ids
            .iter()
            .map(|account_id| {
                wallet
                    .get_account_birthday(*account_id)
                    .expect("snapshots account birthday")
            })
            .collect::<Vec<_>>();
        let ranges_before = wallet
            .suggest_scan_ranges()
            .expect("snapshots suggested scan ranges");
        let hashes_before = retained_heights
            .iter()
            .map(|height| {
                wallet
                    .get_block_hash(*height)
                    .expect("snapshots retained block hash")
            })
            .collect::<Vec<_>>();
        wallet
            .with_raw(|connection, _| {
                connection.execute_batch(
                    "CREATE TRIGGER fail_viewing_key_birthday_rewind
                     AFTER UPDATE OF birthday_height ON accounts
                     BEGIN
                         SELECT RAISE(ABORT, 'injected birthday update failure');
                     END;",
                )
            })
            .expect("installs persistent birthday failure trigger");
        let (decryptor, engine) = WalletSync::build_decryptor();
        let reconfiguration = WalletSyncReconfiguration::new(decryptor);

        let error = call(
            wallet,
            MockChain::reporting(Vec::new(), 500_100),
            &reconfiguration,
            &encoded,
            Some("yes"),
            Some(0),
        )
        .await
        .expect_err("injected rewind failure reaches the RPC");
        assert_eq!(error.code(), LegacyCode::Misc as i32);
        assert!(error.message().contains("Rescan failed"));
        assert!(error.message().contains("injected birthday update failure"));

        let wallet = database.handle().await.expect("reopens wallet database");
        wallet
            .with_raw(|connection, _| {
                connection.execute_batch("DROP TRIGGER fail_viewing_key_birthday_rewind;")
            })
            .expect("removes persistent birthday failure trigger");
        assert_eq!(
            account_ids
                .iter()
                .map(|account_id| {
                    wallet
                        .get_account_birthday(*account_id)
                        .expect("reads rolled-back account birthday")
                })
                .collect::<Vec<_>>(),
            birthdays_before
        );
        assert_eq!(
            wallet
                .suggest_scan_ranges()
                .expect("reads rolled-back scan ranges"),
            ranges_before
        );
        assert_eq!(
            retained_heights
                .iter()
                .map(|height| {
                    wallet
                        .get_block_hash(*height)
                        .expect("reads rolled-back retained block hash")
                })
                .collect::<Vec<_>>(),
            hashes_before
        );
        drop(engine);
    }

    // -- RescanPolicy::parse tests --

    #[test]
    fn rescan_none_defaults_to_whenkeyisnew() {
        assert_eq!(
            RescanPolicy::parse(None).unwrap(),
            RescanPolicy::WhenKeyIsNew
        );
    }

    #[test]
    fn rescan_whenkeyisnew() {
        assert_eq!(
            RescanPolicy::parse(Some("whenkeyisnew")).unwrap(),
            RescanPolicy::WhenKeyIsNew
        );
    }

    #[test]
    fn rescan_yes() {
        assert_eq!(RescanPolicy::parse(Some("yes")).unwrap(), RescanPolicy::Yes);
    }

    #[test]
    fn rescan_no() {
        assert_eq!(RescanPolicy::parse(Some("no")).unwrap(), RescanPolicy::No);
    }

    #[test]
    fn rescan_invalid_value() {
        assert!(RescanPolicy::parse(Some("always")).is_err());
        assert!(RescanPolicy::parse(Some("")).is_err());
        assert!(RescanPolicy::parse(Some("true")).is_err());
    }

    // -- decode_vkey_and_address tests --

    #[test]
    fn decode_valid_mainnet_vkey() {
        let encoded = encoded_mainnet_extfvk();
        let (_, address) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        // Mainnet Sapling addresses start with "zs1".
        assert!(address.starts_with("zs1"));
    }

    #[test]
    fn decode_valid_testnet_vkey() {
        let encoded = encoded_testnet_extfvk();
        let (_, address) = decode_vkey_and_address(
            constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        // Testnet Sapling addresses start with "ztestsapling1".
        assert!(address.starts_with("ztestsapling1"));
    }

    #[test]
    fn decode_same_key_produces_same_address_across_calls() {
        let encoded = encoded_mainnet_extfvk();

        let (_, addr1) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        let (_, addr2) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        assert_eq!(addr1, addr2);
    }

    #[test]
    fn decode_roundtrip() {
        let encoded = encoded_mainnet_extfvk();
        let (extfvk, _) = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &encoded,
        )
        .unwrap();

        let re_encoded = encode_extended_full_viewing_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            &extfvk,
        );
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn decode_invalid_vkey() {
        let result = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "not-a-valid-key",
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_wrong_network_vkey() {
        // Testnet viewing key decoded with mainnet HRP should fail.
        let testnet_encoded = encoded_testnet_extfvk();
        let result = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &testnet_encoded,
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_empty_vkey() {
        let result = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "",
        );
        assert!(result.is_err());
    }

    #[test]
    fn decode_spending_key_rejected_as_viewing_key() {
        // A spending key string should be rejected when decoded as a viewing key,
        // since the HRP will not match.
        let extsk = sapling::zip32::ExtendedSpendingKey::master(&[0; 32]);
        let spending_key_encoded = zcash_keys::encoding::encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &extsk,
        );

        let result = decode_vkey_and_address(
            constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            &spending_key_encoded,
        );
        assert!(result.is_err());
    }
}
