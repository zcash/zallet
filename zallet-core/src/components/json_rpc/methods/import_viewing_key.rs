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
        ViewingKeyImportEffect::RescanScheduled => admitted.wake_wallet_recovery(),
        ViewingKeyImportEffect::KeyImported => {
            if !admitted.reload_keys_and_wake_wallet_recovery().await {
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
    use std::{ops::Range, sync::Arc, time::Duration};

    use super::*;
    use crate::{
        components::{
            chain::{
                BlockLocator, Chain, ChainBlock, ChainError, ChainTx, ChainView, MockChain,
                ReportedUpgrade,
            },
            database::Database,
            sync::{WalletSync, WalletSyncReconfiguration, status},
        },
        config::ZalletConfig,
        error::Error,
        network::Network,
    };
    use futures::{
        StreamExt as _,
        stream::{self, BoxStream},
    };
    #[cfg(not(feature = "spend-index"))]
    use transparent::address::TransparentAddress;
    #[cfg(feature = "spend-index")]
    use transparent::bundle::OutPoint;
    use transparent::{
        builder::Coinbase,
        bundle::{Bundle, TxIn},
    };
    use zcash_client_backend::data_api::{
        AccountBirthday, ScannedBlock, TransactionStatus, WalletRead, WalletWrite,
        chain::{ChainState, CommitmentTreeRoot},
        scanning::{ScanPriority, ScanRange},
    };
    use zcash_client_backend::{
        proto::compact_formats::{ChainMetadata, CompactBlock},
        scanning::{Nullifiers, ScanningKeys, scan_block},
    };
    use zcash_client_sqlite::AccountUuid;
    use zcash_encoding::CompactSize;
    use zcash_keys::encoding::encode_extended_full_viewing_key;
    use zcash_primitives::{
        block::{Block, BlockHash, BlockHeader, BlockHeaderData},
        transaction::{Authorized, Transaction, TransactionData, TxVersion},
    };
    use zcash_protocol::{
        TxId,
        consensus::{BranchId, Network as ConsensusNetwork},
        constants,
    };

    const FIXED_TIP: u32 = 3;

    #[derive(Clone)]
    struct FixedTipChain {
        network: Network,
        mempool_follow_started: Arc<tokio::sync::Notify>,
    }

    impl FixedTipChain {
        fn new(network: Network) -> Self {
            Self {
                network,
                mempool_follow_started: Arc::new(tokio::sync::Notify::new()),
            }
        }
    }

    #[derive(Clone)]
    struct FixedTipView {
        mempool_follow_started: Arc<tokio::sync::Notify>,
    }

    impl Chain for FixedTipChain {
        type View = FixedTipView;

        fn params(&self) -> &Network {
            &self.network
        }

        async fn reported_upgrades(&self) -> Result<Vec<ReportedUpgrade>, Error> {
            Ok(Vec::new())
        }

        async fn broadcast_transaction(&self, _tx: &Transaction) -> Result<(), ChainError> {
            Err(ChainError::backend(
                "fixed-tip test chain does not broadcast transactions",
            ))
        }

        async fn get_sapling_subtree_roots(
            &self,
        ) -> Result<Vec<CommitmentTreeRoot<sapling::Node>>, ChainError> {
            Ok(Vec::new())
        }

        async fn get_orchard_subtree_roots(
            &self,
        ) -> Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError> {
            Ok(Vec::new())
        }

        async fn get_ironwood_subtree_roots(
            &self,
        ) -> Result<Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>>, ChainError> {
            Ok(Vec::new())
        }

        async fn snapshot(&self) -> Result<Self::View, ChainError> {
            Ok(FixedTipView {
                mempool_follow_started: self.mempool_follow_started.clone(),
            })
        }
    }

    impl ChainView for FixedTipView {
        async fn tip(&self) -> Result<ChainBlock, ChainError> {
            Ok(chain_block(height(FIXED_TIP)))
        }

        async fn find_fork_point(
            &self,
            locator: &BlockLocator,
        ) -> Result<Option<ChainBlock>, ChainError> {
            Ok((0..=FIXED_TIP).rev().find_map(|value| {
                let block = chain_block(height(value));
                locator.hashes().contains(&block.hash()).then_some(block)
            }))
        }

        async fn tree_state_as_of(
            &self,
            height: BlockHeight,
        ) -> Result<Option<ChainState>, ChainError> {
            Ok((height <= BlockHeight::from_u32(FIXED_TIP))
                .then(|| ChainState::empty(height, fixed_header(height).hash())))
        }

        async fn get_block_header(
            &self,
            height: BlockHeight,
        ) -> Result<Option<BlockHeader>, ChainError> {
            Ok((height <= BlockHeight::from_u32(FIXED_TIP)).then(|| fixed_header(height)))
        }

        async fn get_block(&self, height: BlockHeight) -> Result<Option<Block>, ChainError> {
            Ok((height <= BlockHeight::from_u32(FIXED_TIP)).then(|| fixed_block(height)))
        }

        fn stream_blocks_to_tip(
            &self,
            start: BlockHeight,
        ) -> BoxStream<'_, Result<Block, ChainError>> {
            stream::iter(
                (u32::from(start)..=FIXED_TIP)
                    .map(|value| Ok(fixed_block(height(value))))
                    .collect::<Vec<_>>(),
            )
            .boxed()
        }

        fn stream_blocks(
            &self,
            range: &Range<BlockHeight>,
        ) -> BoxStream<'_, Result<Block, ChainError>> {
            stream::iter(
                (u32::from(range.start)..u32::from(range.end))
                    .map(|value| Ok(fixed_block(height(value))))
                    .collect::<Vec<_>>(),
            )
            .boxed()
        }

        async fn get_mempool_stream(
            &self,
        ) -> Result<Option<BoxStream<'_, Transaction>>, ChainError> {
            self.mempool_follow_started.notify_one();
            Ok(Some(stream::pending().boxed()))
        }

        async fn get_transaction(&self, _txid: TxId) -> Result<Option<ChainTx>, ChainError> {
            Ok(None)
        }

        async fn get_transaction_status(
            &self,
            _txid: TxId,
        ) -> Result<TransactionStatus, ChainError> {
            Ok(TransactionStatus::TxidNotRecognized)
        }

        #[cfg(feature = "spend-index")]
        async fn outpoint_spend_status(
            &self,
            _outpoint: &OutPoint,
        ) -> Result<crate::components::chain::SpendStatus, ChainError> {
            Ok(crate::components::chain::SpendStatus::Unspent)
        }

        #[cfg(not(feature = "spend-index"))]
        async fn get_address_unspent_outpoints(
            &self,
            _address: &TransparentAddress,
        ) -> Result<Vec<(TxId, u32)>, ChainError> {
            Ok(Vec::new())
        }

        #[cfg(not(feature = "spend-index"))]
        async fn get_address_tx_ids(
            &self,
            _address: &TransparentAddress,
            _range: Range<BlockHeight>,
        ) -> Result<Vec<TxId>, ChainError> {
            Ok(Vec::new())
        }

        #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
        async fn block_height(&self, _hash: &BlockHash) -> Result<Option<BlockHeight>, ChainError> {
            Ok(None)
        }
    }

    fn chain_block(height: BlockHeight) -> ChainBlock {
        ChainBlock::new(height, fixed_header(height).hash())
    }

    fn fixed_header(height: BlockHeight) -> BlockHeader {
        let value = u32::from(height);
        BlockHeaderData {
            version: 4,
            prev_block: if value == 0 {
                BlockHash([0; 32])
            } else {
                fixed_header(BlockHeight::from_u32(value - 1)).hash()
            },
            merkle_root: [0; 32],
            final_sapling_root: [0; 32],
            time: 0,
            bits: 0,
            nonce: [u8::try_from(value).expect("test height fits in one byte"); 32],
            solution: vec![],
        }
        .freeze()
        .expect("test block header is structurally valid")
    }

    fn fixed_block(height: BlockHeight) -> Block {
        let header = fixed_header(height);
        let coinbase_authorization = Coinbase;
        let transparent_bundle = Bundle {
            vin: vec![
                TxIn::<Coinbase>::coinbase(height, None)
                    .expect("test coinbase height is structurally valid"),
            ],
            vout: Vec::new(),
            authorization: coinbase_authorization.clone(),
        }
        .map_authorization(coinbase_authorization);
        let transaction = TransactionData::<Authorized>::from_parts(
            TxVersion::suggested_for_branch(BranchId::Sprout),
            BranchId::Sprout,
            0,
            height,
            Some(transparent_bundle),
            None,
            None,
            None,
        )
        .freeze()
        .expect("test transaction is structurally valid");

        let mut bytes = Vec::new();
        header
            .write(&mut bytes)
            .expect("serializes test block header");
        CompactSize::write(&mut bytes, 1).expect("serializes test transaction count");
        transaction
            .write(&mut bytes)
            .expect("serializes test coinbase transaction");

        Block::read(bytes.as_slice(), &ConsensusNetwork::MainNetwork)
            .expect("test block is structurally valid")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn hot_viewing_key_import_scans_to_an_unchanged_near_tip() {
        crate::i18n::load_languages(&[]);
        let datadir = tempfile::tempdir().expect("creates temporary data directory");
        let config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            ..Default::default()
        };
        let database = Database::open(&config)
            .await
            .expect("creates wallet database");
        let chain = FixedTipChain::new(config.consensus.network());
        let (decryptor, decryptor_engine) = WalletSync::build_decryptor();
        let reconfiguration = WalletSyncReconfiguration::new(decryptor);
        let (sync_status, _sync_status_reader) = status::channel(config.sync.lock_threshold());
        let (steady_state, recover_history, batch_decryptor, data_requests) = WalletSync::spawn(
            &config,
            database.clone(),
            chain.clone(),
            None,
            reconfiguration.clone(),
            decryptor_engine,
            sync_status,
        )
        .await
        .expect("starts wallet sync against the fixed-tip chain");

        tokio::time::timeout(
            Duration::from_secs(1),
            chain.mempool_follow_started.notified(),
        )
        .await
        .expect("steady-state sync reaches stable mempool follow");

        call(
            database
                .handle()
                .await
                .expect("opens wallet for hot viewing-key import"),
            chain,
            &reconfiguration,
            &encoded_mainnet_extfvk(),
            Some("yes"),
            Some(0),
        )
        .await
        .expect("imports viewing key while wallet sync is running");

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let wallet = database
                    .handle()
                    .await
                    .expect("opens wallet while waiting for near-tip recovery");
                let pending_ranges = wallet
                    .suggest_scan_ranges()
                    .expect("reads suggested scan ranges");
                if pending_ranges.is_empty() {
                    assert_eq!(
                        wallet.chain_height().expect("reads wallet chain height"),
                        Some(height(FIXED_TIP)),
                    );
                    break;
                }
                drop(wallet);
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("hot viewing-key import is scanned through the unchanged tip");

        for task in [
            steady_state,
            recover_history,
            batch_decryptor,
            data_requests,
        ] {
            task.abort();
            let error = task.await.expect_err("aborted wallet-sync test task stops");
            assert!(error.is_cancelled());
        }
    }

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
