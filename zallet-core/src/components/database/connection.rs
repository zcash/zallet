use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use nonempty::NonEmpty;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use secrecy::SecretVec;
use shardtree::{ShardTree, error::ShardTreeError};
use transparent::{address::TransparentAddress, bundle::OutPoint, keys::TransparentKeyScope};
use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        AccountBirthday, AccountMeta, AddressInfo, Balance, ChangeReceivers, CoinbaseFilter,
        DecryptedTransaction, InputSource, NoteFilter, ORCHARD_SHARD_HEIGHT, OutputLockStore,
        ReceivedNotes, ReceivedTransactionOutput, SAPLING_SHARD_HEIGHT, TargetValue,
        TransparentKeyOrigin, WalletCommitmentTrees, WalletRead, WalletWrite, Zip32Derivation,
        chain::ChainState,
        error::{FindAccountForAddressError, LockError, RewindError},
        ll::{LowLevelWalletRead, LowLevelWalletWrite, wallet::generate_transparent_gap_addresses},
        scanning::ScanPriority,
        wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
    },
    fees::StandardFeeRule,
    keys::{
        AddressGenerationError, ReceiverRequirement, UnifiedAddressRequest, UnifiedFullViewingKey,
        UnifiedSpendingKey,
    },
    wallet::{
        LockOwner, Note, OutputRef, ReceivedNote, TransparentAddressMetadata,
        WalletTransparentOutput,
    },
};
use zcash_client_sqlite::{WalletDb, error::SqliteClientError, util::SystemClock};
use zcash_keys::keys::transparent::gap_limits::{AddressStore, GapLimits};
use zcash_primitives::{block::BlockHash, transaction::Transaction};
use zcash_protocol::{ShieldedPool, consensus::BlockHeight};
use zip32::DiversifierIndex;

#[cfg(feature = "zcashd-import")]
use zcash_client_sqlite::AccountUuid;

use crate::{
    error::{Error, ErrorKind},
    network::Network,
};

/// The minimum number of pool connections that must remain available for foreground
/// (JSON-RPC and CLI) work after the wallet sync tasks have taken theirs.
///
/// Each foreground task acquires at most one connection at a time (see
/// [`super::Database::handle`]), so any nonzero reservation preserves liveness; the
/// value 4 matches the wallet RPC concurrency that `zcashd` served by default
/// (`-rpcthreads=4`), which is the parallelism integrators already size for.
const MIN_FOREGROUND_CONNECTIONS: usize = 4;

/// Returns the connection-pool size to use for the wallet database.
///
/// This is deadpool's default sizing (twice the logical CPU count, per
/// `deadpool-0.12.3/src/util.rs`; `num_cpus` honours cgroup CPU quotas, so a
/// single-CPU container counts as one), raised to a floor that keeps wallet RPCs
/// serviceable: the sync tasks retain
/// [`crate::components::sync::LONG_LIVED_SYNC_CONNECTIONS`] connections for the
/// lifetime of the process, so on a small host the default alone (e.g. 2 on a
/// single-core machine) could be consumed entirely by sync, starving every other
/// database user forever (deadpool's `Pool::get` waits without a timeout).
fn pool_max_size() -> NonZeroUsize {
    NonZeroUsize::new(with_foreground_headroom(
        deadpool::managed::PoolConfig::default().max_size,
    ))
    .expect("the foreground headroom floor is nonzero")
}

/// Raises a candidate pool size to the smallest size that leaves
/// [`MIN_FOREGROUND_CONNECTIONS`] connections available while the sync tasks hold
/// theirs.
fn with_foreground_headroom(candidate_size: usize) -> usize {
    candidate_size
        .max(crate::components::sync::LONG_LIVED_SYNC_CONNECTIONS + MIN_FOREGROUND_CONNECTIONS)
}

pub(super) fn pool(path: impl AsRef<Path>, params: Network) -> Result<WalletPool, Error> {
    pool_with_size(path, params, pool_max_size())
}

/// Builds a connection pool holding at most `max_size` connections.
///
/// [`pool`] routes the automatic sizing policy above through this. `Database::open`
/// calls it directly when the `database.max_connections` config override is set, taking
/// the value literally (no floor) so the saturated-pool regression tests can force the
/// smallest possible pool. `max_size` is nonzero at the type level because a zero-sized
/// pool would make every `get()` wait forever, which is exactly the silent failure the
/// sizing policy exists to rule out.
pub(super) fn pool_with_size(
    path: impl AsRef<Path>,
    params: Network,
    max_size: NonZeroUsize,
) -> Result<WalletPool, Error> {
    let config = deadpool_sqlite::Config::new(path.as_ref());
    let manager = WalletManager::from_config(&config, params);
    WalletPool::builder(manager)
        .config(deadpool::managed::PoolConfig::new(max_size.get()))
        .build()
        .map_err(|e| ErrorKind::Generic.context(e).into())
}

pub(super) type WalletPool = deadpool::managed::Pool<WalletManager>;

pub(crate) struct WalletManager {
    inner: deadpool_sqlite::Manager,
    /// Connection pools are thread-safe, but SQLite does not reliably follow the busy
    /// handler (configured by `rusqlite` to a timeout after 5s), so we explicitly guard
    /// against SQLite `DatabaseBusy` errors.
    ///
    /// Lock order relative to the connection pool: this lock is only ever taken inside
    /// the synchronous `DbConnection::with*` methods of a connection that has already
    /// been acquired from the pool, and those methods cannot `.await`, so this lock is
    /// never held across a pool acquisition. The converse (waiting on this lock while
    /// holding a pool connection) is the only order that occurs, and is bounded by the
    /// other holders' closures.
    lock: Arc<RwLock<()>>,
    params: Network,
}

impl WalletManager {
    /// Creates a new [`WalletManager`] using the given [`deadpool_sqlite::Config`] backed
    /// by the specified [`deadpool_sqlite::Runtime`].
    #[must_use]
    pub fn from_config(config: &deadpool_sqlite::Config, params: Network) -> Self {
        Self {
            inner: deadpool_sqlite::Manager::from_config(config, deadpool_sqlite::Runtime::Tokio1),
            lock: Arc::new(RwLock::new(())),
            params,
        }
    }

    /// Returns the network parameters the wallet database serves.
    pub(crate) fn params(&self) -> &Network {
        &self.params
    }
}

impl deadpool::managed::Manager for WalletManager {
    type Type = DbConnection;
    type Error = rusqlite::Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        let inner = self.inner.create().await?;
        inner
            .interact(|conn| rusqlite::vtab::array::load_module(conn))
            .await
            .map_err(|_| rusqlite::Error::UnwindingPanic)??;
        Ok(DbConnection {
            inner,
            lock: self.lock.clone(),
            params: self.params,
        })
    }

    async fn recycle(
        &self,
        obj: &mut Self::Type,
        metrics: &deadpool_sqlite::Metrics,
    ) -> deadpool::managed::RecycleResult<Self::Error> {
        self.inner.recycle(&mut obj.inner, metrics).await
    }
}

/// The randomness source handed to every [`WalletDb`] the wallet opens.
///
/// The operating system's CSPRNG, matching what `zcash_client_sqlite` uses for its own
/// wallet databases. A failure to read OS randomness is unrecoverable, so it panics.
pub(crate) type WalletRng = UnwrapErr<SysRng>;

/// The gap limits of every [`WalletDb`] that Zallet opens: the defaults, because Zallet
/// never calls [`WalletDb::with_gap_limits`].
fn wallet_gap_limits() -> GapLimits {
    GapLimits::default()
}

/// Derives gap windows of `key_scope` for `account_id` until the gap start is stable.
///
/// `zcash_client_sqlite` 0.23 derives one window per pass. When a pass derives an address
/// held as a `Foreign` import that has outputs, the gap start moves past the window, where
/// no rows are derived. Reservation then fails with `ReachedGapLimit` until an output
/// arrives at a derived address of the same scope.
///
/// Does not help when `Foreign` imports that are exposed but have no outputs fill the
/// window: those rows stay unreservable.
///
/// Terminates: every pass but the last consumes at least one `Foreign` row. Must run in
/// the same transaction as the reservation.
fn refill_transparent_gap<DbT>(
    wdb: &mut DbT,
    gap_limits: GapLimits,
    account_id: <DbT as LowLevelWalletRead>::AccountId,
    key_scope: TransparentKeyScope,
) -> Result<(), SqliteClientError>
where
    DbT: LowLevelWalletWrite<Error = SqliteClientError>
        + AddressStore<
            Error = SqliteClientError,
            AccountRef = <DbT as LowLevelWalletRead>::AccountRef,
        >,
    <DbT as LowLevelWalletRead>::AccountId: Copy,
    <DbT as LowLevelWalletRead>::AccountRef: Copy,
    <DbT as LowLevelWalletRead>::TxRef: Eq + Hash,
{
    let gap_limit = gap_limits
        .limit_for(key_scope)
        .ok_or(SqliteClientError::AddressGeneration(
            AddressGenerationError::UnsupportedTransparentKeyScope(key_scope),
        ))?;
    // The request `zcash_client_sqlite` uses for its own gap maintenance.
    let request = UnifiedAddressRequest::unsafe_custom(
        ReceiverRequirement::Allow,
        ReceiverRequirement::Allow,
        ReceiverRequirement::Require,
    );

    let account_ref = wdb.get_account_ref(account_id)?;
    let mut gap_start = wdb.find_gap_start(account_ref, key_scope, gap_limit)?;
    loop {
        generate_transparent_gap_addresses(wdb, gap_limits, account_id, key_scope, request)?;
        let next_gap_start = wdb.find_gap_start(account_ref, key_scope, gap_limit)?;
        if next_gap_start == gap_start {
            return Ok(());
        }
        gap_start = next_gap_start;
    }
}

pub(crate) struct DbConnection {
    inner: deadpool_sync::SyncWrapper<rusqlite::Connection>,
    lock: Arc<RwLock<()>>,
    params: Network,
}

impl DbConnection {
    pub(crate) fn params(&self) -> &Network {
        &self.params
    }

    pub(crate) fn with<T>(
        &self,
        f: impl FnOnce(WalletDb<&rusqlite::Connection, Network, SystemClock, WalletRng>) -> T,
    ) -> T {
        tokio::task::block_in_place(|| {
            let _guard = self.lock.read().unwrap();
            f(WalletDb::from_connection(
                self.inner.lock().unwrap().as_ref(),
                self.params,
                SystemClock,
                UnwrapErr(SysRng),
            ))
        })
    }

    pub(crate) fn with_mut<T>(
        &self,
        f: impl FnOnce(WalletDb<&mut rusqlite::Connection, Network, SystemClock, WalletRng>) -> T,
    ) -> T {
        tokio::task::block_in_place(|| {
            let _guard = self.lock.write().unwrap();
            f(WalletDb::from_connection(
                self.inner.lock().unwrap().as_mut(),
                self.params,
                SystemClock,
                UnwrapErr(SysRng),
            ))
        })
    }

    pub(crate) fn with_raw<T>(&self, f: impl FnOnce(&rusqlite::Connection, &Network) -> T) -> T {
        tokio::task::block_in_place(|| {
            let _guard = self.lock.read().unwrap();
            f(self.inner.lock().unwrap().as_ref(), &self.params)
        })
    }

    pub(crate) fn with_raw_mut<T>(
        &self,
        f: impl FnOnce(&mut rusqlite::Connection, &Network) -> T,
    ) -> T {
        tokio::task::block_in_place(|| {
            let _guard = self.lock.write().unwrap();
            f(self.inner.lock().unwrap().as_mut(), &self.params)
        })
    }

    /// Attempts to construct a witness for every note the wallet believes is currently
    /// spendable, returning the block ranges that must be rescanned to repair missing witness
    /// data.
    ///
    /// Note this only covers notes the wallet holds. It cannot detect a note commitment tree
    /// that disagrees with the chain's at positions where the wallet has no note of its own,
    /// so an empty result does not mean the tree is sound.
    pub(crate) fn check_witnesses(&mut self) -> Result<Vec<Range<BlockHeight>>, SqliteClientError> {
        self.with_mut(|mut db_data| db_data.check_witnesses())
    }

    /// Queues the given block ranges to be rescanned at the given priority.
    pub(crate) fn queue_rescans(
        &mut self,
        rescan_ranges: NonEmpty<Range<BlockHeight>>,
        priority: ScanPriority,
    ) -> Result<(), SqliteClientError> {
        self.with_mut(|mut db_data| db_data.queue_rescans(rescan_ranges, priority))
    }

    /// Imports the given pubkeys into the account without key derivation information, and
    /// adds the associated transparent p2pkh addresses.
    ///
    /// This creates a single database transaction for all inserts, significantly reducing
    /// overhead for large migrated wallets.
    ///
    /// The imported addresses will contribute to the balance of the account (for
    /// UFVK-based accounts), but spending funds held by these addresses require the
    /// associated spending keys to be provided explicitly when calling
    /// [`create_proposed_transactions`]. By extension, calls to [`propose_shielding`]
    /// must only include addresses for which the spending application holds or can obtain
    /// the spending keys.
    ///
    /// [`create_proposed_transactions`]: zcash_client_backend::data_api::wallet::create_proposed_transactions
    /// [`propose_shielding`]: zcash_client_backend::data_api::wallet::propose_shielding
    #[cfg(feature = "zcashd-import")]
    pub(crate) fn import_standalone_transparent_pubkeys(
        &mut self,
        account: AccountUuid,
        pubkeys: impl ExactSizeIterator<Item = secp256k1::PublicKey>,
    ) -> Result<
        (),
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletRead>::Error,
    > {
        self.with_mut(|mut db_data| {
            db_data.transactionally(|wdb| {
                let total = pubkeys.len();
                for (i, pubkey) in pubkeys.into_iter().enumerate() {
                    if i % 10000 == 0 && i > 0 {
                        tracing::info!("Stored {i}/{total} pubkeys");
                    }
                    wdb.import_standalone_transparent_pubkey(account, pubkey)?;
                }
                Ok(())
            })
        })
    }
}

impl WalletRead for DbConnection {
    type Error =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletRead>::Error;
    type AccountId =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletRead>::AccountId;
    type Account =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletRead>::Account;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        self.with(|db_data| db_data.get_account_ids())
    }

    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.with(|db_data| db_data.get_account(account_id))
    }

    fn get_derived_account(
        &self,
        derivation: &Zip32Derivation,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.with(|db_data| db_data.get_derived_account(derivation))
    }

    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        self.with(|db_data| db_data.validate_seed(account_id, seed))
    }

    fn seed_relevance_to_derived_accounts(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<zcash_client_backend::data_api::SeedRelevance<Self::AccountId>, Self::Error> {
        self.with(|db_data| db_data.seed_relevance_to_derived_accounts(seed))
    }

    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.with(|db_data| db_data.get_account_for_ufvk(ufvk))
    }

    fn list_addresses(&self, account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> {
        self.with(|db_data| db_data.list_addresses(account))
    }

    fn get_last_generated_address_matching(
        &self,
        account: Self::AccountId,
        address_filter: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        self.with(|db_data| db_data.get_last_generated_address_matching(account, address_filter))
    }

    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        self.with(|db_data| db_data.get_account_birthday(account))
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.with(|db_data| db_data.get_wallet_birthday())
    }

    fn get_wallet_recover_until(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.with(|db_data| db_data.get_wallet_recover_until())
    }

    fn get_wallet_summary(
        &self,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Option<zcash_client_backend::data_api::WalletSummary<Self::AccountId>>, Self::Error>
    {
        self.with(|db_data| db_data.get_wallet_summary(confirmations_policy))
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.with(|db_data| db_data.chain_height())
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        self.with(|db_data| db_data.get_block_hash(block_height))
    }

    fn block_metadata(
        &self,
        height: BlockHeight,
    ) -> Result<Option<zcash_client_backend::data_api::BlockMetadata>, Self::Error> {
        self.with(|db_data| db_data.block_metadata(height))
    }

    fn block_fully_scanned(
        &self,
    ) -> Result<Option<zcash_client_backend::data_api::BlockMetadata>, Self::Error> {
        self.with(|db_data| db_data.block_fully_scanned())
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        self.with(|db_data| db_data.get_max_height_hash())
    }

    fn block_max_scanned(
        &self,
    ) -> Result<Option<zcash_client_backend::data_api::BlockMetadata>, Self::Error> {
        self.with(|db_data| db_data.block_max_scanned())
    }

    fn suggest_scan_ranges(
        &self,
    ) -> Result<Vec<zcash_client_backend::data_api::scanning::ScanRange>, Self::Error> {
        self.with(|db_data| db_data.suggest_scan_ranges())
    }

    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: std::num::NonZeroU32,
    ) -> Result<Option<(TargetHeight, BlockHeight)>, Self::Error> {
        self.with(|db_data| db_data.get_target_and_anchor_heights(min_confirmations))
    }

    fn get_tx_height(
        &self,
        txid: zcash_protocol::TxId,
    ) -> Result<Option<BlockHeight>, Self::Error> {
        self.with(|db_data| db_data.get_tx_height(txid))
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        self.with(|db_data| db_data.get_unified_full_viewing_keys())
    }

    fn get_memo(
        &self,
        note_id: zcash_client_backend::wallet::NoteId,
    ) -> Result<Option<zcash_protocol::memo::Memo>, Self::Error> {
        self.with(|db_data| db_data.get_memo(note_id))
    }

    fn get_transaction(
        &self,
        txid: zcash_protocol::TxId,
    ) -> Result<Option<Transaction>, Self::Error> {
        self.with(|db_data| db_data.get_transaction(txid))
    }

    fn get_sapling_nullifiers(
        &self,
        query: zcash_client_backend::data_api::NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        self.with(|db_data| db_data.get_sapling_nullifiers(query))
    }

    fn get_orchard_nullifiers(
        &self,
        query: zcash_client_backend::data_api::NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        self.with(|db_data| db_data.get_orchard_nullifiers(query))
    }

    fn get_ironwood_nullifiers(
        &self,
        query: zcash_client_backend::data_api::NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        self.with(|db_data| db_data.get_ironwood_nullifiers(query))
    }

    fn get_transparent_receivers(
        &self,
        account: Self::AccountId,
        include_change: bool,
        include_standalone: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        self.with(|db_data| {
            db_data.get_transparent_receivers(account, include_change, include_standalone)
        })
    }

    fn get_ephemeral_transparent_receivers(
        &self,
        account: Self::AccountId,
        exposure_depth: u32,
        exclude_used: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        self.with(|db_data| {
            db_data.get_ephemeral_transparent_receivers(account, exposure_depth, exclude_used)
        })
    }

    fn get_transparent_balances(
        &self,
        account: Self::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<HashMap<TransparentAddress, (TransparentKeyOrigin, Balance)>, Self::Error> {
        self.with(|db_data| {
            db_data.get_transparent_balances(account, target_height, confirmations_policy)
        })
    }

    fn get_transparent_address_metadata(
        &self,
        account: Self::AccountId,
        address: &TransparentAddress,
    ) -> Result<Option<TransparentAddressMetadata>, Self::Error> {
        self.with(|db_data| db_data.get_transparent_address_metadata(account, address))
    }

    fn get_unspent_transparent_outpoints(
        &self,
    ) -> Result<HashMap<OutPoint, Self::AccountId>, Self::Error> {
        self.with(|db_data| db_data.get_unspent_transparent_outpoints())
    }

    #[allow(clippy::type_complexity)]
    fn get_transparent_receiver_accounts(
        &self,
    ) -> Result<
        HashMap<TransparentAddress, (Self::AccountId, Option<TransparentKeyScope>)>,
        Self::Error,
    > {
        self.with(|db_data| db_data.get_transparent_receiver_accounts())
    }

    fn utxo_query_height(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        self.with(|db_data| db_data.utxo_query_height(account))
    }

    fn transaction_data_requests(
        &self,
    ) -> Result<Vec<zcash_client_backend::data_api::TransactionDataRequest>, Self::Error> {
        self.with(|db_data| db_data.transaction_data_requests())
    }

    fn get_received_outputs(
        &self,
        txid: zcash_protocol::TxId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Vec<ReceivedTransactionOutput>, Self::Error> {
        self.with(|db_data| db_data.get_received_outputs(txid, target_height, confirmations_policy))
    }

    fn find_account_for_address<P: zcash_protocol::consensus::Parameters>(
        &self,
        params: &P,
        address: &zcash_keys::address::Address,
    ) -> Result<Option<Self::AccountId>, FindAccountForAddressError<Self::Error>> {
        self.with(|db_data| db_data.find_account_for_address(params, address))
    }
}

impl InputSource for DbConnection {
    type Error =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as InputSource>::Error;
    type AccountId =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as InputSource>::AccountId;
    type NoteRef =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as InputSource>::NoteRef;

    fn get_spendable_note(
        &self,
        txid: &zcash_protocol::TxId,
        protocol: ShieldedPool,
        index: u32,
        target_height: TargetHeight,
        lock_filter: LockFilter<'_>,
    ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error> {
        self.with(|db_data| {
            db_data.get_spendable_note(txid, protocol, index, target_height, lock_filter)
        })
    }

    fn anchor_computable(
        &self,
        protocol: ShieldedPool,
        height: BlockHeight,
    ) -> Result<bool, Self::Error> {
        self.with(|db_data| db_data.anchor_computable(protocol, height))
    }

    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: TargetValue,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        self.with(|db_data| {
            db_data.select_spendable_notes(
                account,
                target_value,
                sources,
                target_height,
                confirmations_policy,
                exclude,
                lock_filter,
            )
        })
    }

    fn select_single_spendable_note(
        &self,
        account: Self::AccountId,
        value: zcash_protocol::value::Zatoshis,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        self.with(|db_data| {
            db_data.select_single_spendable_note(
                account,
                value,
                sources,
                target_height,
                confirmations_policy,
                exclude,
                lock_filter,
            )
        })
    }

    fn select_unspent_notes(
        &self,
        account: Self::AccountId,
        sources: &[ShieldedPool],
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        self.with(|db_data| {
            db_data.select_unspent_notes(account, sources, target_height, exclude, lock_filter)
        })
    }

    fn get_change_receivers(
        &self,
        account: Self::AccountId,
    ) -> Result<ChangeReceivers, Self::Error> {
        self.with(|db_data| db_data.get_change_receivers(account))
    }

    fn get_unspent_transparent_output(
        &self,
        outpoint: &OutPoint,
        target_height: TargetHeight,
    ) -> Result<Option<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.with(|db_data| db_data.get_unspent_transparent_output(outpoint, target_height))
    }

    fn get_spendable_transparent_outputs(
        &self,
        address: &TransparentAddress,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
        lock_filter: LockFilter<'_>,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.with(|db_data| {
            db_data.get_spendable_transparent_outputs(
                address,
                target_height,
                confirmations_policy,
                output_filter,
                lock_filter,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn select_spendable_transparent_outputs(
        &self,
        account: Self::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        output_filter: CoinbaseFilter,
        address_allow_list: Option<&[TransparentAddress]>,
        target_value: TargetValue,
        max_inputs: usize,
        fee_rule: &StandardFeeRule,
        lock_filter: LockFilter<'_>,
    ) -> Result<Vec<WalletTransparentOutput<Self::AccountId>>, Self::Error> {
        self.with(|db_data| {
            db_data.select_spendable_transparent_outputs(
                account,
                target_height,
                confirmations_policy,
                output_filter,
                address_allow_list,
                target_value,
                max_inputs,
                fee_rule,
                lock_filter,
            )
        })
    }

    fn get_account_metadata(
        &self,
        account: Self::AccountId,
        selector: &NoteFilter,
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
        lock_filter: LockFilter<'_>,
    ) -> Result<AccountMeta, Self::Error> {
        self.with(|db_data| {
            db_data.get_account_metadata(account, selector, target_height, exclude, lock_filter)
        })
    }
}

impl WalletWrite for DbConnection {
    type UtxoRef =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletWrite>::UtxoRef;

    fn create_account(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(<Self as WalletRead>::AccountId, UnifiedSpendingKey), <Self as WalletRead>::Error>
    {
        self.with_mut(|mut db_data| {
            db_data.create_account(account_name, seed, birthday, key_source)
        })
    }

    fn import_account_hd(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        account_index: zip32::AccountId,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(Self::Account, UnifiedSpendingKey), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| {
            db_data.import_account_hd(account_name, seed, account_index, birthday, key_source)
        })
    }

    fn import_account_ufvk(
        &mut self,
        account_name: &str,
        unified_key: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
        purpose: zcash_client_backend::data_api::AccountPurpose,
        key_source: Option<&str>,
    ) -> Result<Self::Account, <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| {
            db_data.import_account_ufvk(account_name, unified_key, birthday, purpose, key_source)
        })
    }

    fn delete_account(
        &mut self,
        account: <Self as WalletRead>::AccountId,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.delete_account(account))
    }

    fn set_account_name(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        name: &str,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.set_account_name(account, name))
    }

    #[cfg(feature = "transparent-key-import")]
    fn import_standalone_transparent_address(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        address: TransparentAddress,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.import_standalone_transparent_address(account, address))
    }

    #[cfg(feature = "transparent-key-import")]
    fn import_standalone_transparent_pubkey(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        pubkey: secp256k1::PublicKey,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.import_standalone_transparent_pubkey(account, pubkey))
    }

    #[cfg(feature = "transparent-key-import")]
    fn import_standalone_transparent_script(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        script: zcash_script::script::Redeem,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.import_standalone_transparent_script(account, script))
    }

    fn get_next_available_address(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.get_next_available_address(account, request))
    }

    fn get_address_for_index(
        &mut self,
        account: <Self as WalletRead>::AccountId,
        diversifier_index: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| {
            db_data.get_address_for_index(account, diversifier_index, request)
        })
    }

    fn update_chain_tip(
        &mut self,
        tip_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.update_chain_tip(tip_height))
    }

    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<zcash_client_backend::data_api::ScannedBlock<<Self as WalletRead>::AccountId>>,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.put_blocks(from_state, blocks))
    }

    fn prune_scan_queue_below(
        &mut self,
        height: BlockHeight,
        retain_with_priority: Option<ScanPriority>,
    ) -> Result<u64, <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.prune_scan_queue_below(height, retain_with_priority))
    }

    fn put_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput<<Self as WalletRead>::AccountId>,
    ) -> Result<Self::UtxoRef, <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.put_received_transparent_utxo(output))
    }

    fn store_decrypted_tx(
        &mut self,
        received_tx: DecryptedTransaction<'_, Transaction, <Self as WalletRead>::AccountId>,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.store_decrypted_tx(received_tx))
    }

    fn set_tx_trust(
        &mut self,
        txid: zcash_protocol::TxId,
        trusted: bool,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.set_tx_trust(txid, trusted))
    }

    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[zcash_client_backend::data_api::SentTransaction<
            '_,
            <Self as WalletRead>::AccountId,
        >],
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.store_transactions_to_be_sent(transactions))
    }

    fn truncate_to_height(
        &mut self,
        max_height: BlockHeight,
    ) -> Result<BlockHeight, <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.truncate_to_height(max_height))
    }

    fn truncate_to_chain_state(
        &mut self,
        chain_state: ChainState,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.truncate_to_chain_state(chain_state))
    }

    fn queue_rescan(
        &mut self,
        range: Range<BlockHeight>,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.queue_rescan(range))
    }

    fn rewind_to_chain_state(
        &mut self,
        chain_state: ChainState,
        reset_account_birthdays: HashSet<<Self as WalletRead>::AccountId>,
    ) -> Result<(), RewindError<<Self as WalletRead>::AccountId, <Self as WalletRead>::Error>> {
        self.with_mut(|mut db_data| {
            db_data.rewind_to_chain_state(chain_state, reset_account_birthdays)
        })
    }

    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        account_id: <Self as WalletRead>::AccountId,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, <Self as WalletRead>::Error>
    {
        // See `refill_transparent_gap`.
        self.with_mut(|mut db_data| {
            db_data.transactionally(|wdb| {
                refill_transparent_gap(
                    wdb,
                    wallet_gap_limits(),
                    account_id,
                    TransparentKeyScope::EPHEMERAL,
                )?;
                wdb.reserve_next_n_ephemeral_addresses(account_id, n)
            })
        })
    }

    fn reserve_next_n_internal_addresses(
        &mut self,
        account_id: <Self as WalletRead>::AccountId,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, <Self as WalletRead>::Error>
    {
        // See `refill_transparent_gap`.
        self.with_mut(|mut db_data| {
            db_data.transactionally(|wdb| {
                refill_transparent_gap(
                    wdb,
                    wallet_gap_limits(),
                    account_id,
                    TransparentKeyScope::INTERNAL,
                )?;
                wdb.reserve_next_n_internal_addresses(account_id, n)
            })
        })
    }

    fn set_transaction_status(
        &mut self,
        txid: zcash_protocol::TxId,
        status: zcash_client_backend::data_api::TransactionStatus,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.set_transaction_status(txid, status))
    }

    fn schedule_next_check(
        &mut self,
        address: &TransparentAddress,
        offset_seconds: u32,
    ) -> Result<Option<SystemTime>, <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.schedule_next_check(address, offset_seconds))
    }

    fn notify_address_checked(
        &mut self,
        request: zcash_client_backend::data_api::TransactionsInvolvingAddress,
        as_of_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.notify_address_checked(request, as_of_height))
    }

    #[cfg(feature = "spend-index")]
    fn notify_output_verified_unspent(
        &mut self,
        outpoint: OutPoint,
        as_of_height: BlockHeight,
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.notify_output_verified_unspent(outpoint, as_of_height))
    }

    fn mark_transparent_addresses_exposed(
        &mut self,
        exposures: &[(TransparentAddress, BlockHeight)],
    ) -> Result<(), <Self as WalletRead>::Error> {
        self.with_mut(|mut db_data| db_data.mark_transparent_addresses_exposed(exposures))
    }
}

impl OutputLockStore for DbConnection {
    type Error =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletRead>::Error;
    type AccountId =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletRead>::AccountId;

    fn lock_outputs(
        &mut self,
        outputs: &[OutputRef],
        owner: LockOwner,
        lock_expiry_height: BlockHeight,
    ) -> Result<usize, LockError<Self::Error>> {
        self.with_mut(|mut db_data| db_data.lock_outputs(outputs, owner, lock_expiry_height))
    }

    fn unlock_output(&mut self, output: &OutputRef, owner: LockOwner) -> Result<bool, Self::Error> {
        self.with_mut(|mut db_data| db_data.unlock_output(output, owner))
    }

    fn clear_locked_outputs(&mut self, account: Self::AccountId) -> Result<usize, Self::Error> {
        self.with_mut(|mut db_data| db_data.clear_locked_outputs(account))
    }

    fn get_locked_outputs(&self, account: Self::AccountId) -> Result<Vec<OutputRef>, Self::Error> {
        self.with_mut(|db_data| db_data.get_locked_outputs(account))
    }
}

impl WalletCommitmentTrees for DbConnection {
    type Error =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletCommitmentTrees>::Error;
    type SaplingShardStore<'a> =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletCommitmentTrees>::SaplingShardStore<'a>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        self.with_mut(|mut db_data| db_data.with_sapling_tree_mut(callback))
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[zcash_client_backend::data_api::chain::CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.with_mut(|mut db_data| db_data.put_sapling_subtree_roots(start_index, roots))
    }

    fn get_sapling_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<sapling::Node>, ShardTreeError<Self::Error>> {
        self.with_mut(|mut db_data| db_data.get_sapling_subtree_root(index))
    }

    type OrchardShardStore<'a> =
        <WalletDb<rusqlite::Connection, Network, SystemClock, WalletRng> as WalletCommitmentTrees>::OrchardShardStore<'a>;

    fn with_orchard_tree_mut<F, A, E>(&mut self, callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        self.with_mut(|mut db_data| db_data.with_orchard_tree_mut(callback))
    }

    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[zcash_client_backend::data_api::chain::CommitmentTreeRoot<
            orchard::tree::MerkleHashOrchard,
        >],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.with_mut(|mut db_data| db_data.put_orchard_subtree_roots(start_index, roots))
    }

    fn get_orchard_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, ShardTreeError<Self::Error>> {
        self.with_mut(|mut db_data| db_data.get_orchard_subtree_root(index))
    }

    // Ironwood shares the Orchard note commitment tree's shape (same shard store and depths),
    // so these mirror the Orchard methods; `with_ironwood_tree_mut`, `put_ironwood_subtree_roots`
    // and `get_ironwood_subtree_root` all default to reporting that no Ironwood tree exists,
    // because a backend may not track one. `WalletDb` does, so we forward to it rather than fall
    // back to those defaults (which would silently drop Ironwood tree updates made through this
    // connection, and hide its recorded subtree roots).
    fn with_ironwood_tree_mut<F, A, E>(&mut self, callback: F) -> Result<Option<A>, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        self.with_mut(|mut db_data| db_data.with_ironwood_tree_mut(callback))
    }

    fn put_ironwood_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[zcash_client_backend::data_api::chain::CommitmentTreeRoot<
            orchard::tree::MerkleHashOrchard,
        >],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.with_mut(|mut db_data| db_data.put_ironwood_subtree_roots(start_index, roots))
    }

    fn get_ironwood_subtree_root(
        &mut self,
        index: u64,
    ) -> Result<Option<orchard::tree::MerkleHashOrchard>, ShardTreeError<Self::Error>> {
        self.with_mut(|mut db_data| db_data.get_ironwood_subtree_root(index))
    }
}

#[cfg(test)]
mod tests {
    use super::{MIN_FOREGROUND_CONNECTIONS, with_foreground_headroom};
    use crate::components::sync::LONG_LIVED_SYNC_CONNECTIONS;

    /// The pool must always be able to serve every long-lived sync connection plus the
    /// reserved foreground headroom, however small the host's CPU-derived default is.
    /// Sizes already above the floor are respected unchanged.
    #[test]
    fn pool_size_always_leaves_foreground_headroom() {
        let floor = LONG_LIVED_SYNC_CONNECTIONS + MIN_FOREGROUND_CONNECTIONS;

        // Every candidate at or below the floor (including the pathological 0, and the
        // size deadpool derives on a single-core host) is raised to exactly the floor.
        for candidate in 0..=floor {
            assert_eq!(with_foreground_headroom(candidate), floor);
        }

        // Candidates above the floor are not shrunk: larger hosts keep their larger
        // default pools.
        for candidate in (floor + 1)..(floor + 64) {
            assert_eq!(with_foreground_headroom(candidate), candidate);
        }
    }
}

/// Unit tests for [`refill_transparent_gap`] on a wallet shaped like a `zcashd`
/// migration.
#[cfg(all(test, feature = "transparent-key-import"))]
mod gap_refill_tests {
    use std::num::NonZeroUsize;
    use std::panic::AssertUnwindSafe;

    use futures::FutureExt;
    use proptest::prelude::*;
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use secrecy::SecretVec;
    use tempfile::TempDir;
    use transparent::{
        address::TransparentAddress,
        bundle::{OutPoint, TxOut},
        keys::{AccountPubKey, NonHardenedChildIndex, TransparentKeyScope},
    };
    use zcash_client_backend::{
        data_api::{
            AccountBirthday, WalletRead, WalletWrite, chain::ChainState, ll::LowLevelWalletRead,
        },
        wallet::{TransparentAddressMetadata, WalletTransparentOutput},
    };
    use zcash_client_sqlite::{
        AccountUuid, WalletDb, error::SqliteClientError, util::SystemClock,
        wallet::init::WalletMigrator,
    };
    use zcash_keys::keys::transparent::gap_limits::AddressStore;
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{
        consensus::{self, BlockHeight, NetworkUpgrade, Parameters},
        value::{COIN, Zatoshis},
    };

    use super::{
        DbConnection, WalletPool, pool_with_size, refill_transparent_gap, wallet_gap_limits,
    };
    use crate::{components::database::DbHandle, network::Network};

    /// The network the test wallets are created on.
    const NETWORK: Network = Network::Consensus(consensus::Network::TestNetwork);

    /// The number of imported change indices after the last registered one, as in the
    /// wallet that reported this failure.
    const IMPORTED_RUN_LEN: u32 = 213;

    /// The value of every output the tests record. Any value marks its receiver as used.
    const RECEIVED_VALUE: Zatoshis = Zatoshis::const_from_u64(COIN);

    /// The number of cases per property. Kept small: each builds [`IMPORTED_RUN_LEN`]
    /// imports.
    const CASES: u32 = 4;

    /// A wallet with one account, holding the migrated shape built by [`migrated_wallet`].
    struct MigratedWallet {
        /// Owns the wallet database file for the life of the test.
        _datadir: TempDir,
        pool: WalletPool,
        account: AccountUuid,
        account_pubkey: AccountPubKey,
        /// The last change index that the wallet derived and registered itself.
        last_registered: u32,
    }

    fn internal_pubkey(account_pubkey: &AccountPubKey, index: u32) -> secp256k1::PublicKey {
        account_pubkey
            .derive_address_pubkey(
                TransparentKeyScope::INTERNAL,
                NonHardenedChildIndex::from_index(index).expect("test indices are small"),
            )
            .expect("derivation at a non-hardened index succeeds")
    }

    fn internal_address(account_pubkey: &AccountPubKey, index: u32) -> TransparentAddress {
        TransparentAddress::from_pubkey(&internal_pubkey(account_pubkey, index))
    }

    /// A mined output paying `address`, in a transaction unique to `tag`.
    fn mined_output_to(
        address: &TransparentAddress,
        tag: u32,
        mined_height: BlockHeight,
    ) -> WalletTransparentOutput<AccountUuid> {
        let mut txid = [0; 32];
        txid[..4].copy_from_slice(&tag.to_le_bytes());
        WalletTransparentOutput::from_parts(
            OutPoint::new(txid, 0),
            TxOut::new(RECEIVED_VALUE, address.script().into()),
            Some(mined_height),
            None,
            None,
            None,
        )
        .expect("a P2PKH output has a recipient address")
    }

    /// Runs a test body on a multi-threaded runtime, which [`DbConnection`] requires.
    ///
    /// A panic is caught and resumed outside the runtime, so that the pool is dropped
    /// inside it. Otherwise a failed assertion aborts the test process.
    fn run_in_runtime<F: Future>(body: F) -> F::Output {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("builds a runtime")
            .block_on(AssertUnwindSafe(body).catch_unwind())
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }

    /// Acquires the only connection of the test wallet's pool.
    async fn connection(pool: &WalletPool) -> DbHandle {
        pool.get().await.expect("acquires a connection")
    }

    /// The start of the internal gap.
    fn internal_gap_start(conn: &mut DbConnection, account: AccountUuid) -> Option<u32> {
        conn.with_mut(|mut db| {
            db.transactionally(|wdb| {
                let account_ref = wdb.get_account_ref(account)?;
                wdb.find_gap_start(
                    account_ref,
                    TransparentKeyScope::INTERNAL,
                    wallet_gap_limits().internal(),
                )
                .map(|start| start.map(|i| i.index()))
            })
        })
        .map_err(|e: SqliteClientError| e)
        .expect("reads the gap start")
    }

    /// Reserves change addresses through `zcash_client_sqlite`, without Zallet's repair.
    fn reserve_internal_unrepaired(
        conn: &mut DbConnection,
        account: AccountUuid,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, SqliteClientError> {
        conn.with_mut(|mut db| db.reserve_next_n_internal_addresses(account, n))
    }

    /// Builds a wallet that `zcash_client_sqlite` 0.23 cannot reserve change from.
    ///
    /// The last index `K` of the initial change window has an output. The
    /// [`IMPORTED_RUN_LEN`] indices after `K` are standalone imports with outputs, except
    /// `K + 1 + unused_offset`, which has none and is marked exposed.
    ///
    /// The output at `K` is recorded last, so its gap maintenance upgrades the imports.
    async fn migrated_wallet(seed: [u8; 32], unused_offset: u32) -> MigratedWallet {
        let datadir = tempfile::tempdir().expect("creates a temporary directory");
        let path = datadir.path().join("wallet.sqlite");
        {
            let mut conn = rusqlite::Connection::open(&path).expect("opens the wallet file");
            let mut db =
                WalletDb::from_connection(&mut conn, NETWORK, SystemClock, UnwrapErr(SysRng));
            WalletMigrator::new()
                .init_or_migrate(&mut db)
                .expect("initializes the wallet schema");
        }
        let pool =
            pool_with_size(&path, NETWORK, NonZeroUsize::MIN).expect("builds a connection pool");

        let tip = NETWORK
            .activation_height(NetworkUpgrade::Sapling)
            .expect("Sapling activates on the test network");
        let last_registered = wallet_gap_limits().internal() - 1;
        let imported = (last_registered + 1)..=(last_registered + IMPORTED_RUN_LEN);
        let unused = last_registered + 1 + unused_offset;

        let (account, account_pubkey) = {
            let mut conn = connection(&pool).await;
            let (account, usk) = conn
                .create_account(
                    "migrated",
                    &SecretVec::new(seed.to_vec()),
                    &AccountBirthday::from_parts(
                        ChainState::empty(BlockHeight::from_u32(0), BlockHash([0; 32])),
                        None,
                    ),
                    None,
                )
                .expect("creates the account");
            conn.update_chain_tip(tip).expect("records the chain tip");
            let account_pubkey = usk.transparent().to_account_pubkey();

            let pubkeys: Vec<_> = imported
                .clone()
                .map(|i| internal_pubkey(&account_pubkey, i))
                .collect();
            conn.with_mut(|mut db| db.import_standalone_transparent_pubkeys(account, &pubkeys))
                .expect("imports the change keys as standalone keys");
            for i in imported.clone().filter(|i| *i != unused) {
                conn.put_received_transparent_utxo(&mined_output_to(
                    &internal_address(&account_pubkey, i),
                    i,
                    tip,
                ))
                .expect("records an output at an imported receiver");
            }
            conn.mark_transparent_addresses_exposed(&[(
                internal_address(&account_pubkey, unused),
                tip,
            )])
            .expect("marks the unused import as exposed");
            conn.put_received_transparent_utxo(&mined_output_to(
                &internal_address(&account_pubkey, last_registered),
                last_registered,
                tip,
            ))
            .expect("records an output at the last registered change address");

            (account, account_pubkey)
        };

        MigratedWallet {
            _datadir: datadir,
            pool,
            account,
            account_pubkey,
            last_registered,
        }
    }

    /// Asserts that the `zcash_client_sqlite` reservation fails with `ReachedGapLimit`,
    /// and returns the gap start.
    fn assert_unrepaired_reservation_refused(
        conn: &mut DbConnection,
        wallet: &MigratedWallet,
    ) -> u32 {
        let internal_gap_limit = wallet_gap_limits().internal();
        let gap_start =
            internal_gap_start(conn, wallet.account).expect("the index space is not exhausted");
        assert!(gap_start <= wallet.last_registered + IMPORTED_RUN_LEN);
        let refused = reserve_internal_unrepaired(conn, wallet.account, 1);
        assert!(
            matches!(
                refused,
                Err(SqliteClientError::ReachedGapLimit(TransparentKeyScope::INTERNAL, end))
                    if end == gap_start + internal_gap_limit
            ),
            "unexpected unrepaired reservation result: {refused:?}",
        );
        gap_start
    }

    /// An offset into the imported run that is neither its first nor its last index.
    fn interior_offset() -> impl Strategy<Value = u32> {
        1..(IMPORTED_RUN_LEN - 1)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(CASES))]

        /// Reservation fails without the repair. With it, a full window is reserved right
        /// after the last used import, and the unused exposed import is skipped.
        #[test]
        fn change_is_reservable_after_used_imports(
            seed in any::<[u8; 32]>(),
            unused_offset in interior_offset(),
        ) {
            run_in_runtime(async {
                let wallet = migrated_wallet(seed, unused_offset).await;
                let mut conn = connection(&wallet.pool).await;
                let internal_gap_limit = wallet_gap_limits().internal();
                let last_import = wallet.last_registered + IMPORTED_RUN_LEN;

                assert_unrepaired_reservation_refused(&mut conn, &wallet);

                let reserved = conn
                    .reserve_next_n_internal_addresses(
                        wallet.account,
                        usize::try_from(internal_gap_limit).expect("small"),
                    )
                    .expect("reserves a full window of change after the repair");
                let reserved: Vec<_> = reserved
                    .into_iter()
                    .map(|(address, meta)| (address, meta.address_index().map(|i| i.index())))
                    .collect();
                let expected: Vec<_> = ((last_import + 1)..=(last_import + internal_gap_limit))
                    .map(|i| (internal_address(&wallet.account_pubkey, i), Some(i)))
                    .collect();
                assert_eq!(reserved, expected);
            });
        }

        /// An error after the repair, in the same transaction, leaves the wallet unchanged.
        #[test]
        fn failed_transaction_persists_no_repair(
            seed in any::<[u8; 32]>(),
            unused_offset in interior_offset(),
        ) {
            run_in_runtime(async {
                let wallet = migrated_wallet(seed, unused_offset).await;
                let mut conn = connection(&wallet.pool).await;

                let receivers_before = conn
                    .get_transparent_receivers(wallet.account, true, true)
                    .expect("lists the receivers");
                let gap_start_before = assert_unrepaired_reservation_refused(&mut conn, &wallet);

                let result: Result<(), SqliteClientError> = conn.with_mut(|mut db| {
                    db.transactionally(|wdb| {
                        refill_transparent_gap(
                            wdb,
                            wallet_gap_limits(),
                            wallet.account,
                            TransparentKeyScope::INTERNAL,
                        )?;
                        // The repair must have moved the gap start, or the rollback proves nothing.
                        let account_ref = wdb.get_account_ref(wallet.account)?;
                        assert_ne!(
                            wdb.find_gap_start(
                                account_ref,
                                TransparentKeyScope::INTERNAL,
                                wallet_gap_limits().internal(),
                            )?
                            .map(|i| i.index()),
                            Some(gap_start_before),
                        );
                        Err(SqliteClientError::CorruptedData(
                            "injected failure after the repair".into(),
                        ))
                    })
                });
                assert!(matches!(result, Err(SqliteClientError::CorruptedData(_))));

                assert_eq!(
                    conn.get_transparent_receivers(wallet.account, true, true)
                        .expect("lists the receivers"),
                    receivers_before,
                );
                assert_eq!(
                    assert_unrepaired_reservation_refused(&mut conn, &wallet),
                    gap_start_before,
                );
            });
        }
    }
}
