//! Orchard-to-Ironwood value-pool migration wiring.
//!
//! This module wires the backend-agnostic pool-migration engine into Zallet. The
//! engine crate is still evolving upstream (it lives on a librustzcash feature
//! branch and is not yet released to crates.io), so this module keeps the
//! integration seam small: the rest of Zallet reaches the engine through the
//! [`engine`] re-export rather than depending on the external crate name
//! directly.
//!
//! It also provides [`SpendableSnapshot`], Zallet's implementation of the
//! engine's `MigrationBackend` trait for the PLANNING slice. The engine's
//! `plan_migration` needs only the account's spendable source-pool note values
//! and the chain-tip height, so the snapshot captures both from the wallet up
//! front and serves them back to the engine. Capturing a snapshot (rather than
//! querying the wallet from inside the trait methods) keeps all wallet I/O and its
//! error handling in the RPC layer, and lets the pure planner run synchronously
//! after the last `.await`.
//!
//! Persistence is a separate concern: the engine's `PoolMigrationRead` /
//! `PoolMigrationWrite` store traits (implemented over the wallet database by
//! `zcash_pool_migration_sqlite`) hold a committed migration, and the
//! `MigrationBackend` trait this snapshot implements is now just the planning
//! inputs. Committing a migration uses the `WalletMigration` adapter over the
//! wallet, not this snapshot.

use core::convert::Infallible;
use core::fmt;
use std::sync::OnceLock;

use orchard::circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey};
use orchard::keys::SpendAuthorizingKey;
use pczt::Pczt;
use pczt::roles::prover::Prover;
use pczt::roles::tx_extractor::TransactionExtractor;
use rand::rngs::OsRng;
use rusqlite::Connection;
use zcash_client_backend::data_api::WalletRead;
use zcash_client_sqlite::{AccountUuid, WalletDb, util::SystemClock};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration_backend::build::sign_pczt;
use zcash_pool_migration_backend::engine::{
    CommitError, MigrationBackend, MigrationError, MigrationState, MigrationStatus, MigrationTxId,
    MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite, UnsignedMigrationTx,
    build_preparation_unsigned, build_transfers_unsigned, commit_pending_preparation,
    commit_preparation, commit_transfers, plan_migration,
};
// The migration state machine lives in the engine (the mobile wallet drives it the same way); zallet
// only performs the wallet I/O around the engine's decisions. The decision and transition logic are
// methods on `MigrationState` (`next_step`, `mark_mined`, `mark_broadcast`, `is_terminal`, ...).
use zcash_pool_migration_backend::note_splitting::{FeePolicy, Zip317FeePolicy};
use zcash_pool_migration_backend::preparation::PREP_TX_ACTIONS;
use zcash_pool_migration_backend::state::AdvanceStep;
use zcash_pool_migration_backend::wallet::WalletMigration;
use zcash_pool_migration_sqlite::PoolMigrations;
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId};

use crate::network::Network;

/// The backend-agnostic value-pool migration engine.
///
/// Re-exported from the `zcash_pool_migration_backend` crate (formerly
/// `zcash_ironwood_migration_backend`, renamed upstream to a pool-agnostic name).
/// Its API is not yet stable; treat this re-export as the integration seam and
/// avoid coupling Zallet code to specific items until the engine is released.
pub use zcash_pool_migration_backend as engine;

/// A point-in-time snapshot of the inputs the migration engine needs to PLAN a
/// migration for one account: the values of the account's spendable source-pool
/// (Orchard) notes, and the chain-tip height.
///
/// This is Zallet's `MigrationBackend` for planning. The caller gathers both
/// values from the wallet (mapping any wallet error to an RPC error), then hands
/// the snapshot to `engine::plan_migration`. It holds only already-read values,
/// so it is infallible; committing a migration uses the `WalletMigration`
/// adapter over the wallet, not this snapshot.
pub struct SpendableSnapshot {
    orchard_note_values: Vec<u64>,
    chain_tip_height: u32,
}

impl SpendableSnapshot {
    /// Builds a snapshot from the spendable source-pool note values and the
    /// chain-tip height the caller has already read from the wallet.
    pub fn new(orchard_note_values: Vec<u64>, chain_tip_height: u32) -> Self {
        Self {
            orchard_note_values,
            chain_tip_height,
        }
    }
}

impl MigrationBackend for SpendableSnapshot {
    type Error = Infallible;

    fn spendable_orchard_note_values(&self) -> Result<Vec<u64>, Self::Error> {
        Ok(self.orchard_note_values.clone())
    }

    fn chain_tip_height(&self) -> Result<u32, Self::Error> {
        Ok(self.chain_tip_height)
    }
}

/// Why committing (building/pre-signing) a migration failed, in terms the RPC layer maps to
/// user-facing errors without depending on the engine's error shapes.
pub enum CommitFailure {
    /// The account has no spendable source-pool balance to migrate.
    NothingToMigrate,
    /// There is no committed migration to act on (nothing was loaded from the store).
    NoMigrationInProgress,
    /// A migration is already in progress; starting another would overwrite its pre-signed
    /// transactions. The caller must cancel the current migration first.
    AlreadyInProgress,
    /// Any other build/backend failure, rendered to a string.
    Other(String),
}

fn map_plan_error<E: fmt::Display>(err: MigrationError<E>) -> CommitFailure {
    match err {
        MigrationError::NothingToMigrate => CommitFailure::NothingToMigrate,
        MigrationError::Preparation(e) => CommitFailure::Other(format!(
            "the spendable notes cannot fund the migration: {e}"
        )),
        MigrationError::Backend(e) => CommitFailure::Other(e.to_string()),
    }
}

fn map_commit_error<E: fmt::Display>(err: CommitError<E>) -> CommitFailure {
    match err {
        CommitError::NoMigrationInProgress => CommitFailure::NoMigrationInProgress,
        CommitError::Backend(e) => CommitFailure::Other(e.to_string()),
        CommitError::Build(m) => CommitFailure::Other(m),
    }
}

/// An in-memory migration store used to run the engine's commit functions WITHOUT letting them
/// write to SQLite. `commit_preparation` / `commit_transfers` return the resulting
/// [`MigrationState`], so the caller runs the engine against this store, then persists the returned
/// state to the real SQLite store separately. This keeps the engine's wallet access and the store's
/// database access on ONE connection, used sequentially (never two live borrows at once).
#[derive(Default)]
pub struct InMemoryStore {
    state: Option<MigrationState>,
}

impl InMemoryStore {
    /// An in-memory store pre-seeded with a loaded migration (for `commit_transfers`, which reads
    /// the in-progress migration before filling in the transfers).
    pub fn seeded(state: Option<MigrationState>) -> Self {
        Self { state }
    }
}

impl PoolMigrationRead for InMemoryStore {
    type Error = Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }
}

impl PoolMigrationWrite for InMemoryStore {
    fn put_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.state = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        id: MigrationTxId,
        tx_state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        if let Some(state) = &mut self.state {
            if let Some(tx) = state.transactions.iter_mut().find(|t| t.id == id) {
                tx.state = tx_state;
            }
        }
        Ok(())
    }
}

/// The ZIP-317 fee reserved per note-preparation transaction (the fixed padded action count times
/// the marginal fee), as the engine's planning and preparation both compute it.
fn prep_fee_zatoshi() -> u64 {
    PREP_TX_ACTIONS as u64 * Zip317FeePolicy.marginal_fee_zatoshi()
}

/// Loads the persisted migration from the SQLite store over `conn`.
pub fn load_migration(
    conn: &mut Connection,
) -> Result<Option<MigrationState>, zcash_pool_migration_sqlite::Error> {
    PoolMigrations::new(&mut *conn).get_migration()
}

/// Persists a migration to the SQLite store over `conn`, replacing any existing one.
pub fn persist_migration(
    conn: &mut Connection,
    state: &MigrationState,
) -> Result<(), zcash_pool_migration_sqlite::Error> {
    PoolMigrations::new(&mut *conn).put_migration(state)
}

/// Plans and commits the PREPARATION of a migration over the wallet: builds and pre-signs every
/// preparation transaction and records the transfer placeholders, returning the resulting state
/// (NOT persisted; the caller persists it). Runs the engine synchronously; call inside the blocking
/// database section, after the spending key has been decrypted.
pub fn commit_preparation_over_wallet(
    conn: &mut Connection,
    network: &Network,
    account: AccountUuid,
    usk: UnifiedSpendingKey,
    target_height: u32,
) -> Result<MigrationState, CommitFailure> {
    let mut wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
    let mut migration = WalletMigration::new(&mut wallet, account, usk, InMemoryStore::default());
    let mut rng = OsRng;
    let plan = plan_migration(&migration, prep_fee_zatoshi(), &mut rng).map_err(map_plan_error)?;
    commit_preparation(network, target_height, &mut migration, &plan, &mut rng)
        .map_err(map_commit_error)
}

/// Commits the TRANSFERS of an in-progress migration over the wallet: builds and pre-signs the
/// phase-2 transfer transactions (whose funding notes the mined preparation created), returning the
/// updated state (NOT persisted; the caller persists it). `loaded` is the migration read from the
/// store. Runs the engine synchronously; call inside the blocking database section.
pub fn commit_transfers_over_wallet(
    conn: &mut Connection,
    network: &Network,
    account: AccountUuid,
    usk: UnifiedSpendingKey,
    target_height: u32,
    loaded: MigrationState,
) -> Result<MigrationState, CommitFailure> {
    let mut wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
    let store = InMemoryStore::seeded(Some(loaded));
    let mut migration = WalletMigration::new(&mut wallet, account, usk, store);
    let mut rng = OsRng;
    commit_transfers(network, target_height, &mut migration, &mut rng).map_err(map_commit_error)
}

/// Commits the next ready PREPARATION LAYER of an in-progress multi-layer migration over the wallet:
/// a later preparation layer spends the feeder notes minted by the layer before it, which are
/// witnessable only once that layer is mined, so the layer is built here rather than up front. Builds
/// and pre-signs every transaction of the earliest still-unbuilt layer whose predecessor has mined,
/// returning the updated state (NOT persisted; the caller persists it). `loaded` is the migration read
/// from the store. If no layer is ready it returns the state unchanged. Runs the engine synchronously;
/// call inside the blocking database section.
pub fn commit_pending_preparation_over_wallet(
    conn: &mut Connection,
    network: &Network,
    account: AccountUuid,
    usk: UnifiedSpendingKey,
    target_height: u32,
    loaded: MigrationState,
) -> Result<MigrationState, CommitFailure> {
    let mut wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
    let store = InMemoryStore::seeded(Some(loaded));
    let mut migration = WalletMigration::new(&mut wallet, account, usk, store);
    let mut rng = OsRng;
    commit_pending_preparation(network, target_height, &mut migration, &mut rng)
        .map_err(map_commit_error)
}

/// Plans and builds the PREPARATION of a migration for an EXTERNAL signer: builds every layer-0
/// preparation transaction but leaves it UNSIGNED, returning the resulting state (NOT persisted; the
/// caller persists it) together with the unsigned PCZTs to route to the signing device. Mirrors
/// [`commit_preparation_over_wallet`] but leaves the transactions in `AwaitingSignature`; the caller
/// applies the signed PCZTs with [`MigrationState::apply_signature`]. Runs the engine synchronously;
/// call inside the blocking database section.
pub fn build_preparation_unsigned_over_wallet(
    conn: &mut Connection,
    network: &Network,
    account: AccountUuid,
    usk: UnifiedSpendingKey,
    target_height: u32,
) -> Result<(MigrationState, Vec<UnsignedMigrationTx>), CommitFailure> {
    let mut wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
    let mut migration = WalletMigration::new(&mut wallet, account, usk, InMemoryStore::default());
    let mut rng = OsRng;
    let plan = plan_migration(&migration, prep_fee_zatoshi(), &mut rng).map_err(map_plan_error)?;
    build_preparation_unsigned(network, target_height, &mut migration, &plan, &mut rng)
        .map_err(map_commit_error)
}

/// Builds the TRANSFERS of an in-progress migration for an EXTERNAL signer: builds the phase-2
/// transfer transactions (whose funding notes the mined preparation created) but leaves them
/// UNSIGNED, returning the updated state (NOT persisted; the caller persists it) together with the
/// unsigned PCZTs to route to the signing device. Mirrors [`commit_transfers_over_wallet`] but leaves
/// the transactions in `AwaitingSignature`. `loaded` is the migration read from the store. Runs the
/// engine synchronously; call inside the blocking database section.
pub fn build_transfers_unsigned_over_wallet(
    conn: &mut Connection,
    network: &Network,
    account: AccountUuid,
    usk: UnifiedSpendingKey,
    target_height: u32,
    loaded: MigrationState,
) -> Result<(MigrationState, Vec<UnsignedMigrationTx>), CommitFailure> {
    let mut wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
    let store = InMemoryStore::seeded(Some(loaded));
    let mut migration = WalletMigration::new(&mut wallet, account, usk, store);
    let mut rng = OsRng;
    build_transfers_unsigned(network, target_height, &mut migration, &mut rng)
        .map_err(map_commit_error)
}

/// Signs a migration PCZT with the account's Orchard spend authorization, for offline / air-gapped or
/// external-device signing. Parses the unsigned PCZT, adds only the spend-auth signature (the Signer
/// role; it neither proves nor extracts), and returns the serialized signed PCZT to apply to the
/// migration via [`MigrationState::apply_signature`]. This is the counterpart the external signer runs
/// on the built PCZT that [`build_preparation_unsigned_over_wallet`] /
/// [`build_transfers_unsigned_over_wallet`] produced; a hardware wallet performs the same step on the
/// device.
pub fn sign_migration_pczt(
    usk: &UnifiedSpendingKey,
    pczt_bytes: &[u8],
) -> Result<Vec<u8>, SignFailure> {
    let pczt =
        Pczt::parse(pczt_bytes).map_err(|e| SignFailure(format!("parsing the PCZT: {e:?}")))?;
    let ask = SpendAuthorizingKey::from(usk.orchard());
    let signed =
        sign_pczt(pczt, &ask).map_err(|e| SignFailure(format!("signing the PCZT: {e:?}")))?;
    signed
        .serialize()
        .map_err(|e| SignFailure(format!("serializing the signed PCZT: {e:?}")))
}

/// A failure to sign a migration PCZT with the account's spend authorization.
pub struct SignFailure(pub String);

impl fmt::Display for SignFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Why proving or extracting a migration transaction failed.
pub enum BroadcastError {
    /// The stored PCZT could not be parsed.
    Parse(String),
    /// Proving the PCZT failed.
    Prove(String),
    /// Extracting the transaction from the proved PCZT failed.
    Extract(String),
}

impl fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BroadcastError::Parse(m) => write!(f, "parsing the migration transaction failed: {m}"),
            BroadcastError::Prove(m) => write!(f, "proving the migration transaction failed: {m}"),
            BroadcastError::Extract(m) => {
                write!(f, "extracting the migration transaction failed: {m}")
            }
        }
    }
}

/// The Orchard circuit version the migration's transactions are proved and verified against, derived
/// from the consensus branch at `height`. A migration runs at NU6.3+, whose Orchard protocol
/// revision fixes the circuit version; the same version applies to the Orchard preparation bundles
/// and the Ironwood transfer bundles.
fn orchard_circuit_version(params: &Network, height: BlockHeight) -> OrchardCircuitVersion {
    let branch = BranchId::for_height(params, height);
    bundle_version_for_branch(branch, orchard::ValuePool::Orchard)
        .expect("a migration runs at NU6.3+, which has an Orchard bundle version")
        .circuit_version()
}

/// The Orchard proving key, built once and cached (building it is expensive). The same key proves
/// both the Orchard preparation bundles and the Ironwood transfer bundles. All of a migration's
/// transactions share one circuit version (its consensus branch), so caching a single key is sound.
fn orchard_proving_key(version: OrchardCircuitVersion) -> &'static ProvingKey {
    static PROVING_KEY: OnceLock<ProvingKey> = OnceLock::new();
    PROVING_KEY.get_or_init(|| ProvingKey::build(version))
}

/// The Orchard verifying key, built once and cached. It verifies both the Orchard and the Ironwood
/// bundles when the transaction is extracted.
fn orchard_verifying_key(version: OrchardCircuitVersion) -> &'static VerifyingKey {
    static VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();
    VERIFYING_KEY.get_or_init(|| VerifyingKey::build(version))
}

/// Proves a stored, pre-signed but unproven migration PCZT and extracts the broadcastable
/// transaction. `height` selects the circuit version (the migration's consensus branch). Proving is
/// CPU-heavy, so call this inside the blocking database section; the extracted transaction is then
/// broadcast asynchronously by the caller.
pub fn prove_and_extract(
    params: &Network,
    height: BlockHeight,
    pczt_bytes: &[u8],
) -> Result<Transaction, BroadcastError> {
    let version = orchard_circuit_version(params, height);
    let pczt = Pczt::parse(pczt_bytes).map_err(|e| BroadcastError::Parse(format!("{e:?}")))?;
    let mut prover = Prover::new(pczt);
    if prover.requires_orchard_proof() {
        prover = prover
            .create_orchard_proof(orchard_proving_key(version))
            .map_err(|e| BroadcastError::Prove(format!("{e:?}")))?;
    }
    if prover.requires_ironwood_proof() {
        prover = prover
            .create_ironwood_proof(orchard_proving_key(version))
            .map_err(|e| BroadcastError::Prove(format!("{e:?}")))?;
    }
    let pczt = prover.finish();
    TransactionExtractor::new(pczt)
        .with_orchard(orchard_verifying_key(version))
        .extract()
        .map_err(|e| BroadcastError::Extract(format!("{e:?}")))
}

/// Why advancing a migration one step failed.
pub enum AdvanceError {
    /// No migration is stored.
    NoMigration,
    /// A store (load/persist) failure.
    Store(String),
    /// Building the phase-2 transfers failed.
    Commit(CommitFailure),
    /// Proving or extracting a transaction failed.
    Prove(BroadcastError),
    /// The requested step is not supported for this migration (for example external signing of a
    /// multi-layer preparation, which the seam does not yet cover).
    Unsupported(String),
}

/// The outcome of the blocking half of advancing a migration one step.
pub struct AdvanceOutcome {
    /// The migration state after the step. If `to_broadcast` is set, this is NOT yet persisted (the
    /// caller broadcasts, records the txid, and persists); otherwise it is already persisted.
    pub state: MigrationState,
    /// A proved, extracted transaction to broadcast next, with the id of the migration transaction it
    /// corresponds to.
    pub to_broadcast: Option<(Transaction, MigrationTxId)>,
    /// A short description of what the step did.
    pub message: String,
}

/// The txid bytes of a transaction, for recording its broadcast in the store.
pub fn transaction_txid_bytes(tx: &Transaction) -> [u8; 32] {
    *tx.txid().as_ref()
}

/// Records that the migration transaction `tx_id` was broadcast with `txid` (via the engine's state
/// transition, which also recomputes the overall status), and persists the state.
pub fn record_broadcast(
    conn: &mut Connection,
    state: &mut MigrationState,
    tx_id: MigrationTxId,
    txid: [u8; 32],
) -> Result<(), AdvanceError> {
    state.mark_broadcast(tx_id, txid);
    persist_migration(conn, state).map_err(|e| AdvanceError::Store(e.to_string()))
}

/// The blocking half of advancing a migration one step: load it, detect newly mined transactions,
/// then ask the engine for the next step (`state::next_step`, the same decision the mobile wallet
/// makes from state alone) and perform the wallet I/O it calls for: prove+extract the next
/// broadcastable transaction (returned for the caller to broadcast), build+sign the next ready
/// preparation layer, build+sign the transfers, or report what it is waiting for. zallet only does
/// the I/O; the decision lives in the engine. Runs inside the database write lock; the caller
/// broadcasts asynchronously. `tip` is the current chain tip; transactions build and become due at
/// `tip + 1`.
pub fn advance_blocking(
    conn: &mut Connection,
    network: &Network,
    account: AccountUuid,
    usk: UnifiedSpendingKey,
    tip: u32,
) -> Result<AdvanceOutcome, AdvanceError> {
    let target_height = tip + 1;

    let mut state = load_migration(conn)
        .map_err(|e| AdvanceError::Store(e.to_string()))?
        .ok_or(AdvanceError::NoMigration)?;

    // A terminal migration (complete, or cancelled/failed) is never advanced: report its status and
    // do nothing, so a cancelled migration cannot be driven further or resurrected.
    if state.is_terminal() {
        let message = if matches!(state.status, MigrationStatus::Complete) {
            "the migration is complete"
        } else {
            "the migration was cancelled"
        };
        return Ok(AdvanceOutcome {
            state,
            to_broadcast: None,
            message: message.to_string(),
        });
    }

    // Detect newly mined transactions: a broadcast transaction the wallet now sees at a height.
    // Collect the (id, height) pairs while the wallet is borrowed, then apply the engine's mining
    // transition (which recomputes the overall status).
    let mut newly_mined: Vec<(MigrationTxId, u32)> = Vec::new();
    {
        let wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
        for tx in state.transactions.iter() {
            if let MigrationTxState::Broadcast { txid } = tx.state {
                if let Some(height) = wallet
                    .get_tx_height(TxId::from_bytes(txid))
                    .map_err(|e| AdvanceError::Store(e.to_string()))?
                {
                    newly_mined.push((tx.id, u32::from(height)));
                }
            }
        }
    }
    for (id, height) in newly_mined {
        state.mark_mined(id, height);
    }

    // Decide the next step from state alone (the same decision the mobile wallet makes), then perform
    // the wallet I/O it calls for.
    match state.next_step(target_height) {
        // Prove and extract the next ready transaction; the caller broadcasts it.
        AdvanceStep::Broadcast { id } => {
            let tx_ref = state
                .transactions
                .iter()
                .find(|t| t.id == id)
                .ok_or_else(|| AdvanceError::Store("the next transaction is missing".into()))?;
            let bytes = tx_ref.pczt.clone().ok_or_else(|| {
                AdvanceError::Store("a signed transaction is missing its PCZT".into())
            })?;
            let kind = match tx_ref.kind {
                MigrationTxKind::Preparation { .. } => "preparation",
                MigrationTxKind::Transfer { .. } => "transfer",
            };
            let tx = prove_and_extract(network, BlockHeight::from(tip), &bytes)
                .map_err(AdvanceError::Prove)?;
            Ok(AdvanceOutcome {
                state,
                to_broadcast: Some((tx, id)),
                message: format!("broadcasting a {kind} transaction"),
            })
        }
        // Build and pre-sign the next ready preparation layer, whose predecessor has now mined so its
        // feeder notes are witnessable. This turns its transactions into broadcastable ones.
        AdvanceStep::BuildPreparationLayer { layer } => {
            let mut updated = commit_pending_preparation_over_wallet(
                conn,
                network,
                account,
                usk,
                target_height,
                state,
            )
            .map_err(AdvanceError::Commit)?;
            updated.recompute_status();
            persist_migration(conn, &updated).map_err(|e| AdvanceError::Store(e.to_string()))?;
            Ok(AdvanceOutcome {
                state: updated,
                to_broadcast: None,
                message: format!("built preparation layer {layer}"),
            })
        }
        // Build and pre-sign the transfers, now that the whole preparation is mined.
        AdvanceStep::BuildTransfers => {
            let mut updated =
                commit_transfers_over_wallet(conn, network, account, usk, target_height, state)
                    .map_err(AdvanceError::Commit)?;
            updated.recompute_status();
            persist_migration(conn, &updated).map_err(|e| AdvanceError::Store(e.to_string()))?;
            Ok(AdvanceOutcome {
                state: updated,
                to_broadcast: None,
                message: "built the transfer transactions".into(),
            })
        }
        // Nothing to build or broadcast this step: persist the mining updates and report progress.
        AdvanceStep::Waiting | AdvanceStep::Complete => {
            persist_migration(conn, &state).map_err(|e| AdvanceError::Store(e.to_string()))?;
            let pending = state
                .transactions
                .iter()
                .filter(|t| !matches!(t.state, MigrationTxState::Mined { .. }))
                .count();
            let message = if pending == 0 {
                "the migration is complete".to_string()
            } else {
                format!("waiting for {pending} transaction(s) to mine")
            };
            Ok(AdvanceOutcome {
                state,
                to_broadcast: None,
                message,
            })
        }
    }
}

/// The blocking half of building an EXTERNAL migration's transfers, the external-signer counterpart of
/// the transfer-building that [`advance_blocking`] does in process. It loads the migration, detects
/// newly mined preparation transactions (the same detection `advance_blocking` performs, so an
/// external client uses this instead of advancing and never triggers in-process transfer signing), and
/// once the whole preparation is mined builds the phase-2 transfers UNSIGNED, returning their PCZTs to
/// route to the signing device. If the preparation is not yet fully mined it returns no PCZTs and
/// leaves the migration waiting; a multi-layer preparation whose next step is a later unbuilt layer is
/// reported as unsupported for external signing (the seam covers layer-0 preparation and transfers).
/// Persists the state. Runs inside the database write lock. `tip` is the current chain tip;
/// transactions build at `tip + 1`.
pub fn build_transfers_unsigned_blocking(
    conn: &mut Connection,
    network: &Network,
    account: AccountUuid,
    usk: UnifiedSpendingKey,
    tip: u32,
) -> Result<(MigrationState, Vec<UnsignedMigrationTx>, String), AdvanceError> {
    let target_height = tip + 1;

    let mut state = load_migration(conn)
        .map_err(|e| AdvanceError::Store(e.to_string()))?
        .ok_or(AdvanceError::NoMigration)?;

    if state.is_terminal() {
        return Ok((
            state,
            Vec::new(),
            "the migration is no longer in progress".to_string(),
        ));
    }

    // Detect newly mined transactions (identical to `advance_blocking`).
    let mut newly_mined: Vec<(MigrationTxId, u32)> = Vec::new();
    {
        let wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
        for tx in state.transactions.iter() {
            if let MigrationTxState::Broadcast { txid } = tx.state {
                if let Some(height) = wallet
                    .get_tx_height(TxId::from_bytes(txid))
                    .map_err(|e| AdvanceError::Store(e.to_string()))?
                {
                    newly_mined.push((tx.id, u32::from(height)));
                }
            }
        }
    }
    for (id, height) in newly_mined {
        state.mark_mined(id, height);
    }

    match state.next_step(target_height) {
        // The whole preparation is mined: build the transfers unsigned for the external signer.
        AdvanceStep::BuildTransfers => {
            let (mut updated, unsigned) = build_transfers_unsigned_over_wallet(
                conn,
                network,
                account,
                usk,
                target_height,
                state,
            )
            .map_err(AdvanceError::Commit)?;
            updated.recompute_status();
            persist_migration(conn, &updated).map_err(|e| AdvanceError::Store(e.to_string()))?;
            Ok((
                updated,
                unsigned,
                "built the unsigned transfer transactions".to_string(),
            ))
        }
        // A later preparation layer still needs building: external signing does not cover multi-layer
        // preparation yet.
        AdvanceStep::BuildPreparationLayer { layer } => Err(AdvanceError::Unsupported(format!(
            "external signing of a multi-layer preparation is not yet supported (preparation layer \
             {layer} still needs building)"
        ))),
        // The preparation is not yet fully mined (or nothing is ready to build): persist the mining
        // updates and report what the migration is waiting for.
        AdvanceStep::Broadcast { .. } | AdvanceStep::Waiting | AdvanceStep::Complete => {
            persist_migration(conn, &state).map_err(|e| AdvanceError::Store(e.to_string()))?;
            let pending_prep = state
                .transactions
                .iter()
                .filter(|t| matches!(t.kind, MigrationTxKind::Preparation { .. }))
                .filter(|t| !matches!(t.state, MigrationTxState::Mined { .. }))
                .count();
            let message = if pending_prep == 0 {
                "the preparation is mined; no transfers are pending".to_string()
            } else {
                format!("waiting for {pending_prep} preparation transaction(s) to mine")
            };
            Ok((state, Vec::new(), message))
        }
    }
}
