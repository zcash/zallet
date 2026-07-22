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
//! `zcash_client_sqlite::pool_migration`) hold a committed migration, and the
//! `MigrationBackend` trait this snapshot implements is now just the planning
//! inputs. Committing a migration uses the `WalletMigration` adapter over the
//! wallet, not this snapshot.

use core::convert::Infallible;
use core::fmt;
use std::sync::OnceLock;

use orchard::circuit::{OrchardCircuitVersion, VerifyingKey};
use orchard::keys::{FullViewingKey, SpendAuthorizingKey};
use pczt::Pczt;
use pczt::roles::tx_extractor::TransactionExtractor;
use rand::rngs::OsRng;
use rusqlite::Connection;
use shardtree::error::ShardTreeError;
use zcash_client_backend::data_api::{WalletCommitmentTrees, WalletRead};
use zcash_client_sqlite::{AccountUuid, WalletDb, util::SystemClock};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration_backend::build::sign_pczt;
use zcash_pool_migration_backend::engine::{
    CommitError, MigrationBackend, MigrationError, MigrationState, MigrationStatus, MigrationTxId,
    MigrationTxKind, MigrationTxState, PoolMigrationRead, PoolMigrationWrite, UnsignedMigrationTx,
    build_preparation_unsigned, commit_preparation, plan_migration, prove_preparation,
    prove_transfer,
};
// The migration state machine lives in the engine (the mobile wallet drives it the same way); zallet
// only performs the wallet I/O around the engine's decisions. The decision and transition logic are
// methods on `MigrationState` (`next_step`, `mark_mined`, `mark_broadcast`, `is_terminal`, ...).
use zcash_client_sqlite::pool_migration::orchard_ironwood::PoolMigrations;
use zcash_pool_migration_backend::state::AdvanceStep;
use zcash_pool_migration_backend::wallet::{WalletMigration, WalletMigrationProver};
use zcash_primitives::transaction::components::orchard::bundle_version_for_branch;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId};
use zcash_protocol::value::Zatoshis;

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

    fn spendable_orchard_note_values(&self) -> Result<Vec<Zatoshis>, Self::Error> {
        Ok(self
            .orchard_note_values
            .iter()
            .map(|&v| {
                Zatoshis::from_u64(v).expect("a spendable wallet note value is a valid amount")
            })
            .collect())
    }

    fn chain_tip_height(&self) -> Result<BlockHeight, Self::Error> {
        Ok(BlockHeight::from_u32(self.chain_tip_height))
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
        MigrationError::InvalidBalance(e) => {
            CommitFailure::Other(format!("the account balance is invalid: {e}"))
        }
        MigrationError::Fee(e) => {
            CommitFailure::Other(format!("the migration fee could not be computed: {e}"))
        }
        MigrationError::Nu63NotActive => CommitFailure::Other(
            "NU6.3 (the Ironwood pool) is not active at the target height".to_string(),
        ),
    }
}

fn map_commit_error<E: fmt::Display>(err: CommitError<E>) -> CommitFailure {
    match err {
        CommitError::NoMigrationInProgress => CommitFailure::NoMigrationInProgress,
        CommitError::MigrationInProgress => CommitFailure::AlreadyInProgress,
        CommitError::Backend(e) => CommitFailure::Other(e.to_string()),
        CommitError::Build(m) => CommitFailure::Other(m.to_string()),
        CommitError::Serialize(e) => {
            CommitFailure::Other(format!("serializing a migration transaction failed: {e:?}"))
        }
        CommitError::StalePlan => CommitFailure::Other(
            "the migration plan is stale (the wallet's spendable notes changed); retry".to_string(),
        ),
        CommitError::InconsistentPlan(m) => {
            CommitFailure::Other(format!("the migration plan is inconsistent: {m}"))
        }
        CommitError::Nu63NotActive => CommitFailure::Other(
            "NU6.3 (the Ironwood pool) is not active at the target height".to_string(),
        ),
    }
}

/// An in-memory migration store used to run the engine's commit function WITHOUT letting it write
/// to SQLite. `commit_preparation` returns the resulting [`MigrationState`], so the caller runs the
/// engine against this store, then persists the returned state to the real SQLite store separately.
/// This keeps the engine's wallet access and the store's database access on ONE connection, used
/// sequentially (never two live borrows at once).
#[derive(Default)]
pub struct InMemoryStore {
    state: Option<MigrationState>,
}

impl PoolMigrationRead for InMemoryStore {
    type Error = Infallible;

    fn get_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
        Ok(self.state.clone())
    }
}

impl PoolMigrationWrite for InMemoryStore {
    fn replace_migration(&mut self, state: &MigrationState) -> Result<(), Self::Error> {
        self.state = Some(state.clone());
        Ok(())
    }

    fn update_transaction(
        &mut self,
        _id: MigrationTxId,
        _tx_state: MigrationTxState,
    ) -> Result<(), Self::Error> {
        // No-op: this in-memory store only backs the engine's commit functions, which persist the
        // whole migration via `replace_migration`. Per-transaction state transitions run against the
        // real SQLite store during advance/broadcast, and `MigrationState` exposes no cross-crate
        // per-transaction state setter to apply one here.
        Ok(())
    }
}

/// Loads the persisted migration from the SQLite store over `conn`.
pub fn load_migration(
    conn: &mut Connection,
) -> Result<Option<MigrationState>, zcash_client_sqlite::pool_migration::orchard_ironwood::Error> {
    PoolMigrations::new(&mut *conn).get_migration()
}

/// Persists a migration to the SQLite store over `conn`, replacing any existing one.
pub fn persist_migration(
    conn: &mut Connection,
    state: &MigrationState,
) -> Result<(), zcash_client_sqlite::pool_migration::orchard_ironwood::Error> {
    PoolMigrations::new(&mut *conn).replace_migration(state)
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
    let wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
    let mut migration = WalletMigration::new(&wallet, account, usk, InMemoryStore::default());
    let mut rng = OsRng;
    let plan = plan_migration(network, &migration, &mut rng).map_err(map_plan_error)?;
    commit_preparation(
        network,
        BlockHeight::from_u32(target_height),
        &mut migration,
        &plan,
        &mut rng,
    )
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
    let wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
    let mut migration = WalletMigration::new(&wallet, account, usk, InMemoryStore::default());
    let mut rng = OsRng;
    let plan = plan_migration(network, &migration, &mut rng).map_err(map_plan_error)?;
    build_preparation_unsigned(
        network,
        BlockHeight::from_u32(target_height),
        &mut migration,
        &plan,
        &mut rng,
    )
    .map_err(map_commit_error)
}

/// Signs a migration PCZT with the account's Orchard spend authorization, for offline / air-gapped or
/// external-device signing. Parses the unsigned PCZT, adds only the spend-auth signature (the Signer
/// role; it neither proves nor extracts), and returns the serialized signed PCZT to apply to the
/// migration via [`MigrationState::apply_signature`]. This is the counterpart the external signer runs
/// on the built PCZTs that [`build_preparation_unsigned_over_wallet`] produced (a single pass builds
/// every preparation transaction AND every transfer); a hardware wallet performs the same step on the
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

/// The Orchard verifying key, built once and cached. It verifies both the Orchard and the Ironwood
/// bundles when the transaction is extracted.
fn orchard_verifying_key(version: OrchardCircuitVersion) -> &'static VerifyingKey {
    static VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();
    VERIFYING_KEY.get_or_init(|| VerifyingKey::build(version))
}

/// Extracts the broadcastable transaction from an already-proven migration PCZT, verifying its
/// Orchard (and, for a transfer, Ironwood) proofs against the circuit's verifying key. `height`
/// selects the circuit version (the migration's consensus branch). Proving itself is done through
/// the engine (`prove_preparation` / `prove_transfer`), which installs the deferred anchor and
/// witnesses from the wallet's own commitment tree before proving.
fn extract_proven(
    params: &Network,
    height: BlockHeight,
    pczt_bytes: &[u8],
) -> Result<Transaction, BroadcastError> {
    let version = orchard_circuit_version(params, height);
    let pczt = Pczt::parse(pczt_bytes).map_err(|e| BroadcastError::Parse(format!("{e:?}")))?;
    TransactionExtractor::new(pczt)
        .with_orchard(orchard_verifying_key(version))
        .extract()
        .map_err(|e| BroadcastError::Extract(format!("{e:?}")))
}

/// The highest Orchard checkpoint at or below `from` whose commitment-tree root is available, or
/// `None` if there is none. A migration preparation spends the wallet's existing Orchard notes, so
/// it anchors to the newest settled (rooted) checkpoint; right after scanning, the tip checkpoint is
/// not yet rooted, so this walks down from `from` to the newest checkpoint with a root. This mirrors
/// the anchor selection the mobile wallet performs.
fn highest_rooted_orchard_checkpoint<W>(
    db: &mut W,
    from: BlockHeight,
) -> Result<Option<BlockHeight>, AdvanceError>
where
    W: WalletCommitmentTrees,
    <W as WalletCommitmentTrees>::Error: fmt::Debug,
{
    let mut height = u32::from(from);
    loop {
        let bh = BlockHeight::from_u32(height);
        let rooted = db
            .with_orchard_tree_mut::<_, _, ShardTreeError<<W as WalletCommitmentTrees>::Error>>(
                |tree| Ok(tree.root_at_checkpoint_id(&bh)?.is_some()),
            )
            .map_err(|e| AdvanceError::Store(format!("{e:?}")))?;
        if rooted {
            return Ok(Some(bh));
        }
        if height == 0 {
            return Ok(None);
        }
        height -= 1;
    }
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
    state.mark_broadcast(tx_id, TxId::from_bytes(txid));
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
        let message = if matches!(state.status(), MigrationStatus::Complete) {
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
    let mut newly_mined: Vec<(MigrationTxId, BlockHeight)> = Vec::new();
    {
        let wallet = WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
        for tx in state.transactions().iter() {
            if let MigrationTxState::Broadcast { txid } = tx.state() {
                if let Some(height) = wallet
                    .get_tx_height(txid)
                    .map_err(|e| AdvanceError::Store(e.to_string()))?
                {
                    newly_mined.push((tx.id(), height));
                }
            }
        }
    }
    for (id, height) in newly_mined {
        state.mark_mined(id, height);
    }

    // Decide the next step from state alone (the same decision the mobile wallet makes), then perform
    // the wallet I/O it calls for.
    match state.next_step(BlockHeight::from_u32(target_height)) {
        // Prove and extract the next ready transaction; the caller broadcasts it. Proving runs
        // through the engine, which installs each spend's deferred Orchard anchor and witnesses from
        // the wallet's own commitment tree (the transaction was built and signed with the anchor
        // absent, per ZIP 374), then produces the proofs.
        // Prove the next due transaction (`Signed -> Proved`) and store the proven PCZT, WITHOUT
        // broadcasting. Proving installs the deferred Orchard anchor and every spend's witness from
        // the wallet's own commitment tree; for a transfer this must happen while its drawn anchor
        // boundary is still within the wallet's checkpoint-pruning window, so proving is a step
        // separate from (and earlier than) broadcasting, which waits for the privacy broadcast
        // schedule. The proven state is persisted here; the caller broadcasts it in a later step.
        AdvanceStep::Prove { id } => {
            let (is_transfer, kind) = {
                let tx_ref = state
                    .transactions()
                    .iter()
                    .find(|t| t.id() == id)
                    .ok_or_else(|| AdvanceError::Store("the next transaction is missing".into()))?;
                match tx_ref.kind() {
                    MigrationTxKind::Preparation { .. } => (false, "preparation"),
                    MigrationTxKind::Transfer { .. } => (true, "transfer"),
                }
            };
            // Prove in place, scoping the wallet's mutable borrow of `conn`.
            {
                let mut walletdb =
                    WalletDb::from_connection(&mut *conn, *network, SystemClock, OsRng);
                let fvk = FullViewingKey::from(usk.orchard());
                if is_transfer {
                    // A transfer proves against the anchor boundary drawn for it at plan time. The
                    // state machine only offers a transfer to prove once that boundary has settled
                    // below the tip, so its checkpoint exists and is still within the pruning window.
                    let mut prover = WalletMigrationProver::new(&mut walletdb, account, fvk);
                    prove_transfer(&mut prover, &mut state, id).map_err(|e| {
                        AdvanceError::Prove(BroadcastError::Prove(format!("{e:?}")))
                    })?;
                } else {
                    // A preparation spends the wallet's existing Orchard notes; anchor it to the
                    // newest rooted checkpoint at or below the tip.
                    let anchor = highest_rooted_orchard_checkpoint(
                        &mut walletdb,
                        BlockHeight::from_u32(tip),
                    )?
                    .ok_or_else(|| {
                        AdvanceError::Prove(BroadcastError::Prove(
                            "no rooted Orchard checkpoint is available to anchor the \
                                     preparation"
                                .into(),
                        ))
                    })?;
                    let mut prover = WalletMigrationProver::new(&mut walletdb, account, fvk);
                    prove_preparation(&mut prover, &mut state, id, anchor).map_err(|e| {
                        AdvanceError::Prove(BroadcastError::Prove(format!("{e:?}")))
                    })?;
                }
            }
            // The transaction is now `Proved`; persist it (no broadcast this step).
            persist_migration(conn, &state).map_err(|e| AdvanceError::Store(e.to_string()))?;
            Ok(AdvanceOutcome {
                state,
                to_broadcast: None,
                message: format!("proving a {kind} transaction"),
            })
        }
        // Broadcast an ALREADY-PROVEN transaction: extract the stored proven PCZT and hand it to the
        // caller. Proving happened in an earlier `Prove` step, so this needs no wallet-tree access.
        AdvanceStep::Broadcast { id } => {
            let kind = {
                let tx_ref = state
                    .transactions()
                    .iter()
                    .find(|t| t.id() == id)
                    .ok_or_else(|| AdvanceError::Store("the next transaction is missing".into()))?;
                match tx_ref.kind() {
                    MigrationTxKind::Preparation { .. } => "preparation",
                    MigrationTxKind::Transfer { .. } => "transfer",
                }
            };
            let proven_bytes = state
                .transactions()
                .iter()
                .find(|t| t.id() == id)
                .ok_or_else(|| AdvanceError::Store("the proven transaction is missing".into()))?
                .pczt()
                .clone();
            let tx = extract_proven(network, BlockHeight::from(tip), &proven_bytes)
                .map_err(AdvanceError::Prove)?;
            Ok(AdvanceOutcome {
                state,
                to_broadcast: Some((tx, id)),
                message: format!("broadcasting a {kind} transaction"),
            })
        }
        // Nothing to build or broadcast this step: persist the mining updates and report progress.
        // Every preparation layer and every transfer was built and pre-signed up front by
        // `commit_preparation`, so advancing only ever proves and broadcasts due transactions (the
        // `Broadcast` arm above); there is no incremental build step.
        AdvanceStep::Waiting | AdvanceStep::Complete => {
            persist_migration(conn, &state).map_err(|e| AdvanceError::Store(e.to_string()))?;
            let pending = state
                .transactions()
                .iter()
                .filter(|t| !matches!(t.state(), MigrationTxState::Mined { .. }))
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

/// The pre-built unsigned transfers to route to an external signer: the loaded migration state,
/// each transfer's `(id, unsigned PCZT)`, and a human-readable status message.
type UnsignedTransfers = (MigrationState, Vec<(MigrationTxId, Pczt)>, String);

/// Returns the migration's pre-built UNSIGNED transfer transactions, for an EXTERNAL signer.
///
/// A single `commit_preparation` / `build_preparation_unsigned` pass now builds and pre-signs (or,
/// for an external signer, leaves unsigned) every preparation transaction AND every transfer up
/// front — a transfer's funding note is recovered from the still-unmined preparation bundle that
/// mints it, so nothing waits on mining to be built. The transfers therefore already exist in the
/// stored migration (in `AwaitingSignature` until the device signs them). This loads the migration
/// and returns those transfers' unsigned PCZTs to route to the signing device; it builds nothing
/// and persists nothing. `tip` is unused, retained for RPC-signature stability. Runs inside the
/// database write lock.
pub fn build_transfers_unsigned_blocking(
    conn: &mut Connection,
    _network: &Network,
    _account: AccountUuid,
    _usk: UnifiedSpendingKey,
    _tip: u32,
) -> Result<UnsignedTransfers, AdvanceError> {
    let state = load_migration(conn)
        .map_err(|e| AdvanceError::Store(e.to_string()))?
        .ok_or(AdvanceError::NoMigration)?;

    if state.is_terminal() {
        return Ok((
            state,
            Vec::new(),
            "the migration is no longer in progress".to_string(),
        ));
    }

    let transfers: Vec<(MigrationTxId, Pczt)> = state
        .transactions()
        .iter()
        .filter(|t| matches!(t.kind(), MigrationTxKind::Transfer { .. }))
        .filter(|t| matches!(t.state(), MigrationTxState::AwaitingSignature))
        .map(|t| {
            Pczt::parse(t.pczt())
                .map(|pczt| (t.id(), pczt))
                .map_err(|e| {
                    AdvanceError::Store(format!("a stored transfer PCZT is corrupt: {e:?}"))
                })
        })
        .collect::<Result<_, _>>()?;

    let message = if transfers.is_empty() {
        "no transfers are awaiting signature".to_string()
    } else {
        format!(
            "{} unsigned transfer transaction(s) awaiting signature",
            transfers.len()
        )
    };
    Ok((state, transfers, message))
}
