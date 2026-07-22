//! Shared types and validation for the generic value-pool migration RPC surface.
//!
//! The migration surface is a pool-to-pool workflow (`z_startpoolmigration` and the
//! companion status, advance, cancel, and list methods) spread across sibling method
//! modules. This module holds what they share: the pool-agnostic [`Pool`] type, the
//! [`SUPPORTED_MIGRATIONS`] table that is the single extension point for new pool
//! pairs, the fixed migration identifier and pools, the plan/progress/phase response
//! shapes and their mapping from the engine's state, and the input validation.
//!
//! `z_startpoolmigration` builds, pre-signs, and persists the migration; the status
//! and list methods read the persisted state; cancel marks it cancelled; and
//! `z_advancepoolmigration` proves, broadcasts, and (for a multi-layer preparation)
//! builds each later transaction as its dependencies mine, driving the migration to
//! completion.

use base64ct::{Base64, Encoding};
use documented::Documented;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use pczt::Pczt;
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Serialize;
use zcash_client_backend::data_api::{Account, WalletRead};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_pool_migration_backend::engine::{
    MigrationState, MigrationStatus, MigrationTxId, MigrationTxKind, MigrationTxState,
    UnsignedMigrationTx,
};
use zcash_pool_migration_backend::state::{
    Blocker, NextAction, TransactionStatus as EngineTransactionStatus,
};
use zcash_protocol::consensus::{BlockHeight, NetworkUpgrade, Parameters};

use crate::components::keystore::KeyStore;
use crate::components::{database::DbConnection, json_rpc::server::LegacyCode};
use crate::migrate::{AdvanceError, CommitFailure};

/// The identifier of the wallet's pool migration. The store holds at most one migration at a time,
/// so a single fixed identifier names it: `z_startpoolmigration` returns this, and the status,
/// advance, and cancel methods accept it.
pub(crate) const MIGRATION_ID: &str = "orchard-to-ironwood";

/// The only supported migration is Orchard -> Ironwood, so a stored migration's pools and enabling
/// upgrade are fixed rather than recorded per migration.
pub(crate) const MIGRATION_FROM_POOL: Pool = Pool::Orchard;
pub(crate) const MIGRATION_TO_POOL: Pool = Pool::Ironwood;
pub(crate) const MIGRATION_ENABLING_UPGRADE: NetworkUpgrade = NetworkUpgrade::Nu6_3;

/// Wire name of the Sapling value pool.
const POOL_NAME_SAPLING: &str = "sapling";
/// Wire name of the Orchard value pool.
const POOL_NAME_ORCHARD: &str = "orchard";
/// Wire name of the Ironwood value pool.
const POOL_NAME_IRONWOOD: &str = "ironwood";

/// A Zcash shielded value pool that can take part in a pool-to-pool migration.
///
/// Serialized as its lowercase wire name (`"sapling"`, `"orchard"`, `"ironwood"`). New
/// pools are added here and, if they can be migrated, wired into
/// [`SUPPORTED_MIGRATIONS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Pool {
    /// The Sapling shielded value pool.
    Sapling,
    /// The Orchard shielded value pool.
    Orchard,
    /// The Ironwood shielded value pool (NU6.3, ZIP 2005).
    Ironwood,
}

impl Pool {
    /// Returns the lowercase wire name of this pool.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Pool::Sapling => POOL_NAME_SAPLING,
            Pool::Orchard => POOL_NAME_ORCHARD,
            Pool::Ironwood => POOL_NAME_IRONWOOD,
        }
    }

    /// Parses a pool from its wire name, returning an `InvalidParameter` RPC error for
    /// any unrecognized value.
    pub(crate) fn parse(label: &str, value: &str) -> RpcResult<Self> {
        match value {
            POOL_NAME_SAPLING => Ok(Pool::Sapling),
            POOL_NAME_ORCHARD => Ok(Pool::Orchard),
            POOL_NAME_IRONWOOD => Ok(Pool::Ironwood),
            other => Err(LegacyCode::InvalidParameter.with_message(format!(
                "{label}: unknown value pool {other:?}; expected one of \
                 {POOL_NAME_SAPLING:?}, {POOL_NAME_ORCHARD:?}, {POOL_NAME_IRONWOOD:?}",
            ))),
        }
    }
}

/// One supported pool-to-pool migration and the network upgrade that enables it.
struct SupportedMigration {
    /// The value pool funds are migrated from.
    from: Pool,
    /// The value pool funds are migrated to.
    to: Pool,
    /// The network upgrade that must be active for this migration to run.
    enabling_upgrade: NetworkUpgrade,
}

/// The single source of truth for which pool-to-pool migrations exist and which
/// network upgrade each one requires.
///
/// This is the one extension point for supporting new migrations: adding a pool pair
/// here makes it selectable through the whole RPC surface. Migrating from the Orchard
/// pool to the Ironwood pool requires NU6.3 (ZIP 2005).
const SUPPORTED_MIGRATIONS: &[SupportedMigration] = &[SupportedMigration {
    from: Pool::Orchard,
    to: Pool::Ironwood,
    enabling_upgrade: NetworkUpgrade::Nu6_3,
}];

/// Looks up a supported migration by its ordered pool pair.
fn supported_migration(from: Pool, to: Pool) -> Option<&'static SupportedMigration> {
    SUPPORTED_MIGRATIONS
        .iter()
        .find(|m| m.from == from && m.to == to)
}

/// Parses and validates a pool pair, returning the parsed pools and the network
/// upgrade that enables the migration.
///
/// Validates that the pair is present in [`SUPPORTED_MIGRATIONS`] and that its enabling
/// upgrade is active at the wallet's current chain height, returning an
/// `InvalidParameter` RPC error otherwise.
pub(crate) fn validate_pool_pair(
    wallet: &DbConnection,
    from_pool: &str,
    to_pool: &str,
) -> RpcResult<(Pool, Pool, NetworkUpgrade)> {
    let from_pool = Pool::parse("from_pool", from_pool)?;
    let to_pool = Pool::parse("to_pool", to_pool)?;

    if from_pool == to_pool {
        return Err(LegacyCode::InvalidParameter.with_message(format!(
            "from_pool and to_pool must differ; both were {:?}",
            from_pool.name(),
        )));
    }

    let migration = supported_migration(from_pool, to_pool).ok_or_else(|| {
        LegacyCode::InvalidParameter.with_message(format!(
            "migrating from the {:?} pool to the {:?} pool is not supported",
            from_pool.name(),
            to_pool.name(),
        ))
    })?;

    let params = wallet.params();
    let activation = params.activation_height(migration.enabling_upgrade);

    let chain_height = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;

    match activation {
        Some(height) if chain_height >= height => {
            Ok((from_pool, to_pool, migration.enabling_upgrade))
        }
        _ => Err(LegacyCode::InvalidParameter.with_message(format!(
            "migrating from the {:?} pool to the {:?} pool requires network upgrade {} \
             to be active",
            from_pool.name(),
            to_pool.name(),
            migration.enabling_upgrade,
        ))),
    }
}

/// Decrypts the account's unified spending key. This is the async step that must run BEFORE the
/// blocking build/prove section (no `.await` may occur while the database write lock is held).
/// Mirrors the send path: find the account's ZIP-32 derivation, decrypt its seed, and derive the
/// spending key.
pub(crate) async fn decrypt_account_usk(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account_id: AccountUuid,
) -> RpcResult<UnifiedSpendingKey> {
    let account = wallet
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InvalidParameter.with_static("no such account"))?;
    let derivation = account.source().key_derivation().ok_or_else(|| {
        LegacyCode::InvalidAddressOrKey
            .with_static("the account has no spending key to migrate with")
    })?;
    let seed = keystore
        .decrypt_seed(derivation.seed_fingerprint())
        .await
        .map_err(|e| match e.kind() {
            crate::error::ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
            }
            _ => LegacyCode::Database.with_message(e.to_string()),
        })?;
    UnifiedSpendingKey::from_seed(
        wallet.params(),
        seed.expose_secret(),
        derivation.account_index(),
    )
    .map_err(|e| LegacyCode::InvalidAddressOrKey.with_message(e.to_string()))
}

/// One built-but-unsigned migration transaction, as returned to a client driving an EXTERNAL
/// (hardware or offline) signer: its stable id within the migration and its unsigned PCZT, base64
/// encoded. The client signs the PCZT out of band (on the device) and hands the signed PCZT back via
/// `z_applypoolmigrationsignature`, matched to the transaction by this `id`.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct UnsignedMigrationTransaction {
    /// The stable identifier of the transaction within the migration.
    pub id: u32,
    /// The unsigned PCZT to sign externally, base64 encoded.
    pub pczt: String,
}

/// Base64-encodes the engine's unsigned PCZTs into the RPC response shape, preserving each
/// transaction's id so the signed PCZT can be matched back on the way in.
pub(crate) fn encode_unsigned(
    unsigned: Vec<UnsignedMigrationTx>,
) -> Vec<UnsignedMigrationTransaction> {
    unsigned
        .into_iter()
        .map(|u| UnsignedMigrationTransaction {
            id: u32::from(u.id()),
            pczt: Base64::encode_string(u.pczt()),
        })
        .collect()
}

/// Base64-encodes `(id, PCZT)` pairs into the RPC response shape. Used where the unsigned PCZTs are
/// read straight from a stored [`MigrationState`] (its transactions already hold them) rather than
/// freshly returned by the engine as [`UnsignedMigrationTx`].
pub(crate) fn encode_unsigned_pairs(
    unsigned: Vec<(MigrationTxId, Pczt)>,
) -> Result<Vec<UnsignedMigrationTransaction>, ErrorObjectOwned> {
    unsigned
        .into_iter()
        .map(|(id, pczt)| {
            let bytes = pczt.serialize().map_err(|e| {
                LegacyCode::Misc.with_message(format!("serializing a migration PCZT failed: {e:?}"))
            })?;
            Ok(UnsignedMigrationTransaction {
                id: u32::from(id),
                pczt: Base64::encode_string(&bytes),
            })
        })
        .collect()
}

/// Validates that a migration identifier is well-formed (currently just non-empty).
pub(crate) fn validate_migration_id(migration_id: &str) -> RpcResult<()> {
    if migration_id.trim().is_empty() {
        return Err(LegacyCode::InvalidParameter.with_static("migration_id must not be empty"));
    }
    Ok(())
}

/// The lifecycle phase of a pool migration.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MigrationPhase {
    /// The migration has been scheduled but no transactions have been created.
    Scheduled,
    /// The migration is creating and broadcasting transactions.
    InProgress,
    /// Every planned transaction has been mined.
    Completed,
    /// The migration was cancelled before completing.
    Cancelled,
}

impl MigrationPhase {
    /// The lifecycle phase corresponding to a stored migration's overall status.
    pub(crate) fn from_status(status: MigrationStatus) -> Self {
        match status {
            MigrationStatus::Planning | MigrationStatus::Committed => MigrationPhase::Scheduled,
            MigrationStatus::InProgress => MigrationPhase::InProgress,
            MigrationStatus::Complete => MigrationPhase::Completed,
            MigrationStatus::Failed => MigrationPhase::Cancelled,
        }
    }
}

/// Builds the response plan summary from the number of transactions a migration comprises.
pub(crate) fn migration_plan(transaction_count: u32) -> MigrationPlan {
    MigrationPlan { transaction_count }
}

/// Summarizes a migration's progress: how many of its transactions have been mined, out of the
/// total the migration comprises.
pub(crate) fn migration_progress(state: &MigrationState) -> MigrationProgress {
    let total_transactions = state.transactions().len() as u32;
    let completed_transactions = state
        .transactions()
        .iter()
        .filter(|t| matches!(t.state(), MigrationTxState::Mined { .. }))
        .count() as u32;
    MigrationProgress {
        completed_transactions,
        total_transactions,
    }
}

/// Whether this is a preparation (note-splitting) or a transfer (pool-crossing) transaction.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MigrationTxRole {
    /// A same-pool note-preparation transaction that mints self-funding notes.
    Preparation,
    /// A transfer that crosses one funding note into the destination pool.
    Transfer,
}

/// The lifecycle state of one migration transaction.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MigrationTxLifecycle {
    /// Built and awaiting an external signature: its unsigned PCZT has been exported to a hardware or
    /// offline signer, and the wallet is waiting for the signed PCZT to be applied.
    AwaitingSignature,
    /// Built and pre-signed, ready to prove and broadcast once it is due.
    Signed,
    /// Proved against a real anchor, ready to broadcast.
    Proved,
    /// Broadcast to the network, awaiting confirmation.
    Broadcast,
    /// Mined into a block.
    Mined,
}

/// Why a migration transaction is not yet actionable.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MigrationTxBlocker {
    /// Waiting for its dependency transactions (an earlier preparation layer, or the whole
    /// preparation) to mine, so its input notes become witnessable in a new anchor bucket. A
    /// multi-layer preparation signs and broadcasts each layer in a separate anchor bucket, so a
    /// later layer cannot be built until its predecessor has mined.
    Dependencies,
    /// Built and due only at a later height (the privacy broadcast schedule): waiting for the chain
    /// tip to reach its scheduled height.
    Schedule,
    /// A transfer whose drawn anchor boundary has not yet settled: waiting for the chain tip to move
    /// strictly past the boundary block so its checkpoint exists and the transfer can be proved
    /// against it (while it is still within the wallet's checkpoint-pruning window).
    AnchorBoundary,
    /// Built as an unsigned PCZT and waiting for an external (hardware or offline) signer to return
    /// the signed PCZT, which the wallet then applies before proving and broadcasting.
    Signature,
}

/// The action a wallet takes next on a ready migration transaction.
#[derive(Clone, Copy, Debug, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MigrationTxAction {
    /// Prove this pre-signed transaction now (install its deferred anchor and witnesses and store the
    /// proven PCZT): its dependencies are mined and, for a transfer, its anchor boundary has settled
    /// within the wallet's checkpoint-pruning window. It is not broadcast yet.
    Prove,
    /// Broadcast this already-proven transaction now that its scheduled broadcast height has arrived.
    Broadcast,
}

/// The status of one migration transaction, as a wallet renders it and decides the next step. This
/// is the machine-readable companion to the human status string: a mobile wallet, which cannot
/// pre-sign a multi-layer migration up front and may be restarted between layers, uses it to show
/// the user which transaction to sign or broadcast next and what the rest are waiting on.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct MigrationTransactionStatus {
    /// Stable identifier of this transaction within the migration.
    id: u32,
    /// Whether this is a preparation or a transfer transaction.
    kind: MigrationTxRole,
    /// For a preparation transaction, its layer, which is also its anchor bucket: layer 0 is signed
    /// first, and each later layer is signed only once its predecessor has mined. Absent for
    /// transfers.
    layer: Option<u32>,
    /// For a transfer, which crossing it performs. Absent for preparation transactions.
    crossing: Option<u32>,
    /// The transaction's current lifecycle state.
    state: MigrationTxLifecycle,
    /// The transactions that must be mined before this one can be built or broadcast.
    depends_on: Vec<u32>,
    /// The height at or after which this transaction is due to broadcast.
    scheduled_height: u32,
    /// Whether the wallet can act on this transaction right now.
    ready: bool,
    /// The action available now, when `ready` is true.
    action: Option<MigrationTxAction>,
    /// Why the transaction is not yet actionable, when it is waiting (and not already broadcast or
    /// mined).
    blocked_on: Option<MigrationTxBlocker>,
    /// The transaction id, once broadcast (hex, big-endian display form).
    txid: Option<String>,
    /// The height it was mined at, once mined.
    mined_height: Option<u32>,
}

/// Maps one engine transaction status to the JSON-RPC shape: flattens the engine's `kind` into
/// `layer`/`crossing`, maps the lifecycle and reason enums to their serde-friendly counterparts, and
/// renders the txid as a big-endian hex string.
fn to_rpc_status(es: EngineTransactionStatus) -> MigrationTransactionStatus {
    let (kind, layer, crossing) = match es.kind() {
        MigrationTxKind::Preparation { layer, .. } => {
            (MigrationTxRole::Preparation, Some(layer as u32), None)
        }
        MigrationTxKind::Transfer { crossing } => {
            (MigrationTxRole::Transfer, None, Some(crossing as u32))
        }
    };
    // The engine dropped the `Planned` and `Expired` lifecycle states: a single commit pass now
    // builds and pre-signs every transaction up front (so none is ever merely `Planned`), and expiry
    // handling is not yet modelled. The RPC's `MigrationTxLifecycle` still defines those variants;
    // they are simply never produced now.
    let state = match es.state() {
        MigrationTxState::AwaitingSignature => MigrationTxLifecycle::AwaitingSignature,
        MigrationTxState::Signed => MigrationTxLifecycle::Signed,
        MigrationTxState::Proved => MigrationTxLifecycle::Proved,
        MigrationTxState::Broadcast { .. } => MigrationTxLifecycle::Broadcast,
        MigrationTxState::Mined { .. } => MigrationTxLifecycle::Mined,
    };
    // Everything is built up front, so a transaction is either proved (installing its anchor and
    // witnesses) or, once proved, broadcast; the old `BuildAndSign` action no longer exists.
    let action = es.action().map(|a| match a {
        NextAction::Prove => MigrationTxAction::Prove,
        NextAction::Broadcast => MigrationTxAction::Broadcast,
    });
    let blocked_on = es.blocked_on().map(|b| match b {
        Blocker::Dependencies => MigrationTxBlocker::Dependencies,
        Blocker::Schedule => MigrationTxBlocker::Schedule,
        Blocker::AnchorBoundary => MigrationTxBlocker::AnchorBoundary,
        Blocker::Signature => MigrationTxBlocker::Signature,
    });
    let txid = es.txid().map(|txid| {
        let mut bytes = *txid.as_ref();
        bytes.reverse();
        hex::encode(bytes)
    });
    MigrationTransactionStatus {
        id: u32::from(es.id()),
        kind,
        layer,
        crossing,
        state,
        depends_on: es.depends_on().iter().map(|d| u32::from(*d)).collect(),
        scheduled_height: es.scheduled_height().into(),
        ready: es.ready(),
        action,
        blocked_on,
        txid,
        mined_height: es.mined_height().map(u32::from),
    }
}

/// Builds the per-transaction status view for the RPC at `target_height` (the height the next
/// transaction would build at, i.e. `chain_tip + 1`), by mapping the engine's shared
/// `transaction_statuses` decision logic into the JSON-RPC shape. The engine owns the ready/blocked
/// rules so a wallet (the mobile wallet, or zallet here) renders the same next-actions from state.
pub(crate) fn migration_transactions(
    state: &MigrationState,
    target_height: u32,
) -> Vec<MigrationTransactionStatus> {
    state
        .transaction_statuses(BlockHeight::from_u32(target_height))
        .into_iter()
        .map(to_rpc_status)
        .collect()
}

/// The RPC error for a migration id that does not name the wallet's migration, or when no migration
/// is stored.
pub(crate) fn no_such_migration() -> ErrorObjectOwned {
    LegacyCode::InvalidParameter.with_static("no such migration")
}

/// Maps a migration build/commit failure to an RPC error.
pub(crate) fn map_commit_failure(failure: CommitFailure) -> ErrorObjectOwned {
    match failure {
        CommitFailure::NothingToMigrate => LegacyCode::InvalidParameter
            .with_static("the account has no spendable source-pool balance to migrate"),
        CommitFailure::NoMigrationInProgress => {
            LegacyCode::InvalidParameter.with_static("no migration is in progress")
        }
        CommitFailure::AlreadyInProgress => LegacyCode::InvalidParameter
            .with_static("a migration is already in progress; cancel it before starting another"),
        CommitFailure::Other(message) => LegacyCode::Misc.with_message(message),
    }
}

/// Maps a migration advance/build failure to an RPC error.
pub(crate) fn map_advance_error(err: AdvanceError) -> ErrorObjectOwned {
    match err {
        AdvanceError::NoMigration => no_such_migration(),
        AdvanceError::Store(message) => LegacyCode::Database.with_message(message),
        AdvanceError::Commit(failure) => map_commit_failure(failure),
        AdvanceError::Prove(e) => LegacyCode::Misc.with_message(e.to_string()),
        AdvanceError::Unsupported(message) => LegacyCode::InvalidParameter.with_message(message),
    }
}

/// The plan produced when a migration is committed.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct MigrationPlan {
    /// The number of transactions the migration is expected to require.
    transaction_count: u32,
}

/// Progress of an in-flight migration.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct MigrationProgress {
    /// The number of planned transactions that have been mined so far.
    completed_transactions: u32,
    /// The total number of transactions the migration requires.
    total_transactions: u32,
}
