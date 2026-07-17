//! `z_previewpoolmigration`: preview the migration plan for a pool migration.
//!
//! Unlike the rest of the pool-migration surface (which is still a scaffold; see
//! [`pool_migration`](super::pool_migration)), this method is fully wired: it enumerates the
//! account's spendable source-pool (Orchard) notes and runs the backend-agnostic migration
//! engine's PLANNING slice (`zcash_pool_migration_backend::engine::plan_migration`) to show how
//! that balance would be decomposed into the self-funding notes that cross the Orchard -> Ironwood
//! turnstile, when each note's transfer is scheduled to broadcast, and when it expires.
//!
//! It is READ-ONLY: it computes and returns a plan but schedules, builds, proves, and broadcasts
//! nothing. Actually carrying out a migration needs the (still-unreleased) engine `commit` and
//! reconcile slices that build, pre-sign, and persist the PCZTs, so that path stays behind
//! [`not_implemented`](super::pool_migration::not_implemented) in `z_startpoolmigration`. This
//! preview is the achievable planning slice today, and the preview a wallet shows the user for
//! consent (ZIP 318 requires consent to the pool-crossing amounts before any funds leave the pool).

use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use rand::rngs::OsRng;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::{
    data_api::{InputSource, WalletRead, wallet::TargetHeight},
    fees::orchard::InputView as _,
};
use zcash_protocol::ShieldedPool;

use super::pool_migration::{Pool, validate_pool_pair};
use crate::{
    components::{
        database::DbConnection,
        json_rpc::{server::LegacyCode, utils::parse_account_parameter},
        keystore::KeyStore,
    },
    migrate::{
        SnapshotError, SpendableSnapshot,
        engine::{
            engine::{MigrationError, MigrationPlan, plan_migration},
            note_splitting::{FeePolicy, Zip317FeePolicy},
            preparation::{PREP_TX_ACTIONS, PreparationPlan},
        },
    },
};

/// Response to a `z_previewpoolmigration` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = PoolMigrationPreview;

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "Either the UUID or ZIP 32 account index of the account whose balance to migrate.";
pub(super) const PARAM_FROM_POOL_DESC: &str =
    "The value pool to migrate funds from (\"sapling\", \"orchard\", or \"ironwood\").";
pub(super) const PARAM_TO_POOL_DESC: &str =
    "The value pool to migrate funds to (\"sapling\", \"orchard\", or \"ironwood\").";
pub(super) const PARAM_MINCONF_DESC: &str =
    "Only include source-pool notes confirmed at least this many times (default 1).";

/// The default minimum number of confirmations a source-pool note must have to be planned over.
const DEFAULT_MINCONF: u32 = 1;

/// The proposed migration plan for moving an account's balance between two pools.
///
/// Read-only preview of the plan produced by the migration engine. Nothing is scheduled or
/// broadcast; the fields describe what a migration run would prepare, cross, and leave behind.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct PoolMigrationPreview {
    /// The value pool funds would be migrated from.
    from_pool: Pool,
    /// The value pool funds would be migrated to.
    to_pool: Pool,
    /// The network upgrade that enables this migration (for example `"Nu6.3"`).
    enabling_upgrade: String,
    /// The account's total spendable balance in the source pool (in zatoshis): the sum of the
    /// spendable source-pool notes the plan decomposes.
    account_balance_zat: u64,
    /// The fee (in zatoshis) reserved for each note-preparation transaction: the ZIP-317 fee of a
    /// padded preparation transaction (its fixed action count times the marginal fee).
    prep_fee_zat: u64,
    /// The total value (in zatoshis) that would migrate to the destination pool: the sum of the
    /// crossing values of the funding notes the plan actually mints (after reconciling the split
    /// against the preparation fees).
    total_migratable_zat: u64,
    /// Residual (in zatoshis) left in the source pool by the note split because it could not form a
    /// whole self-funding note (or the note cap was reached). This is the note-split residual only;
    /// the preparation transactions may leave further residual notes (see
    /// [`PreviewPreparation::residual_note_count`]).
    source_change_zat: u64,
    /// The number of self-funding notes the plan would mint (equal to `funding_notes.len()`).
    funding_note_count: u32,
    /// The per-note breakdown, one entry per funding note the plan mints, paired with that note's
    /// transfer schedule.
    funding_notes: Vec<PreviewFundingNote>,
    /// A summary of the note-split decomposition before it was reconciled against the preparation
    /// fees (the funding notes above are this split minus any denominations dropped to fit the
    /// fees).
    note_split: PreviewNoteSplit,
    /// A summary of the note-preparation transactions that would mint the funding notes.
    preparation: PreviewPreparation,
}

/// One funding note in a [`PoolMigrationPreview`], with its transfer schedule.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct PreviewFundingNote {
    /// The value (in zatoshis) of the self-funding note minted in the source pool: its crossing
    /// value plus the fee buffer that lets it pay its own migration-transfer fee.
    output_zat: u64,
    /// The denomination value (in zatoshis) that crosses the turnstile when this note is spent.
    crossing_zat: u64,
    /// The block height at which this note's migration transfer is scheduled to be broadcast.
    broadcast_height: u32,
    /// The block height at (and after) which this note's migration transfer is no longer valid.
    expiry_height: u32,
}

/// A summary of the note-split decomposition in a [`PoolMigrationPreview`], before reconciliation
/// against the preparation fees.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct PreviewNoteSplit {
    /// The number of denominations the raw split produced.
    note_count: u32,
    /// The total value (in zatoshis) the raw split would migrate (the sum of its crossing values).
    total_migratable_zat: u64,
    /// The crossing values (in zatoshis) the raw split chose, one per denomination.
    crossing_values: Vec<u64>,
}

/// A summary of the note-preparation transactions in a [`PoolMigrationPreview`].
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct PreviewPreparation {
    /// The number of sequential dependency layers of preparation transactions.
    layer_count: u32,
    /// The total number of preparation transactions across all layers.
    transaction_count: u32,
    /// The number of residual notes the preparation leaves in the source pool (at most one worth a
    /// fee, plus any sub-fee dust).
    residual_note_count: u32,
}

pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account: JsonValue,
    from_pool: &str,
    to_pool: &str,
    minconf: Option<u32>,
) -> Response {
    let (from_pool, to_pool, enabling_upgrade) = validate_pool_pair(wallet, from_pool, to_pool)?;
    let account_id = parse_account_parameter(wallet, keystore, &account).await?;

    let minconf = minconf.unwrap_or(DEFAULT_MINCONF);

    // The chain tip: the height the schedule's delays accumulate from, and the basis for the target
    // height at which notes are selected. Absent it, the wallet has not synced far enough to plan.
    let chain_height = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;
    let target_height = TargetHeight::from(chain_height + 1);

    // Enumerate the account's spendable source-pool (Orchard) notes as individual values: the engine
    // decomposes their total, and the preparation planner needs the per-note values. Mirrors the note
    // selection and confirmation filter used by `z_listunspent`.
    let received = wallet
        .select_unspent_notes(account_id, &[ShieldedPool::Orchard], target_height, &[])
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let mut orchard_note_values = Vec::new();
    for note in received.orchard().iter() {
        let mined_height = wallet
            .get_tx_height(*note.txid())
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
        // Include only notes mined with at least `minconf` confirmations; skip unmined notes.
        match mined_height {
            Some(h) if h <= target_height.saturating_sub(minconf) => {
                orchard_note_values.push(u64::from(note.value()));
            }
            _ => {}
        }
    }

    let account_balance_zat: u64 = orchard_note_values.iter().sum();

    // The ZIP-317 fee of a padded note-preparation transaction, which the note split and the
    // preparation planner both reserve. Built from the crate's own constants (no magic numbers).
    let prep_fee_zat = PREP_TX_ACTIONS as u64 * Zip317FeePolicy.marginal_fee_zatoshi();

    // No `.await` past this point: build the snapshot backend and run the pure planner synchronously.
    let backend = SpendableSnapshot::new(orchard_note_values, u32::from(chain_height));
    let mut rng = OsRng;
    let plan = plan_migration(&backend, prep_fee_zat, &mut rng).map_err(map_plan_error)?;

    Ok(preview_from_plan(
        from_pool,
        to_pool,
        enabling_upgrade.to_string(),
        account_balance_zat,
        &plan,
    ))
}

/// Maps a migration-planning error to an RPC error.
fn map_plan_error(err: MigrationError<SnapshotError>) -> jsonrpsee::types::ErrorObjectOwned {
    match err {
        MigrationError::NothingToMigrate => LegacyCode::InvalidParameter
            .with_static("the account has no spendable source-pool balance to migrate"),
        MigrationError::Preparation(e) => LegacyCode::InvalidParameter.with_message(format!(
            "the spendable notes cannot fund the migration: {e}"
        )),
        // Planning calls only the snapshot's read methods, which never fail; a backend error here
        // would indicate a future change to `plan_migration`, so surface it rather than hide it.
        MigrationError::Backend(e) => LegacyCode::Misc.with_message(format!("{e}")),
    }
}

/// Assembles the RPC response from a planned migration.
///
/// Kept pure (no wallet access) so the response contract can be unit-tested directly against a plan.
fn preview_from_plan(
    from_pool: Pool,
    to_pool: Pool,
    enabling_upgrade: String,
    account_balance_zat: u64,
    plan: &MigrationPlan,
) -> PoolMigrationPreview {
    // Each funding note holds its crossing value plus a fixed transfer fee buffer, so the crossing
    // value is the funding note less that buffer.
    let buffer = Zip317FeePolicy.transfer_fee_buffer_zatoshi();

    let funding_notes = plan
        .funding_notes()
        .iter()
        .zip(plan.schedule())
        .map(|(&output_zat, schedule)| PreviewFundingNote {
            output_zat,
            crossing_zat: output_zat.saturating_sub(buffer),
            broadcast_height: schedule.broadcast_height(),
            expiry_height: schedule.expiry_height(),
        })
        .collect::<Vec<_>>();

    let total_migratable_zat = funding_notes.iter().map(|n| n.crossing_zat).sum();

    PoolMigrationPreview {
        from_pool,
        to_pool,
        enabling_upgrade,
        account_balance_zat,
        prep_fee_zat: plan.note_split().prep_fee_zatoshi(),
        total_migratable_zat,
        source_change_zat: plan.note_split().change().unwrap_or(0),
        funding_note_count: funding_notes.len() as u32,
        funding_notes,
        note_split: PreviewNoteSplit {
            note_count: plan.note_split().crossing_values().len() as u32,
            total_migratable_zat: plan.note_split().total_migratable_zatoshi(),
            crossing_values: plan.note_split().crossing_values().to_vec(),
        },
        preparation: preparation_summary(plan.preparation()),
    }
}

/// Summarizes a preparation plan for the preview.
fn preparation_summary(preparation: &PreparationPlan) -> PreviewPreparation {
    PreviewPreparation {
        layer_count: preparation.layer_count() as u32,
        transaction_count: preparation.transaction_count() as u32,
        residual_note_count: preparation.residual_count() as u32,
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use zcash_protocol::value::COIN;

    use super::*;
    use crate::migrate::engine::engine::{
        MigrationBackend, MigrationState, MigrationTxId, MigrationTxState,
    };

    /// A minimal planning backend for tests: a fixed set of spendable note values and a chain tip.
    /// Persistence is unsupported (planning never uses it), mirroring `SpendableSnapshot`.
    struct MockBackend {
        notes: Vec<u64>,
        tip: u32,
    }

    impl MigrationBackend for MockBackend {
        type Error = SnapshotError;

        fn spendable_orchard_note_values(&self) -> Result<Vec<u64>, Self::Error> {
            Ok(self.notes.clone())
        }

        fn chain_tip_height(&self) -> Result<u32, Self::Error> {
            Ok(self.tip)
        }

        fn store_migration(&mut self, _state: &MigrationState) -> Result<(), Self::Error> {
            Err(SnapshotError::PersistenceUnsupported)
        }

        fn load_migration(&self) -> Result<Option<MigrationState>, Self::Error> {
            Ok(None)
        }

        fn update_transaction(
            &mut self,
            _id: MigrationTxId,
            _state: MigrationTxState,
        ) -> Result<(), Self::Error> {
            Err(SnapshotError::PersistenceUnsupported)
        }
    }

    /// The ZIP-317 fee the preview reserves, as `call` computes it.
    fn prep_fee() -> u64 {
        PREP_TX_ACTIONS as u64 * Zip317FeePolicy.marginal_fee_zatoshi()
    }

    #[test]
    fn preview_reports_a_scheduled_conserving_plan() {
        // Decompose a sample Orchard balance held as one large note and check the response mirrors
        // the plan: every funding note has a positive crossing its output covers by exactly the fee
        // buffer, each is scheduled, and the migratable total is the sum of the crossings.
        let notes = vec![723 * COIN];
        let account_balance_zat: u64 = notes.iter().sum();
        let backend = MockBackend {
            notes,
            tip: 2_000_000,
        };
        let mut rng = OsRng;
        let plan = plan_migration(&backend, prep_fee(), &mut rng).expect("a funded balance plans");

        let preview = preview_from_plan(
            Pool::Orchard,
            Pool::Ironwood,
            "Nu6.3".to_string(),
            account_balance_zat,
            &plan,
        );

        assert_eq!(preview.account_balance_zat, account_balance_zat);
        assert_eq!(preview.prep_fee_zat, prep_fee());
        assert_eq!(
            preview.funding_note_count as usize,
            preview.funding_notes.len()
        );
        assert!(preview.funding_note_count > 0);

        // One schedule entry per funding note (the engine guarantees this).
        assert_eq!(preview.funding_notes.len(), plan.schedule().len());

        let buffer = Zip317FeePolicy.transfer_fee_buffer_zatoshi();
        let mut crossings_sum = 0u64;
        for note in &preview.funding_notes {
            assert!(note.crossing_zat > 0, "every crossing value is positive");
            assert_eq!(
                note.output_zat,
                note.crossing_zat + buffer,
                "the output funds the crossing plus exactly the fee buffer"
            );
            assert!(
                note.expiry_height > note.broadcast_height,
                "expiry follows broadcast"
            );
            crossings_sum += note.crossing_zat;
        }
        assert_eq!(preview.total_migratable_zat, crossings_sum);

        // The migratable value never exceeds the input balance.
        assert!(preview.total_migratable_zat <= preview.account_balance_zat);
        // Reconciliation only drops funding notes, so at most as many as the raw split.
        assert!(preview.funding_notes.len() <= preview.note_split.note_count as usize);
    }

    #[test]
    fn empty_balance_has_nothing_to_migrate() {
        let backend = MockBackend {
            notes: Vec::new(),
            tip: 2_000_000,
        };
        let mut rng = OsRng;
        assert!(matches!(
            plan_migration(&backend, prep_fee(), &mut rng),
            Err(MigrationError::NothingToMigrate)
        ));
    }
}
