//! `z_previewpoolmigration`: preview the note-split plan for a pool migration.
//!
//! Unlike the rest of the pool-migration surface (which is still a scaffold; see
//! [`pool_migration`](super::pool_migration)), this method is fully wired: it reads the
//! account's spendable balance in the source pool and runs the backend-agnostic
//! note-split planner (`zcash_ironwood_migration_backend::note_splitting`) to show how
//! that balance would be decomposed into the self-funding notes that cross the
//! Orchard -> Ironwood turnstile.
//!
//! It is READ-ONLY: it computes and returns a plan but schedules, builds, proves, and
//! broadcasts nothing. Actually carrying out a migration needs the (still-unreleased)
//! Ironwood PCZT builder APIs, so that path stays behind [`not_implemented`] in
//! `z_startpoolmigration`. This preview is the achievable planning slice today.

use std::num::NonZeroU32;

use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use rand::rngs::OsRng;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{AccountBalance, WalletRead, wallet::ConfirmationsPolicy};
use zcash_primitives::transaction::fees::zip317::MINIMUM_FEE;
use zcash_protocol::value::Zatoshis;

use super::pool_migration::{Pool, validate_pool_pair};
use crate::{
    components::{
        database::DbConnection,
        json_rpc::{server::LegacyCode, utils::parse_account_parameter},
        keystore::KeyStore,
    },
    migrate::engine::note_splitting::{
        CanonicalPowerOfTen, DenominationStrategy, NoteSplitPlan, RandomizedOneTwoFive,
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
    "Only include outputs in transactions confirmed at least this many times.";
pub(super) const PARAM_STRATEGY_DESC: &str =
    "The denomination strategy to preview: \"randomized\" (default) or \"canonical\".";

/// Wire name of the randomized `{1, 2, 5} * 10^k` denomination strategy.
const STRATEGY_RANDOMIZED: &str = "randomized";
/// Wire name of the deterministic canonical power-of-ten denomination strategy.
const STRATEGY_CANONICAL: &str = "canonical";

/// The proposed note-split plan for migrating an account's balance between two pools.
///
/// Read-only preview of the decomposition produced by the note-split planner. Nothing is
/// scheduled or broadcast; the fields describe what a migration run would prepare.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct PoolMigrationPreview {
    /// The value pool funds would be migrated from.
    from_pool: Pool,
    /// The value pool funds would be migrated to.
    to_pool: Pool,
    /// The network upgrade that enables this migration (for example `"Nu6.3"`).
    enabling_upgrade: String,
    /// The denomination strategy this plan was computed with (`"randomized"` or
    /// `"canonical"`).
    strategy: String,
    /// The account's total spendable balance in the source pool, in zatoshis.
    account_balance_zat: u64,
    /// The fee (in zatoshis) reserved for the note-split ("prep") transaction before
    /// decomposition.
    ///
    /// This preview reserves the ZIP-317 minimum fee; the final prep fee is computed by
    /// the migration engine when the build path is wired in.
    prep_fee_zat: u64,
    /// The total input (in zatoshis) the plan decomposes (equal to
    /// `account_balance_zat`).
    total_input_zat: u64,
    /// The total value (in zatoshis) that would migrate to the destination pool: the sum
    /// of the crossing values.
    total_migratable_zat: u64,
    /// Residual (in zatoshis) left in the source pool because it could not form a whole
    /// self-funding note (or the note cap was reached). Zero if the balance was consumed
    /// exactly.
    source_change_zat: u64,
    /// The number of self-funding notes the split would prepare.
    note_count: u32,
    /// The per-note breakdown, one entry per prepared note.
    notes: Vec<PreviewNote>,
}

/// One prepared note in a [`PoolMigrationPreview`].
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct PreviewNote {
    /// The value (in zatoshis) of the prepared note: its crossing value plus the fee
    /// buffer that lets it pay its own migration-transfer fee.
    output_zat: u64,
    /// The denomination value (in zatoshis) that crosses the turnstile when this note is
    /// spent.
    crossing_zat: u64,
}

/// Validates the requested denomination strategy and returns its canonical wire name,
/// defaulting to the recommended randomized strategy.
///
/// Kept separate from [`build_strategy`] so the (cheap) validation runs before any wallet
/// I/O, and so the non-`Send` strategy object is only constructed after the last `.await`.
fn strategy_name(strategy: Option<&str>) -> RpcResult<&'static str> {
    match strategy.unwrap_or(STRATEGY_RANDOMIZED) {
        STRATEGY_RANDOMIZED => Ok(STRATEGY_RANDOMIZED),
        STRATEGY_CANONICAL => Ok(STRATEGY_CANONICAL),
        other => Err(LegacyCode::InvalidParameter.with_message(format!(
            "strategy: unknown denomination strategy {other:?}; expected \
             {STRATEGY_RANDOMIZED:?} or {STRATEGY_CANONICAL:?}",
        ))),
    }
}

/// Constructs the denomination strategy for a canonical name returned by
/// [`strategy_name`]. The name is assumed already validated.
fn build_strategy(name: &str) -> Box<dyn DenominationStrategy> {
    match name {
        STRATEGY_CANONICAL => Box::new(CanonicalPowerOfTen::zip_draft()),
        // Any already-validated name other than canonical is the randomized default.
        _ => Box::new(RandomizedOneTwoFive::recommended()),
    }
}

/// Returns the spendable balance the given pool holds in the supplied account balance.
fn spendable_in_pool(account_balance: &AccountBalance, pool: Pool) -> Zatoshis {
    match pool {
        Pool::Sapling => account_balance.sapling_balance().spendable_value(),
        Pool::Orchard => account_balance.orchard_balance().spendable_value(),
        Pool::Ironwood => account_balance.ironwood_balance().spendable_value(),
    }
}

pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account: JsonValue,
    from_pool: &str,
    to_pool: &str,
    minconf: Option<u32>,
    strategy: Option<String>,
) -> Response {
    let (from_pool, to_pool, enabling_upgrade) = validate_pool_pair(wallet, from_pool, to_pool)?;
    // Validate the strategy name before any wallet I/O; the strategy object itself is not
    // `Send`, so it is built below, after the last `.await`.
    let strategy_name = strategy_name(strategy.as_deref())?;
    let account_id = parse_account_parameter(wallet, keystore, &account).await?;

    let confirmations_policy = match minconf.and_then(NonZeroU32::new) {
        Some(c) => ConfirmationsPolicy::new_symmetrical(c, false),
        None => ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
    };

    let summary = wallet
        .get_wallet_summary(confirmations_policy)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;

    let account_balance = summary.account_balances().get(&account_id).ok_or_else(|| {
        LegacyCode::InvalidParameter.with_message(format!(
            "Error: account {account} has not been generated by z_getnewaccount."
        ))
    })?;

    let total_input_zat = spendable_in_pool(account_balance, from_pool).into_u64();
    let prep_fee_zat = MINIMUM_FEE.into_u64();

    // No `.await` past this point: build the (non-`Send`) strategy and plan synchronously.
    let mut rng = OsRng;
    let plan = build_strategy(strategy_name).plan(total_input_zat, prep_fee_zat, &mut rng);

    Ok(preview_from_plan(
        from_pool,
        to_pool,
        enabling_upgrade.to_string(),
        strategy_name.to_string(),
        total_input_zat,
        &plan,
    ))
}

/// Assembles the RPC response from a computed note-split plan.
///
/// Kept pure (no wallet access) so the response contract can be unit-tested directly
/// against a plan.
fn preview_from_plan(
    from_pool: Pool,
    to_pool: Pool,
    enabling_upgrade: String,
    strategy: String,
    account_balance_zat: u64,
    plan: &NoteSplitPlan,
) -> PoolMigrationPreview {
    let notes = plan
        .migration_outputs()
        .iter()
        .zip(plan.crossing_values())
        .map(|(&output_zat, &crossing_zat)| PreviewNote {
            output_zat,
            crossing_zat,
        })
        .collect::<Vec<_>>();

    PoolMigrationPreview {
        from_pool,
        to_pool,
        enabling_upgrade,
        strategy,
        account_balance_zat,
        prep_fee_zat: plan.prep_fee_zatoshi(),
        total_input_zat: plan.total_input_zatoshi(),
        total_migratable_zat: plan.total_migratable_zatoshi(),
        source_change_zat: plan.orchard_change().unwrap_or(0),
        note_count: notes.len() as u32,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use zcash_protocol::value::COIN;

    use super::*;
    use crate::migrate::engine::note_splitting::plan_note_split;

    #[test]
    fn strategy_name_defaults_to_randomized() {
        assert_eq!(strategy_name(None).unwrap(), STRATEGY_RANDOMIZED);
    }

    #[test]
    fn strategy_name_parses_known_strategies() {
        assert_eq!(
            strategy_name(Some("randomized")).unwrap(),
            STRATEGY_RANDOMIZED
        );
        assert_eq!(
            strategy_name(Some("canonical")).unwrap(),
            STRATEGY_CANONICAL
        );
    }

    #[test]
    fn strategy_name_rejects_unknown() {
        assert!(strategy_name(Some("bogus")).is_err());
        assert!(strategy_name(Some("")).is_err());
    }

    #[test]
    fn preview_conserves_value_and_reports_notes() {
        // Decompose a sample Orchard balance and check the response mirrors the plan and
        // conserves value: migratable + change + prep fee + fee buffers == input.
        let prep_fee = MINIMUM_FEE.into_u64();
        let total_input = 723 * COIN;

        let mut rng = OsRng;
        let plan = plan_note_split(total_input, prep_fee, &mut rng);

        let preview = preview_from_plan(
            Pool::Orchard,
            Pool::Ironwood,
            "Nu6.3".to_string(),
            STRATEGY_RANDOMIZED.to_string(),
            total_input,
            &plan,
        );

        assert_eq!(preview.account_balance_zat, total_input);
        assert_eq!(preview.total_input_zat, total_input);
        assert_eq!(preview.prep_fee_zat, prep_fee);
        assert_eq!(preview.note_count as usize, preview.notes.len());
        assert_eq!(preview.notes.len(), plan.migration_outputs().len());

        // Every crossing value is positive and each output covers its crossing.
        let crossings_sum: u64 = preview.notes.iter().map(|n| n.crossing_zat).sum();
        for note in &preview.notes {
            assert!(note.crossing_zat > 0);
            assert!(note.output_zat >= note.crossing_zat);
        }
        assert_eq!(preview.total_migratable_zat, crossings_sum);

        // Value conservation: the prepared notes plus the residual plus the reserved prep
        // fee never exceed the input.
        let notes_total: u64 = preview.notes.iter().map(|n| n.output_zat).sum();
        assert_eq!(
            notes_total + preview.source_change_zat + preview.prep_fee_zat,
            total_input
        );
    }

    #[test]
    fn preview_of_dust_balance_migrates_nothing() {
        // A balance below the smallest self-funding note migrates nothing and is kept as
        // change.
        let prep_fee = MINIMUM_FEE.into_u64();
        let total_input = prep_fee + 1;

        let mut rng = OsRng;
        let plan = plan_note_split(total_input, prep_fee, &mut rng);
        let preview = preview_from_plan(
            Pool::Orchard,
            Pool::Ironwood,
            "Nu6.3".to_string(),
            STRATEGY_RANDOMIZED.to_string(),
            total_input,
            &plan,
        );

        assert_eq!(preview.note_count, 0);
        assert_eq!(preview.total_migratable_zat, 0);
        assert!(preview.notes.is_empty());
    }
}
