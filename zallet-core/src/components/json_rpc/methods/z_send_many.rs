use std::convert::Infallible;
use std::num::NonZeroU32;

use abscissa_core::Application;
use jsonrpsee::core::{JsonValue, RpcResult};
use secrecy::ExposeSecret;
use serde_json::json;
use zcash_address::unified;
use zcash_client_backend::data_api::wallet::SpendingKeys;
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::{
    data_api::{
        Account,
        wallet::{
            ConfirmationsPolicy, create_proposed_transactions,
            input_selection::{GreedyInputSelector, SpendPolicy, TransparentSpendPolicy},
            propose_transfer,
        },
    },
    fees::{
        DustOutputPolicy, StandardFeeRule, TransparentChangePolicy,
        standard::MultiOutputChangeStrategy,
    },
    wallet::OvkPolicy,
};
use zcash_client_sqlite::ReceivedNoteId;
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{
    PoolType, ShieldedPool,
    value::{MAX_MONEY, Zatoshis},
};

use crate::{
    components::{
        chain::Chain,
        database::DbHandle,
        json_rpc::{
            asyncop::{ContextInfo, OperationId},
            payments::{
                AmountParameter, IncompatiblePrivacyPolicy, PrivacyPolicy, SendResult,
                broadcast_transactions, build_request, enforce_privacy_policy,
                get_account_for_address, get_legacy_pool_account,
            },
            server::LegacyCode,
        },
        keystore::KeyStore,
    },
    fl,
    prelude::*,
};

#[cfg(feature = "zcashd-import")]
use crate::components::json_rpc::utils::collect_standalone_transparent_keys;

/// Response to a `z_sendmany` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = OperationId;

pub(super) const PARAM_FROMADDRESS_DESC: &str =
    "The transparent or shielded address to send the funds from.";
pub(super) const PARAM_AMOUNTS_DESC: &str =
    "An array of JSON objects representing the amounts to send.";
pub(super) const PARAM_AMOUNTS_REQUIRED: bool = true;
pub(super) const PARAM_MINCONF_DESC: &str = "Only use funds confirmed at least this many times.";
pub(super) const PARAM_FEE_DESC: &str = "If set, it must be null.";
pub(super) const PARAM_PRIVACY_POLICY_DESC: &str =
    "Policy for what information leakage is acceptable.";

/// The sources of funds a transfer from `source` may draw upon.
///
/// Spending from a bare transparent address draws only on that address's UTXOs: the funds are
/// already public, and confining selection to the named address avoids linking it to the
/// account's other transparent receivers. Every other source stays shielded-only, so a
/// shielded send can never silently reach into transparent funds.
///
/// Coinbase UTXOs are excluded: `TransparentSpendPolicy` defaults to
/// `CoinbasePolicy::NonCoinbase`, and consensus requires coinbase to be spent to a single
/// shielded output, which is `z_shieldcoinbase`'s job.
///
/// The privacy policy deliberately does not narrow this: the selector returns its best
/// proposal, and `enforce_privacy_policy` rejects it afterwards if it leaks more than the
/// caller permitted.
fn spend_policy_for(source: &Address) -> SpendPolicy {
    match source {
        Address::Transparent(taddr) => SpendPolicy::shielded_pools([])
            .with_transparent(TransparentSpendPolicy::from_one_address(*taddr)),
        _ => SpendPolicy::default(),
    }
}

/// The sources of funds a transfer from `ANY_TADDR` may draw upon.
///
/// `zcashd` treated the transparent addresses of a wallet as a single pool of funds, and
/// `ANY_TADDR` drew on any of them. Zallet holds that pool in one account (see
/// [`get_legacy_pool_account`]), and [`TransparentSpendPolicy::any_account_addr`] reproduces
/// the selection within it: the proposer spends whichever of the account's transparent
/// receivers cover the request, linking them on-chain when one address does not suffice.
///
/// That linkage is bounded by the caller's privacy policy rather than here: a proposal
/// spending more than one transparent address is rejected by `enforce_privacy_policy` unless
/// the caller permitted `AllowLinkingAccountAddresses` (or `NoPrivacy`, when the transaction
/// also has a transparent output or transparent change).
///
/// Like a bare transparent source, this permits no shielded pool: `ANY_TADDR` names
/// transparent funds, so it must not become a way to spend the account's notes. Coinbase is
/// likewise excluded (`CoinbasePolicy::NonCoinbase`), matching `zcashd`, which sent callers
/// to `z_shieldcoinbase` for coinbase funds.
fn legacy_pool_spend_policy() -> SpendPolicy {
    SpendPolicy::shielded_pools([]).with_transparent(TransparentSpendPolicy::any_account_addr())
}

/// Whether change may be returned to the transparent pool.
///
/// Permitted exactly when `spend_policy` can spend transparent funds in the first place, which
/// keeps a fully transparent send transparent end to end rather than sweeping its change into a
/// shielded pool. A shielded send therefore cannot acquire a transparent change output by this
/// route.
///
/// The change strategy independently enforces the same thing (it emits transparent change only
/// when the transaction's net flows are fully transparent, i.e. it has no shielded input or
/// output at all), but that is its invariant, not ours.
fn transparent_change_policy_for(spend_policy: &SpendPolicy) -> TransparentChangePolicy {
    match spend_policy.transparent() {
        Some(_) => TransparentChangePolicy::TransparentChangeAllowed,
        None => TransparentChangePolicy::ShieldChange,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn call<C: Chain>(
    mut wallet: DbHandle,
    keystore: KeyStore,
    chain: C,
    fromaddress: String,
    amounts: Vec<AmountParameter>,
    minconf: Option<u32>,
    fee: Option<JsonValue>,
    privacy_policy: Option<String>,
) -> RpcResult<(
    Option<ContextInfo>,
    impl Future<Output = RpcResult<SendResult>>,
)> {
    // TODO: Check that Sapling is active, by inspecting height of `chain` snapshot.
    //       https://github.com/zcash/zallet/issues/237

    if fee.is_some() {
        return Err(LegacyCode::InvalidParameter
            .with_static("Zallet always calculates fees internally; the fee field must be null."));
    }

    let request = build_request(&amounts)?;

    let (account, spend_policy) = match fromaddress.as_str() {
        // Select from the legacy transparent address pool, which this wallet holds in a
        // single account. Enabled by `features.legacy_pool_seed_fingerprint`.
        "ANY_TADDR" => (
            get_legacy_pool_account(wallet.as_ref())?,
            legacy_pool_spend_policy(),
        ),
        // Select the account corresponding to the given address.
        _ => {
            let address = Address::decode(wallet.params(), &fromaddress).ok_or_else(|| {
                LegacyCode::InvalidAddressOrKey.with_static(
                "Invalid from address: should be a taddr, zaddr, UA, or the string 'ANY_TADDR'.",
            )
            })?;

            let account = get_account_for_address(wallet.as_ref(), &address)?;

            (account, spend_policy_for(&address))
        }
    };

    let privacy_policy = match privacy_policy.as_deref() {
        Some("LegacyCompat") => Err(LegacyCode::InvalidParameter
            .with_static("LegacyCompat privacy policy is unsupported in Zallet")),
        Some(s) => PrivacyPolicy::from_str(s).ok_or_else(|| {
            LegacyCode::InvalidParameter.with_message(format!("Unknown privacy policy {s}"))
        }),
        None => Ok(PrivacyPolicy::FullPrivacy),
    }?;

    // Sanity check for transaction size
    // TODO: https://github.com/zcash/zallet/issues/255

    let confirmations_policy = match minconf {
        Some(minconf) => NonZeroU32::new(minconf).map_or(
            ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
            |c| ConfirmationsPolicy::new_symmetrical(c, false),
        ),
        None => {
            APP.config().builder.confirmations_policy().map_err(|_| {
                LegacyCode::Wallet.with_message(
                    "Configuration error: minimum confirmations for spending trusted TXOs cannot exceed that for untrusted TXOs.")
            })?
        }
    };

    let params = *wallet.params();

    // TODO: Fetch the real maximums within the account so we can detect correctly.
    //       https://github.com/zcash/zallet/issues/257
    let mut max_sapling_available = Zatoshis::const_from_u64(MAX_MONEY);
    let mut max_orchard_available = Zatoshis::const_from_u64(MAX_MONEY);

    for payment in request.payments().values() {
        let value = payment
            .amount()
            .expect("We set this for every payment above");

        match Address::try_from_zcash_address(&params, payment.recipient_address().clone()) {
            Err(e) => return Err(LegacyCode::InvalidParameter.with_message(e.to_string())),
            Ok(Address::Transparent(_) | Address::Tex(_)) => {
                if !privacy_policy.allow_revealed_recipients() {
                    return Err(IncompatiblePrivacyPolicy::TransparentRecipient.into());
                }
            }
            Ok(Address::Sapling(_)) => {
                match (
                    privacy_policy.allow_revealed_amounts(),
                    max_sapling_available - value,
                ) {
                    (false, None) => {
                        return Err(IncompatiblePrivacyPolicy::RevealingSaplingAmount.into());
                    }
                    (false, Some(rest)) => max_sapling_available = rest,
                    (true, _) => (),
                }
            }
            Ok(Address::Unified(ua)) => {
                match (
                    privacy_policy.allow_revealed_amounts(),
                    (
                        ua.receiver_types().contains(&unified::Typecode::Orchard),
                        max_orchard_available - value,
                    ),
                    (
                        ua.receiver_types().contains(&unified::Typecode::Sapling),
                        max_sapling_available - value,
                    ),
                ) {
                    // The preferred receiver is Orchard, and we either allow revealed
                    // amounts or have sufficient Orchard funds available to avoid it.
                    (true, (true, _), _) => (),
                    (false, (true, Some(rest)), _) => max_orchard_available = rest,

                    // The preferred receiver is Sapling, and we either allow revealed
                    // amounts or have sufficient Sapling funds available to avoid it.
                    (true, _, (true, _)) => (),
                    (false, _, (true, Some(rest))) => max_sapling_available = rest,

                    // We need to reveal something in order to make progress.
                    _ => {
                        if privacy_policy.allow_revealed_recipients() {
                            // Nothing to do here.
                        } else if privacy_policy.allow_revealed_amounts() {
                            return Err(IncompatiblePrivacyPolicy::TransparentReceiver.into());
                        } else {
                            return Err(IncompatiblePrivacyPolicy::RevealingReceiverAmounts.into());
                        }
                    }
                }
            }
        }
    }

    let transparent_change_policy = transparent_change_policy_for(&spend_policy);

    // Where shielded change goes when the transaction has no shielded flows to infer a pool
    // from. A transaction that does have shielded flows ignores this and keeps its change in
    // the pool it is already using.
    //
    // This stays Orchard rather than Ironwood: the change strategy promotes it to Ironwood
    // itself once NU6.3 is active (the turnstile forbids value from entering the Orchard
    // pool, so change out of a purely transparent transaction has to land in Ironwood), and
    // it does so against the transaction's target height, which is not known here. Naming
    // Ironwood outright would instead send change to a pool that does not exist yet on a
    // chain where NU6.3 has not activated.
    let fallback_change_pool = ShieldedPool::Orchard;

    // Shielded change is split across several notes, per the wallet's note-management
    // configuration, so the account keeps a usable set of denominations.
    let split_policy = APP.config().note_management.split_policy();

    // Change too small to be worth its own output is added to the fee instead.
    let dust_output_policy = DustOutputPolicy::default();

    // No memo is attached to change. A change memo would force the change into a shielded
    // pool, since a transparent output cannot carry one.
    let change_memo = None;

    let change_strategy = MultiOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        change_memo,
        fallback_change_pool,
        dust_output_policy,
        split_policy,
    )
    .with_transparent_change_policy(transparent_change_policy);

    let input_selector = GreedyInputSelector::new();

    let proposal = propose_transfer::<_, _, _, _, Infallible>(
        wallet.as_mut(),
        &params,
        account.id(),
        &input_selector,
        &change_strategy,
        request,
        confirmations_policy,
        &spend_policy,
        // Do not request a specific transaction version; building falls back to the version
        // implied by the target height.
        None,
    )
    // TODO: Map errors to `zcashd` shape.
    .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to propose transaction: {e}")))?;

    enforce_privacy_policy(&proposal, privacy_policy)?;

    let orchard_actions_limit = APP.config().builder.limits.orchard_actions().into();
    for step in proposal.steps() {
        let orchard_spends = step
            .shielded_inputs()
            .iter()
            .flat_map(|inputs| inputs.notes())
            .filter(|note| note.note().pool() == ShieldedPool::Orchard)
            .count();

        let orchard_outputs = step
            .payment_pools()
            .values()
            .filter(|pool| pool == &&PoolType::ORCHARD)
            .count()
            + step
                .balance()
                .proposed_change()
                .iter()
                .filter(|change| change.output_pool() == PoolType::ORCHARD)
                .count();

        let orchard_actions = orchard_spends.max(orchard_outputs);

        if orchard_actions > orchard_actions_limit {
            let (count, kind) = if orchard_outputs <= orchard_actions_limit {
                (orchard_spends, "inputs")
            } else if orchard_spends <= orchard_actions_limit {
                (orchard_outputs, "outputs")
            } else {
                (orchard_actions, "actions")
            };

            return Err(LegacyCode::Misc.with_message(fl!(
                "err-excess-orchard-actions",
                count = count,
                kind = kind,
                limit = orchard_actions_limit,
                config = "-orchardactionlimit=N",
                bound = format!("N >= %u"),
            )));
        }
    }

    let derivation = account.source().key_derivation().ok_or_else(|| {
        LegacyCode::InvalidAddressOrKey
            .with_static("Invalid from address, no payment source found for address.")
    })?;

    // Fetch spending key last, to avoid a keystore decryption if unnecessary.
    let seed = keystore
        .decrypt_seed(derivation.seed_fingerprint())
        .await
        .map_err(|e| match e.kind() {
            // TODO: Improve internal error types.
            //       https://github.com/zcash/zallet/issues/256
            crate::error::ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
            }
            _ => LegacyCode::Database.with_message(e.to_string()),
        })?;
    let usk = UnifiedSpendingKey::from_seed(
        wallet.params(),
        seed.expose_secret(),
        derivation.account_index(),
    )
    .map_err(|e| LegacyCode::InvalidAddressOrKey.with_message(e.to_string()))?;

    #[cfg(feature = "zcashd-import")]
    let standalone_keys =
        collect_standalone_transparent_keys(wallet.as_ref(), &keystore, account.id(), &proposal)
            .await?;

    // TODO: verify that the proposal satisfies the requested privacy policy

    Ok((
        Some(ContextInfo::new(
            "z_sendmany",
            json!({
                "fromaddress": fromaddress,
                "amounts": amounts,
                "minconf": minconf
            }),
        )),
        run(
            wallet,
            chain,
            proposal,
            #[cfg(feature = "zcashd-import")]
            SpendingKeys::new(usk, standalone_keys),
            #[cfg(not(feature = "zcashd-import"))]
            SpendingKeys::from_unified_spending_key(usk),
        ),
    ))
}

/// Construct and send the transaction, returning the resulting txid.
/// Errors in transaction construction will throw.
///
/// Notes:
/// 1. #1159 Currently there is no limit set on the number of elements, which could
///    make the tx too large.
/// 2. #1360 Note selection is not optimal.
/// 3. #1277 Spendable notes are not locked, so an operation running in parallel
///    could also try to use them.
async fn run<C: Chain>(
    mut wallet: DbHandle,
    chain: C,
    proposal: Proposal<StandardFeeRule, ReceivedNoteId>,
    spending_keys: SpendingKeys,
) -> RpcResult<SendResult> {
    let prover = LocalTxProver::bundled();
    let (wallet, txids) = crate::spawn_blocking!("z_sendmany prover", move || {
        let params = *wallet.params();
        create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
            wallet.as_mut(),
            &params,
            &prover,
            &prover,
            &spending_keys,
            OvkPolicy::Sender,
            &proposal,
        )
        .map(|txids| (wallet, txids))
    })
    .await
    // TODO: Map errors to `zcashd` shape.
    .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to propose transaction: {e}")))?
    .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to propose transaction: {e}")))?;

    broadcast_transactions(&wallet, chain, txids.into()).await
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use zcash_client_backend::{
        data_api::wallet::input_selection::{CoinbasePolicy, TransparentSource},
        fees::TransparentChangePolicy,
    };
    use zcash_keys::{
        address::{Address, UnifiedAddress},
        keys::{UnifiedAddressRequest, UnifiedSpendingKey},
    };
    use zcash_protocol::consensus::Network;
    use zip32::AccountId;

    use super::{
        SpendPolicy, legacy_pool_spend_policy, spend_policy_for, transparent_change_policy_for,
    };

    /// `ANY_TADDR` draws on the legacy pool's transparent funds, on any address within it, and
    /// on nothing else.
    #[test]
    fn legacy_pool_source_spends_any_account_taddr_and_no_shielded_pool() {
        let policy = legacy_pool_spend_policy();

        // As for a bare transparent source, the empty permitted-pool set says exhaustively
        // that no shielded note can be spent, including from pools added after this was
        // written.
        assert!(
            policy.shielded().is_empty(),
            "the legacy pool holds transparent funds, so no shielded pool may be spent, got {:?}",
            policy.shielded(),
        );

        let transparent = policy
            .transparent()
            .expect("the legacy pool permits transparent spending");

        // The whole point of `ANY_TADDR`: the proposer picks the addresses, rather than the
        // caller naming one.
        assert!(
            matches!(transparent.source(), TransparentSource::AnyAccountAddr),
            "`ANY_TADDR` must draw on any of the account's transparent receivers, got {:?}",
            transparent.source(),
        );

        // Coinbase is `z_shieldcoinbase`'s job, in Zallet as in `zcashd`.
        assert_eq!(transparent.coinbase(), CoinbasePolicy::NonCoinbase);

        // A fully transparent send keeps its change transparent.
        assert_eq!(
            transparent_change_policy_for(&policy),
            TransparentChangePolicy::TransparentChangeAllowed,
        );
    }

    /// A unified address carrying every receiver type, derived from `seed` and `account`.
    ///
    /// No wallet database and no chain: the policy derivations under test are pure functions
    /// of the source address, which is what makes them unit-testable here rather than in
    /// `integration-tests`.
    ///
    /// Returns `None` for the seeds and diversifiers ZIP 32 rejects, so a property can skip
    /// them rather than assert on an address that cannot exist.
    fn ua_from(seed: &[u8; 32], account: u32) -> Option<UnifiedAddress> {
        let account = AccountId::try_from(account).ok()?;
        let usk = UnifiedSpendingKey::from_seed(&Network::TestNetwork, seed, account).ok()?;
        let (ua, _) = usk
            .to_unified_full_viewing_key()
            .default_address(UnifiedAddressRequest::ALLOW_ALL)
            .ok()?;
        Some(ua)
    }

    /// ZIP 32 account indices are non-hardened, so they occupy the low 31 bits.
    fn arb_account() -> impl Strategy<Value = u32> {
        0u32..(1 << 31)
    }

    proptest! {
        // Each case derives a spending key, which is expensive, so take fewer samples than
        // the default 256. The properties hold for every source address, not for rare
        // corners of the seed space, so a modest sample establishes them.
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// Whatever key it was derived from, a transparent source draws only on that one
        /// address's UTXOs, and on no shielded note.
        #[test]
        fn transparent_source_spends_only_that_address_and_no_shielded_pool(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
        ) {
            let Some(ua) = ua_from(&seed, account) else { return Ok(()) };
            let Some(&taddr) = ua.transparent() else { return Ok(()) };

            let policy = spend_policy_for(&Address::Transparent(taddr));

            // A transparent send must not reach into the account's shielded funds. The
            // permitted-pool SET being empty says this exhaustively: it forbids every
            // shielded pool, including any added to `ShieldedPool` after this was written,
            // which enumerating the variants here would not.
            prop_assert!(
                policy.shielded().is_empty(),
                "a transparent source must permit no shielded pool, got {:?}",
                policy.shielded(),
            );

            let transparent = policy
                .transparent()
                .expect("a transparent source permits transparent spending");

            // Only the named address, so spending it does not link the source to the
            // account's other transparent receivers.
            match transparent.source() {
                TransparentSource::FromAddresses(addrs) => prop_assert_eq!(
                    addrs.iter().copied().collect::<Vec<_>>(),
                    vec![taddr],
                    "selection must be confined to the named address",
                ),
                other => prop_assert!(
                    false,
                    "expected a single-address source, got {other:?}",
                ),
            }

            // Coinbase must be spent to a single shielded output (`z_shieldcoinbase`'s
            // job), so a general transfer never draws on it.
            prop_assert_eq!(transparent.coinbase(), CoinbasePolicy::NonCoinbase);
        }

        /// The property whose absence made transparent spending impossible, inverted: a
        /// shielded source must never be able to select a transparent input, even though the
        /// unified address it names does carry a transparent receiver.
        #[test]
        fn shielded_source_permits_no_transparent_spending(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
        ) {
            let Some(ua) = ua_from(&seed, account) else { return Ok(()) };

            let policy = spend_policy_for(&Address::Unified(ua));

            prop_assert!(
                policy.transparent().is_none(),
                "a shielded source must not permit transparent spending",
            );

            // Shielded selection is left exactly as it was before transparent spending
            // existed. Comparing against the default's pool set keeps that true for any
            // pool added later, rather than pinning today's three.
            let unchanged = SpendPolicy::default();
            prop_assert_eq!(policy.shielded(), unchanged.shielded());
        }

        /// Change may be returned to the transparent pool exactly when the source could spend
        /// transparent funds in the first place.
        #[test]
        fn transparent_change_permitted_exactly_when_transparent_funds_are_spendable(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
        ) {
            let Some(ua) = ua_from(&seed, account) else { return Ok(()) };
            let Some(&taddr) = ua.transparent() else { return Ok(()) };

            let transparent_source = spend_policy_for(&Address::Transparent(taddr));
            prop_assert_eq!(
                transparent_change_policy_for(&transparent_source),
                TransparentChangePolicy::TransparentChangeAllowed,
                "a fully transparent send keeps its change transparent",
            );

            let shielded_source = spend_policy_for(&Address::Unified(ua));
            prop_assert_eq!(
                transparent_change_policy_for(&shielded_source),
                TransparentChangePolicy::ShieldChange,
                "a shielded send must not acquire a transparent change output",
            );
        }
    }
}
