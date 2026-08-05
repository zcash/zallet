use std::convert::Infallible;

use abscissa_core::Application;

use jsonrpsee::core::{JsonValue, RpcResult};
use serde_json::json;
use zcash_client_backend::data_api::wallet::SpendingKeys;
use zcash_client_backend::proposal::Proposal;
use zcash_client_backend::{
    data_api::{
        Account,
        wallet::{
            create_proposed_transactions,
            input_selection::{SpendPolicy, TransparentSpendPolicy},
        },
    },
    fees::StandardFeeRule,
    wallet::OvkPolicy,
};
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId};
use zcash_keys::{address::Address, keys::UnifiedFullViewingKey};
use zcash_proofs::prover::LocalTxProver;

use crate::{
    components::{
        chain::Chain,
        database::DbHandle,
        json_rpc::{
            asyncop::{ContextInfo, OperationId},
            payments::{
                AmountParameter, SendResult, build_request, confirmations_policy_for_minconf,
                get_account_for_address, get_legacy_pool_account, parse_privacy_policy,
                propose_and_check, spend_policy_for, spending_key_for_account,
                verify_and_broadcast_transactions,
            },
            server::LegacyCode,
        },
        keystore::KeyStore,
    },
    fl,
    prelude::APP,
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

    let privacy_policy = parse_privacy_policy(privacy_policy.as_deref())?;

    // Reject an oversized recipient set before input selection and proving, which both
    // scale with it. Every recipient needs at least one output in its pool, so this only
    // rejects requests the post-proposal per-pool check would reject anyway.
    //
    // TODO: also bound the serialized transaction size.
    // https://github.com/zcash/zallet/issues/255
    let actions_limit: usize = APP.config().builder.limits.orchard_actions().into();
    if amounts.len() > actions_limit {
        return Err(LegacyCode::Misc.with_message(fl!(
            "err-excess-recipients",
            count = amounts.len(),
            limit = actions_limit,
            config = "-orchardactionlimit=N",
            bound = "N >= %u".to_string(),
        )));
    }

    let confirmations_policy = confirmations_policy_for_minconf(minconf)?;

    let params = *wallet.params();
    let proposal = propose_and_check(
        wallet.as_mut(),
        &params,
        account.id(),
        request,
        privacy_policy,
        confirmations_policy,
        &spend_policy,
    )?;

    let derivation = account.source().key_derivation().ok_or_else(|| {
        LegacyCode::InvalidAddressOrKey.with_message(fl!("err-from-address-no-payment-source"))
    })?;

    // Fetch spending key last, to avoid a keystore decryption if unnecessary.
    let usk =
        spending_key_for_account(wallet.as_ref(), &keystore, account.id(), derivation).await?;

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
            account.id(),
            usk.to_unified_full_viewing_key(),
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
/// `ufvk` must be derived from the wallet seed: the built transactions' transparent
/// outputs are verified against it before broadcast, because their addresses come from
/// wallet database records that are not integrity-protected.
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
    account_id: AccountUuid,
    ufvk: UnifiedFullViewingKey,
    proposal: Proposal<StandardFeeRule, ReceivedNoteId>,
    spending_keys: SpendingKeys,
) -> RpcResult<SendResult> {
    let prover = LocalTxProver::bundled();
    let (wallet, proposal, txids) = crate::spawn_blocking!("z_sendmany prover", move || {
        let params = *wallet.params();
        create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
            wallet.as_mut(),
            &params,
            &prover,
            &prover,
            &spending_keys,
            OvkPolicy::Sender,
            &proposal,
            // No expiry-height override; each transaction keeps its builder-derived expiry.
            None,
        )
        .map(|txids| (wallet, proposal, txids))
    })
    .await
    // TODO: Map errors to `zcashd` shape.
    .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to propose transaction: {e}")))?
    .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to propose transaction: {e}")))?;

    verify_and_broadcast_transactions(&wallet, chain, account_id, &ufvk, &proposal, txids.into())
        .await
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    use zcash_client_backend::{
        data_api::wallet::input_selection::{CoinbasePolicy, TransparentSource},
        fees::TransparentChangePolicy,
    };
    use zcash_keys::{
        address::{Address, UnifiedAddress},
        keys::{UnifiedAddressRequest, UnifiedSpendingKey},
    };
    use zcash_protocol::{ShieldedPool, consensus::Network};
    use zip32::AccountId;

    use super::{SpendPolicy, legacy_pool_spend_policy};
    use crate::components::json_rpc::payments::{spend_policy_for, transparent_change_policy_for};

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
            // Some seeds derive an address without every shielded receiver; those
            // receiver-restricted cases are covered by
            // `unified_source_spends_only_its_receivers_pools`.
            prop_assume!(ua.orchard().is_some() && ua.sapling().is_some());

            let policy = spend_policy_for(&Address::Unified(ua));

            prop_assert!(
                policy.transparent().is_none(),
                "a shielded source must not permit transparent spending",
            );

            // The address carries every shielded receiver type, so its permitted pools
            // are exactly the full set. Comparing against the default's pool set keeps
            // that true for any pool added later, rather than pinning today's three.
            let unchanged = SpendPolicy::default();
            prop_assert_eq!(policy.shielded(), unchanged.shielded());
        }

        /// A bare Sapling source draws only on the Sapling pool, never on the account's
        /// Orchard or Ironwood notes, and on no transparent UTXO.
        #[test]
        fn sapling_source_spends_only_the_sapling_pool(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
        ) {
            let Some(ua) = ua_from(&seed, account) else { return Ok(()) };
            let Some(saddr) = ua.sapling().cloned() else { return Ok(()) };

            let policy = spend_policy_for(&Address::Sapling(saddr));

            prop_assert_eq!(
                policy.shielded(),
                &BTreeSet::from([ShieldedPool::Sapling]),
                "a Sapling source must draw only on the Sapling pool",
            );
            prop_assert!(
                policy.transparent().is_none(),
                "a shielded source must not permit transparent spending",
            );
        }

        /// A receiver-restricted unified address selects inputs only from the value pools
        /// its receivers name, as the `z_sendmany` documentation promises. An Orchard
        /// receiver names both the Orchard pool and the Ironwood pool (where payments to
        /// Orchard receivers are accounted once Ironwood is active).
        #[test]
        fn unified_source_spends_only_its_receivers_pools(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
            include_transparent in any::<bool>(),
        ) {
            let Some(ua) = ua_from(&seed, account) else { return Ok(()) };
            let orchard = ua.orchard().copied();
            let sapling = ua.sapling().cloned();
            // The transparent receiver's presence must make no difference to the
            // permitted pools, so the property quantifies over it.
            let transparent = include_transparent
                .then(|| ua.transparent().copied())
                .flatten();

            let orchard_pools = BTreeSet::from([ShieldedPool::Orchard, ShieldedPool::Ironwood]);
            let sapling_pools = BTreeSet::from([ShieldedPool::Sapling]);

            // Each combo pairs a receiver subset with the exact pool set it must permit.
            // Some seeds derive an address without every shielded receiver, so only the
            // combos this seed can express are exercised.
            let mut combos = Vec::new();
            if orchard.is_some() {
                combos.push((orchard, None, orchard_pools.clone()));
            }
            if sapling.is_some() {
                combos.push((None, sapling, sapling_pools.clone()));
            }
            if orchard.is_some() && sapling.is_some() {
                combos.push((
                    orchard,
                    sapling,
                    orchard_pools.union(&sapling_pools).copied().collect(),
                ));
            }

            for (orchard, sapling, expected) in combos {
                let Some(ua) = UnifiedAddress::from_receivers(orchard, sapling, transparent)
                else {
                    continue;
                };

                let policy = spend_policy_for(&Address::Unified(ua));

                prop_assert_eq!(
                    policy.shielded(),
                    &expected,
                    "permitted pools must be exactly those named by the source's receivers",
                );
                prop_assert!(
                    policy.transparent().is_none(),
                    "a shielded source must not permit transparent spending",
                );
            }
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
