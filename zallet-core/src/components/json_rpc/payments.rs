use std::{collections::HashSet, convert::Infallible, fmt, num::NonZeroU32};

use abscissa_core::Application;
use jsonrpsee::core::JsonValue;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use transparent::{address::TransparentAddress, keys::AccountPubKey};
use zcash_address::{ZcashAddress, unified};
use zcash_client_backend::{
    data_api::{
        Account as _, AccountBalance, WalletRead,
        wallet::{
            ConfirmationsPolicy,
            input_selection::{GreedyInputSelector, SpendPolicy, TransparentSpendPolicy},
            propose_transfer,
        },
    },
    fees::{
        DustOutputPolicy, StandardFeeRule, TransparentChangePolicy,
        standard::MultiOutputChangeStrategy,
    },
    proposal::{Proposal, Step},
    wallet::TransparentAddressSource,
    zip321::{Payment, TransactionRequest},
};
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId, wallet::Account};
use zcash_keys::{address::Address, keys::UnifiedFullViewingKey};
use zcash_protocol::{
    PoolType, ShieldedPool, TxId,
    consensus::{BlockHeight, NetworkUpgrade, Parameters as _},
    memo::MemoBytes,
    value::Zatoshis,
};
use zip32::{AccountId, fingerprint::SeedFingerprint};

use crate::{
    components::{chain::Chain, database::DbConnection},
    fl,
    network::Network,
    prelude::APP,
};

use super::{
    server::LegacyCode,
    utils::{ZCASH_LEGACY_ACCOUNT, zatoshis_from_value},
};

// `deny_unknown_fields` matches `zcashd`, which rejects unknown keys in the
// amounts objects. Silently ignoring them is dangerous for a payment API: a
// misspelled `memo` key would send the payment without its memo.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AmountParameter {
    /// A taddr, zaddr, or Unified Address.
    address: String,

    /// The numeric amount in ZEC.
    amount: JsonValue,

    /// If the address is a zaddr, raw data represented in hexadecimal string format. If
    /// the output is being sent to a transparent address, it’s an error to include this
    /// field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    memo: Option<String>,
}

impl AmountParameter {
    pub fn address(&self) -> &String {
        &self.address
    }

    pub fn amount(&self) -> &JsonValue {
        &self.amount
    }

    pub fn memo(&self) -> &Option<String> {
        &self.memo
    }
}

/// Parses an array of output amounts into a ZIP 321 transaction request.
///
/// Rejects an empty array, duplicate recipient addresses, malformed addresses, addresses
/// that cannot be interpreted on this network, and total output value overflow.
///
/// Everything downstream may therefore treat a request's recipients as decodable; several
/// callers rely on that rather than re-reporting a decoding failure of their own.
pub(super) fn build_request(
    params: &Network,
    amounts: &[AmountParameter],
) -> RpcResult<TransactionRequest> {
    if amounts.is_empty() {
        return Err(
            LegacyCode::InvalidParameter.with_static("Invalid parameter, amounts array is empty.")
        );
    }

    let mut recipient_addrs = HashSet::new();
    let mut payments = vec![];
    let mut total_out = Zatoshis::ZERO;

    for amount in amounts {
        let addr: ZcashAddress = amount.address().parse().map_err(|_| {
            LegacyCode::InvalidParameter.with_message(format!(
                "Invalid parameter, unknown address format: {}",
                amount.address(),
            ))
        })?;

        if !recipient_addrs.insert(addr.clone()) {
            return Err(LegacyCode::InvalidParameter.with_message(format!(
                "Invalid parameter, duplicated recipient address: {}",
                amount.address(),
            )));
        }

        // A syntactically valid address may still belong to another network, or name a
        // receiver this build cannot resolve. Rejecting it here keeps address validation in
        // one place, and reports it before the wallet is consulted at all.
        Address::try_from_zcash_address(params, addr.clone()).map_err(|e| {
            LegacyCode::InvalidParameter.with_message(format!(
                "Invalid parameter, address not valid on this network: {} ({e})",
                amount.address(),
            ))
        })?;

        let memo = amount.memo().as_deref().map(parse_memo).transpose()?;
        let value = zatoshis_from_value(amount.amount())?;

        let payment = Payment::new(addr, Some(value), memo, None, None, vec![]).map_err(|e| {
            LegacyCode::InvalidParameter.with_static(match e {
                zcash_client_backend::zip321::PaymentError::TransparentMemo => {
                    "Cannot send memo to transparent recipient"
                }
                zcash_client_backend::zip321::PaymentError::ZeroValuedTransparentOutput => {
                    "Cannot send zero-valued output to transparent recipient"
                }
            })
        })?;

        payments.push(payment);
        total_out = (total_out + value)
            .ok_or_else(|| LegacyCode::InvalidParameter.with_static("Value too large"))?;
    }

    TransactionRequest::new(payments).map_err(|e| {
        // TODO: Map errors to `zcashd` shape.
        LegacyCode::InvalidParameter.with_message(format!("Invalid payment request: {e}"))
    })
}

/// Maps the optional `minconf` JSON-RPC argument onto a [`ConfirmationsPolicy`],
/// falling back to the wallet's configured policy when absent.
///
/// `minconf = 0` permits spending unconfirmed (trusted) funds; any other value
/// requires that many confirmations for trusted and untrusted TXOs alike.
pub(super) fn confirmations_policy_for_minconf(
    minconf: Option<u32>,
) -> RpcResult<ConfirmationsPolicy> {
    match minconf {
        Some(minconf) => Ok(NonZeroU32::new(minconf).map_or(
            ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
            |c| ConfirmationsPolicy::new_symmetrical(c, false),
        )),
        None => {
            APP.config().builder.confirmations_policy().map_err(|_| {
                LegacyCode::Wallet.with_message(fl!("err-confirmations-policy-invalid"))
            })
        }
    }
}

/// The sources of funds a transfer from `source` may draw upon.
///
/// Spending from a bare transparent address draws only on that address's UTXOs: the funds are
/// already public, and confining selection to the named address avoids linking it to the
/// account's other transparent receivers. Every other source stays shielded-only, so a
/// shielded send can never silently reach into transparent funds.
///
/// A shielded source selects inputs only from the value pools its receivers name, as the
/// `z_sendmany` documentation promises: a bare Sapling address or a Sapling-only unified
/// address does not reach into the account's Orchard notes, and an Orchard-only unified
/// address does not reach into its Sapling notes. An Orchard receiver corresponds to both
/// the Orchard pool and the Ironwood pool: once Ironwood is active, payments to Orchard
/// receivers are accounted to the Ironwood bundle, so an Orchard-receiver source must be
/// able to draw on both. A unified address's transparent receiver deliberately does *not*
/// permit transparent spending (see above).
///
/// Coinbase UTXOs are excluded: `TransparentSpendPolicy` defaults to
/// `CoinbasePolicy::NonCoinbase`, and consensus requires coinbase to be spent to a single
/// shielded output, which is `z_shieldcoinbase`'s job.
///
/// The privacy policy deliberately does not narrow this: the selector returns its best
/// proposal, and [`enforce_privacy_policy`] rejects it afterwards if it leaks more than the
/// caller permitted.
pub(super) fn spend_policy_for(source: &Address) -> SpendPolicy {
    /// The pools an Orchard receiver's funds can live in.
    const ORCHARD_RECEIVER_POOLS: [ShieldedPool; 2] =
        [ShieldedPool::Orchard, ShieldedPool::Ironwood];

    match source {
        Address::Transparent(taddr) => SpendPolicy::shielded_pools([])
            .with_transparent(TransparentSpendPolicy::from_one_address(*taddr)),
        Address::Sapling(_) => SpendPolicy::shielded_pools([ShieldedPool::Sapling]),
        Address::Unified(ua) => SpendPolicy::shielded_pools(
            ua.sapling()
                .is_some()
                .then_some(ShieldedPool::Sapling)
                .into_iter()
                .chain(
                    ua.orchard()
                        .is_some()
                        .then_some(ORCHARD_RECEIVER_POOLS)
                        .into_iter()
                        .flatten(),
                ),
        ),
        // A TEX address (ZIP 320) names transparent funds held by a counterparty and
        // cannot correspond to a wallet account, so no spend policy applies; account
        // resolution rejects it before this is consulted. Named explicitly (rather
        // than `_`) so that a future `Address` variant is a compile error here
        // instead of silently receiving an empty spend policy.
        Address::Tex(_) => SpendPolicy::shielded_pools([]),
    }
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
pub(super) fn transparent_change_policy_for(spend_policy: &SpendPolicy) -> TransparentChangePolicy {
    match spend_policy.transparent() {
        Some(_) => TransparentChangePolicy::TransparentChangeAllowed,
        None => TransparentChangePolicy::ShieldChange,
    }
}

/// The shielded pool in which a payment to an Orchard receiver is constructed at
/// `target_height`.
///
/// From NU6.3 (Ironwood, ZIP 2005) the Orchard turnstile is one-way: value may leave the
/// Orchard pool but never enter it, so such a payment is delivered through the Ironwood
/// bundle and its value lands in the Ironwood pool. Only the funds already in that pool can
/// pay the recipient without crossing; Orchard funds spent to an external receiver cross the
/// turnstile, and the crossing amount shows in the transaction's public value balances.
///
/// The recipient's address is the same either way. ZIP 316 has no Ironwood typecode, so an
/// Ironwood note is received at an Orchard receiver; it is the pool behind the receiver that
/// moves at activation, not the encoding.
///
/// This mirrors `zcash_client_backend`'s `ironwood_active_at`, which its input selector
/// applies to the same target height when it assigns a payment its output pool. Both that
/// predicate and the classification built on it (`resolve_shielded_destination`) are private
/// upstream, so the rule is restated here rather than shared.
fn orchard_receiver_pool(params: &Network, target_height: BlockHeight) -> ShieldedPool {
    if params.is_nu_active(NetworkUpgrade::Nu6_3, target_height) {
        ShieldedPool::Ironwood
    } else {
        ShieldedPool::Orchard
    }
}

/// The value an account can spend right now in `pool`.
///
/// Written as a match so that adding a [`ShieldedPool`] variant fails compilation here,
/// forcing the new pool to be given a balance rather than silently reading as empty.
fn spendable_in(balance: &AccountBalance, pool: ShieldedPool) -> Zatoshis {
    match pool {
        ShieldedPool::Sapling => balance.sapling_balance(),
        ShieldedPool::Orchard => balance.orchard_balance(),
        ShieldedPool::Ironwood => balance.ironwood_balance(),
    }
    .spendable_value()
}

/// Rejects a request whose recipients cannot be paid within `privacy_policy`, given the
/// funds in `balance` and the pools a transaction targeting `target_height` would use.
///
/// This runs before input selection and proving, both of which are expensive, and reports
/// the privacy conflict directly rather than leaving the caller to infer it from a failed
/// proposal. It is a pre-flight check, not the authority: [`enforce_privacy_policy`] is what
/// holds the guarantee, because it inspects the proposal that will actually be built. The
/// two must agree on which pools are distinct, or a send rejected here would have been
/// accepted there (or the reverse); [`orchard_receiver_pool`] is what keeps them aligned.
///
/// The check ignores fees, so the balances over-estimate what a payment can really draw on.
/// That is the safe direction: a pool that cannot cover a payment even before fees certainly
/// cannot cover it after them, so this never rejects a send that would have succeeded.
fn check_recipients_against_privacy_policy(
    params: &Network,
    target_height: BlockHeight,
    request: &TransactionRequest,
    privacy_policy: PrivacyPolicy,
    balance: &AccountBalance,
) -> Result<(), IncompatiblePrivacyPolicy> {
    let mut max_sapling_available = spendable_in(balance, ShieldedPool::Sapling);

    // A payment to an Orchard receiver is constructed in whichever pool
    // `orchard_receiver_pool` names, so only that pool's funds can pay one without crossing.
    // The other pool of the Orchard family is deliberately not counted: spending it would
    // cross the turnstile and reveal the amount, which is what this check exists to detect.
    let mut max_orchard_receiver_available =
        spendable_in(balance, orchard_receiver_pool(params, target_height));

    for payment in request.payments().values() {
        let value = payment
            .amount()
            .expect("Every payment built by `build_request` has an amount");

        // `build_request` has already rejected any recipient that does not decode on this
        // network, so this cannot fail for a request that reached us.
        let recipient =
            Address::try_from_zcash_address(params, payment.recipient_address().clone())
                .expect("Every recipient of a request built by `build_request` decodes");

        match recipient {
            Address::Transparent(_) | Address::Tex(_) => {
                if !privacy_policy.allow_revealed_recipients() {
                    return Err(IncompatiblePrivacyPolicy::TransparentRecipient);
                }
            }
            Address::Sapling(_) => {
                match (
                    privacy_policy.allow_revealed_amounts(),
                    max_sapling_available - value,
                ) {
                    (false, None) => {
                        return Err(IncompatiblePrivacyPolicy::RevealingShieldedAmount(
                            ShieldedPool::Sapling,
                        ));
                    }
                    (false, Some(rest)) => max_sapling_available = rest,
                    (true, _) => (),
                }
            }
            Address::Unified(ua) => {
                match (
                    privacy_policy.allow_revealed_amounts(),
                    (
                        ua.receiver_types().contains(&unified::Typecode::Orchard),
                        max_orchard_receiver_available - value,
                    ),
                    (
                        ua.receiver_types().contains(&unified::Typecode::Sapling),
                        max_sapling_available - value,
                    ),
                ) {
                    // The preferred receiver is Orchard, and we either allow revealed
                    // amounts or have sufficient funds in the pool that receiver is paid
                    // from to avoid it.
                    (true, (true, _), _) => (),
                    (false, (true, Some(rest)), _) => max_orchard_receiver_available = rest,

                    // The preferred receiver is Sapling, and we either allow revealed
                    // amounts or have sufficient Sapling funds available to avoid it.
                    (true, _, (true, _)) => (),
                    (false, _, (true, Some(rest))) => max_sapling_available = rest,

                    // We need to reveal something in order to make progress.
                    _ => {
                        if privacy_policy.allow_revealed_recipients() {
                            // Nothing to do here.
                        } else if privacy_policy.allow_revealed_amounts() {
                            return Err(IncompatiblePrivacyPolicy::TransparentReceiver);
                        } else {
                            return Err(IncompatiblePrivacyPolicy::RevealingReceiverAmounts);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Validates the recipients against the privacy policy, proposes a transfer, and
/// enforces both the privacy policy and the configured Orchard action limit on the
/// resulting proposal.
///
/// Shared by the JSON-RPC methods that build a transaction from a
/// [`TransactionRequest`] (`z_sendmany`, `pczt_create`).
pub(super) fn propose_and_check(
    wallet: &mut DbConnection,
    params: &Network,
    account_id: AccountUuid,
    request: TransactionRequest,
    privacy_policy: PrivacyPolicy,
    confirmations_policy: ConfirmationsPolicy,
    spend_policy: &SpendPolicy,
) -> RpcResult<Proposal<StandardFeeRule, ReceivedNoteId>> {
    // The account's real per-pool balances, so the recipient check below can tell whether a
    // payment can be funded without crossing pools. This uses the same `confirmations_policy`
    // that input selection will use, so the check and the selector agree on which notes are
    // spendable rather than the check working from a more optimistic view.
    let summary = wallet
        .get_wallet_summary(confirmations_policy)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        // A wallet with no scanned range has no balances to check against. Failing here is
        // better than proceeding as though the account were empty, which would reject every
        // shielded send under a strict policy, or as though it were unlimited, which would
        // skip the check entirely.
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;

    // An account holding nothing may be absent from the summary. That is "no funds", not "no
    // such account": `account_id` was resolved from the caller's `fromaddress` before we got
    // here, so it exists.
    let empty = AccountBalance::ZERO;
    let account_balance = summary
        .account_balances()
        .get(&account_id)
        .unwrap_or(&empty);

    // The height the transaction will target, which decides which pool a payment to an
    // Orchard receiver is constructed in. This is the same call `propose_transfer` makes
    // first, with the same argument, so the check and the proposal cannot disagree about
    // the target height; `None` is its `SyncRequired`, reported here as the wallet summary's
    // absence is above.
    let (target_height, _) = wallet
        .get_target_and_anchor_heights(confirmations_policy.trusted())
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| LegacyCode::InWarmup.with_static("Wallet sync required"))?;

    check_recipients_against_privacy_policy(
        params,
        target_height.into(),
        &request,
        privacy_policy,
        account_balance,
    )?;

    let transparent_change_policy = transparent_change_policy_for(spend_policy);

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
        wallet,
        params,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        confirmations_policy,
        spend_policy,
        // Inputs are not locked: the proposal is built, signed and stored within this
        // operation, and Zallet exposes no RPC by which a caller could release a lock
        // left behind by an operation that failed partway through.
        //
        // A PCZT breaks that assumption — `pczt_create` returns the proposal's inputs to
        // the caller and the transaction is finished later, or never — but there is still
        // no way to release a lock, so locking here would strand notes rather than protect
        // them. `pczt_extract` records the transaction, which is what marks them spent.
        None,
        // Do not request a specific transaction version; building falls back to the version
        // implied by the target height.
        None,
    )
    // TODO: Map errors to `zcashd` shape.
    .map_err(|e| {
        LegacyCode::Wallet
            .with_message(fl!("err-propose-transaction-failed", error = e.to_string()))
    })?;

    enforce_privacy_policy(&proposal, privacy_policy)?;

    let actions_limit = APP.config().builder.limits.orchard_actions().into();
    check_shielded_action_limits(&proposal, actions_limit).map_err(|e| {
        LegacyCode::Misc.with_message(fl!(
            "err-excess-shielded-actions",
            pool = PoolType::Shielded(e.pool).to_string(),
            count = e.count,
            kind = e.kind,
            limit = actions_limit,
            config = "-orchardactionlimit=N",
            bound = "N >= %u".to_string(),
        ))
    })?;

    Ok(proposal)
}

/// A strategy to use for managing privacy when constructing a transaction.
///
/// Policy for what information leakage is acceptable in a transaction created via a
/// JSON-RPC method.
///
/// This should only be used with existing JSON-RPC methods; it was introduced in `zcashd`
/// because shoe-horning cross-pool controls into existing methods was hard. A better
/// approach for new JSON-RPC methods is to design the interaction pattern such that the
/// caller receives a "transaction proposal", and they can consider the privacy
/// implications of a proposal before committing to it.
//
// Note: This intentionally does not implement `PartialOrd`. See `Self::meet` for a
// correct comparison.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum PrivacyPolicy {
    /// Only allow fully-shielded transactions (involving a single shielded value pool).
    FullPrivacy,

    /// Allow funds to cross between shielded value pools, revealing the amount that
    /// crosses pools.
    AllowRevealedAmounts,

    /// Allow transparent recipients.
    ///
    /// This also implies revealing information described under
    /// [`PrivacyPolicy::AllowRevealedAmounts`].
    AllowRevealedRecipients,

    /// Allow transparent funds to be spent, revealing the sending addresses and amounts.
    ///
    /// This implies revealing information described under
    /// [`PrivacyPolicy::AllowRevealedAmounts`].
    AllowRevealedSenders,

    /// Allow transaction to both spend transparent funds and have transparent recipients.
    ///
    /// This implies revealing information described under
    /// [`PrivacyPolicy::AllowRevealedSenders`] and
    /// [`PrivacyPolicy::AllowRevealedRecipients`].
    AllowFullyTransparent,

    /// Allow selecting transparent coins from the full account, rather than just the
    /// funds sent to the transparent receiver in the provided Unified Address.
    ///
    /// This implies revealing information described under
    /// [`PrivacyPolicy::AllowRevealedSenders`].
    AllowLinkingAccountAddresses,

    /// Allow the transaction to reveal any information necessary to create it.
    ///
    /// This implies revealing information described under
    /// [`PrivacyPolicy::AllowFullyTransparent`] and
    /// [`PrivacyPolicy::AllowLinkingAccountAddresses`].
    NoPrivacy,
}

impl From<PrivacyPolicy> for &'static str {
    fn from(value: PrivacyPolicy) -> Self {
        match value {
            PrivacyPolicy::FullPrivacy => "FullPrivacy",
            PrivacyPolicy::AllowRevealedAmounts => "AllowRevealedAmounts",
            PrivacyPolicy::AllowRevealedRecipients => "AllowRevealedRecipients",
            PrivacyPolicy::AllowRevealedSenders => "AllowRevealedSenders",
            PrivacyPolicy::AllowFullyTransparent => "AllowFullyTransparent",
            PrivacyPolicy::AllowLinkingAccountAddresses => "AllowLinkingAccountAddresses",
            PrivacyPolicy::NoPrivacy => "NoPrivacy",
        }
    }
}

impl fmt::Display for PrivacyPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", <&'static str>::from(*self))
    }
}

impl PrivacyPolicy {
    pub(super) fn from_str(s: &str) -> Option<Self> {
        match s {
            "FullPrivacy" => Some(Self::FullPrivacy),
            "AllowRevealedAmounts" => Some(Self::AllowRevealedAmounts),
            "AllowRevealedRecipients" => Some(Self::AllowRevealedRecipients),
            "AllowRevealedSenders" => Some(Self::AllowRevealedSenders),
            "AllowFullyTransparent" => Some(Self::AllowFullyTransparent),
            "AllowLinkingAccountAddresses" => Some(Self::AllowLinkingAccountAddresses),
            "NoPrivacy" => Some(Self::NoPrivacy),
            // Unknown privacy policy.
            _ => None,
        }
    }

    /// Returns the meet (greatest lower bound) of `self` and `other`.
    ///
    /// Privacy policies form a lattice where the relation is "strictness". I.e., `x ≤ y`
    /// means "Policy `x` allows at least everything that policy `y` allows."
    ///
    /// This function returns the strictest policy that allows everything allowed by
    /// `self` and also everything allowed by `other`.
    ///
    /// See [zcash/zcash#6240] for the graph that this models.
    ///
    /// [zcash/zcash#6240]: https://github.com/zcash/zcash/issues/6240
    pub(super) fn meet(self, other: Self) -> Self {
        match self {
            PrivacyPolicy::FullPrivacy => other,
            PrivacyPolicy::AllowRevealedAmounts => match other {
                PrivacyPolicy::FullPrivacy => self,
                _ => other,
            },
            PrivacyPolicy::AllowRevealedRecipients => match other {
                PrivacyPolicy::FullPrivacy | PrivacyPolicy::AllowRevealedAmounts => self,
                PrivacyPolicy::AllowRevealedSenders => PrivacyPolicy::AllowFullyTransparent,
                PrivacyPolicy::AllowLinkingAccountAddresses => PrivacyPolicy::NoPrivacy,
                _ => other,
            },
            PrivacyPolicy::AllowRevealedSenders => match other {
                PrivacyPolicy::FullPrivacy | PrivacyPolicy::AllowRevealedAmounts => self,
                PrivacyPolicy::AllowRevealedRecipients => PrivacyPolicy::AllowFullyTransparent,
                _ => other,
            },
            PrivacyPolicy::AllowFullyTransparent => match other {
                PrivacyPolicy::FullPrivacy
                | PrivacyPolicy::AllowRevealedAmounts
                | PrivacyPolicy::AllowRevealedRecipients
                | PrivacyPolicy::AllowRevealedSenders => self,
                PrivacyPolicy::AllowLinkingAccountAddresses => PrivacyPolicy::NoPrivacy,
                _ => other,
            },
            PrivacyPolicy::AllowLinkingAccountAddresses => match other {
                PrivacyPolicy::FullPrivacy
                | PrivacyPolicy::AllowRevealedAmounts
                | PrivacyPolicy::AllowRevealedSenders => self,
                PrivacyPolicy::AllowRevealedRecipients | PrivacyPolicy::AllowFullyTransparent => {
                    PrivacyPolicy::NoPrivacy
                }
                _ => other,
            },
            PrivacyPolicy::NoPrivacy => self,
        }
    }

    /// This policy is compatible with a given policy if it is identical to or less strict
    /// than the given policy.
    ///
    /// For example, if a transaction requires a policy no stricter than
    /// [`PrivacyPolicy::AllowRevealedSenders`], then that transaction can safely be
    /// constructed if the user specifies [`PrivacyPolicy::AllowLinkingAccountAddresses`],
    /// because `AllowLinkingAccountAddresses` is compatible with `AllowRevealedSenders`
    /// (the transaction will not link addresses anyway). However, if the transaction
    /// required [`PrivacyPolicy::AllowRevealedRecipients`], it could not be constructed,
    /// because `AllowLinkingAccountAddresses` is _not_ compatible with
    /// `AllowRevealedRecipients` (the transaction reveals recipients, which is not
    /// allowed by `AllowLinkingAccountAddresses`.
    pub(super) fn is_compatible_with(&self, other: Self) -> bool {
        self == &self.meet(other)
    }

    pub(super) fn allow_revealed_amounts(&self) -> bool {
        self.is_compatible_with(PrivacyPolicy::AllowRevealedAmounts)
    }

    pub(super) fn allow_revealed_recipients(&self) -> bool {
        self.is_compatible_with(PrivacyPolicy::AllowRevealedRecipients)
    }
}

/// What a single proposal step reveals: the least permissive [`PrivacyPolicy`] that still
/// allows it, and the error describing the leak if the caller's policy does not reach it.
///
/// Returns `None` when the step reveals nothing, which every policy permits.
///
/// This is the single source of truth for the privacy implications of a step.
/// [`enforce_privacy_policy`] and [`required_privacy_policy`] are both derived from it, so
/// the check and the report cannot disagree about what a proposal leaks.
fn step_privacy_requirement<NoteRef>(
    step: &Step<NoteRef>,
) -> Option<(PrivacyPolicy, IncompatiblePrivacyPolicy)> {
    let has_transparent_recipient = step.output_in_pool(PoolType::Transparent);
    let has_transparent_change = step.change_in_pool(PoolType::Transparent);

    if step.input_in_pool(PoolType::Transparent) {
        let received_addrs = step
            .transparent_inputs()
            .iter()
            .map(|input| input.recipient_address())
            .collect::<HashSet<_>>();

        if received_addrs.len() > 1 {
            if has_transparent_recipient || has_transparent_change {
                Some((
                    PrivacyPolicy::NoPrivacy,
                    IncompatiblePrivacyPolicy::NoPrivacy,
                ))
            } else {
                Some((
                    PrivacyPolicy::AllowLinkingAccountAddresses,
                    IncompatiblePrivacyPolicy::LinkingAccountAddresses,
                ))
            }
        } else if has_transparent_recipient || has_transparent_change {
            Some((
                PrivacyPolicy::AllowFullyTransparent,
                IncompatiblePrivacyPolicy::FullyTransparent,
            ))
        } else {
            Some((
                PrivacyPolicy::AllowRevealedSenders,
                IncompatiblePrivacyPolicy::TransparentSender,
            ))
        }
    } else if has_transparent_recipient {
        Some((
            PrivacyPolicy::AllowRevealedRecipients,
            IncompatiblePrivacyPolicy::TransparentRecipient,
        ))
    } else if has_transparent_change {
        // The same policy as an explicit transparent recipient, but reported separately:
        // the caller did not ask for this output.
        Some((
            PrivacyPolicy::AllowRevealedRecipients,
            IncompatiblePrivacyPolicy::TransparentChange,
        ))
    } else {
        shielded_pool_crossed_into(step).map(|pool| {
            // TODO: This should only trigger when there is a non-fee valueBalance.
            // TODO: Determine whether this is due to the presence of an explicit
            // recipient address in that pool, or having insufficient funds to pay a
            // UA within a single pool.
            (
                PrivacyPolicy::AllowRevealedAmounts,
                IncompatiblePrivacyPolicy::RevealingShieldedAmount(pool),
            )
        })
    }
}

/// Every shielded pool, for the privacy checks below, which must consider all cross-pool
/// value flows.
///
/// Written as a match so that adding a `ShieldedPool` variant fails compilation here,
/// forcing the new pool to be modeled by the privacy policy rather than bypassing it.
pub(super) fn all_shielded_pools() -> [ShieldedPool; 3] {
    match ShieldedPool::Sapling {
        ShieldedPool::Sapling | ShieldedPool::Orchard | ShieldedPool::Ironwood => [
            ShieldedPool::Sapling,
            ShieldedPool::Orchard,
            ShieldedPool::Ironwood,
        ],
    }
}

/// Returns a shielded pool that the given step moves value into from a different
/// shielded pool, if any.
///
/// Crossing between shielded pools reveals the crossing amount in the transaction's
/// public value balances, so it requires [`PrivacyPolicy::AllowRevealedAmounts`].
fn shielded_pool_crossed_into<NoteRef>(step: &Step<NoteRef>) -> Option<ShieldedPool> {
    let input_pools = all_shielded_pools()
        .into_iter()
        .filter(|pool| step.input_in_pool(PoolType::Shielded(*pool)))
        .collect::<Vec<_>>();

    all_shielded_pools().into_iter().find(|pool| {
        (step.output_in_pool(PoolType::Shielded(*pool))
            || step.change_in_pool(PoolType::Shielded(*pool)))
            && input_pools.iter().any(|input_pool| input_pool != pool)
    })
}

pub(super) fn enforce_privacy_policy<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
    privacy_policy: PrivacyPolicy,
) -> Result<(), IncompatiblePrivacyPolicy> {
    for step in proposal.steps() {
        // Each `allow_*` predicate is itself `is_compatible_with` of the corresponding
        // policy, so checking the step's requirement directly is the same test the
        // per-branch predicates used to perform.
        if let Some((required, incompatible)) = step_privacy_requirement(step)
            && !privacy_policy.is_compatible_with(required)
        {
            return Err(incompatible);
        }
    }

    Ok(())
}

/// Returns the privacy policy required to execute the given proposal.
///
/// This is the inverse of [`enforce_privacy_policy`]: rather than checking a caller-supplied
/// policy against the information a proposal would leak, it computes the strictest
/// [`PrivacyPolicy`] that still permits the proposal. Any policy that
/// [`PrivacyPolicy::is_compatible_with`] the returned value is sufficient to execute the
/// transaction; the returned value is itself the strictest such policy.
///
/// Both directions read the same per-step classification from
/// [`step_privacy_requirement`], so `enforce_privacy_policy(proposal, p)` succeeds exactly
/// when `p.is_compatible_with(required_privacy_policy(proposal))`.
///
/// This reports the privacy implications of a proposed transaction without requiring the
/// caller to commit to a policy up front.
pub(super) fn required_privacy_policy<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
) -> PrivacyPolicy {
    // The required policy for the whole proposal is the meet (greatest lower bound, i.e.
    // most-permissive-needed) of the policies required by each step. We start from
    // `FullPrivacy` (the strictest policy, the lattice top); `meet` with each step's
    // requirement relaxes it exactly as much as that step's leakage demands. A step that
    // reveals nothing has no requirement, and leaves the running policy alone.
    proposal
        .steps()
        .iter()
        .fold(PrivacyPolicy::FullPrivacy, |required, step| {
            required.meet(
                step_privacy_requirement(step)
                    .map_or(PrivacyPolicy::FullPrivacy, |(step_required, _)| {
                        step_required
                    }),
            )
        })
}

/// A shielded pool in which a proposal step exceeds the per-pool action limit.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ShieldedActionLimitExceeded {
    pub(super) pool: ShieldedPool,
    pub(super) count: usize,
    /// Which side of the pool's bundle exceeds the limit: `"inputs"`, `"outputs"`, or
    /// `"actions"` when both do.
    pub(super) kind: &'static str,
}

/// Checks every step of the proposal against the per-pool action limit.
///
/// The limit applies per shielded pool: each pool's spends and outputs bound the memory
/// needed to prove and construct that pool's part of the transaction.
pub(super) fn check_shielded_action_limits<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
    limit: usize,
) -> Result<(), ShieldedActionLimitExceeded> {
    for step in proposal.steps() {
        for pool in all_shielded_pools() {
            let spends = step
                .shielded_inputs()
                .iter()
                .flat_map(|inputs| inputs.notes())
                .filter(|note| note.note().pool() == pool)
                .count();

            let outputs = step
                .payment_pools()
                .values()
                .filter(|payment_pool| **payment_pool == PoolType::Shielded(pool))
                .count()
                + step
                    .balance()
                    .proposed_change()
                    .iter()
                    .filter(|change| change.output_pool() == PoolType::Shielded(pool))
                    .count();

            let actions = spends.max(outputs);

            if actions > limit {
                let (count, kind) = if outputs <= limit {
                    (spends, "inputs")
                } else if spends <= limit {
                    (outputs, "outputs")
                } else {
                    (actions, "actions")
                };

                return Err(ShieldedActionLimitExceeded { pool, count, kind });
            }
        }
    }

    Ok(())
}

/// Parses the optional `privacy_policy` JSON-RPC argument into a [`PrivacyPolicy`],
/// defaulting to [`PrivacyPolicy::FullPrivacy`] when absent and rejecting the unsupported
/// `"LegacyCompat"` policy.
pub(super) fn parse_privacy_policy(privacy_policy: Option<&str>) -> RpcResult<PrivacyPolicy> {
    match privacy_policy {
        Some("LegacyCompat") => {
            Err(LegacyCode::InvalidParameter.with_message(fl!("err-privacy-policy-legacy-compat")))
        }
        Some(s) => PrivacyPolicy::from_str(s).ok_or_else(|| {
            LegacyCode::InvalidParameter.with_message(fl!("err-privacy-policy-unknown", policy = s))
        }),
        None => Ok(PrivacyPolicy::FullPrivacy),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum IncompatiblePrivacyPolicy {
    /// Requested [`PrivacyPolicy`] doesn’t include `NoPrivacy`.
    NoPrivacy,

    /// Requested [`PrivacyPolicy`] doesn’t include `AllowLinkingAccountAddresses`.
    LinkingAccountAddresses,

    /// Requested [`PrivacyPolicy`] doesn’t include `AllowFullyTransparent`.
    FullyTransparent,

    /// Requested [`PrivacyPolicy`] doesn’t include `AllowRevealedSenders`.
    TransparentSender,

    /// Requested [`PrivacyPolicy`] doesn’t include `AllowRevealedRecipients`.
    TransparentRecipient,

    /// Requested [`PrivacyPolicy`] doesn’t include `AllowRevealedRecipients`.
    TransparentChange,

    /// Requested [`PrivacyPolicy`] doesn’t include `AllowRevealedRecipients`, but we are
    /// trying to pay a UA where we can only select a transparent receiver.
    TransparentReceiver,

    /// Requested [`PrivacyPolicy`] doesn’t include `AllowRevealedAmounts`, but we don’t
    /// have enough funds in the given shielded pool to avoid revealing amounts by
    /// crossing into it from another pool.
    RevealingShieldedAmount(ShieldedPool),

    /// Requested [`PrivacyPolicy`] doesn’t include `AllowRevealedAmounts`, but we are
    /// trying to pay a UA where we don’t have enough funds in any single pool that it has
    /// a receiver for.
    RevealingReceiverAmounts,
}

impl From<IncompatiblePrivacyPolicy> for ErrorObjectOwned {
    fn from(e: IncompatiblePrivacyPolicy) -> Self {
        LegacyCode::InvalidParameter.with_message(match e {
            IncompatiblePrivacyPolicy::NoPrivacy => fl!(
                "err-privpol-no-privacy-not-allowed",
                parameter = "privacyPolicy",
                policy = "NoPrivacy"
            ),
            IncompatiblePrivacyPolicy::LinkingAccountAddresses => format!(
                "{} {}",
                fl!("err-privpol-linking-addrs-not-allowed"),
                fl!(
                    "rec-privpol-privacy-weakening",
                    parameter = "privacyPolicy",
                    policy = "AllowLinkingAccountAddresses"
                )
            ),
            IncompatiblePrivacyPolicy::FullyTransparent => format!(
                "{} {}",
                fl!("err-privpol-fully-transparent-not-allowed"),
                fl!(
                    "rec-privpol-privacy-weakening",
                    parameter = "privacyPolicy",
                    policy = "AllowFullyTransparent"
                )
            ),
            IncompatiblePrivacyPolicy::TransparentSender => format!(
                "{} {}",
                fl!("err-privpol-transparent-sender-not-allowed"),
                fl!(
                    "rec-privpol-privacy-weakening",
                    parameter = "privacyPolicy",
                    policy = "AllowRevealedSenders"
                )
            ),
            IncompatiblePrivacyPolicy::TransparentRecipient => format!(
                "{} {}",
                fl!("err-privpol-transparent-recipient-not-allowed"),
                fl!(
                    "rec-privpol-privacy-weakening",
                    parameter = "privacyPolicy",
                    policy = "AllowRevealedRecipients"
                )
            ),
            IncompatiblePrivacyPolicy::TransparentChange => format!(
                "{} {}",
                fl!("err-privpol-transparent-change-not-allowed"),
                fl!(
                    "rec-privpol-privacy-weakening",
                    parameter = "privacyPolicy",
                    policy = "AllowRevealedRecipients"
                )
            ),
            IncompatiblePrivacyPolicy::TransparentReceiver => format!(
                "{} {}",
                fl!("err-privpol-transparent-receiver-not-allowed"),
                fl!(
                    "rec-privpol-privacy-weakening",
                    parameter = "privacyPolicy",
                    policy = "AllowRevealedRecipients"
                )
            ),
            IncompatiblePrivacyPolicy::RevealingShieldedAmount(pool) => format!(
                "{} {}",
                fl!(
                    "err-privpol-revealing-amount-not-allowed",
                    pool = PoolType::Shielded(pool).to_string()
                ),
                fl!(
                    "rec-privpol-privacy-weakening",
                    parameter = "privacyPolicy",
                    policy = "AllowRevealedAmounts"
                )
            ),
            IncompatiblePrivacyPolicy::RevealingReceiverAmounts => format!(
                "{} {}",
                fl!("err-privpol-revealing-receiver-amounts-not-allowed"),
                fl!(
                    "rec-privpol-privacy-weakening",
                    parameter = "privacyPolicy",
                    policy = "AllowRevealedAmounts"
                )
            ),
        })
    }
}

/// Maximum decoded memo size in bytes, matching [`MemoBytes::from_bytes`].
const MAX_MEMO_BYTES: usize = 512;

pub(super) fn parse_memo(memo_hex: &str) -> RpcResult<MemoBytes> {
    if memo_hex.len() > MAX_MEMO_BYTES * 2 {
        return Err(LegacyCode::InvalidParameter
            .with_static("Invalid parameter, memo is longer than the maximum allowed 512 bytes."));
    }

    let memo_bytes = hex::decode(memo_hex).map_err(|_| {
        LegacyCode::InvalidParameter
            .with_static("Invalid parameter, expected memo data in hexadecimal format.")
    })?;

    MemoBytes::from_bytes(&memo_bytes).map_err(|_| {
        LegacyCode::InvalidParameter
            .with_static("Invalid parameter, memo is longer than the maximum allowed 512 bytes.")
    })
}

#[cfg(test)]
mod amount_parameter_tests {
    use super::AmountParameter;

    #[test]
    fn accepts_the_known_keys() {
        for json in [
            r#"{"address": "taddr", "amount": 1}"#,
            r#"{"address": "zaddr", "amount": "0.5", "memo": "00"}"#,
        ] {
            serde_json::from_str::<AmountParameter>(json).expect("known keys parse");
        }
    }

    /// An unknown key must be rejected, as in `zcashd`: silently ignoring one
    /// means a misspelled `memo` sends the payment without its memo.
    #[test]
    fn rejects_an_unknown_key() {
        let err = match serde_json::from_str::<AmountParameter>(
            r#"{"address": "zaddr", "amount": 1, "memmo": "00"}"#,
        ) {
            Ok(_) => panic!("unknown key should be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("memmo"), "{err}");
    }
}

#[cfg(test)]
mod parse_memo_tests {
    use super::*;
    use jsonrpsee::types::ErrorObject;

    fn invalid_parameter_message(err: ErrorObject<'_>) -> String {
        err.message().to_string()
    }

    #[test]
    fn parse_memo_accepts_max_length_hex() {
        let memo_hex = "00".repeat(MAX_MEMO_BYTES);
        assert!(parse_memo(&memo_hex).is_ok());
    }

    #[test]
    fn parse_memo_rejects_overlong_hex_before_decode() {
        let memo_hex = "00".repeat(MAX_MEMO_BYTES + 1);
        let err = parse_memo(&memo_hex).expect_err("overlong memo should be rejected");
        assert_eq!(
            invalid_parameter_message(err),
            "Invalid parameter, memo is longer than the maximum allowed 512 bytes."
        );
    }

    #[test]
    fn parse_memo_rejects_invalid_hex() {
        let err = parse_memo("not-hex").expect_err("invalid hex should be rejected");
        assert_eq!(
            invalid_parameter_message(err),
            "Invalid parameter, expected memo data in hexadecimal format."
        );
    }
}

#[cfg(test)]
mod legacy_pool_tests {
    use proptest::prelude::*;
    use zip32::{AccountId, fingerprint::SeedFingerprint};

    use super::{ZCASH_LEGACY_ACCOUNT, is_legacy_pool_account};

    /// A ZIP 32 account index that is not the legacy one. Indices are non-hardened, so they
    /// occupy the low 31 bits, and the legacy index is the largest of them.
    fn arb_regular_account_index() -> impl Strategy<Value = u32> {
        0u32..ZCASH_LEGACY_ACCOUNT
    }

    proptest! {
        /// The legacy pool is one account of one seed: the account at the legacy ZIP 32
        /// index, derived from the seed the operator named. Nothing else may be spent as
        /// `ANY_TADDR`, since every other account is a separate pool of funds under Zallet's
        /// semantics.
        ///
        /// Established over arbitrary seeds and arbitrary regular account indices, rather
        /// than a hardcoded pair, so it holds for whatever seed a wallet actually carries.
        #[test]
        fn legacy_pool_is_only_the_named_seeds_legacy_account(
            legacy_seed in any::<[u8; 32]>(),
            other_seed in any::<[u8; 32]>(),
            regular_index in arb_regular_account_index(),
        ) {
            // Two distinct `zcashd` wallets, hence two distinct seeds.
            prop_assume!(legacy_seed != other_seed);

            let legacy_seed_fp = SeedFingerprint::from_bytes(legacy_seed);
            let other_seed_fp = SeedFingerprint::from_bytes(other_seed);
            let legacy_index = AccountId::try_from(ZCASH_LEGACY_ACCOUNT)
                .expect("the legacy account index is a valid ZIP 32 account index");
            let regular_index = AccountId::try_from(regular_index)
                .expect("indices below the legacy one are valid ZIP 32 account indices");

            prop_assert!(is_legacy_pool_account(
                &legacy_seed_fp,
                legacy_index,
                &legacy_seed_fp,
            ));

            // A regular account of the legacy seed is a pool of funds in its own right.
            prop_assert!(!is_legacy_pool_account(
                &legacy_seed_fp,
                regular_index,
                &legacy_seed_fp,
            ));

            // Another `zcashd` wallet's legacy account is not this wallet's legacy pool.
            prop_assert!(!is_legacy_pool_account(
                &other_seed_fp,
                legacy_index,
                &legacy_seed_fp,
            ));

            // And neither is any other account of that other wallet.
            prop_assert!(!is_legacy_pool_account(
                &other_seed_fp,
                regular_index,
                &legacy_seed_fp,
            ));
        }
    }
}

pub(super) fn get_account_for_address(
    wallet: &DbConnection,
    address: &Address,
) -> RpcResult<Account> {
    // A bare transparent address is generally not a wallet address in its own right: it is
    // a *receiver* of one of the account's unified addresses, so it never compares equal to
    // any `AddressInfo` in the scan below (those hold the whole UA). `find_account_for_address`
    // resolves an address through its receivers, so it maps such a taddr back to its owning
    // account; without it, a taddr `fromaddress` can never be spent from.
    if let Some(account_id) = wallet
        .find_account_for_address(wallet.params(), address)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
    {
        return Ok(wallet
            .get_account(account_id)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            .expect("present"));
    }

    // Fall back to scanning the account address lists, which also covers address kinds the
    // receiver index does not resolve.
    // TODO: Make this more efficient with a `WalletRead` method.
    //       https://github.com/zcash/librustzcash/issues/1944
    for account_id in wallet
        .get_account_ids()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
    {
        for address_info in wallet
            .list_addresses(account_id)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        {
            if address_info.address() == address {
                return Ok(wallet
                    .get_account(account_id)
                    .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
                    .expect("present"));
            }
        }
    }

    Err(LegacyCode::InvalidAddressOrKey.with_message(fl!("err-from-address-no-payment-source")))
}

/// Whether an account with this ZIP 32 derivation holds the legacy `zcashd` pool of funds
/// belonging to the wallet identified by `legacy_seed_fp`.
///
/// From v4.7.0 onwards, `zcashd` derived every address handed out by the legacy
/// `getnewaddress` and `z_getnewaddress` methods from the wallet's mnemonic at ZIP 32
/// account index [`ZCASH_LEGACY_ACCOUNT`], so the pool is exactly that one account of that
/// one seed. `zallet migrate-zcashd-wallet` preserves it: it re-points a pre-v4.7.0 wallet's
/// legacy account at the mnemonic `zcashd` would have grown on upgrade, and imports the
/// wallet's standalone (`importprivkey`) transparent keys into the same account.
///
/// A regular account of the legacy seed is therefore not the legacy pool, and neither is
/// another seed's legacy account: both would spend funds the caller did not name.
fn is_legacy_pool_account(
    seed_fingerprint: &SeedFingerprint,
    account_index: AccountId,
    legacy_seed_fp: &SeedFingerprint,
) -> bool {
    seed_fingerprint == legacy_seed_fp && u32::from(account_index) == ZCASH_LEGACY_ACCOUNT
}

/// Returns the account holding the legacy `zcashd` pool of funds.
///
/// Which of the wallet's seeds is the legacy one cannot be inferred: a Zallet wallet may hold
/// accounts derived from several seeds, while `zcashd`'s legacy semantics were defined for a
/// single wallet. The operator names it with the `features.legacy_pool_seed_fingerprint`
/// config option (whose value `zallet migrate-zcashd-wallet` prints on import). With the
/// option unset, this wallet has no legacy pool and callers that ask to spend from it are
/// rejected.
pub(super) fn get_legacy_pool_account(wallet: &DbConnection) -> RpcResult<Account> {
    legacy_pool_account(wallet).map_err(|e| match e {
        LegacyPoolError::Disabled => {
            LegacyCode::WalletAccountsUnsupported.with_message(fl!("err-legacy-pool-disabled"))
        }
        LegacyPoolError::NotFound(legacy_seed_fp) => LegacyCode::Wallet.with_message(fl!(
            "err-legacy-pool-not-found",
            seed_fp = legacy_seed_fp.to_string(),
        )),
        LegacyPoolError::Db(msg) => LegacyCode::Database.with_message(msg),
    })
}

/// The ways in which resolving the legacy `zcashd` pool account can fail.
pub(crate) enum LegacyPoolError {
    /// `features.legacy_pool_seed_fingerprint` is not set in the Zallet config.
    Disabled,
    /// No account of the wallet is the legacy account of the configured seed.
    NotFound(SeedFingerprint),
    /// A wallet database error occurred.
    Db(String),
}

/// Returns the account holding the legacy `zcashd` pool of funds. See
/// [`get_legacy_pool_account`] for the semantics; this is the transport-neutral core shared
/// with the CLI command layer.
pub(crate) fn legacy_pool_account(wallet: &DbConnection) -> Result<Account, LegacyPoolError> {
    let legacy_seed_fp = APP
        .config()
        .features
        .legacy_pool_seed_fingerprint
        .ok_or(LegacyPoolError::Disabled)?;

    // TODO: Make this more efficient with a `WalletRead` method.
    //       https://github.com/zcash/librustzcash/issues/1944
    for account_id in wallet
        .get_account_ids()
        .map_err(|e| LegacyPoolError::Db(e.to_string()))?
    {
        let account = wallet
            .get_account(account_id)
            .map_err(|e| LegacyPoolError::Db(e.to_string()))?
            // This would be a race condition between this and account deletion.
            .ok_or_else(|| LegacyPoolError::Db("Account vanished mid-call".into()))?;

        // Accounts imported from a UFVK have no ZIP 32 derivation, and cannot be the legacy
        // pool: `zcashd` derived the pool from the wallet's seed.
        if account.source().key_derivation().is_some_and(|derivation| {
            is_legacy_pool_account(
                derivation.seed_fingerprint(),
                derivation.account_index(),
                &legacy_seed_fp,
            )
        }) {
            return Ok(account);
        }
    }

    Err(LegacyPoolError::NotFound(legacy_seed_fp))
}

/// Why a transparent output of a built transaction failed verification against the
/// account's seed-derived key material.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum TransparentOutputError<E> {
    /// The output's script does not have a recognizable transparent address form.
    UnrecognizedScript { vout: usize },
    /// The wallet has no derivation record for the output's address.
    UnknownAddress(TransparentAddress),
    /// The wallet's record for the output's address does not claim derivation from the
    /// account key.
    #[cfg(feature = "transparent-key-import")]
    NotDerived(TransparentAddress),
    /// Re-derivation at the recorded derivation path does not reproduce the output's
    /// address.
    DerivationMismatch(TransparentAddress),
    /// The account key has no transparent component to derive from.
    NoTransparentKey(TransparentAddress),
    /// A requested payment output is absent from the transaction.
    MissingPayment(TransparentAddress),
    /// The derivation-record lookup failed.
    Lookup(E),
}

/// Checks that every transparent output of a built transaction is accounted for.
///
/// Shielded outputs are constructed in-process from the spending key material passed to
/// the transaction builder, but transparent change and ephemeral (ZIP 320) output
/// addresses are read from wallet database records that are not integrity-protected.
/// Each transparent output must therefore either exactly match one of `expected_payments`
/// (consuming it, so a payment vouches for at most one output), or re-derive from
/// `account_pubkey` — the account's seed-derived transparent key — at the derivation path
/// the wallet records for its address. The record itself is untrusted; only the
/// re-derivation equality establishes that the funds remain under the account's key.
///
/// All of `expected_payments` must be consumed: a transaction that fails to pay a
/// requested recipient is as unaccountable as one that pays an unrecognized output.
pub(super) fn check_transparent_outputs<E>(
    outputs: impl IntoIterator<Item = (Option<TransparentAddress>, Zatoshis)>,
    mut expected_payments: Vec<(TransparentAddress, Zatoshis)>,
    account_pubkey: Option<&AccountPubKey>,
    mut address_source: impl FnMut(&TransparentAddress) -> Result<Option<TransparentAddressSource>, E>,
) -> Result<(), TransparentOutputError<E>> {
    for (vout, (addr, value)) in outputs.into_iter().enumerate() {
        let addr = addr.ok_or(TransparentOutputError::UnrecognizedScript { vout })?;

        if let Some(index) = expected_payments
            .iter()
            .position(|(expected_addr, expected_value)| {
                *expected_addr == addr && *expected_value == value
            })
        {
            expected_payments.swap_remove(index);
            continue;
        }

        match address_source(&addr).map_err(TransparentOutputError::Lookup)? {
            None => return Err(TransparentOutputError::UnknownAddress(addr)),
            Some(TransparentAddressSource::Derived {
                scope,
                address_index,
            }) => {
                let derived = account_pubkey
                    .ok_or(TransparentOutputError::NoTransparentKey(addr))?
                    .derive_address_pubkey(scope, address_index)
                    .map_err(|_| TransparentOutputError::DerivationMismatch(addr))?;
                if TransparentAddress::from_pubkey(&derived) != addr {
                    return Err(TransparentOutputError::DerivationMismatch(addr));
                }
            }
            // Sources without derivation information (standalone imported keys) cannot be
            // tied to the account key. Change and ephemeral outputs are always derived, so
            // fail closed.
            #[cfg(feature = "transparent-key-import")]
            Some(_) => return Err(TransparentOutputError::NotDerived(addr)),
        }
    }

    if let Some((addr, _)) = expected_payments.first() {
        return Err(TransparentOutputError::MissingPayment(*addr));
    }

    Ok(())
}

/// The transparent (address, amount) pairs that the given proposal explicitly pays to
/// requested recipients, one list per proposal step.
///
/// Transparent-pool payments resolve to the receiver the transaction builder pays: a
/// unified address's transparent receiver, a bare transparent address, or the P2PKH
/// address underlying a TEX address. Ephemeral (ZIP 320) intermediate outputs are not
/// payments — they appear in a step's proposed change and must instead verify as
/// wallet-derived.
fn proposed_transparent_payments<FeeRuleT, NoteRef>(
    params: &Network,
    proposal: &Proposal<FeeRuleT, NoteRef>,
) -> RpcResult<Vec<Vec<(TransparentAddress, Zatoshis)>>> {
    proposal
        .steps()
        .iter()
        .map(|step| {
            let mut payments = vec![];
            for (payment_index, pool) in step.payment_pools() {
                if pool == &PoolType::Transparent {
                    let payment = step
                        .transaction_request()
                        .payments()
                        .get(payment_index)
                        .ok_or_else(|| {
                            LegacyCode::Wallet.with_static(
                                "Internal error: proposal step references a nonexistent payment.",
                            )
                        })?;
                    let value = payment.amount().ok_or_else(|| {
                        LegacyCode::Wallet
                            .with_static("Internal error: proposal step payment has no amount.")
                    })?;
                    let addr = match Address::try_from_zcash_address(
                        params,
                        payment.recipient_address().clone(),
                    ) {
                        Ok(Address::Transparent(addr)) => addr,
                        Ok(Address::Tex(data)) => TransparentAddress::PublicKeyHash(data),
                        Ok(Address::Unified(ua)) => *ua.transparent().ok_or_else(|| {
                            LegacyCode::Wallet.with_static(
                                "Internal error: transparent-pool payment to a unified address \
                                 without a transparent receiver.",
                            )
                        })?,
                        Ok(Address::Sapling(_)) | Err(_) => {
                            return Err(LegacyCode::Wallet.with_static(
                                "Internal error: transparent-pool payment to a non-transparent \
                                 address.",
                            ));
                        }
                    };
                    payments.push((addr, value));
                }
            }
            Ok(payments)
        })
        .collect()
}

/// Verifies the built transactions against the proposal and the account's seed-derived
/// key material, then broadcasts them to the network, if configured to do so.
///
/// A transaction containing a transparent output that verifies neither as a payment
/// requested by the proposal nor as an address derived from `ufvk` (see
/// [`check_transparent_outputs`]) is never handed to the broadcast step. `ufvk` must be
/// derived from the wallet seed, not read from the database.
pub(super) async fn verify_and_broadcast_transactions<C: Chain, FeeRuleT, NoteRef>(
    wallet: &DbConnection,
    chain: C,
    account_id: AccountUuid,
    ufvk: &UnifiedFullViewingKey,
    proposal: &Proposal<FeeRuleT, NoteRef>,
    txids: Vec<TxId>,
) -> RpcResult<SendResult> {
    let params = *wallet.params();
    let expected_payments = proposed_transparent_payments(&params, proposal)?;

    // The builder creates one transaction per proposal step, in step order.
    if txids.len() != expected_payments.len() {
        return Err(LegacyCode::Wallet.with_static(
            "Internal error: built transaction count does not match proposal step count.",
        ));
    }

    let mut transactions = Vec::with_capacity(txids.len());
    for (txid, expected) in txids.iter().zip(expected_payments) {
        let tx = wallet
            .get_transaction(*txid)
            .map_err(|e| {
                LegacyCode::Database.with_message(format!("Failed to get transaction: {e}"))
            })?
            .ok_or_else(|| {
                LegacyCode::Wallet
                    .with_message(format!("Wallet does not contain transaction {txid}"))
            })?;

        let outputs = tx
            .transparent_bundle()
            .map(|bundle| {
                bundle
                    .vout
                    .iter()
                    .map(|txout| (txout.recipient_address(), txout.value()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        check_transparent_outputs(outputs, expected, ufvk.transparent(), |addr| {
            wallet
                .get_transparent_address_metadata(account_id, addr)
                .map(|meta| meta.map(|m| m.source().clone()))
        })
        .map_err(|e| match e {
            TransparentOutputError::Lookup(e) => LegacyCode::Database.with_message(e.to_string()),
            TransparentOutputError::UnrecognizedScript { vout } => {
                LegacyCode::Wallet.with_message(fl!(
                    "err-transparent-output-not-wallet-derived",
                    output = format!("output index {vout}"),
                ))
            }
            TransparentOutputError::MissingPayment(addr) => LegacyCode::Wallet.with_message(fl!(
                "err-transparent-payment-missing",
                address = Address::Transparent(addr).encode(&params),
            )),
            TransparentOutputError::UnknownAddress(addr)
            | TransparentOutputError::DerivationMismatch(addr)
            | TransparentOutputError::NoTransparentKey(addr) => {
                LegacyCode::Wallet.with_message(fl!(
                    "err-transparent-output-not-wallet-derived",
                    output = Address::Transparent(addr).encode(&params),
                ))
            }
            #[cfg(feature = "transparent-key-import")]
            TransparentOutputError::NotDerived(addr) => LegacyCode::Wallet.with_message(fl!(
                "err-transparent-output-not-wallet-derived",
                output = Address::Transparent(addr).encode(&params),
            )),
        })?;

        transactions.push(tx);
    }

    let broadcast = APP.config().external.broadcast();
    if broadcast {
        for tx in &transactions {
            chain.broadcast_transaction(tx).await.map_err(|e| {
                LegacyCode::Wallet
                    .with_message(format!("SendTransaction: Transaction commit failed:: {e}"))
            })?;
        }
    }

    Ok(SendResult::new(txids, broadcast))
}

/// The result of sending a payment.
#[derive(Clone, Debug, Serialize, documented::Documented, JsonSchema)]
pub(crate) struct SendResult {
    /// The ID of the resulting transaction, if the payment only produced one.
    ///
    /// Omitted if more than one transaction was sent; see [`SendResult::txids`] in that
    /// case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    txid: Option<String>,

    /// The IDs of the transactions resulting from the payment.
    ///
    /// These are created and recorded in the wallet regardless of whether they were
    /// broadcast; see [`SendResult::broadcast`].
    txids: Vec<String>,

    /// Whether the transactions were submitted to the network.
    ///
    /// `false` when the `external.broadcast` config option is disabled: the
    /// transactions were built and recorded in the wallet, marking their inputs
    /// pending-spent, but never sent. Nothing else in this response distinguishes that
    /// from a completed send, so a client that treats a successful operation as "the
    /// payment is on its way" must check this field.
    broadcast: bool,
}

impl SendResult {
    fn new(txids: Vec<TxId>, broadcast: bool) -> Self {
        let txids = txids
            .into_iter()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>();

        Self {
            txid: (txids.len() == 1).then(|| txids.first().expect("present").clone()),
            txids,
            broadcast,
        }
    }
}

#[cfg(test)]
pub(crate) mod arb {
    //! Reusable test constructors for [`AmountParameter`], shared across the send-path RPC
    //! method tests (`z_sendmany` and, later, the account-based send methods).
    use serde_json::json;

    use super::AmountParameter;

    // Transparent addresses reused from the `validate_address` / `fund_source` tests.
    pub(crate) const T_ADDR_1: &str = "t1VydNnkjBzfL1iAMyUbwGKJAF7PgvuCfMY";
    pub(crate) const T_ADDR_2: &str = "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd";
    pub(crate) const SAPLING_ADDR: &str =
        "zs1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75c8v35z";
    // Unified addresses (carrying Orchard/Sapling/transparent receivers) from the
    // librustzcash test vectors.
    pub(crate) const UNIFIED_ADDR_1: &str = "u10j2s9sy4dmuakf57z58jc5t8yuswega82jpd2hk3q62l6fsphwyjxvmvfwy8skvvvea6dnkl8l9zpjf3m27qsav9y9nlj59hagmjf5xh0xxyqr8lymnmtjn6gzgrn04dr5s0k9k9wuxc2udzjh4llv47zm6jn6ff0j65s54h3m6p0n9ajswrqzpvy8eh4d5pvypyc6rp5m07uwmjp4sr0upca5hl7gr4pxg45m7vlnx5r7va4n6mfyr98twvjrhcyalwhddelnnjrkhcj0wcp5eyas2c2kcadrxyzw28vvv47q74";
    pub(crate) const UNIFIED_ADDR_2: &str = "u13j3q8q8f9hx2nx0w9l52dqksy4png7fgm0lqjh8ahn9enyvz5z9xnwzdcdjmpf756s2y88rnyr9px4f4k9w03sl6fr4vwsqcvg8ggfjx";

    // A pool of distinct, valid recipient addresses spanning the transparent, Sapling, and
    // unified (Orchard) protocols.
    pub(crate) const ADDR_POOL: &[&str] = &[
        T_ADDR_1,
        T_ADDR_2,
        SAPLING_ADDR,
        UNIFIED_ADDR_1,
        UNIFIED_ADDR_2,
    ];

    /// Constructs an [`AmountParameter`] paying `zec` (a decimal ZEC string) to `address`.
    pub(crate) fn amount(address: &str, zec: &str) -> AmountParameter {
        serde_json::from_value(json!({ "address": address, "amount": zec }))
            .expect("valid AmountParameter")
    }

    /// Constructs an [`AmountParameter`] paying `zec` to `address` carrying a hex `memo`.
    pub(crate) fn amount_with_memo(address: &str, zec: &str, memo: &str) -> AmountParameter {
        serde_json::from_value(json!({ "address": address, "amount": zec, "memo": memo }))
            .expect("valid AmountParameter")
    }
}

#[cfg(test)]
mod transparent_output_tests {
    use std::convert::Infallible;

    use proptest::prelude::*;
    use transparent::{
        address::TransparentAddress,
        keys::{AccountPubKey, NonHardenedChildIndex, TransparentKeyScope},
    };
    use zcash_client_backend::wallet::TransparentAddressSource;
    use zcash_keys::keys::UnifiedSpendingKey;
    use zcash_protocol::{
        consensus,
        value::{MAX_MONEY, Zatoshis},
    };
    use zip32::AccountId;

    use super::{TransparentOutputError, check_transparent_outputs};

    /// The account-level transparent public key derived from `seed` and `account`; the
    /// trusted key the checks under test re-derive against. No wallet database: the check
    /// is a pure function of the outputs, the expected payments, this key, and the
    /// (untrusted) derivation records fed to it, which is what makes it unit-testable
    /// here rather than in `integration-tests`.
    ///
    /// Returns `None` for the seeds ZIP 32 rejects, so a property can skip them.
    fn account_pubkey_from(seed: &[u8; 32], account: u32) -> Option<AccountPubKey> {
        let account = AccountId::try_from(account).ok()?;
        let usk =
            UnifiedSpendingKey::from_seed(&consensus::Network::TestNetwork, seed, account).ok()?;
        usk.to_unified_full_viewing_key().transparent().cloned()
    }

    /// The address the wallet would legitimately place at (`scope`, `index`) under `key`.
    fn derived_addr(
        key: &AccountPubKey,
        scope: TransparentKeyScope,
        index: NonHardenedChildIndex,
    ) -> Option<TransparentAddress> {
        key.derive_address_pubkey(scope, index)
            .ok()
            .map(|pk| TransparentAddress::from_pubkey(&pk))
    }

    /// A derivation-record lookup that claims every address lives at (`scope`, `index`).
    /// The record is untrusted input to the check, so a property may claim whatever an
    /// attacker could write.
    fn claims(
        scope: TransparentKeyScope,
        index: NonHardenedChildIndex,
    ) -> impl FnMut(&TransparentAddress) -> Result<Option<TransparentAddressSource>, Infallible>
    {
        move |_| {
            Ok(Some(TransparentAddressSource::Derived {
                scope,
                address_index: index,
            }))
        }
    }

    /// A derivation-record lookup with no record for any address.
    fn no_record(_: &TransparentAddress) -> Result<Option<TransparentAddressSource>, Infallible> {
        Ok(None)
    }

    /// ZIP 32 account indices are non-hardened, so they occupy the low 31 bits.
    fn arb_account() -> impl Strategy<Value = u32> {
        0u32..(1 << 31)
    }

    /// Every scope the wallet derives transparent addresses under, including the
    /// ephemeral (ZIP 320) scope.
    fn arb_scope() -> impl Strategy<Value = TransparentKeyScope> {
        prop_oneof![
            Just(TransparentKeyScope::EXTERNAL),
            Just(TransparentKeyScope::INTERNAL),
            Just(TransparentKeyScope::EPHEMERAL),
        ]
    }

    fn arb_index() -> impl Strategy<Value = NonHardenedChildIndex> {
        (0u32..(1 << 31)).prop_map(NonHardenedChildIndex::const_from_index)
    }

    fn arb_value() -> impl Strategy<Value = Zatoshis> {
        (0u64..=MAX_MONEY).prop_map(Zatoshis::const_from_u64)
    }

    proptest! {
        // Each case derives key material, which is expensive, so take fewer samples than
        // the default 256. The properties hold for every key, not for rare corners of the
        // seed space, so a modest sample establishes them.
        #![proptest_config(ProptestConfig::with_cases(32))]

        /// An output whose recorded (scope, index) re-derives to its own address is the
        /// wallet's, whatever the scope: internal change, an ephemeral (ZIP 320) output,
        /// or an external receiver.
        #[test]
        fn derived_output_accepted_at_its_recorded_path(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
            scope in arb_scope(),
            index in arb_index(),
            value in arb_value(),
        ) {
            let Some(key) = account_pubkey_from(&seed, account) else { return Ok(()) };
            let Some(addr) = derived_addr(&key, scope, index) else { return Ok(()) };

            prop_assert_eq!(
                check_transparent_outputs(
                    [(Some(addr), value)],
                    vec![],
                    Some(&key),
                    claims(scope, index),
                ),
                Ok(()),
            );
        }

        /// The attack this check exists for: a change or ephemeral output substituted
        /// with an address under someone else's key is rejected, even though its
        /// derivation record is internally consistent.
        #[test]
        fn substituted_output_address_rejected(
            wallet_seed in any::<[u8; 32]>(),
            attacker_seed in any::<[u8; 32]>(),
            account in arb_account(),
            scope in arb_scope(),
            index in arb_index(),
            value in arb_value(),
        ) {
            prop_assume!(wallet_seed != attacker_seed);
            let Some(wallet_key) = account_pubkey_from(&wallet_seed, account) else {
                return Ok(());
            };
            let Some(attacker_key) = account_pubkey_from(&attacker_seed, account) else {
                return Ok(());
            };
            let Some(attacker_addr) = derived_addr(&attacker_key, scope, index) else {
                return Ok(());
            };

            prop_assert_eq!(
                check_transparent_outputs(
                    [(Some(attacker_addr), value)],
                    vec![],
                    Some(&wallet_key),
                    claims(scope, index),
                ),
                Err(TransparentOutputError::DerivationMismatch(attacker_addr)),
            );
        }

        /// A record claiming a different index than the one the address was derived at is
        /// rejected: the check trusts the re-derivation equality, not the record.
        #[test]
        fn record_claiming_wrong_index_rejected(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
            scope in arb_scope(),
            index in arb_index(),
            other_index in arb_index(),
            value in arb_value(),
        ) {
            prop_assume!(index != other_index);
            let Some(key) = account_pubkey_from(&seed, account) else { return Ok(()) };
            let Some(addr) = derived_addr(&key, scope, index) else { return Ok(()) };
            let Some(other_addr) = derived_addr(&key, scope, other_index) else {
                return Ok(());
            };
            prop_assume!(addr != other_addr);

            prop_assert_eq!(
                check_transparent_outputs(
                    [(Some(addr), value)],
                    vec![],
                    Some(&key),
                    claims(scope, other_index),
                ),
                Err(TransparentOutputError::DerivationMismatch(addr)),
            );
        }

        /// An output exactly matching a requested payment is accepted without consulting
        /// any derivation record, and each payment vouches for exactly one output: a
        /// duplicate of the same output does not ride along.
        #[test]
        fn requested_payment_accepted_exactly_once(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
            scope in arb_scope(),
            index in arb_index(),
            value in arb_value(),
        ) {
            let Some(key) = account_pubkey_from(&seed, account) else { return Ok(()) };
            // Any address serves as a recipient; one not under the wallet's key is the
            // interesting case.
            let Some(addr) = derived_addr(&key, scope, index) else { return Ok(()) };

            prop_assert_eq!(
                check_transparent_outputs(
                    [(Some(addr), value)],
                    vec![(addr, value)],
                    None,
                    no_record,
                ),
                Ok(()),
            );

            prop_assert_eq!(
                check_transparent_outputs(
                    [(Some(addr), value), (Some(addr), value)],
                    vec![(addr, value)],
                    None,
                    no_record,
                ),
                Err(TransparentOutputError::UnknownAddress(addr)),
            );
        }

        /// An output with no derivation record at all is rejected, as is an output
        /// paying a requested recipient a different amount than requested.
        #[test]
        fn unrecorded_output_rejected(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
            scope in arb_scope(),
            index in arb_index(),
            value in arb_value(),
            other_value in arb_value(),
        ) {
            let Some(key) = account_pubkey_from(&seed, account) else { return Ok(()) };
            let Some(addr) = derived_addr(&key, scope, index) else { return Ok(()) };

            prop_assert_eq!(
                check_transparent_outputs([(Some(addr), value)], vec![], Some(&key), no_record),
                Err(TransparentOutputError::UnknownAddress(addr)),
            );

            prop_assume!(value != other_value);
            prop_assert!(
                check_transparent_outputs(
                    [(Some(addr), other_value)],
                    vec![(addr, value)],
                    Some(&key),
                    no_record,
                )
                .is_err(),
            );
        }

        /// A transaction missing a requested payment output is rejected.
        #[test]
        fn missing_requested_payment_rejected(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
            scope in arb_scope(),
            index in arb_index(),
            value in arb_value(),
        ) {
            let Some(key) = account_pubkey_from(&seed, account) else { return Ok(()) };
            let Some(addr) = derived_addr(&key, scope, index) else { return Ok(()) };

            prop_assert_eq!(
                check_transparent_outputs::<Infallible>(
                    [],
                    vec![(addr, value)],
                    Some(&key),
                    no_record,
                ),
                Err(TransparentOutputError::MissingPayment(addr)),
            );
        }

        /// A derived record cannot vouch for anything when the account has no
        /// transparent key component to re-derive from.
        #[test]
        fn output_without_transparent_key_rejected(
            seed in any::<[u8; 32]>(),
            account in arb_account(),
            scope in arb_scope(),
            index in arb_index(),
            value in arb_value(),
        ) {
            let Some(key) = account_pubkey_from(&seed, account) else { return Ok(()) };
            let Some(addr) = derived_addr(&key, scope, index) else { return Ok(()) };

            prop_assert_eq!(
                check_transparent_outputs(
                    [(Some(addr), value)],
                    vec![],
                    None,
                    claims(scope, index),
                ),
                Err(TransparentOutputError::NoTransparentKey(addr)),
            );
        }
    }

    /// An output whose script has no transparent address form cannot be verified.
    #[test]
    fn unrecognized_script_rejected() {
        assert_eq!(
            check_transparent_outputs::<Infallible>(
                [(None, Zatoshis::ZERO)],
                vec![],
                None,
                no_record,
            ),
            Err(TransparentOutputError::UnrecognizedScript { vout: 0 }),
        );
    }
}

#[cfg(test)]
mod build_request_tests {
    use std::collections::HashSet;

    use proptest::prelude::*;

    use zcash_protocol::consensus;

    use super::arb::*;
    use super::*;
    use crate::components::json_rpc::utils::zec_str;

    /// The network the shared [`arb`] addresses are encoded for, and so the one a request
    /// carrying them has to be built against.
    fn params() -> Network {
        Network::Consensus(consensus::Network::MainNetwork)
    }

    fn err_message(amounts: &[AmountParameter]) -> String {
        build_request(&params(), amounts)
            .expect_err("build_request should fail")
            .message()
            .to_string()
    }

    #[test]
    fn rejects_empty_array() {
        assert_eq!(
            err_message(&[]),
            "Invalid parameter, amounts array is empty.",
        );
    }

    #[test]
    fn builds_single_recipient() {
        let request = build_request(&params(), &[amount(T_ADDR_1, "0.1")]).expect("valid request");
        assert_eq!(request.payments().len(), 1);
    }

    #[test]
    fn builds_multiple_distinct_recipients() {
        let request = build_request(
            &params(),
            &[amount(T_ADDR_1, "0.1"), amount(T_ADDR_2, "0.2")],
        )
        .expect("valid request");
        assert_eq!(request.payments().len(), 2);
    }

    #[test]
    fn rejects_duplicate_recipient() {
        let msg = err_message(&[amount(T_ADDR_1, "0.1"), amount(T_ADDR_1, "0.2")]);
        assert_eq!(
            msg,
            format!("Invalid parameter, duplicated recipient address: {T_ADDR_1}"),
        );
    }

    #[test]
    fn rejects_unknown_address_format() {
        let msg = err_message(&[amount("not-an-address", "0.1")]);
        assert_eq!(
            msg,
            "Invalid parameter, unknown address format: not-an-address",
        );
    }

    /// An address that parses but belongs to another network is rejected here too.
    ///
    /// This is what lets everything downstream treat a request's recipients as decodable;
    /// [`check_recipients_against_privacy_policy`] relies on it rather than carrying an
    /// error case of its own for something this function has already ruled out.
    #[test]
    fn rejects_address_from_another_network() {
        let testnet = Network::Consensus(consensus::Network::TestNetwork);

        let err = build_request(&testnet, &[amount(T_ADDR_1, "0.1")])
            .expect_err("a mainnet address is not valid on testnet");

        assert!(
            err.message()
                .starts_with("Invalid parameter, address not valid on this network:"),
            "unexpected message: {}",
            err.message(),
        );
    }

    #[test]
    fn rejects_memo_to_transparent_recipient() {
        // The memo is valid hex (so memo parsing succeeds), but transparent recipients
        // cannot carry a memo.
        let msg = err_message(&[amount_with_memo(T_ADDR_1, "0.1", "00")]);
        assert_eq!(msg, "Cannot send memo to transparent recipient");
    }

    #[test]
    fn builds_batch_across_all_protocols_at_once() {
        // An exchange paying out to recipients on different protocols (transparent, Sapling,
        // and two unified/Orchard) in a single transaction.
        let request = build_request(
            &params(),
            &[
                amount(T_ADDR_1, "0.1"),
                amount(SAPLING_ADDR, "0.2"),
                amount(UNIFIED_ADDR_1, "0.3"),
                amount(UNIFIED_ADDR_2, "0.4"),
            ],
        )
        .expect("a mixed-protocol batch should build a request");
        assert_eq!(request.payments().len(), 4);
    }

    proptest! {
        /// For any non-empty list of recipients drawn from the address pool, `build_request`
        /// succeeds with one payment per recipient exactly when all addresses are distinct,
        /// and otherwise rejects the request as a duplicate.
        #[test]
        fn dedups_iff_all_recipients_distinct(
            indices in prop::collection::vec(0..ADDR_POOL.len(), 1..8),
        ) {
            let amounts = indices
                .iter()
                .map(|&i| amount(ADDR_POOL[i], "0.1"))
                .collect::<Vec<_>>();

            let unique = indices.iter().collect::<HashSet<_>>().len();
            let result = build_request(&params(), &amounts);

            if unique == indices.len() {
                let request = result.expect("distinct recipients should build a request");
                prop_assert_eq!(request.payments().len(), indices.len());
            } else {
                let err = result.expect_err("duplicate recipients should be rejected");
                prop_assert!(err.message().contains("duplicated recipient address"));
            }
        }

        /// An exchange-style batch withdrawal: any set of distinct recipients drawn from the
        /// mixed-protocol pool, each with its own amount, builds a request with exactly that
        /// many payments. Exercises N recipients spanning the transparent, Sapling, and
        /// unified (Orchard) protocols simultaneously.
        #[test]
        fn builds_distinct_mixed_protocol_batches(
            pool_indices in prop::sample::subsequence(
                (0..ADDR_POOL.len()).collect::<Vec<_>>(),
                1..=ADDR_POOL.len(),
            ),
            zatoshis in prop::collection::vec(1u64..=1_000_000_000, ADDR_POOL.len()),
        ) {
            let amounts = pool_indices
                .iter()
                .enumerate()
                .map(|(i, &pool_idx)| amount(ADDR_POOL[pool_idx], &zec_str(zatoshis[i])))
                .collect::<Vec<_>>();

            let request = build_request(&params(), &amounts)
                .expect("a batch of distinct mixed-protocol recipients should build a request");
            prop_assert_eq!(request.payments().len(), pool_indices.len());
        }
    }
}

#[cfg(test)]
mod privacy_policy_tests {
    use proptest::prelude::*;

    use super::*;

    const ALL_POLICIES: &[PrivacyPolicy] = &[
        PrivacyPolicy::FullPrivacy,
        PrivacyPolicy::AllowRevealedAmounts,
        PrivacyPolicy::AllowRevealedRecipients,
        PrivacyPolicy::AllowRevealedSenders,
        PrivacyPolicy::AllowFullyTransparent,
        PrivacyPolicy::AllowLinkingAccountAddresses,
        PrivacyPolicy::NoPrivacy,
    ];

    #[test]
    fn parse_privacy_policy_defaults_to_full_privacy_when_absent() {
        assert_eq!(
            parse_privacy_policy(None).unwrap(),
            PrivacyPolicy::FullPrivacy,
        );
    }

    #[test]
    fn parse_privacy_policy_accepts_every_known_policy() {
        // Every policy round-trips through its string name.
        for &policy in ALL_POLICIES {
            let name: &'static str = policy.into();
            assert_eq!(parse_privacy_policy(Some(name)).unwrap(), policy);
        }
    }

    #[test]
    fn parse_privacy_policy_rejects_legacy_compat() {
        // These messages are localized, so the loader must be populated before
        // asserting on them; `fl!` is inert until a language is loaded.
        crate::i18n::load_languages(&[]);

        let err = parse_privacy_policy(Some("LegacyCompat"))
            .expect_err("LegacyCompat should be rejected");
        assert_eq!(
            err.message(),
            "LegacyCompat privacy policy is unsupported in Zallet",
        );
    }

    #[test]
    fn parse_privacy_policy_rejects_unknown_policy() {
        crate::i18n::load_languages(&[]);

        let err =
            parse_privacy_policy(Some("Whatever")).expect_err("unknown policy should be rejected");
        assert_eq!(err.message(), "Unknown privacy policy Whatever");
    }

    #[test]
    fn meet_with_full_privacy_is_identity() {
        // `FullPrivacy` is the lattice top: meeting it with any policy yields that policy.
        for &policy in ALL_POLICIES {
            assert_eq!(PrivacyPolicy::FullPrivacy.meet(policy), policy);
            assert_eq!(policy.meet(PrivacyPolicy::FullPrivacy), policy);
        }
    }

    #[test]
    fn meet_with_no_privacy_is_no_privacy() {
        // `NoPrivacy` is the lattice bottom: meeting it with any policy yields `NoPrivacy`.
        for &policy in ALL_POLICIES {
            assert_eq!(
                PrivacyPolicy::NoPrivacy.meet(policy),
                PrivacyPolicy::NoPrivacy,
            );
            assert_eq!(
                policy.meet(PrivacyPolicy::NoPrivacy),
                PrivacyPolicy::NoPrivacy,
            );
        }
    }

    #[test]
    fn meet_is_commutative() {
        for &a in ALL_POLICIES {
            for &b in ALL_POLICIES {
                assert_eq!(
                    a.meet(b),
                    b.meet(a),
                    "meet should be commutative: {a} vs {b}"
                );
            }
        }
    }

    #[test]
    fn meet_combines_transparent_sender_and_recipient() {
        // Revealing both senders and recipients requires the fully-transparent policy.
        assert_eq!(
            PrivacyPolicy::AllowRevealedSenders.meet(PrivacyPolicy::AllowRevealedRecipients),
            PrivacyPolicy::AllowFullyTransparent,
        );
    }

    #[test]
    fn a_policy_is_compatible_with_itself_and_stricter_ones() {
        // A caller-supplied policy must permit everything a required policy needs. Any policy
        // satisfies `FullPrivacy`, and `NoPrivacy` satisfies any required policy.
        for &policy in ALL_POLICIES {
            assert!(policy.is_compatible_with(PrivacyPolicy::FullPrivacy));
            assert!(PrivacyPolicy::NoPrivacy.is_compatible_with(policy));
        }
    }

    /// A proptest strategy yielding an arbitrary [`PrivacyPolicy`].
    fn arb_policy() -> impl Strategy<Value = PrivacyPolicy> {
        prop::sample::select(ALL_POLICIES.to_vec())
    }

    proptest! {
        /// `meet` is the greatest-lower-bound of a lattice, so it must be idempotent,
        /// commutative, and associative. `required_privacy_policy` folds proposal steps with
        /// `meet`, so these algebraic laws are what make that fold well-defined.
        #[test]
        fn meet_is_idempotent(a in arb_policy()) {
            prop_assert_eq!(a.meet(a), a);
        }

        #[test]
        fn meet_is_commutative_prop(a in arb_policy(), b in arb_policy()) {
            prop_assert_eq!(a.meet(b), b.meet(a));
        }

        #[test]
        fn meet_is_associative(a in arb_policy(), b in arb_policy(), c in arb_policy()) {
            prop_assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)));
        }

        /// Any string that is neither a known policy name nor the rejected `"LegacyCompat"`
        /// is reported as an unknown policy.
        #[test]
        fn parse_privacy_policy_rejects_arbitrary_unknown_strings(s in "[A-Za-z]{0,24}") {
            crate::i18n::load_languages(&[]);

            prop_assume!(PrivacyPolicy::from_str(&s).is_none() && s != "LegacyCompat");
            let err = parse_privacy_policy(Some(&s))
                .expect_err("an unknown policy name should be rejected");
            let expected = format!("Unknown privacy policy {s}");
            prop_assert_eq!(err.message(), expected);
        }
    }
}

#[cfg(test)]
mod recipient_preflight_tests {
    //! Tests for [`check_recipients_against_privacy_policy`], [`orchard_receiver_pool`] and
    //! [`spendable_in`]: the pre-flight that rejects a request whose recipients cannot be
    //! paid within the caller's privacy policy.
    //!
    //! All three are pure functions of the request, the policy, the target height, and the
    //! account's balances, so neither a wallet database nor a chain is needed here. Whether
    //! the balance and height handed to the check are the wallet's real ones is
    //! `propose_and_check`'s job, and is covered in `integration-tests`.

    use proptest::prelude::*;
    use zcash_keys::keys::{ReceiverRequirement, UnifiedAddressRequest, UnifiedSpendingKey};
    use zcash_protocol::{
        consensus,
        value::{BalanceError, COIN, MAX_MONEY},
    };
    use zip32::AccountId;

    use super::arb::{T_ADDR_1, amount};
    use super::*;

    /// A raw zatoshi amount, for terse fixtures.
    ///
    /// This is `zcash_protocol::value::testing::zats` verbatim, inlined only because that
    /// module cannot be enabled here: every `test-dependencies` feature in librustzcash at
    /// the pinned revision constrains `proptest` to `<1.7`, and this workspace is on 1.11,
    /// so turning any of them on fails resolution outright. Everything else in this module
    /// composes the crates' ordinary public constructors.
    const fn zats(amount: u64) -> Zatoshis {
        Zatoshis::const_from_u64(amount)
    }

    /// The network every address here is encoded for, and that the check runs against.
    ///
    /// Which network is irrelevant to the code under test; the two must simply agree, or
    /// address decoding fails before the policy is ever consulted. Mainnet, so that the
    /// shared [`arb`] address constants can be used alongside the addresses derived here,
    /// and because it has a scheduled NU6.3 activation to place heights either side of.
    const CONSENSUS_NETWORK: consensus::Network = consensus::Network::MainNetwork;

    fn params() -> Network {
        Network::Consensus(CONSENSUS_NETWORK)
    }

    /// The first height at which a payment to an Orchard receiver is built in the Ironwood
    /// pool.
    ///
    /// Read from the network rather than written out, so these tests follow the activation
    /// rather than pinning a second copy of it.
    fn from_ironwood() -> BlockHeight {
        params()
            .activation_height(NetworkUpgrade::Nu6_3)
            .expect("NU6.3 has a scheduled activation height on mainnet")
    }

    /// The last height at which a payment to an Orchard receiver is built in the Orchard
    /// pool.
    fn before_ironwood() -> BlockHeight {
        from_ironwood() - 1
    }

    /// Every payment in these tests is one ZEC, so a pool's funding can be stated in whole
    /// ZEC and read directly against it.
    const PAYMENT_ZEC: &str = "1";
    const PAYMENT: u64 = COIN;

    /// Far more than any payment here, for the cases that are about the policy rather than
    /// the funds. Half the money supply, so that two pools can hold it at once without
    /// breaching the cap [`AccountBalance`] enforces across all of them.
    const AMPLE: u64 = MAX_MONEY / 2;

    /// The same, for a case that funds all three shielded pools at once.
    const AMPLE_EACH: u64 = MAX_MONEY / 3;

    /// A unified address carrying only an Orchard receiver.
    const ORCHARD_ONLY: UnifiedAddressRequest = UnifiedAddressRequest::ORCHARD;

    /// A unified address carrying only a Sapling receiver.
    ///
    /// `unsafe_custom` is sound here: the request names a shielded receiver, which is the
    /// invariant its checked counterpart exists to enforce.
    const SAPLING_ONLY: UnifiedAddressRequest = UnifiedAddressRequest::unsafe_custom(
        ReceiverRequirement::Omit,
        ReceiverRequirement::Require,
        ReceiverRequirement::Omit,
    );

    /// A unified address carrying both shielded receivers, so either pool can pay it.
    ///
    /// `Require` rather than [`UnifiedAddressRequest::SHIELDED`], which is `Allow` and so
    /// only promises *at least one* of them — not enough for a test whose whole point is
    /// that the check may choose between two pools.
    ///
    /// ZIP 316 forbids a unified address with no shielded receiver, so there is no way to
    /// build one without — which is why [`IncompatiblePrivacyPolicy::TransparentReceiver`],
    /// reachable only for such an address, has no test below.
    const BOTH_SHIELDED: UnifiedAddressRequest = UnifiedAddressRequest::unsafe_custom(
        ReceiverRequirement::Require,
        ReceiverRequirement::Require,
        ReceiverRequirement::Omit,
    );

    /// The seed the fixed recipient addresses are derived from.
    const SEED: [u8; 32] = [0x2a; 32];

    /// The unified full viewing key a recipient address is derived from.
    ///
    /// Which key an address belongs to is irrelevant to a check that never looks at the
    /// wallet — only the receivers it carries matter — so the fixed cases below pass [`SEED`]
    /// and stay deterministic, while the properties vary the seed.
    ///
    /// Returns `None` for the seeds ZIP 32 rejects, so a property can skip them rather than
    /// assert on a key that cannot exist.
    ///
    /// `zcash_keys` ships `arb_unified_addr` for exactly this, but its `test-dependencies`
    /// feature is unusable here (see `Cargo.toml`), so this composes the crate's ordinary
    /// public constructors instead.
    fn ufvk(seed: &[u8; 32]) -> Option<UnifiedFullViewingKey> {
        UnifiedSpendingKey::from_seed(&CONSENSUS_NETWORK, seed, AccountId::ZERO)
            .ok()
            .map(|usk| usk.to_unified_full_viewing_key())
    }

    /// A unified address carrying exactly `request`'s receivers, from the fixed seed.
    fn ua(request: UnifiedAddressRequest) -> String {
        ua_from(&SEED, request).expect("the fixed seed yields a key with the requested receivers")
    }

    /// A unified address carrying exactly `request`'s receivers, from an arbitrary seed.
    fn ua_from(seed: &[u8; 32], request: UnifiedAddressRequest) -> Option<String> {
        let (addr, _) = ufvk(seed)?.default_address(request).ok()?;
        Some(addr.encode(&CONSENSUS_NETWORK))
    }

    /// A bare Sapling address, which names one pool and so cannot be paid from another
    /// without revealing the crossing amount.
    fn sapling_addr(seed: &[u8; 32]) -> String {
        sapling_addr_from(seed).expect("the fixed seeds yield a key with a Sapling receiver")
    }

    /// A bare Sapling address from an arbitrary seed.
    fn sapling_addr_from(seed: &[u8; 32]) -> Option<String> {
        let (_, addr) = ufvk(seed)?.sapling()?.default_address();
        Some(Address::from(addr).encode(&CONSENSUS_NETWORK))
    }

    /// An account balance with the given spendable values, in zatoshis.
    ///
    /// [`AccountBalance`] caps the sum across every pool at `MAX_MONEY`, so this surfaces a
    /// [`BalanceError`] rather than swallowing it: a fixture that breaches the cap is a
    /// broken fixture, and should say so rather than silently drop a pool's funding.
    fn account_balance(sapling: u64, orchard: u64, ironwood: u64) -> AccountBalance {
        let mut balance = AccountBalance::ZERO;
        balance
            .with_sapling_balance_mut::<_, BalanceError>(|b| b.add_spendable_value(zats(sapling)))
            .expect("the fixture's balances are within MAX_MONEY");
        balance
            .with_orchard_balance_mut::<_, BalanceError>(|b| b.add_spendable_value(zats(orchard)))
            .expect("the fixture's balances are within MAX_MONEY");
        balance
            .with_ironwood_balance_mut::<_, BalanceError>(|b| b.add_spendable_value(zats(ironwood)))
            .expect("the fixture's balances are within MAX_MONEY");
        balance
    }

    /// Runs the check over payments of `(address, ZEC amount)`.
    fn check(
        recipients: &[(&str, &str)],
        privacy_policy: PrivacyPolicy,
        target_height: BlockHeight,
        balance: &AccountBalance,
    ) -> Result<(), IncompatiblePrivacyPolicy> {
        let amounts = recipients
            .iter()
            .map(|(addr, zec)| amount(addr, zec))
            .collect::<Vec<_>>();
        let request =
            build_request(&params(), &amounts).expect("the recipients form a valid request");
        check_recipients_against_privacy_policy(
            &params(),
            target_height,
            &request,
            privacy_policy,
            balance,
        )
    }

    /// Asserts that the check rejected the request for the given reason.
    #[track_caller]
    fn assert_rejects(
        result: Result<(), IncompatiblePrivacyPolicy>,
        expected: IncompatiblePrivacyPolicy,
    ) {
        assert_eq!(
            result.expect_err("the request should be rejected"),
            expected
        );
    }

    /// Before NU6.3, a payment to an Orchard receiver is built in the Orchard pool.
    #[test]
    fn orchard_receiver_pool_is_orchard_before_nu6_3() {
        assert_eq!(
            orchard_receiver_pool(&params(), before_ironwood()),
            ShieldedPool::Orchard,
        );
    }

    /// From NU6.3 onwards it is built in the Ironwood pool instead, starting at the
    /// activation height itself.
    #[test]
    fn orchard_receiver_pool_is_ironwood_from_nu6_3() {
        for height in [from_ironwood(), from_ironwood() + 1] {
            assert_eq!(
                orchard_receiver_pool(&params(), height),
                ShieldedPool::Ironwood,
            );
        }
    }

    /// Each pool's spendable value is read from that pool, and no other.
    #[test]
    fn spendable_in_reads_each_pool_separately() {
        let balance = account_balance(1, 2, 3);

        assert_eq!(spendable_in(&balance, ShieldedPool::Sapling), zats(1));
        assert_eq!(spendable_in(&balance, ShieldedPool::Orchard), zats(2));
        assert_eq!(spendable_in(&balance, ShieldedPool::Ironwood), zats(3));
    }

    /// The defect this module exists for: a Sapling recipient the Sapling pool cannot cover
    /// can only be paid by crossing into it from another pool, which reveals the crossing
    /// amount. Before the pre-flight had the account's real balances it could not see this,
    /// and left the conflict to be reported after input selection had already run.
    #[test]
    fn underfunded_sapling_recipient_is_rejected_under_full_privacy() {
        let addr = sapling_addr(&SEED);

        assert_rejects(
            check(
                &[(&addr, PAYMENT_ZEC)],
                PrivacyPolicy::FullPrivacy,
                before_ironwood(),
                &account_balance(PAYMENT - 1, AMPLE, 0),
            ),
            IncompatiblePrivacyPolicy::RevealingShieldedAmount(ShieldedPool::Sapling),
        );
    }

    /// The same payment is accepted once the Sapling pool can cover it on its own.
    #[test]
    fn funded_sapling_recipient_is_accepted_under_full_privacy() {
        let addr = sapling_addr(&SEED);

        check(
            &[(&addr, PAYMENT_ZEC)],
            PrivacyPolicy::FullPrivacy,
            before_ironwood(),
            &account_balance(PAYMENT, 0, 0),
        )
        .expect("a payment the Sapling pool covers reveals nothing");
    }

    /// A unified address can be paid into either of its shielded receivers, so it is
    /// rejected only when *neither* pool covers the payment alone.
    #[test]
    fn unified_recipient_is_rejected_when_no_single_pool_covers_it() {
        let addr = ua(BOTH_SHIELDED);

        assert_rejects(
            check(
                &[(&addr, PAYMENT_ZEC)],
                PrivacyPolicy::FullPrivacy,
                before_ironwood(),
                // Together the pools hold more than enough; neither does alone, so paying
                // this address has to cross between them.
                &account_balance(PAYMENT - 1, PAYMENT - 1, 0),
            ),
            IncompatiblePrivacyPolicy::RevealingReceiverAmounts,
        );
    }

    /// Either shielded pool covering the payment on its own is enough, whichever receiver
    /// the address carries.
    #[test]
    fn unified_recipient_is_accepted_when_one_pool_covers_it() {
        for (request, sapling, orchard) in [
            (BOTH_SHIELDED, PAYMENT, 0),
            (BOTH_SHIELDED, 0, PAYMENT),
            (ORCHARD_ONLY, 0, PAYMENT),
            (SAPLING_ONLY, PAYMENT, 0),
        ] {
            let addr = ua(request);

            check(
                &[(&addr, PAYMENT_ZEC)],
                PrivacyPolicy::FullPrivacy,
                before_ironwood(),
                &account_balance(sapling, orchard, 0),
            )
            .expect("a pool that covers the payment alone reveals nothing");
        }
    }

    /// Before NU6.3 an Orchard receiver is paid out of the Orchard pool, so Orchard funds
    /// cover it without crossing.
    #[test]
    fn orchard_funds_pay_an_orchard_receiver_before_nu6_3() {
        let addr = ua(ORCHARD_ONLY);

        check(
            &[(&addr, PAYMENT_ZEC)],
            PrivacyPolicy::FullPrivacy,
            before_ironwood(),
            &account_balance(0, PAYMENT, 0),
        )
        .expect("Orchard funds pay an Orchard receiver in the Orchard era");
    }

    /// The regression this change fixes.
    ///
    /// From NU6.3 the Orchard turnstile is one-way, so a payment to an Orchard receiver is
    /// built in the Ironwood pool: Orchard funds can reach it only by crossing, which
    /// reveals the amount. Counting Orchard towards the Orchard receiver — as folding the
    /// two pools into one balance does — accepts this send here, and leaves
    /// `enforce_privacy_policy` to reject it after input selection has already run, with a
    /// different error.
    #[test]
    fn orchard_funds_cannot_pay_an_orchard_receiver_from_nu6_3() {
        let addr = ua(ORCHARD_ONLY);

        assert_rejects(
            check(
                &[(&addr, PAYMENT_ZEC)],
                PrivacyPolicy::FullPrivacy,
                from_ironwood(),
                &account_balance(0, PAYMENT, 0),
            ),
            IncompatiblePrivacyPolicy::RevealingReceiverAmounts,
        );
    }

    /// The other side of the same rule: from NU6.3 it is the Ironwood balance that pays an
    /// Orchard receiver without crossing.
    #[test]
    fn ironwood_funds_pay_an_orchard_receiver_from_nu6_3() {
        let addr = ua(ORCHARD_ONLY);

        check(
            &[(&addr, PAYMENT_ZEC)],
            PrivacyPolicy::FullPrivacy,
            from_ironwood(),
            &account_balance(0, 0, PAYMENT),
        )
        .expect("Ironwood funds pay an Orchard receiver in the Ironwood era");
    }

    /// The routing is symmetric: before NU6.3 the payment is built in the Orchard pool, so
    /// Ironwood funds are the ones that would have to cross.
    #[test]
    fn ironwood_funds_cannot_pay_an_orchard_receiver_before_nu6_3() {
        let addr = ua(ORCHARD_ONLY);

        assert_rejects(
            check(
                &[(&addr, PAYMENT_ZEC)],
                PrivacyPolicy::FullPrivacy,
                before_ironwood(),
                &account_balance(0, 0, PAYMENT),
            ),
            IncompatiblePrivacyPolicy::RevealingReceiverAmounts,
        );
    }

    /// Orchard and Ironwood are separate value pools, so their balances are never added
    /// together: an account holding most of the payment in each still cannot pay an Orchard
    /// receiver without crossing, in either era.
    #[test]
    fn orchard_and_ironwood_balances_are_never_summed() {
        let addr = ua(ORCHARD_ONLY);

        for height in [before_ironwood(), from_ironwood()] {
            assert_rejects(
                check(
                    &[(&addr, PAYMENT_ZEC)],
                    PrivacyPolicy::FullPrivacy,
                    height,
                    &account_balance(0, PAYMENT - 1, PAYMENT - 1),
                ),
                IncompatiblePrivacyPolicy::RevealingReceiverAmounts,
            );
        }
    }

    /// A pool's balance is spent down across the payments that draw on it, so two payments
    /// the pool can each afford individually may still not both fit.
    #[test]
    fn availability_is_spent_down_across_payments() {
        let first = sapling_addr(&SEED);
        let second = sapling_addr(&[0x2b; 32]);
        assert_ne!(first, second, "the payments must have distinct recipients");

        // Enough for either payment, not for both.
        let balance = account_balance(2 * PAYMENT - 1, 0, 0);

        check(
            &[(&first, PAYMENT_ZEC)],
            PrivacyPolicy::FullPrivacy,
            before_ironwood(),
            &balance,
        )
        .expect("one payment fits");

        assert_rejects(
            check(
                &[(&first, PAYMENT_ZEC), (&second, PAYMENT_ZEC)],
                PrivacyPolicy::FullPrivacy,
                before_ironwood(),
                &balance,
            ),
            IncompatiblePrivacyPolicy::RevealingShieldedAmount(ShieldedPool::Sapling),
        );
    }

    /// Balances only decide whether a *crossing* is needed, so a policy that already permits
    /// revealed amounts accepts a shielded recipient however little the account holds — and
    /// whichever pool the recipient would be paid from.
    #[test]
    fn allowing_revealed_amounts_accepts_any_shielded_recipient() {
        let sapling = sapling_addr(&SEED);
        let unified = ua(BOTH_SHIELDED);
        let empty = AccountBalance::ZERO;

        for addr in [&sapling, &unified] {
            for height in [before_ironwood(), from_ironwood()] {
                check(
                    &[(addr, PAYMENT_ZEC)],
                    PrivacyPolicy::AllowRevealedAmounts,
                    height,
                    &empty,
                )
                .expect("revealing the crossing amount is permitted");
            }
        }
    }

    proptest! {
        // Each case derives a spending key, which is expensive, so take fewer samples than
        // the default 256.
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// A transparent recipient reveals its amount whether or not the account can afford
        /// it, so the decision rests on the policy alone. This is what keeps the check from
        /// coupling the transparent arm to pool balances.
        ///
        /// Quantified over the balances rather than over the policies: the claim is that the
        /// balances do not enter into it, and `allow_revealed_recipients` is the whole of
        /// what does. One policy either side of that predicate settles it — which of the
        /// policies fall on which side is [`PrivacyPolicy::is_compatible_with`]'s business,
        /// and is covered in `privacy_policy_tests`.
        #[test]
        fn transparent_recipients_do_not_consult_balances(
            sapling in 0u64..=AMPLE_EACH,
            orchard in 0u64..=AMPLE_EACH,
            ironwood in 0u64..=AMPLE_EACH,
        ) {
            let balance = account_balance(sapling, orchard, ironwood);

            for policy in [PrivacyPolicy::FullPrivacy, PrivacyPolicy::AllowRevealedRecipients] {
                let result = check(
                    &[(T_ADDR_1, PAYMENT_ZEC)],
                    policy,
                    before_ironwood(),
                    &balance,
                );
                if policy.allow_revealed_recipients() {
                    prop_assert!(result.is_ok(), "{policy:?} permits transparent recipients");
                } else {
                    prop_assert_eq!(
                        result.expect_err("a transparent recipient is rejected"),
                        IncompatiblePrivacyPolicy::TransparentRecipient,
                    );
                }
            }
        }

        /// An account holding ample funds in the pool a recipient is paid from never has to
        /// cross, so no shielded recipient is rejected.
        ///
        /// The pool that has to be funded is the point: before NU6.3 that is Orchard, and
        /// from NU6.3 it is Ironwood, so this fails if the routing is dropped.
        ///
        /// Asserted under `FullPrivacy` alone, which is the strongest form of the claim: it
        /// is the strictest policy, so every weaker one accepts whatever it accepts.
        #[test]
        fn ample_funds_in_the_paying_pool_accept_every_shielded_recipient(
            seed in prop::array::uniform32(any::<u8>()),
        ) {
            let Some(sapling) = sapling_addr_from(&seed) else { return Ok(()) };
            let Some(unified) = ua_from(&seed, BOTH_SHIELDED) else { return Ok(()) };

            for height in [before_ironwood(), from_ironwood()] {
                let balance = match orchard_receiver_pool(&params(), height) {
                    ShieldedPool::Sapling => account_balance(AMPLE, 0, 0),
                    ShieldedPool::Orchard => account_balance(AMPLE, AMPLE, 0),
                    ShieldedPool::Ironwood => account_balance(AMPLE, 0, AMPLE),
                };

                for addr in [&sapling, &unified] {
                    prop_assert!(
                        check(&[(addr, PAYMENT_ZEC)], PrivacyPolicy::FullPrivacy, height, &balance)
                            .is_ok(),
                        "{addr} was rejected under FullPrivacy at height {height:?}",
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod proposal_policy_tests {
    //! Tests for the pure proposal checks — [`enforce_privacy_policy`],
    //! [`required_privacy_policy`], and [`check_shielded_action_limits`] — over
    //! in-memory proposals built from dummy notes. Note contents beyond pool and value
    //! are irrelevant to the code under test, so fixed keys and randomness suffice.

    use std::collections::BTreeMap;

    use incrementalmerkletree::Position;
    use nonempty::NonEmpty;
    use zcash_client_backend::{
        data_api::wallet::{ConfirmationsPolicy, TargetHeight},
        fees::{ChangeValue, TransactionBalance},
        proposal::ShieldedInputs,
        wallet::{Note, ReceivedNote},
    };
    use zcash_protocol::consensus::BlockHeight;

    use super::*;

    /// The value of every dummy input note.
    const NOTE_VALUE: u64 = 20_000;

    /// Constructs a dummy note in the given shielded pool.
    fn note_in_pool(pool: ShieldedPool, value: u64) -> Note {
        match pool {
            ShieldedPool::Sapling => {
                let (_, recipient) =
                    sapling::zip32::ExtendedSpendingKey::master(&[0x2a; 32]).default_address();
                Note::Sapling(sapling::Note::from_parts(
                    recipient,
                    sapling::value::NoteValue::from_raw(value),
                    sapling::Rseed::AfterZip212([0x1b; 32]),
                ))
            }
            ShieldedPool::Orchard | ShieldedPool::Ironwood => {
                let sk: orchard::keys::SpendingKey =
                    Option::from(orchard::keys::SpendingKey::from_bytes([0x2a; 32]))
                        .expect("valid spending key");
                let recipient = orchard::keys::FullViewingKey::from(&sk)
                    .address_at(0u32, zip32::Scope::External);
                let rho =
                    Option::from(orchard::note::Rho::from_bytes(&[0; 32])).expect("valid rho");
                let rseed = Option::from(orchard::note::RandomSeed::from_bytes([0x1b; 32], &rho))
                    .expect("valid rseed");
                let (version, value_pool) = if pool == ShieldedPool::Ironwood {
                    (orchard::note::NoteVersion::V3, orchard::ValuePool::Ironwood)
                } else {
                    (orchard::note::NoteVersion::V2, orchard::ValuePool::Orchard)
                };
                Note::Orchard {
                    note: Option::from(orchard::note::Note::from_parts(
                        recipient,
                        orchard::value::NoteValue::from_raw(value),
                        rho,
                        rseed,
                        version,
                    ))
                    .expect("valid note"),
                    pool: value_pool,
                }
            }
        }
    }

    /// Wraps one dummy note of [`NOTE_VALUE`] per entry of `pools` as a step's shielded
    /// inputs.
    fn shielded_inputs_spending(pools: &[ShieldedPool]) -> ShieldedInputs<u32> {
        let notes = pools
            .iter()
            .enumerate()
            .map(|(i, pool)| {
                ReceivedNote::from_parts(
                    i as u32,
                    TxId::from_bytes([0; 32]),
                    i as u16,
                    note_in_pool(*pool, NOTE_VALUE),
                    zip32::Scope::External,
                    Position::from(i as u64),
                    Some(BlockHeight::from_u32(100)),
                    None,
                )
            })
            .collect::<Vec<_>>();
        ShieldedInputs::from_parts(NonEmpty::from_vec(notes).expect("at least one input pool"))
    }

    /// A single-step proposal spending one dummy note per entry of `input_pools`, paying
    /// `request` (whose payments are placed in `payment_pools`) and returning `change`;
    /// the input value not consumed by payments or change becomes the fee, keeping the
    /// step balanced.
    fn build_proposal(
        input_pools: &[ShieldedPool],
        request: TransactionRequest,
        payment_pools: BTreeMap<usize, PoolType>,
        change: Vec<ChangeValue>,
    ) -> Proposal<(), u32> {
        let input_total = NOTE_VALUE * input_pools.len() as u64;
        let payments_total = u64::from(
            request
                .total()
                .expect("no overflow")
                .expect("all payments carry amounts"),
        );
        let change_total = change.iter().map(|c| u64::from(c.value())).sum::<u64>();
        let fee = input_total
            .checked_sub(payments_total + change_total)
            .expect("inputs cover outputs");

        Proposal::single_step(
            request,
            payment_pools,
            vec![],
            Some(shielded_inputs_spending(input_pools)),
            BlockHeight::from_u32(100),
            TransactionBalance::new(change, Zatoshis::const_from_u64(fee)).expect("valid balance"),
            (),
            TargetHeight::from(BlockHeight::from_u32(101)),
            ConfirmationsPolicy::default(),
            false,
            false,
        )
        .expect("valid proposal")
    }

    /// A proposal with no payments: spends one dummy note per entry of `input_pools` and
    /// returns `change`.
    fn change_only_proposal(
        input_pools: &[ShieldedPool],
        change: Vec<ChangeValue>,
    ) -> Proposal<(), u32> {
        build_proposal(
            input_pools,
            TransactionRequest::empty(),
            BTreeMap::new(),
            change,
        )
    }

    fn change(pool: ShieldedPool, value: u64) -> ChangeValue {
        ChangeValue::shielded(pool, Zatoshis::const_from_u64(value), None)
    }

    /// A step that keeps value within a single shielded pool reveals nothing, whichever
    /// pool it is.
    #[test]
    fn same_pool_spend_satisfies_full_privacy() {
        for pool in all_shielded_pools() {
            let proposal = change_only_proposal(&[pool], vec![change(pool, 10_000)]);
            assert_eq!(
                enforce_privacy_policy(&proposal, PrivacyPolicy::FullPrivacy),
                Ok(()),
                "within {pool:?}",
            );
            assert_eq!(
                required_privacy_policy(&proposal),
                PrivacyPolicy::FullPrivacy,
                "within {pool:?}",
            );
        }
    }

    /// Moving value between two distinct shielded pools reveals the crossing amount in
    /// the transaction's public value balances, so `FullPrivacy` must reject it for
    /// every ordered pool pair — including the pairs involving Ironwood that a pairwise
    /// Sapling↔Orchard check would miss.
    #[test]
    fn crossing_into_any_other_pool_requires_revealed_amounts() {
        for from in all_shielded_pools() {
            for to in all_shielded_pools() {
                if from == to {
                    continue;
                }
                let proposal = change_only_proposal(&[from], vec![change(to, 10_000)]);
                assert_eq!(
                    enforce_privacy_policy(&proposal, PrivacyPolicy::FullPrivacy),
                    Err(IncompatiblePrivacyPolicy::RevealingShieldedAmount(to)),
                    "crossing {from:?} -> {to:?}",
                );
                assert_eq!(
                    enforce_privacy_policy(&proposal, PrivacyPolicy::AllowRevealedAmounts),
                    Ok(()),
                    "crossing {from:?} -> {to:?}",
                );
                assert_eq!(
                    required_privacy_policy(&proposal),
                    PrivacyPolicy::AllowRevealedAmounts,
                    "crossing {from:?} -> {to:?}",
                );
            }
        }
    }

    /// A payment (not just change) into a pool the inputs don't come from is likewise a
    /// crossing.
    #[test]
    fn payment_into_another_pool_requires_revealed_amounts() {
        let request = TransactionRequest::new(vec![
            Payment::new(
                arb::SAPLING_ADDR.parse::<ZcashAddress>().expect("valid"),
                Some(Zatoshis::const_from_u64(10_000)),
                None,
                None,
                None,
                vec![],
            )
            .expect("valid payment"),
        ])
        .expect("valid request");

        let proposal = build_proposal(
            &[ShieldedPool::Orchard],
            request,
            [(0, PoolType::SAPLING)].into_iter().collect(),
            vec![],
        );

        assert_eq!(
            enforce_privacy_policy(&proposal, PrivacyPolicy::FullPrivacy),
            Err(IncompatiblePrivacyPolicy::RevealingShieldedAmount(
                ShieldedPool::Sapling
            )),
        );
        assert_eq!(
            required_privacy_policy(&proposal),
            PrivacyPolicy::AllowRevealedAmounts,
        );
    }

    /// The transaction-size cap applies to every shielded pool's spends, not only
    /// Orchard's.
    #[test]
    fn action_limit_applies_to_spends_in_every_pool() {
        for pool in all_shielded_pools() {
            let proposal = change_only_proposal(&[pool; 3], vec![change(pool, 10_000)]);
            assert_eq!(
                check_shielded_action_limits(&proposal, 2),
                Err(ShieldedActionLimitExceeded {
                    pool,
                    count: 3,
                    kind: "inputs",
                }),
                "spends in {pool:?}",
            );
            assert_eq!(
                check_shielded_action_limits(&proposal, 3),
                Ok(()),
                "spends in {pool:?}",
            );
        }
    }

    /// Change outputs count against the same per-pool limit as spends.
    #[test]
    fn action_limit_applies_to_outputs_in_every_pool() {
        for pool in all_shielded_pools() {
            let proposal = change_only_proposal(&[pool; 2], vec![change(pool, 10_000); 3]);
            assert_eq!(
                check_shielded_action_limits(&proposal, 2),
                Err(ShieldedActionLimitExceeded {
                    pool,
                    count: 3,
                    kind: "outputs",
                }),
                "outputs in {pool:?}",
            );
        }
    }

    /// When both sides of a pool's bundle exceed the limit, the combined action count is
    /// reported.
    #[test]
    fn action_limit_reports_actions_when_both_sides_exceed() {
        for pool in all_shielded_pools() {
            let proposal = change_only_proposal(&[pool; 3], vec![change(pool, 10_000); 3]);
            assert_eq!(
                check_shielded_action_limits(&proposal, 2),
                Err(ShieldedActionLimitExceeded {
                    pool,
                    count: 3,
                    kind: "actions",
                }),
                "actions in {pool:?}",
            );
        }
    }

    /// The limit is per pool: spends spread across pools may exceed it in aggregate as
    /// long as no single pool does.
    #[test]
    fn action_limit_is_per_pool() {
        let proposal = change_only_proposal(
            &[
                ShieldedPool::Sapling,
                ShieldedPool::Sapling,
                ShieldedPool::Orchard,
                ShieldedPool::Orchard,
            ],
            vec![],
        );
        assert_eq!(check_shielded_action_limits(&proposal, 2), Ok(()));
    }
}
