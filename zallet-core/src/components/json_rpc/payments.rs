use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
    fmt,
    sync::{LazyLock, Mutex},
};

use abscissa_core::Application;
use documented::Documented;
use jsonrpsee::core::JsonValue;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use transparent::{address::TransparentAddress, keys::AccountPubKey};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        Account as _, WalletRead,
        wallet::{
            ConfirmationsPolicy,
            input_selection::{GreedyInputSelector, SpendPolicy},
            propose_transfer,
        },
    },
    fees::{
        DustOutputPolicy, StandardFeeRule, TransparentChangePolicy,
        standard::MultiOutputChangeStrategy,
    },
    proposal::Proposal,
    wallet::TransparentAddressSource,
    zip321::{Payment, TransactionRequest},
};
use zcash_client_sqlite::{AccountUuid, ReceivedNoteId, wallet::Account};
use zcash_keys::{address::Address, keys::UnifiedFullViewingKey};
use zcash_protocol::{PoolType, ShieldedPool, TxId, memo::MemoBytes, value::Zatoshis};
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

#[derive(Serialize, Deserialize, JsonSchema)]
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
/// Rejects an empty array, duplicate recipient addresses, malformed addresses, and total
/// output value overflow.
pub(super) fn build_request(amounts: &[AmountParameter]) -> RpcResult<TransactionRequest> {
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

    pub(super) fn allow_revealed_senders(&self) -> bool {
        self.is_compatible_with(PrivacyPolicy::AllowRevealedSenders)
    }

    pub(super) fn allow_fully_transparent(&self) -> bool {
        self.is_compatible_with(PrivacyPolicy::AllowFullyTransparent)
    }

    pub(super) fn allow_linking_account_addresses(&self) -> bool {
        self.is_compatible_with(PrivacyPolicy::AllowLinkingAccountAddresses)
    }

    pub(super) fn allow_no_privacy(&self) -> bool {
        self.is_compatible_with(PrivacyPolicy::NoPrivacy)
    }
}

pub(super) fn enforce_privacy_policy<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
    privacy_policy: PrivacyPolicy,
) -> Result<(), IncompatiblePrivacyPolicy> {
    for step in proposal.steps() {
        let has_transparent_recipient = step.output_in_pool(PoolType::Transparent);
        let has_transparent_change = step.change_in_pool(PoolType::Transparent);
        let has_sapling_recipient =
            step.output_in_pool(PoolType::SAPLING) || step.change_in_pool(PoolType::SAPLING);
        let has_orchard_recipient =
            step.output_in_pool(PoolType::ORCHARD) || step.change_in_pool(PoolType::ORCHARD);

        if step.input_in_pool(PoolType::Transparent) {
            let received_addrs = step
                .transparent_inputs()
                .iter()
                .map(|input| input.recipient_address())
                .collect::<HashSet<_>>();

            if received_addrs.len() > 1 {
                if has_transparent_recipient || has_transparent_change {
                    if !privacy_policy.allow_no_privacy() {
                        return Err(IncompatiblePrivacyPolicy::NoPrivacy);
                    }
                } else if !privacy_policy.allow_linking_account_addresses() {
                    return Err(IncompatiblePrivacyPolicy::LinkingAccountAddresses);
                }
            } else if has_transparent_recipient || has_transparent_change {
                if !privacy_policy.allow_fully_transparent() {
                    return Err(IncompatiblePrivacyPolicy::FullyTransparent);
                }
            } else if !privacy_policy.allow_revealed_senders() {
                return Err(IncompatiblePrivacyPolicy::TransparentSender);
            }
        } else if has_transparent_recipient {
            if !privacy_policy.allow_revealed_recipients() {
                return Err(IncompatiblePrivacyPolicy::TransparentRecipient);
            }
        } else if has_transparent_change {
            if !privacy_policy.allow_revealed_recipients() {
                return Err(IncompatiblePrivacyPolicy::TransparentChange);
            }
        } else if step.input_in_pool(PoolType::ORCHARD) && has_sapling_recipient {
            // TODO: This should only trigger when there is a non-fee valueBalance.
            if !privacy_policy.allow_revealed_amounts() {
                // TODO: Determine whether this is due to the presence of an explicit
                // Sapling recipient address, or having insufficient funds to pay a UA
                // within a single pool.
                return Err(IncompatiblePrivacyPolicy::RevealingSaplingAmount);
            }
        } else if step.input_in_pool(PoolType::SAPLING) && has_orchard_recipient {
            // TODO: This should only trigger when there is a non-fee valueBalance.
            if !privacy_policy.allow_revealed_amounts() {
                return Err(IncompatiblePrivacyPolicy::RevealingOrchardAmount);
            }
        }
    }

    // If we reach here, no step revealed anything; this proposal satisfies any privacy
    // policy.
    assert!(privacy_policy.is_compatible_with(PrivacyPolicy::FullPrivacy));
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
/// This reports the privacy implications of a proposed transaction without requiring the
/// caller to commit to a policy up front.
// Extracted ahead of its caller: this is not yet wired into a JSON-RPC method on this
// branch, hence `allow(dead_code)`; drop the attribute when the propose path lands.
#[allow(dead_code)]
pub(super) fn required_privacy_policy<FeeRuleT, NoteRef>(
    proposal: &Proposal<FeeRuleT, NoteRef>,
) -> PrivacyPolicy {
    // The required policy for the whole proposal is the meet (greatest lower bound, i.e.
    // most-permissive-needed) of the policies required by each step. We start from
    // `FullPrivacy` (the strictest policy, the lattice top); `meet` with each step's
    // requirement relaxes it exactly as much as that step's leakage demands.
    proposal
        .steps()
        .iter()
        .fold(PrivacyPolicy::FullPrivacy, |required, step| {
            // This mirrors the branch structure of `enforce_privacy_policy` exactly; keep
            // the two in sync. Each step fires exactly one branch, yielding the single
            // policy level that step requires.
            let has_transparent_recipient = step.output_in_pool(PoolType::Transparent);
            let has_transparent_change = step.change_in_pool(PoolType::Transparent);
            let has_sapling_recipient =
                step.output_in_pool(PoolType::SAPLING) || step.change_in_pool(PoolType::SAPLING);
            let has_orchard_recipient =
                step.output_in_pool(PoolType::ORCHARD) || step.change_in_pool(PoolType::ORCHARD);

            let step_required = if step.input_in_pool(PoolType::Transparent) {
                let received_addrs = step
                    .transparent_inputs()
                    .iter()
                    .map(|input| input.recipient_address())
                    .collect::<HashSet<_>>();

                if received_addrs.len() > 1 {
                    if has_transparent_recipient || has_transparent_change {
                        PrivacyPolicy::NoPrivacy
                    } else {
                        PrivacyPolicy::AllowLinkingAccountAddresses
                    }
                } else if has_transparent_recipient || has_transparent_change {
                    PrivacyPolicy::AllowFullyTransparent
                } else {
                    PrivacyPolicy::AllowRevealedSenders
                }
            } else if has_transparent_recipient || has_transparent_change {
                PrivacyPolicy::AllowRevealedRecipients
            } else if (step.input_in_pool(PoolType::ORCHARD) && has_sapling_recipient)
                || (step.input_in_pool(PoolType::SAPLING) && has_orchard_recipient)
            {
                // TODO: As in `enforce_privacy_policy`, this should only trigger when there
                // is a non-fee valueBalance.
                PrivacyPolicy::AllowRevealedAmounts
            } else {
                // Nothing is revealed by this step.
                PrivacyPolicy::FullPrivacy
            };

            required.meet(step_required)
        })
}

/// Parses the optional `privacy_policy` JSON-RPC argument into a [`PrivacyPolicy`],
/// defaulting to [`PrivacyPolicy::FullPrivacy`] when absent and rejecting the unsupported
/// `"LegacyCompat"` policy.
// Extracted ahead of its caller; not yet wired into a JSON-RPC method on this branch, hence
// `allow(dead_code)`.
#[allow(dead_code)]
pub(super) fn parse_privacy_policy(privacy_policy: Option<&str>) -> RpcResult<PrivacyPolicy> {
    match privacy_policy {
        Some("LegacyCompat") => Err(LegacyCode::InvalidParameter
            .with_static("LegacyCompat privacy policy is unsupported in Zallet")),
        Some(s) => PrivacyPolicy::from_str(s).ok_or_else(|| {
            LegacyCode::InvalidParameter.with_message(format!("Unknown privacy policy {s}"))
        }),
        None => Ok(PrivacyPolicy::FullPrivacy),
    }
}

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
    /// have enough Sapling funds to avoid revealing amounts.
    RevealingSaplingAmount,

    /// Requested [`PrivacyPolicy`] doesn’t include `AllowRevealedAmounts`, but we don’t
    /// have enough Orchard funds to avoid revealing amounts.
    RevealingOrchardAmount,

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
            IncompatiblePrivacyPolicy::RevealingSaplingAmount => format!(
                "{} {}",
                fl!("err-privpol-revealing-amount-not-allowed", pool = "Sapling"),
                fl!(
                    "rec-privpol-privacy-weakening",
                    parameter = "privacyPolicy",
                    policy = "AllowRevealedAmounts"
                )
            ),
            IncompatiblePrivacyPolicy::RevealingOrchardAmount => format!(
                "{} {}",
                fl!("err-privpol-revealing-amount-not-allowed", pool = "Orchard"),
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

/// Maximum number of proposals retained by [`RequiredPolicyCache`].
const REQUIRED_POLICY_CACHE_CAPACITY: usize = 256;

/// What [`RequiredPolicyCache`] records about a proposed PCZT.
#[derive(Clone)]
struct CachedProposalInfo {
    /// The strictest privacy policy that still permits this transaction.
    required_policy: PrivacyPolicy,
    /// The transparent payments the caller explicitly requested, one entry per proposal step
    /// (in step order). See [`verify_and_broadcast_transactions`]'s `expected_payments`
    /// parameter, which this is recorded for.
    transparent_payments: Vec<Vec<(TransparentAddress, Zatoshis)>>,
}

/// A bounded, insertion-ordered cache mapping a PCZT (by content hash) to what
/// `z_finalizetransaction` needs in order to check it: the [`PrivacyPolicy`] required to
/// execute it, and the transparent payments its proposal explicitly requested.
///
/// `z_proposetransaction` computes both exactly from the proposal and records them here;
/// `z_finalizetransaction` looks them up so it can enforce that the caller acknowledged a
/// sufficient policy, and that every transparent output not explicitly requested is a
/// wallet-derived address, without having to re-derive either from the (lossy) PCZT. Entries
/// are evicted in insertion order once the capacity is exceeded.
struct RequiredPolicyCache {
    by_pczt: HashMap<[u8; 32], CachedProposalInfo>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl RequiredPolicyCache {
    fn new(capacity: usize) -> Self {
        Self {
            by_pczt: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn get(&self, key: &[u8; 32]) -> Option<CachedProposalInfo> {
        self.by_pczt.get(key).cloned()
    }

    fn insert(&mut self, key: [u8; 32], info: CachedProposalInfo) {
        // Re-inserting an existing key just refreshes the entry without growing the cache.
        if self.by_pczt.insert(key, info).is_none() {
            self.order.push_back(key);
            while self.order.len() > self.capacity {
                if let Some(evicted) = self.order.pop_front() {
                    self.by_pczt.remove(&evicted);
                }
            }
        }
    }
}

static REQUIRED_POLICY_CACHE: LazyLock<Mutex<RequiredPolicyCache>> =
    LazyLock::new(|| Mutex::new(RequiredPolicyCache::new(REQUIRED_POLICY_CACHE_CAPACITY)));

/// The cache key for a PCZT: the SHA-256 of its serialized bytes.
///
/// `z_proposetransaction` and `z_finalizetransaction` hash the same canonical serialization, so
/// the entry recorded at proposal time is found again at finalize time.
pub(super) fn pczt_policy_key(pczt_bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(pczt_bytes).into()
}

/// Records what `z_finalizetransaction` needs to check the PCZT identified by `key`: the
/// privacy policy required to execute it, and the transparent payments its proposal explicitly
/// requested (see [`verify_and_broadcast_transactions`]).
pub(super) fn record_required_policy(
    key: [u8; 32],
    required_policy: PrivacyPolicy,
    transparent_payments: Vec<Vec<(TransparentAddress, Zatoshis)>>,
) {
    REQUIRED_POLICY_CACHE
        .lock()
        .expect("policy cache mutex is not poisoned")
        .insert(
            key,
            CachedProposalInfo {
                required_policy,
                transparent_payments,
            },
        );
}

/// Returns the previously-recorded required policy for the PCZT identified by `key`, if it is
/// still cached.
pub(super) fn cached_required_policy(key: &[u8; 32]) -> Option<PrivacyPolicy> {
    REQUIRED_POLICY_CACHE
        .lock()
        .expect("policy cache mutex is not poisoned")
        .get(key)
        .map(|info| info.required_policy)
}

/// Returns the previously-recorded expected transparent payments for the PCZT identified by
/// `key`, if it is still cached.
///
/// `None` covers both "not cached" (eviction, a process restart since this cache is in-memory
/// only, or a PCZT proposed by a different node) and "cached with no transparent payments in
/// any step": both make an exact `expected_payments` list unavailable, and
/// [`verify_and_broadcast_transactions`] treats `None` as "skip this check" rather than
/// misreporting a proposal with transparent payments as having none. This mirrors
/// `cached_required_policy`'s cache-miss behavior (accept the caller's acknowledgement without
/// cross-checking it): we cannot reliably re-derive either property from the PCZT alone, so a
/// miss trades this defense-in-depth check for availability rather than rejecting an otherwise
/// valid transaction. See zcash/wallet#217.
pub(super) fn cached_expected_transparent_payments(
    key: &[u8; 32],
) -> Option<Vec<Vec<(TransparentAddress, Zatoshis)>>> {
    REQUIRED_POLICY_CACHE
        .lock()
        .expect("policy cache mutex is not poisoned")
        .get(key)
        .map(|info| info.transparent_payments)
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

/// Proposes a transfer of `request` from `account`, drawing only on the funds `spend_policy`
/// permits.
///
/// Every send path builds its proposal here, so they agree on the fee rule, the change strategy,
/// and the input selector, and differ only in the spend policy they ask for. That policy is what
/// distinguishes `z_sendmany`'s source address from the account methods' `fund_source`.
///
/// The privacy policy is deliberately not consulted: the selector returns its best proposal, and
/// `enforce_privacy_policy` rejects it afterwards if it leaks more than the caller permitted.
pub(super) fn propose_transfer_with_policy(
    wallet: &mut DbConnection,
    params: &Network,
    account: AccountUuid,
    request: TransactionRequest,
    confirmations_policy: ConfirmationsPolicy,
    spend_policy: &SpendPolicy,
) -> RpcResult<Proposal<StandardFeeRule, ReceivedNoteId>> {
    // Where shielded change goes when the transaction has no shielded flows to infer a pool
    // from. A transaction that does have shielded flows ignores this and keeps its change in
    // the pool it is already using.
    //
    // This stays Orchard rather than Ironwood: the change strategy promotes it to Ironwood
    // itself once NU6.3 is active (the turnstile forbids value from entering the Orchard pool,
    // so change out of a purely transparent transaction has to land in Ironwood), and it does
    // so against the transaction's target height, which is not known here. Naming Ironwood
    // outright would instead send change to a pool that does not exist yet on a chain where
    // NU6.3 has not activated.
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
    .with_transparent_change_policy(transparent_change_policy_for(spend_policy));

    let input_selector = GreedyInputSelector::new();

    // Do not request a specific transaction version; building falls back to the version implied
    // by the target height.
    let proposed_version = None;

    propose_transfer::<_, _, _, _, Infallible>(
        wallet,
        params,
        account,
        &input_selector,
        &change_strategy,
        request,
        confirmations_policy,
        spend_policy,
        proposed_version,
    )
    // TODO: Map errors to `zcashd` shape.
    .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to propose transaction: {e}")))
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

    Err(LegacyCode::InvalidAddressOrKey
        .with_static("Invalid from address, no payment source found for address."))
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
    let legacy_seed_fp = APP
        .config()
        .features
        .legacy_pool_seed_fingerprint
        .ok_or_else(|| {
            LegacyCode::WalletAccountsUnsupported.with_static(
                "The legacy pool of funds is disabled. To enable it, set \
                 `features.legacy_pool_seed_fingerprint` in the Zallet config file to the \
                 seed fingerprint of the `zcashd` wallet migrated into this wallet.",
            )
        })?;

    // TODO: Make this more efficient with a `WalletRead` method.
    //       https://github.com/zcash/librustzcash/issues/1944
    for account_id in wallet
        .get_account_ids()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
    {
        let account = wallet
            .get_account(account_id)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            // This would be a race condition between this and account deletion.
            .ok_or_else(|| LegacyCode::Database.with_static("Account vanished mid-call"))?;

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

    Err(LegacyCode::Wallet.with_message(format!(
        "This wallet holds no legacy account for seed fingerprint {legacy_seed_fp}. Check that \
         `features.legacy_pool_seed_fingerprint` names a `zcashd` wallet migrated into it.",
    )))
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
pub(super) fn proposed_transparent_payments<FeeRuleT, NoteRef>(
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
pub(super) async fn verify_and_broadcast_transactions<C: Chain>(
    wallet: &DbConnection,
    chain: C,
    account_id: AccountUuid,
    ufvk: &UnifiedFullViewingKey,
    // The transparent payments the caller explicitly requested, one entry per proposal step
    // (in step order), or `None` to skip the check entirely. Outputs matching one of these
    // exactly are the caller's requested payments; every other transparent output must be a
    // wallet-derived address (change or an ephemeral ZIP 320 output), verified against `ufvk`.
    // `None` is for callers that cannot supply this reliably (see
    // `z_finalizetransaction`'s cache-miss fallback); it trades this defense-in-depth check
    // for availability rather than rejecting a transaction that would otherwise be valid.
    expected_payments: Option<Vec<Vec<(TransparentAddress, Zatoshis)>>>,
    txids: Vec<TxId>,
) -> RpcResult<SendResult> {
    let params = *wallet.params();

    let mut transactions = Vec::with_capacity(txids.len());

    if let Some(expected_payments) = expected_payments {
        // The builder creates one transaction per proposal step, in step order.
        if txids.len() != expected_payments.len() {
            return Err(LegacyCode::Wallet.with_static(
                "Internal error: built transaction count does not match proposal step count.",
            ));
        }

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
                TransparentOutputError::Lookup(e) => {
                    LegacyCode::Database.with_message(e.to_string())
                }
                TransparentOutputError::UnrecognizedScript { vout } => {
                    LegacyCode::Wallet.with_message(fl!(
                        "err-transparent-output-not-wallet-derived",
                        output = format!("output index {vout}"),
                    ))
                }
                TransparentOutputError::MissingPayment(addr) => {
                    LegacyCode::Wallet.with_message(fl!(
                        "err-transparent-payment-missing",
                        address = Address::Transparent(addr).encode(&params),
                    ))
                }
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
    } else {
        for txid in &txids {
            let tx = wallet
                .get_transaction(*txid)
                .map_err(|e| {
                    LegacyCode::Database.with_message(format!("Failed to get transaction: {e}"))
                })?
                .ok_or_else(|| {
                    LegacyCode::Wallet
                        .with_message(format!("Wallet does not contain transaction {txid}"))
                })?;
            transactions.push(tx);
        }
    }

    if APP.config().external.broadcast() {
        for tx in &transactions {
            chain.broadcast_transaction(tx).await.map_err(|e| {
                LegacyCode::Wallet
                    .with_message(format!("SendTransaction: Transaction commit failed:: {e}"))
            })?;
        }
    }

    Ok(SendResult::new(txids))
}

/// The result of sending a payment.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct SendResult {
    /// The ID of the resulting transaction, if the payment only produced one.
    ///
    /// Omitted if more than one transaction was sent; see [`SendResult::txids`] in that
    /// case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    txid: Option<String>,

    /// The IDs of the sent transactions resulting from the payment.
    txids: Vec<String>,
}

impl SendResult {
    fn new(txids: Vec<TxId>) -> Self {
        let txids = txids
            .into_iter()
            .map(|txid| txid.to_string())
            .collect::<Vec<_>>();

        Self {
            txid: (txids.len() == 1).then(|| txids.first().expect("present").clone()),
            txids,
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

    use super::arb::*;
    use super::*;
    use crate::components::json_rpc::utils::zec_str;

    fn err_message(amounts: &[AmountParameter]) -> String {
        build_request(amounts)
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
        let request = build_request(&[amount(T_ADDR_1, "0.1")]).expect("valid request");
        assert_eq!(request.payments().len(), 1);
    }

    #[test]
    fn builds_multiple_distinct_recipients() {
        let request = build_request(&[amount(T_ADDR_1, "0.1"), amount(T_ADDR_2, "0.2")])
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
        let request = build_request(&[
            amount(T_ADDR_1, "0.1"),
            amount(SAPLING_ADDR, "0.2"),
            amount(UNIFIED_ADDR_1, "0.3"),
            amount(UNIFIED_ADDR_2, "0.4"),
        ])
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
            let result = build_request(&amounts);

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

            let request = build_request(&amounts)
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
        let err = parse_privacy_policy(Some("LegacyCompat"))
            .expect_err("LegacyCompat should be rejected");
        assert_eq!(
            err.message(),
            "LegacyCompat privacy policy is unsupported in Zallet",
        );
    }

    #[test]
    fn parse_privacy_policy_rejects_unknown_policy() {
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
            prop_assume!(PrivacyPolicy::from_str(&s).is_none() && s != "LegacyCompat");
            let err = parse_privacy_policy(Some(&s))
                .expect_err("an unknown policy name should be rejected");
            let expected = format!("Unknown privacy policy {s}");
            prop_assert_eq!(err.message(), expected);
        }
    }
}
