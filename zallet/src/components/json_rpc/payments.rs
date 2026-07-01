use std::{collections::HashSet, fmt};

use abscissa_core::Application;
use jsonrpsee::core::JsonValue;
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::WalletRead,
    proposal::Proposal,
    zip321::{Payment, TransactionRequest},
};
use zcash_client_sqlite::wallet::Account;
use zcash_keys::address::Address;
use zcash_protocol::{PoolType, ShieldedPool, TxId, memo::MemoBytes, value::Zatoshis};

use crate::{
    components::{chain::Chain, database::DbConnection},
    fl,
    prelude::APP,
};

use super::{server::LegacyCode, utils::zatoshis_from_value};

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
        // TODO: Break out this granularity from `Step::involves`
        let input_in_pool = |pool_type: PoolType| match pool_type {
            PoolType::Transparent => step.is_shielding() || !step.transparent_inputs().is_empty(),
            PoolType::SAPLING => step.shielded_inputs().iter().any(|s_in| {
                s_in.notes()
                    .iter()
                    .any(|note| matches!(note.note().protocol(), ShieldedPool::Sapling))
            }),
            PoolType::ORCHARD => step.shielded_inputs().iter().any(|s_in| {
                s_in.notes()
                    .iter()
                    .any(|note| matches!(note.note().protocol(), ShieldedPool::Orchard))
            }),
            // The wallet does not yet spend Ironwood notes, so no step has Ironwood inputs.
            PoolType::Shielded(ShieldedPool::Ironwood) => false,
        };
        let output_in_pool =
            |pool_type: PoolType| step.payment_pools().values().any(|pool| *pool == pool_type);
        let change_in_pool = |pool_type: PoolType| {
            step.balance()
                .proposed_change()
                .iter()
                .any(|c| c.output_pool() == pool_type)
        };

        let has_transparent_recipient = output_in_pool(PoolType::Transparent);
        let has_transparent_change = change_in_pool(PoolType::Transparent);
        let has_sapling_recipient =
            output_in_pool(PoolType::SAPLING) || change_in_pool(PoolType::SAPLING);
        let has_orchard_recipient =
            output_in_pool(PoolType::ORCHARD) || change_in_pool(PoolType::ORCHARD);

        if input_in_pool(PoolType::Transparent) {
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
        } else if input_in_pool(PoolType::ORCHARD) && has_sapling_recipient {
            // TODO: This should only trigger when there is a non-fee valueBalance.
            if !privacy_policy.allow_revealed_amounts() {
                // TODO: Determine whether this is due to the presence of an explicit
                // Sapling recipient address, or having insufficient funds to pay a UA
                // within a single pool.
                return Err(IncompatiblePrivacyPolicy::RevealingSaplingAmount);
            }
        } else if input_in_pool(PoolType::SAPLING) && has_orchard_recipient {
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

pub(super) fn get_account_for_address(
    wallet: &DbConnection,
    address: &Address,
) -> RpcResult<Account> {
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

/// Broadcasts the specified transactions to the network, if configured to do so.
pub(super) async fn broadcast_transactions<C: Chain>(
    wallet: &DbConnection,
    chain: C,
    txids: Vec<TxId>,
) -> RpcResult<SendResult> {
    if APP.config().external.broadcast() {
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

            chain.broadcast_transaction(&tx).await.map_err(|e| {
                LegacyCode::Wallet
                    .with_message(format!("SendTransaction: Transaction commit failed:: {e}"))
            })?;
        }
    }

    Ok(SendResult::new(txids))
}

/// The result of sending a payment.
#[derive(Clone, Debug, Serialize)]
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
