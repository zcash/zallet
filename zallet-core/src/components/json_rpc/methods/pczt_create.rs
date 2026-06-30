//! PCZT create method — create a PCZT from a transaction proposal.
//!
//! This is the functional replacement for `createrawtransaction` +
//! `fundrawtransaction`: it selects inputs and computes change for a set of
//! recipients, producing a complete (but unproven and unsigned) PCZT.

use std::collections::HashSet;
use std::convert::Infallible;
use std::num::NonZeroU32;

use abscissa_core::Application;
use base64ct::{Base64, Encoding};
use documented::Documented;
use jsonrpsee::core::RpcResult;
use pczt::roles::updater::Updater;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use transparent::keys::TransparentKeyScope;
use zcash_address::{ZcashAddress, unified};
use zcash_client_backend::{
    data_api::{
        Account, WalletRead,
        wallet::{
            ConfirmationsPolicy, create_pczt_from_proposal, input_selection::GreedyInputSelector,
            propose_transfer,
        },
    },
    fees::{DustOutputPolicy, StandardFeeRule, standard::MultiOutputChangeStrategy},
    wallet::OvkPolicy,
    zip321::{Payment, PaymentError, TransactionRequest},
};
use zcash_keys::address::Address;
use zcash_protocol::{
    PoolType, ShieldedProtocol,
    consensus::{NetworkType, Parameters},
    value::{MAX_MONEY, Zatoshis},
};

use crate::{
    components::{
        database::DbHandle,
        json_rpc::{
            payments::{
                IncompatiblePrivacyPolicy, PrivacyPolicy, enforce_privacy_policy,
                get_account_for_address, parse_memo,
            },
            server::LegacyCode,
            utils::zatoshis_from_value,
        },
    },
    fl,
    prelude::*,
};

/// Maximum number of recipients accepted in a single `pczt_create` call.
///
/// A funded transaction is ultimately bounded by the consensus size limit and
/// the configured Orchard action limit, but we reject obviously abusive inputs
/// before doing any proposal work.
const MAX_RECIPIENTS: usize = 1000;

pub(crate) type Response = RpcResult<ResultType>;

/// Result of creating a PCZT.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct CreateResult {
    /// The base64-encoded PCZT.
    pub pczt: String,
}

pub(crate) type ResultType = CreateResult;

/// A recipient amount for `pczt_create`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub(crate) struct AmountParam {
    /// Recipient address.
    pub address: String,
    /// Amount in ZEC.
    pub amount: serde_json::Value,
    /// Optional memo (shielded recipients only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

pub(super) const PARAM_FROM_ADDRESS_DESC: &str = "The address to send funds from.";
pub(super) const PARAM_AMOUNTS_DESC: &str = "An array of recipient amounts.";
pub(super) const PARAM_AMOUNTS_REQUIRED: bool = true;
pub(super) const PARAM_MINCONF_DESC: &str = "Minimum confirmations for inputs.";
pub(super) const PARAM_PRIVACY_POLICY_DESC: &str = "Privacy policy for the transaction.";

/// Creates a PCZT from a transaction proposal.
pub(crate) async fn call(
    mut wallet: DbHandle,
    from_address: String,
    amounts: Vec<AmountParam>,
    minconf: Option<u32>,
    privacy_policy: Option<String>,
) -> Response {
    if amounts.is_empty() {
        return Err(
            LegacyCode::InvalidParameter.with_static("Invalid parameter, amounts array is empty.")
        );
    }

    if amounts.len() > MAX_RECIPIENTS {
        return Err(LegacyCode::InvalidParameter.with_message(format!(
            "Too many recipients: {} exceeds maximum of {MAX_RECIPIENTS}",
            amounts.len(),
        )));
    }

    // Parse amounts into payments.
    let mut recipient_addrs = HashSet::new();
    let mut payments = vec![];

    for amount in &amounts {
        let addr: ZcashAddress = amount.address.parse().map_err(|_| {
            LegacyCode::InvalidParameter.with_message(format!(
                "Invalid parameter, unknown address format: {}",
                amount.address,
            ))
        })?;

        if !recipient_addrs.insert(addr.clone()) {
            return Err(LegacyCode::InvalidParameter.with_message(format!(
                "Invalid parameter, duplicated recipient address: {}",
                amount.address,
            )));
        }

        let memo = amount.memo.as_deref().map(parse_memo).transpose()?;
        let value = zatoshis_from_value(&amount.amount)?;

        let payment = Payment::new(addr, Some(value), memo, None, None, vec![]).map_err(|e| {
            LegacyCode::InvalidParameter.with_static(match e {
                PaymentError::TransparentMemo => "Cannot send memo to transparent recipient",
                PaymentError::ZeroValuedTransparentOutput => {
                    "Cannot send zero-valued output to transparent recipient"
                }
            })
        })?;

        payments.push(payment);
    }

    let request = TransactionRequest::new(payments).map_err(|e| {
        LegacyCode::InvalidParameter.with_message(format!("Invalid payment request: {e}"))
    })?;

    // Resolve `from_address` to an account.
    let account = {
        let address = Address::decode(wallet.params(), &from_address).ok_or_else(|| {
            LegacyCode::InvalidAddressOrKey
                .with_static("Invalid from address: should be a taddr, zaddr, or UA.")
        })?;

        get_account_for_address(wallet.as_ref(), &address)
    }?;

    let privacy_policy = match privacy_policy.as_deref() {
        Some("LegacyCompat") => Err(LegacyCode::InvalidParameter
            .with_static("LegacyCompat privacy policy is unsupported in Zallet")),
        Some(s) => PrivacyPolicy::from_str(s).ok_or_else(|| {
            LegacyCode::InvalidParameter.with_message(format!("Unknown privacy policy {s}"))
        }),
        None => Ok(PrivacyPolicy::FullPrivacy),
    }?;

    let confirmations_policy = match minconf {
        Some(minconf) => NonZeroU32::new(minconf).map_or(
            ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
            |c| ConfirmationsPolicy::new_symmetrical(c, false),
        ),
        None => APP.config().builder.confirmations_policy().map_err(|_| {
            LegacyCode::Wallet.with_message(
                "Configuration error: minimum confirmations for spending trusted TXOs cannot exceed that for untrusted TXOs.")
        })?,
    };

    let params = *wallet.params();

    // Check the privacy policy against the recipients (same as `z_send_many`).
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
                    (true, (true, _), _) => (),
                    (false, (true, Some(rest)), _) => max_orchard_available = rest,
                    (true, _, (true, _)) => (),
                    (false, _, (true, Some(rest))) => max_sapling_available = rest,
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

    let change_strategy = MultiOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedProtocol::Orchard,
        DustOutputPolicy::default(),
        APP.config().note_management.split_policy(),
    );

    let input_selector = GreedyInputSelector::new();

    let proposal = propose_transfer::<_, _, _, _, Infallible>(
        wallet.as_mut(),
        &params,
        account.id(),
        &input_selector,
        &change_strategy,
        request,
        confirmations_policy,
    )
    .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to propose transaction: {e}")))?;

    enforce_privacy_policy(&proposal, privacy_policy)?;

    // Check Orchard action limits (same as `z_send_many`).
    let orchard_actions_limit = APP.config().builder.limits.orchard_actions().into();
    for step in proposal.steps() {
        let orchard_spends = step
            .shielded_inputs()
            .iter()
            .flat_map(|inputs| inputs.notes())
            .filter(|note| note.note().protocol() == ShieldedProtocol::Orchard)
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

    // Derivation info used to populate the zallet signing hints below.
    let derivation = account.source().key_derivation().ok_or_else(|| {
        LegacyCode::InvalidAddressOrKey
            .with_static("Invalid from address, no payment source found for address.")
    })?;

    // Build the PCZT from the proposal. This selects inputs, computes change,
    // runs IO finalization, and records the native ZIP 32 / BIP 32 derivation
    // metadata, but does not create proofs or signatures.
    let pczt = create_pczt_from_proposal::<_, _, Infallible, _, Infallible, _>(
        wallet.as_mut(),
        &params,
        account.id(),
        OvkPolicy::Sender,
        &proposal,
    )
    .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to create PCZT: {e}")))?;

    // Collect the per-input transparent derivation info from the proposal, in
    // the same order as the PCZT's transparent inputs.
    let mut input_metadata = Vec::new();
    for step in proposal.steps() {
        for transparent_input in step.transparent_inputs() {
            let address = transparent_input.recipient_address();
            let meta = wallet
                .get_transparent_address_metadata(account.id(), address)
                .ok()
                .flatten();
            input_metadata.push(meta);
        }
    }

    if input_metadata.len() != pczt.transparent().inputs().len() {
        return Err(
            LegacyCode::Misc.with_static("Internal error: transparent input count mismatch")
        );
    }

    let network_id: u8 = match params.network_type() {
        NetworkType::Main => 0,
        NetworkType::Test => 1,
        NetworkType::Regtest => 2,
    };

    // Record signing hints as proprietary fields. The PCZT format does carry
    // native ZIP 32 / BIP 32 derivation metadata (populated above), but as of
    // pczt 0.8.0-rc.1 there is no way to read it back: `Zip32Derivation` is
    // crate-private, and the only public API touching the metadata is the
    // Redactor, which clears it. An offline `pczt_sign` therefore cannot use
    // it. These `zallet.v1.*` fields are a stand-in for that native path until
    // the upstream accessors land.
    let updater = Updater::new(pczt);
    let mut pczt = updater
        .update_global_with(|mut global| {
            global.set_proprietary(
                "zallet.v1.seed_fingerprint".to_string(),
                derivation.seed_fingerprint().to_bytes().to_vec(),
            );
            global.set_proprietary(
                "zallet.v1.account_index".to_string(),
                u32::from(derivation.account_index()).to_le_bytes().to_vec(),
            );
            global.set_proprietary("zallet.v1.network".to_string(), vec![network_id]);
        })
        .finish();

    if !input_metadata.is_empty() {
        let updater = Updater::new(pczt);
        pczt = updater
            .update_transparent_with(|mut bundle| {
                for (index, meta) in input_metadata.iter().enumerate() {
                    if let Some(meta) = meta {
                        // Only derived addresses carry a scope and index.
                        if let (Some(scope), Some(address_index)) =
                            (meta.scope(), meta.address_index())
                        {
                            bundle.update_input_with(index, |mut input| {
                                // scope: 0 = external, 1 = internal, 2 = ephemeral/other.
                                let scope_value = if scope == TransparentKeyScope::EXTERNAL {
                                    0u32
                                } else if scope == TransparentKeyScope::INTERNAL {
                                    1u32
                                } else {
                                    2u32
                                };
                                input.set_proprietary(
                                    "zallet.v1.scope".to_string(),
                                    scope_value.to_le_bytes().to_vec(),
                                );
                                input.set_proprietary(
                                    "zallet.v1.address_index".to_string(),
                                    address_index.index().to_le_bytes().to_vec(),
                                );
                                Ok(())
                            })?;
                        }
                    }
                }
                Ok(())
            })
            .map_err(|_| {
                LegacyCode::Wallet.with_static("Failed to record transparent signing hints")
            })?
            .finish();
    }

    Ok(CreateResult {
        pczt: Base64::encode_string(&pczt.serialize()),
    })
}
