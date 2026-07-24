//! PCZT create method — create a PCZT from a transaction proposal.
//!
//! This is the functional replacement for `createrawtransaction` +
//! `fundrawtransaction`: it selects inputs and computes change for a set of
//! recipients, producing a complete (but unproven and unsigned) PCZT.

use std::convert::Infallible;
use std::num::NonZeroU32;

use abscissa_core::Application;
use documented::Documented;
use jsonrpsee::core::RpcResult;
use pczt::roles::updater::Updater;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::{
    data_api::{
        Account, WalletRead,
        wallet::{ConfirmationsPolicy, create_pczt_from_proposal, input_selection::SpendPolicy},
    },
    wallet::OvkPolicy,
};
use zcash_keys::address::Address;

use super::pczt_common::{
    PROP_ACCOUNT_INDEX, PROP_ADDRESS_INDEX, PROP_SCOPE, PROP_SEED_FINGERPRINT, encode_key_scope,
    encode_pczt_base64,
};
use super::pczt_error::PcztError;
use crate::{
    components::{
        database::DbHandle,
        json_rpc::{
            payments::{
                AmountParameter, PrivacyPolicy, build_request, get_account_for_address,
                propose_and_check,
            },
            server::LegacyCode,
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

pub(super) const PARAM_FROM_ADDRESS_DESC: &str = "The address to send funds from.";
pub(super) const PARAM_AMOUNTS_DESC: &str = "An array of recipient amounts.";
pub(super) const PARAM_AMOUNTS_REQUIRED: bool = true;
pub(super) const PARAM_MINCONF_DESC: &str = "Minimum confirmations for inputs.";
pub(super) const PARAM_PRIVACY_POLICY_DESC: &str = "Privacy policy for the transaction.";

/// Creates a PCZT from a transaction proposal.
pub(crate) async fn call(
    mut wallet: DbHandle,
    from_address: String,
    amounts: Vec<AmountParameter>,
    minconf: Option<u32>,
    privacy_policy: Option<String>,
) -> Response {
    if amounts.len() > MAX_RECIPIENTS {
        return Err(LegacyCode::InvalidParameter.with_message(fl!(
            "err-pczt-too-many-recipients",
            given = amounts.len(),
            maximum = MAX_RECIPIENTS,
        )));
    }

    let request = build_request(&amounts)?;

    // Resolve `from_address` to an account.
    let account = {
        let address = Address::decode(wallet.params(), &from_address).ok_or_else(|| {
            LegacyCode::InvalidAddressOrKey.with_message(fl!("err-invalid-from-address"))
        })?;

        get_account_for_address(wallet.as_ref(), &address)
    }?;

    let privacy_policy = match privacy_policy.as_deref() {
        Some("LegacyCompat") => {
            Err(LegacyCode::InvalidParameter.with_message(fl!("err-privacy-policy-legacy-compat")))
        }
        Some(s) => PrivacyPolicy::from_str(s).ok_or_else(|| {
            LegacyCode::InvalidParameter.with_message(fl!("err-privacy-policy-unknown", policy = s))
        }),
        None => Ok(PrivacyPolicy::FullPrivacy),
    }?;

    let confirmations_policy = match minconf {
        Some(minconf) => NonZeroU32::new(minconf).map_or(
            ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
            |c| ConfirmationsPolicy::new_symmetrical(c, false),
        ),
        None => APP.config().builder.confirmations_policy().map_err(|_| {
            LegacyCode::Wallet.with_message(fl!("err-confirmations-policy-invalid"))
        })?,
    };

    let params = *wallet.params();
    let proposal = propose_and_check(
        wallet.as_mut(),
        &params,
        account.id(),
        request,
        privacy_policy,
        confirmations_policy,
        // pczt_create only spends shielded funds; the default policy permits every shielded
        // pool present in the build and no transparent spending.
        &SpendPolicy::default(),
    )?;

    // Derivation info used to populate the zallet signing hints below.
    let derivation = account.source().key_derivation().ok_or_else(|| {
        LegacyCode::InvalidAddressOrKey.with_message(fl!("err-from-address-no-payment-source"))
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
        // Do not override the builder-derived expiry height.
        None,
        // Our proposal uses the default (padded) Orchard change strategy, so the
        // bundle type must be `DEFAULT` to match it.
        orchard::builder::BundleType::DEFAULT,
    )
    .map_err(|e| {
        LegacyCode::Wallet.with_message(fl!("err-pczt-create-failed", error = e.to_string()))
    })?;

    // Collect the per-input transparent derivation info from the proposal, in
    // the same order as the PCZT's transparent inputs.
    let mut input_metadata = Vec::new();
    for step in proposal.steps() {
        for transparent_input in step.transparent_inputs() {
            let address = transparent_input.recipient_address();
            let meta = wallet
                .get_transparent_address_metadata(account.id(), address)
                .map_err(|e| {
                    LegacyCode::Database.with_message(fl!(
                        "err-pczt-transparent-metadata-lookup",
                        error = e.to_string(),
                    ))
                })?;
            input_metadata.push(meta);
        }
    }

    if input_metadata.len() != pczt.transparent().inputs().len() {
        return Err(LegacyCode::Misc.with_message(fl!("err-pczt-transparent-input-count-mismatch")));
    }

    // Record signing hints as proprietary fields. The PCZT format does carry
    // native ZIP 32 / BIP 32 derivation metadata (populated above), but as of
    // pczt 0.8.0-rc.1 there is no way to read it back: `Zip32Derivation` is
    // crate-private, and the only public API touching the metadata is the
    // Redactor, which clears it. An offline `pczt_sign` therefore cannot use
    // it. These `zallet.v1.*` fields are a stand-in for that native path until
    // the upstream accessors land.
    let pczt = Updater::new(pczt)
        .update_global_with(|mut global| {
            global.set_proprietary(
                PROP_SEED_FINGERPRINT.to_string(),
                derivation.seed_fingerprint().to_bytes().to_vec(),
            );
            global.set_proprietary(
                PROP_ACCOUNT_INDEX.to_string(),
                u32::from(derivation.account_index()).to_le_bytes().to_vec(),
            );
        })
        // A no-op when there are no transparent inputs.
        .update_transparent_with(|mut bundle| {
            for (index, meta) in input_metadata.iter().enumerate() {
                if let Some(meta) = meta {
                    // Only derived addresses carry a scope and index.
                    if let (Some(scope), Some(address_index)) = (meta.scope(), meta.address_index())
                    {
                        bundle.update_input_with(index, |mut input| {
                            input.set_proprietary(
                                PROP_SCOPE.to_string(),
                                encode_key_scope(scope).to_le_bytes().to_vec(),
                            );
                            input.set_proprietary(
                                PROP_ADDRESS_INDEX.to_string(),
                                address_index.index().to_le_bytes().to_vec(),
                            );
                            Ok(())
                        })?;
                    }
                }
            }
            Ok(())
        })
        .map_err(PcztError::RecordSigningHints)?
        .finish();

    Ok(CreateResult {
        pczt: encode_pczt_base64(pczt)?,
    })
}
