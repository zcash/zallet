//! PCZT create method — create a PCZT from a transaction proposal.
//!
//! This is the functional replacement for `createrawtransaction` +
//! `fundrawtransaction`: it selects inputs and computes change for a set of
//! recipients, producing a complete (but unproven and unsigned) PCZT.

use std::convert::Infallible;

use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use pczt::Pczt;
use pczt::roles::updater::Updater;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::{
    data_api::{
        Account, WalletRead,
        wallet::{ConfirmationsPolicy, create_pczt_from_proposal, input_selection::SpendPolicy},
    },
    wallet::OvkPolicy,
    zip321::TransactionRequest,
};
use zcash_client_sqlite::AccountUuid;
use zcash_keys::address::Address;

use super::pczt_common::{
    PROP_ACCOUNT_INDEX, PROP_ADDRESS_INDEX, PROP_PRIVACY_POLICY, PROP_SCOPE, PROP_SEED_FINGERPRINT,
    encode_key_scope, encode_pczt_base64,
};
use super::pczt_error::PcztError;
use crate::{
    components::{
        database::DbHandle,
        json_rpc::{
            fund_source::FundSource,
            payments::{
                AmountParameter, PrivacyPolicy, build_request, confirmations_policy_for_minconf,
                get_account_for_address, parse_privacy_policy, propose_and_check,
                required_privacy_policy, spend_policy_for,
            },
            server::LegacyCode,
        },
    },
    fl,
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
    /// The minimum privacy policy required to execute this PCZT.
    ///
    /// Any policy compatible with this one is sufficient; `pczt_sign` requires
    /// the caller to acknowledge at least this policy. Inspect this (and the
    /// PCZT itself) before signing to see what the transaction will reveal.
    pub privacy_policy: String,
}

pub(crate) type ResultType = CreateResult;

pub(super) const PARAM_FROM_DESC: &str = "The address, or the account UUID, to send funds from.";
pub(super) const PARAM_AMOUNTS_DESC: &str = "An array of recipient amounts.";
pub(super) const PARAM_AMOUNTS_REQUIRED: bool = true;
pub(super) const PARAM_MINCONF_DESC: &str = "Minimum confirmations for inputs.";
pub(super) const PARAM_PRIVACY_POLICY_DESC: &str = "Privacy policy for the transaction.";
pub(super) const PARAM_FUND_SOURCE_DESC: &str = "Where funds may be drawn from, when `from` is an account UUID: \"orchard\", \"sapling\", \
     \"any_transparent\", or an array of transparent addresses.";

/// Creates a PCZT from a transaction proposal.
pub(crate) async fn call(
    mut wallet: DbHandle,
    from: String,
    amounts: Vec<AmountParameter>,
    minconf: Option<u32>,
    privacy_policy: Option<String>,
    fund_source: Option<JsonValue>,
) -> Response {
    if amounts.len() > MAX_RECIPIENTS {
        return Err(LegacyCode::InvalidParameter.with_message(fl!(
            "err-pczt-too-many-recipients",
            given = amounts.len(),
            maximum = MAX_RECIPIENTS,
        )));
    }

    let request = build_request(&amounts)?;

    // Resolve `from` to an account and the sources of funds selection may draw
    // upon. An address confines a transparent source to that address and a
    // shielded source to the shielded pools; an account UUID draws on the pools
    // named by `fund_source` (by default, any shielded pool).
    let (account, spend_policy) = if let Some(address) = Address::decode(wallet.params(), &from) {
        if fund_source.is_some() {
            return Err(LegacyCode::InvalidParameter
                .with_message(fl!("err-pczt-fund-source-requires-account")));
        }

        let account = get_account_for_address(wallet.as_ref(), &address)?;
        let spend_policy = spend_policy_for(&address);
        (account, spend_policy)
    } else if let Ok(uuid) = from.parse() {
        let account_id = AccountUuid::from_uuid(uuid);
        let account = wallet
            .as_ref()
            .get_account(account_id)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            .ok_or_else(|| {
                LegacyCode::InvalidParameter.with_message(fl!("err-account-not-found"))
            })?;

        let spend_policy = match &fund_source {
            Some(value) => FundSource::parse(value, wallet.params())?.spend_policy(),
            None => SpendPolicy::default(),
        };
        (account, spend_policy)
    } else {
        return Err(LegacyCode::InvalidAddressOrKey.with_message(fl!("err-pczt-from-invalid")));
    };

    let privacy_policy = parse_privacy_policy(privacy_policy.as_deref())?;
    let confirmations_policy = confirmations_policy_for_minconf(minconf)?;

    let (pczt, required_policy) = build_pczt(
        &mut wallet,
        &account,
        &spend_policy,
        request,
        privacy_policy,
        confirmations_policy,
    )?;

    Ok(CreateResult {
        pczt: encode_pczt_base64(pczt)?,
        privacy_policy: required_policy.to_string(),
    })
}

/// Proposes a transfer and builds an unproven, unsigned PCZT from it.
///
/// Enforces `privacy_policy` and the configured Orchard action limit on the
/// proposal, then records Zallet's signing hints and the proposal's minimum
/// required privacy policy as proprietary fields. The required policy is
/// returned alongside the PCZT so the caller can report it.
///
/// Shared with `z_sendfromaccount`, which sends the built PCZT in one shot.
pub(super) fn build_pczt(
    wallet: &mut DbHandle,
    account: &zcash_client_sqlite::wallet::Account,
    spend_policy: &SpendPolicy,
    request: TransactionRequest,
    privacy_policy: PrivacyPolicy,
    confirmations_policy: ConfirmationsPolicy,
) -> RpcResult<(Pczt, PrivacyPolicy)> {
    let params = *wallet.params();
    let proposal = propose_and_check(
        wallet.as_mut(),
        &params,
        account.id(),
        request,
        privacy_policy,
        confirmations_policy,
        spend_policy,
    )?;

    // The minimum policy the proposal actually requires, reported to the caller
    // and recorded in the PCZT for `pczt_sign` to check acknowledgement
    // against. `privacy_policy` was already enforced above, so this is always
    // compatible with what the caller permitted.
    let required_policy = required_privacy_policy(&proposal);

    // Derivation info used to populate the zallet signing hints below. A
    // view-only account has none; it can still create a PCZT (the flagship
    // offline-signing flow), it just cannot record hints naming its own seed.
    let derivation = account.source().key_derivation();

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
                PROP_PRIVACY_POLICY.to_string(),
                <&'static str>::from(required_policy).as_bytes().to_vec(),
            );
            if let Some(derivation) = derivation {
                global.set_proprietary(
                    PROP_SEED_FINGERPRINT.to_string(),
                    derivation.seed_fingerprint().to_bytes().to_vec(),
                );
                global.set_proprietary(
                    PROP_ACCOUNT_INDEX.to_string(),
                    u32::from(derivation.account_index()).to_le_bytes().to_vec(),
                );
            }
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

    Ok((pczt, required_policy))
}
