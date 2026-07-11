use std::convert::Infallible;
use std::num::NonZeroU32;

use abscissa_core::Application;
use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use orchard::builder::BundleType;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use zcash_client_backend::{
    data_api::{
        WalletRead,
        wallet::{ConfirmationsPolicy, create_pczt_from_proposal},
    },
    wallet::OvkPolicy,
};

use crate::{
    components::{
        database::DbHandle,
        json_rpc::{
            fund_source::FundSource,
            payments::{
                AmountParameter, build_request, pczt_policy_key, propose_transfer_with_policy,
                record_required_policy, required_privacy_policy,
            },
            server::LegacyCode,
            utils::parse_account_parameter,
        },
        keystore::KeyStore,
    },
    prelude::*,
};

/// Response to a `z_proposetransaction` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// A proposed transaction, returned for inspection before it is finalized.
#[derive(Clone, Debug, Serialize, Deserialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// The proposed transaction as a hex-encoded PCZT.
    ///
    /// This can be inspected to review the transaction's effects, and later passed to
    /// `z_finalizetransaction` to sign and broadcast it.
    pczt: String,

    /// The privacy policy required to execute this transaction.
    ///
    /// This is the strictest policy that permits the proposed transaction; it must be supplied
    /// to `z_finalizetransaction` as acknowledgement of the transaction's privacy implications.
    privacy_policy: String,
}

pub(super) const PARAM_ACCOUNT_DESC: &str = "The UUID of the account to send the funds from.";
pub(super) const PARAM_FUND_SOURCE_DESC: &str = "Where funds may be drawn from: \"orchard\", \"sapling\", \"any_transparent\", or an array \
     of transparent addresses.";
pub(super) const PARAM_RECIPIENTS_DESC: &str =
    "An array of JSON objects representing the amounts to send.";
pub(super) const PARAM_RECIPIENTS_REQUIRED: bool = true;
pub(super) const PARAM_MINCONF_DESC: &str = "Only use funds confirmed at least this many times.";

pub(crate) async fn call(
    mut wallet: DbHandle,
    keystore: KeyStore,
    account: JsonValue,
    fund_source: JsonValue,
    recipients: Vec<AmountParameter>,
    minconf: Option<u32>,
) -> Response {
    let request = build_request(&recipients)?;

    let account_id = parse_account_parameter(wallet.as_ref(), &keystore, &account).await?;

    // Validate that the account exists before proposing, for a clear error.
    if wallet
        .as_ref()
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .is_none()
    {
        return Err(LegacyCode::InvalidParameter
            .with_message(format!("No account with UUID {}", account_id.expose_uuid())));
    }

    let fund_source = FundSource::parse(&fund_source, wallet.params())?;

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

    let proposal = propose_transfer_with_policy(
        wallet.as_mut(),
        &params,
        account_id,
        request,
        confirmations_policy,
        &fund_source.spend_policy(),
    )?;

    // No privacy policy is required to PROPOSE: the point of this method is to let the caller
    // see what the transaction would reveal, and decide. The policy is reported here and
    // enforced at `z_finalizetransaction`.
    let privacy_policy = required_privacy_policy(&proposal);

    // Build the PCZT from the proposal. This touches no spending key and generates no proof;
    // both are deferred to `z_finalizetransaction`.
    // No expiry override: let the builder derive the expiry from the target height.
    let target_expiry_height = None;

    // The change strategy does not request unpadded Orchard bundles, so the bundle type must
    // be the default; the two have to agree or the PCZT will not match the proposal.
    let orchard_pool_bundle_type = BundleType::DEFAULT;

    let pczt = create_pczt_from_proposal::<_, _, Infallible, _, Infallible, _>(
        wallet.as_mut(),
        &params,
        account_id,
        OvkPolicy::Sender,
        &proposal,
        target_expiry_height,
        orchard_pool_bundle_type,
    )
    .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to create PCZT: {e}")))?;

    // Record the required policy so `z_finalizetransaction` can check the caller's
    // acknowledgement against what the transaction actually reveals, rather than re-deriving it
    // from the PCZT, which does not carry enough information to do so faithfully.
    let pczt_bytes = pczt
        .serialize()
        .map_err(|e| LegacyCode::Wallet.with_message(format!("Failed to serialize PCZT: {e:?}")))?;
    record_required_policy(pczt_policy_key(&pczt_bytes), privacy_policy);

    Ok(ResultType {
        pczt: hex::encode(pczt_bytes),
        privacy_policy: privacy_policy.to_string(),
    })
}
