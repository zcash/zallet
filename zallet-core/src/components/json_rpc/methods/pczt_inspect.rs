//! PCZT inspect method — decode a PCZT and describe what it commits to.
//!
//! This is the review step of the PCZT flow: before handing a PCZT to
//! `pczt_sign`, a caller (particularly one whose PCZT has passed through
//! other parties) can see the transaction's recipients, amounts, and recorded
//! privacy requirement, and check them against what they originally created.
//!
//! Everything reported here is read from the PCZT as the creator recorded it;
//! none of it is cryptographically verified until `pczt_extract`. A malicious
//! counterparty can misstate values or strip fields, so treat this as a
//! description of what the PCZT *claims*, sufficient for spotting alterations
//! relative to a PCZT you created yourself.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use pczt::roles::prover::Prover;
use pczt::roles::signer::extract_orchard_spend_auth_signatures;
use schemars::JsonSchema;
use serde::Serialize;
use transparent::address::TransparentAddress;
use zcash_keys::address::Address;
use zcash_protocol::TxId;
use zcash_script::script;
use zip32::fingerprint::SeedFingerprint;

use super::pczt_common::{
    PROP_ACCOUNT_INDEX, PROP_BACKEND_PROPOSAL_INFO, PROP_PRIVACY_POLICY, PROP_SEED_FINGERPRINT,
    decode_pczt_base64,
};
use crate::network::Network;

pub(crate) type Response = RpcResult<ResultType>;

/// A transparent input of the PCZT.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct TransparentInputInfo {
    /// The ID of the transaction whose output is being spent.
    pub prevout_txid: String,
    /// The index of the output being spent.
    pub prevout_index: u32,
    /// The value of the output being spent, in zatoshis, as claimed by the
    /// PCZT's creator.
    pub value_zat: u64,
    /// The address the spent output was received at, when its script is a
    /// standard one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// A transparent output of the PCZT.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct TransparentOutputInfo {
    /// The value of the output, in zatoshis.
    pub value_zat: u64,
    /// The recipient address, when the output script is a standard one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The user-facing address this output pays, as recorded by the creator
    /// (e.g. the unified address whose transparent receiver `address` is).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_address: Option<String>,
}

/// The transparent half of the PCZT.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct TransparentInfo {
    /// The transparent inputs.
    pub inputs: Vec<TransparentInputInfo>,
    /// The transparent outputs.
    pub outputs: Vec<TransparentOutputInfo>,
}

/// A shielded output of the PCZT, as recorded by its creator.
///
/// These fields are optional in the PCZT format and may have been redacted;
/// an on-chain observer cannot recover them, and neither can this method.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct ShieldedOutputInfo {
    /// The value of the output, in zatoshis, if recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_zat: Option<u64>,
    /// The user-facing address this output pays, if recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_address: Option<String>,
}

/// The Sapling bundle of the PCZT.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct SaplingInfo {
    /// The number of Sapling spends.
    pub spends: usize,
    /// The Sapling outputs.
    pub outputs: Vec<ShieldedOutputInfo>,
    /// The net value of Sapling spends minus outputs, in zatoshis.
    pub value_balance_zat: i128,
    /// Whether every required Sapling proof is present.
    pub proofs_complete: bool,
}

/// An Orchard-family (Orchard or Ironwood) bundle of the PCZT.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct OrchardInfo {
    /// The number of actions.
    pub actions: usize,
    /// The number of actions that carry a spend-auth signature (including the
    /// padding dummies signed at creation).
    pub signed_actions: usize,
    /// The outputs of the actions.
    pub outputs: Vec<ShieldedOutputInfo>,
    /// The net value of spends minus outputs, in zatoshis.
    pub value_balance_zat: i128,
    /// Whether the bundle proof is present (or no proof is required).
    pub proof_complete: bool,
}

/// The account signing hints recorded in the PCZT by `pczt_create`.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct SigningHintsInfo {
    /// The fingerprint of the wallet seed whose keys should sign.
    pub seed_fingerprint: String,
    /// The ZIP 32 account index within that seed.
    pub account_index: u32,
}

/// Description of a PCZT.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct InspectResult {
    /// The transaction version.
    pub tx_version: u32,
    /// The consensus branch the transaction commits to, as hex.
    pub consensus_branch_id: String,
    /// The block height after which the transaction can no longer be mined.
    pub expiry_height: u32,
    /// The minimum privacy policy the transaction requires, as recorded by
    /// `pczt_create`. Absent for a PCZT created elsewhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_policy: Option<String>,
    /// The account signing hints recorded by `pczt_create`, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_hints: Option<SigningHintsInfo>,
    /// Whether this wallet's backend created the PCZT (and can therefore
    /// record the extracted transaction; see `pczt_extract`).
    pub wallet_created: bool,
    /// The transaction fee implied by the recorded values, in zatoshis:
    /// transparent inputs minus transparent outputs, plus each shielded
    /// bundle's net value balance. Relies on the creator-claimed transparent
    /// input values, which are not verified here.
    pub fee_zat: i128,
    /// The transparent inputs and outputs.
    pub transparent: TransparentInfo,
    /// The Sapling bundle.
    pub sapling: SaplingInfo,
    /// The Orchard bundle.
    pub orchard: OrchardInfo,
    /// The Ironwood bundle.
    pub ironwood: OrchardInfo,
}

pub(crate) type ResultType = InspectResult;

pub(super) const PARAM_PCZT_DESC: &str = "The base64-encoded PCZT to inspect.";

/// The address paying `script_pubkey`, when it is a standard script.
fn address_for_script(params: &Network, script_pubkey: &[u8]) -> Option<String> {
    script::FromChain::parse(&script::Code(script_pubkey.to_vec()))
        .ok()
        .as_ref()
        .and_then(TransparentAddress::from_script_from_chain)
        .map(|addr| Address::Transparent(addr).encode(params))
}

/// Converts a magnitude-and-is-negative pair into a signed zatoshi amount.
fn value_balance(&(magnitude, is_negative): &(u64, bool)) -> i128 {
    let magnitude = i128::from(magnitude);
    if is_negative { -magnitude } else { magnitude }
}

/// Decodes a PCZT and describes what it commits to.
pub(crate) fn call(params: &Network, pczt_base64: &str) -> Response {
    let pczt = decode_pczt_base64(pczt_base64)?;

    let proprietary = pczt.global().proprietary();

    let privacy_policy = proprietary
        .get(PROP_PRIVACY_POLICY)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(String::from);

    // Malformed hints are reported as absent rather than rejected: inspection
    // should describe as much of a questionable PCZT as it can, and the strict
    // validation belongs to `pczt_sign`.
    let signing_hints = proprietary
        .get(PROP_SEED_FINGERPRINT)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .map(SeedFingerprint::from_bytes)
        .zip(
            proprietary
                .get(PROP_ACCOUNT_INDEX)
                .and_then(|bytes| <[u8; 4]>::try_from(bytes.as_slice()).ok())
                .map(u32::from_le_bytes),
        )
        .map(|(seed_fp, account_index)| SigningHintsInfo {
            seed_fingerprint: seed_fp.to_string(),
            account_index,
        });

    let wallet_created = proprietary.contains_key(PROP_BACKEND_PROPOSAL_INFO);

    let transparent = TransparentInfo {
        inputs: pczt
            .transparent()
            .inputs()
            .iter()
            .map(|input| TransparentInputInfo {
                prevout_txid: TxId::from_bytes(*input.prevout_txid()).to_string(),
                prevout_index: *input.prevout_index(),
                value_zat: *input.value(),
                address: address_for_script(params, input.script_pubkey()),
            })
            .collect(),
        outputs: pczt
            .transparent()
            .outputs()
            .iter()
            .map(|output| TransparentOutputInfo {
                value_zat: *output.value(),
                address: address_for_script(params, output.script_pubkey()),
                user_address: output.user_address().clone(),
            })
            .collect(),
    };

    // Which actions already carry spend-auth signatures, per pool.
    let (orchard_signed, ironwood_signed) = {
        let mut orchard = 0;
        let mut ironwood = 0;
        for sig in extract_orchard_spend_auth_signatures(&pczt) {
            match sig.value_pool() {
                orchard::ValuePool::Orchard => orchard += 1,
                orchard::ValuePool::Ironwood => ironwood += 1,
            }
        }
        (orchard, ironwood)
    };

    let shielded_outputs = |outputs: Vec<(Option<u64>, Option<String>)>| {
        outputs
            .into_iter()
            .map(|(value_zat, user_address)| ShieldedOutputInfo {
                value_zat,
                user_address,
            })
            .collect::<Vec<_>>()
    };

    let sapling_outputs = shielded_outputs(
        pczt.sapling()
            .outputs()
            .iter()
            .map(|out| (*out.value(), out.user_address().clone()))
            .collect(),
    );
    let orchard_outputs = shielded_outputs(
        pczt.orchard()
            .actions()
            .iter()
            .map(|act| (*act.output().value(), act.output().user_address().clone()))
            .collect(),
    );
    let ironwood_outputs = shielded_outputs(
        pczt.ironwood()
            .actions()
            .iter()
            .map(|act| (*act.output().value(), act.output().user_address().clone()))
            .collect(),
    );

    let sapling_value_balance = *pczt.sapling().value_sum();
    let orchard_value_balance = value_balance(pczt.orchard().value_sum());
    let ironwood_value_balance = value_balance(pczt.ironwood().value_sum());

    let transparent_in: i128 = transparent
        .inputs
        .iter()
        .map(|input| i128::from(input.value_zat))
        .sum();
    let transparent_out: i128 = transparent
        .outputs
        .iter()
        .map(|output| i128::from(output.value_zat))
        .sum();

    // fee = net transparent inflow + each shielded bundle's net outflow. As
    // with everything here, this is as claimed: the transparent input values
    // are the creator's assertions about the chain.
    let fee_zat = transparent_in - transparent_out
        + sapling_value_balance
        + orchard_value_balance
        + ironwood_value_balance;

    let sapling_count = pczt.sapling().spends().len();
    let orchard_count = pczt.orchard().actions().len();
    let ironwood_count = pczt.ironwood().actions().len();

    // The Prover reports which proofs are still missing.
    let prover = Prover::new(pczt.clone());

    Ok(InspectResult {
        tx_version: *pczt.global().tx_version(),
        consensus_branch_id: format!("{:08x}", pczt.global().consensus_branch_id()),
        expiry_height: *pczt.global().expiry_height(),
        privacy_policy,
        signing_hints,
        wallet_created,
        fee_zat,
        transparent,
        sapling: SaplingInfo {
            spends: sapling_count,
            outputs: sapling_outputs,
            value_balance_zat: sapling_value_balance,
            proofs_complete: !prover.requires_sapling_proofs(),
        },
        orchard: OrchardInfo {
            actions: orchard_count,
            signed_actions: orchard_signed,
            outputs: orchard_outputs,
            value_balance_zat: orchard_value_balance,
            proof_complete: !prover.requires_orchard_proof(),
        },
        ironwood: OrchardInfo {
            actions: ironwood_count,
            signed_actions: ironwood_signed,
            outputs: ironwood_outputs,
            value_balance_zat: ironwood_value_balance,
            proof_complete: !prover.requires_ironwood_proof(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::value_balance;

    #[test]
    fn value_balance_sign_convention() {
        assert_eq!(value_balance(&(0, false)), 0);
        assert_eq!(value_balance(&(0, true)), 0);
        assert_eq!(value_balance(&(5000, false)), 5000);
        assert_eq!(value_balance(&(5000, true)), -5000);
        // The magnitude of the most negative sum representable in the wire
        // format survives the conversion.
        assert_eq!(value_balance(&(u64::MAX, true)), -i128::from(u64::MAX));
    }
}
