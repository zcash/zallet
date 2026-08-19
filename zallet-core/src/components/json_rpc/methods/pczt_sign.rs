//! PCZT sign method — sign a PCZT with the wallet's keys.

use std::collections::HashSet;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use pczt::Pczt;
use pczt::roles::signer::{Error as SignerError, Signer, extract_orchard_spend_auth_signatures};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Serialize;
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zcash_keys::keys::UnifiedSpendingKey;

use super::pczt_common::{
    PROP_ADDRESS_INDEX, PROP_PRIVACY_POLICY, PROP_SCOPE, decode_key_scope, decode_pczt_base64,
    encode_pczt_base64, read_signing_hints,
};
use super::pczt_error::PcztError;
use crate::{
    components::{
        database::DbHandle,
        json_rpc::{
            payments::{PrivacyPolicy, parse_privacy_policy},
            server::LegacyCode,
        },
        keystore::KeyStore,
    },
    fl,
};

pub(crate) type Response = RpcResult<ResultType>;

/// Result of signing a PCZT.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct SignResult {
    /// The base64-encoded signed PCZT.
    pub pczt: String,
    /// Number of transparent inputs signed.
    pub transparent_signed: usize,
    /// Number of Sapling spends signed.
    pub sapling_signed: usize,
    /// Number of Orchard actions signed.
    ///
    /// Actions that already carried a signature (a previous signer's, or the
    /// padding dummies signed when the PCZT was created) are not counted here,
    /// nor reported as unsigned.
    pub orchard_signed: usize,
    /// Number of Ironwood actions signed, under the same accounting as
    /// `orchard_signed`.
    pub ironwood_signed: usize,
    /// Indices of transparent inputs that could not be signed.
    pub unsigned_transparent: Vec<usize>,
    /// Indices of Sapling spends that could not be signed.
    pub unsigned_sapling: Vec<usize>,
    /// Indices of Orchard actions that could not be signed.
    pub unsigned_orchard: Vec<usize>,
    /// Indices of Ironwood actions that could not be signed.
    pub unsigned_ironwood: Vec<usize>,
}

pub(crate) type ResultType = SignResult;

pub(super) const PARAM_PCZT_DESC: &str = "The base64-encoded PCZT to sign.";
pub(super) const PARAM_PRIVACY_POLICY_DESC: &str = "Policy acknowledging what information the transaction may reveal, using the same values as \
     `z_sendmany`. Defaults to \"FullPrivacy\".";
pub(super) const PARAM_STRICT_DESC: &str = "If true, fail if any inputs cannot be signed.";

/// Attempts to sign each candidate index, returning how many were signed and
/// which were left unsigned.
///
/// `attempt` returns `None` when the wallet holds no key for the pool at all,
/// which reports every candidate unsigned — the same outcome as a key that
/// turns out not to match, and true either way: this wallet did not sign them.
/// `pool` names the input kind for the debug log.
fn sign_each(
    pool: &str,
    candidates: impl Iterator<Item = usize>,
    mut attempt: impl FnMut(usize) -> Option<Result<(), SignerError>>,
) -> (usize, Vec<usize>) {
    let mut signed = 0;
    let mut unsigned = Vec::new();

    for i in candidates {
        match attempt(i) {
            Some(Ok(())) => signed += 1,
            Some(Err(e)) => {
                tracing::debug!("{pool} {i} left unsigned: {e:?}");
                unsigned.push(i);
            }
            None => unsigned.push(i),
        }
    }

    (signed, unsigned)
}

/// Checks the caller's privacy-policy acknowledgement against the requirement
/// recorded in the PCZT.
///
/// A PCZT without a recorded requirement (one created elsewhere) cannot be
/// checked: the requirement is not re-derivable from the PCZT alone, so the
/// supplied policy is accepted as the caller's own acknowledgement.
fn check_privacy_policy(pczt: &Pczt, acknowledged: PrivacyPolicy) -> RpcResult<()> {
    let Some(recorded) = pczt.global().proprietary().get(PROP_PRIVACY_POLICY) else {
        return Ok(());
    };

    let required = std::str::from_utf8(recorded)
        .ok()
        .and_then(PrivacyPolicy::from_str)
        .ok_or_else(|| {
            LegacyCode::InvalidParameter.with_message(fl!("err-pczt-invalid-recorded-policy"))
        })?;

    if acknowledged.is_compatible_with(required) {
        Ok(())
    } else {
        Err(LegacyCode::InvalidParameter.with_message(fl!(
            "err-pczt-policy-not-acknowledged",
            required = <&'static str>::from(required),
            acknowledged = <&'static str>::from(acknowledged),
        )))
    }
}

/// Signs a PCZT with the wallet's keys.
///
/// Signs every input that the wallet holds keys for, using the account
/// identified by the `zallet.v1.*` signing hints that `pczt_create` records.
/// Inputs that do not belong to this wallet are left unsigned and reported, as
/// is every input of a PCZT that carries no hints (one created by a different
/// wallet).
pub(crate) async fn call(
    wallet: DbHandle,
    keystore: KeyStore,
    pczt_base64: &str,
    privacy_policy: Option<String>,
    strict: Option<bool>,
) -> Response {
    let pczt = decode_pczt_base64(pczt_base64)?;

    // Signing is the point of no return for the information the transaction
    // reveals, so the acknowledgement is checked here. The default of
    // `FullPrivacy` refuses to sign anything that reveals more than a fully
    // shielded transfer.
    check_privacy_policy(&pczt, parse_privacy_policy(privacy_policy.as_deref())?)?;

    let hints = read_signing_hints(&pczt)?;

    // Read the per-input transparent derivation hints before the Signer
    // consumes the PCZT.
    //
    // An unusable hint only means the input goes unsigned, so it is logged at
    // `debug!` alongside the per-input signing failures below rather than at
    // `warn!`: these messages name the account's HD address index, which is a
    // privacy signal that should not reach a default-level log.
    let transparent_derivation_info: Vec<Option<(TransparentKeyScope, NonHardenedChildIndex)>> =
        pczt.transparent()
            .inputs()
            .iter()
            .enumerate()
            .map(|(i, input)| {
                let scope_bytes = input.proprietary().get(PROP_SCOPE)?;
                let addr_idx_bytes = input.proprietary().get(PROP_ADDRESS_INDEX)?;

                let scope_u32 = match scope_bytes.as_slice().try_into() {
                    Ok(bytes) => u32::from_le_bytes(bytes),
                    Err(_) => {
                        tracing::debug!("Malformed {PROP_SCOPE} for transparent input {i}");
                        return None;
                    }
                };
                let addr_idx_u32 = match addr_idx_bytes.as_slice().try_into() {
                    Ok(bytes) => u32::from_le_bytes(bytes),
                    Err(_) => {
                        tracing::debug!("Malformed {PROP_ADDRESS_INDEX} for transparent input {i}");
                        return None;
                    }
                };

                let Some(scope) = decode_key_scope(scope_u32) else {
                    tracing::debug!("Invalid scope {scope_u32} for transparent input {i}");
                    return None;
                };

                let addr_idx = NonHardenedChildIndex::from_index(addr_idx_u32).or_else(|| {
                    tracing::debug!(
                        "Invalid address index {addr_idx_u32} for transparent input {i}"
                    );
                    None
                })?;

                Some((scope, addr_idx))
            })
            .collect();

    // Actions that already carry a spend-auth signature: a previous signer's
    // contribution, or the padding dummies that the IO Finalizer signs when the
    // PCZT is created. Attempting to re-sign them can only fail (we do not hold
    // a dummy's ephemeral key), so they are skipped rather than reported as
    // unsigned.
    //
    // There is no equivalent skip for Sapling spends or transparent inputs: as
    // of pczt 0.8.0-rc.1 neither `Spend::spend_auth_sig` nor an input's
    // `partial_signatures` has a public accessor, so an already-signed one
    // cannot be recognized. It is reported unsigned instead, which is at least
    // true of *this* wallet. Neither pool pads with dummies, so this affects
    // only the report for a PCZT another party has already signed.
    let (presigned_orchard, presigned_ironwood): (HashSet<usize>, HashSet<usize>) = {
        let mut orchard_set = HashSet::new();
        let mut ironwood_set = HashSet::new();
        for sig in extract_orchard_spend_auth_signatures(&pczt) {
            match sig.value_pool() {
                orchard::ValuePool::Orchard => orchard_set.insert(sig.action_index()),
                orchard::ValuePool::Ironwood => ironwood_set.insert(sig.action_index()),
            };
        }
        (orchard_set, ironwood_set)
    };

    // Count shielded inputs before the Signer consumes the PCZT.
    let sapling_count = pczt.sapling().spends().len();
    let orchard_count = pczt.orchard().actions().len();
    let ironwood_count = pczt.ironwood().actions().len();

    // Locate the spending key named by the hints. Failure to decrypt the named
    // seed (other than the wallet being locked) means this wallet does not hold
    // it — the multi-party case — and is treated like an absent hint rather
    // than a server fault.
    //
    // The seed is not bound to an account record here, as it is on the account-based
    // spend paths (see `payments::spending_key_for_account`): the key is named by the
    // PCZT's hints rather than by an account, so there is no record to bind it to.
    // `z_sendfromaccount` binds before it drives this method over its own PCZT.
    let usk = match &hints {
        None => None,
        Some(hints) => match keystore.decrypt_seed(&hints.seed_fp).await {
            Ok(seed) => Some(
                UnifiedSpendingKey::from_seed(
                    wallet.params(),
                    seed.expose_secret(),
                    hints.account_idx,
                )
                .map_err(|e| {
                    LegacyCode::InvalidAddressOrKey
                        .with_message(fl!("err-pczt-derive-spending-key", error = e.to_string()))
                })?,
            ),
            Err(e)
                if matches!(e.kind(), crate::error::ErrorKind::Generic)
                    && e.to_string() == "Wallet is locked" =>
            {
                return Err(LegacyCode::WalletUnlockNeeded.with_message(e.to_string()));
            }
            Err(e) => {
                tracing::info!(
                    "Seed named by the PCZT's signing hints is not in this wallet; \
                     leaving all inputs unsigned: {e}"
                );
                None
            }
        },
    };

    let mut signer = Signer::new(pczt).map_err(PcztError::SignerInit)?;

    // Ironwood notes are Orchard-shaped, so both pools sign under the same
    // spend authorizing key. Both keys are absent exactly when the wallet does
    // not hold the seed the PCZT names.
    let sapling_ask = usk.as_ref().map(|usk| &usk.sapling().expsk.ask);
    let orchard_ask = usk
        .as_ref()
        .map(|usk| orchard::keys::SpendAuthorizingKey::from(usk.orchard()));

    // Sign transparent inputs. An input we lack derivation info for, or whose
    // key derivation or signature fails, is recorded as unsigned: it may belong
    // to a different key. This pass is not `sign_each`'s shape, because
    // deriving the per-input key is itself a step that can fail.
    let (transparent_signed, unsigned_transparent) = {
        let mut signed = 0;
        let mut unsigned = Vec::new();
        for (i, derivation_info) in transparent_derivation_info.iter().enumerate() {
            let Some((usk, (scope, addr_idx))) = usk.as_ref().zip(derivation_info.as_ref()) else {
                unsigned.push(i);
                continue;
            };
            match usk.transparent().derive_secret_key(*scope, *addr_idx) {
                Ok(sk) => match signer.sign_transparent(i, &sk) {
                    Ok(()) => signed += 1,
                    Err(e) => {
                        tracing::debug!("Transparent input {i} left unsigned: {e:?}");
                        unsigned.push(i);
                    }
                },
                Err(e) => {
                    tracing::debug!(
                        "Transparent input {i} left unsigned: key derivation failed: {e:?}"
                    );
                    unsigned.push(i);
                }
            }
        }
        (signed, unsigned)
    };

    let (sapling_signed, unsigned_sapling) = sign_each("Sapling spend", 0..sapling_count, |i| {
        sapling_ask.map(|ask| signer.sign_sapling(i, ask))
    });

    let (orchard_signed, unsigned_orchard) = sign_each(
        "Orchard action",
        (0..orchard_count).filter(|i| !presigned_orchard.contains(i)),
        |i| orchard_ask.as_ref().map(|ask| signer.sign_orchard(i, ask)),
    );

    let (ironwood_signed, unsigned_ironwood) = sign_each(
        "Ironwood action",
        (0..ironwood_count).filter(|i| !presigned_ironwood.contains(i)),
        |i| orchard_ask.as_ref().map(|ask| signer.sign_ironwood(i, ask)),
    );

    if strict.unwrap_or(false)
        && (!unsigned_transparent.is_empty()
            || !unsigned_sapling.is_empty()
            || !unsigned_orchard.is_empty()
            || !unsigned_ironwood.is_empty())
    {
        return Err(LegacyCode::Verify.with_message(fl!(
            "err-pczt-strict-unsigned",
            transparent = unsigned_transparent.len(),
            sapling = unsigned_sapling.len(),
            orchard = unsigned_orchard.len(),
            ironwood = unsigned_ironwood.len(),
        )));
    }

    Ok(SignResult {
        pczt: encode_pczt_base64(signer.finish())?,
        transparent_signed,
        sapling_signed,
        orchard_signed,
        ironwood_signed,
        unsigned_transparent,
        unsigned_sapling,
        unsigned_orchard,
        unsigned_ironwood,
    })
}
