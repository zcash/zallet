//! PCZT sign method — sign a PCZT with the wallet's keys.

use std::collections::HashSet;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use pczt::Pczt;
use pczt::roles::signer::{Signer, extract_orchard_spend_auth_signatures};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Serialize;
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zcash_keys::keys::UnifiedSpendingKey;
use zip32::{AccountId, fingerprint::SeedFingerprint};

use super::pczt_common::{
    PROP_ACCOUNT_INDEX, PROP_ADDRESS_INDEX, PROP_PRIVACY_POLICY, PROP_SCOPE, PROP_SEED_FINGERPRINT,
    decode_key_scope, decode_pczt_base64, encode_pczt_base64,
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
pub(super) const PARAM_PRIVACY_POLICY_DESC: &str =
    "Policy acknowledging what information the transaction may reveal.";
pub(super) const PARAM_STRICT_DESC: &str = "If true, fail if any inputs cannot be signed.";

/// The account signing hints recorded in a PCZT created by this wallet.
struct SigningHints {
    seed_fp: SeedFingerprint,
    account_idx: AccountId,
}

/// Reads the `zallet.v1.*` account signing hints, if present.
///
/// A PCZT created elsewhere (another wallet, `zcash-devtool`, a multi-party
/// flow this wallet did not initiate) carries no hints; that is not an error —
/// the wallet simply has no way to locate its keys, and every input is
/// reported as unsigned.
///
/// Hints that are present but malformed are rejected: they indicate a
/// corrupted or tampered PCZT, not a foreign one.
fn read_signing_hints(pczt: &Pczt) -> RpcResult<Option<SigningHints>> {
    let proprietary = pczt.global().proprietary();

    let (Some(seed_fp_bytes), Some(account_idx_bytes)) = (
        proprietary.get(PROP_SEED_FINGERPRINT),
        proprietary.get(PROP_ACCOUNT_INDEX),
    ) else {
        return Ok(None);
    };

    let seed_fp =
        SeedFingerprint::from_bytes(seed_fp_bytes.as_slice().try_into().map_err(|_| {
            LegacyCode::InvalidParameter.with_message(fl!("err-pczt-invalid-seed-fingerprint"))
        })?);

    let account_idx_u32 =
        u32::from_le_bytes(account_idx_bytes.as_slice().try_into().map_err(|_| {
            LegacyCode::InvalidParameter.with_message(fl!("err-pczt-invalid-account-index"))
        })?);

    let account_idx = AccountId::try_from(account_idx_u32).map_err(|_| {
        LegacyCode::InvalidParameter.with_message(fl!(
            "err-pczt-account-index-out-of-range",
            index = account_idx_u32,
        ))
    })?;

    Ok(Some(SigningHints {
        seed_fp,
        account_idx,
    }))
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
                        tracing::warn!("Malformed {PROP_SCOPE} for transparent input {i}");
                        return None;
                    }
                };
                let addr_idx_u32 = match addr_idx_bytes.as_slice().try_into() {
                    Ok(bytes) => u32::from_le_bytes(bytes),
                    Err(_) => {
                        tracing::warn!("Malformed {PROP_ADDRESS_INDEX} for transparent input {i}");
                        return None;
                    }
                };

                let Some(scope) = decode_key_scope(scope_u32) else {
                    tracing::warn!("Invalid scope {scope_u32} for transparent input {i}");
                    return None;
                };

                let addr_idx = NonHardenedChildIndex::from_index(addr_idx_u32).or_else(|| {
                    tracing::warn!(
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

    let mut transparent_signed = 0;
    let mut unsigned_transparent = Vec::new();
    let mut sapling_signed = 0;
    let mut unsigned_sapling = Vec::new();
    let mut orchard_signed = 0;
    let mut unsigned_orchard = Vec::new();
    let mut ironwood_signed = 0;
    let mut unsigned_ironwood = Vec::new();

    match &usk {
        None => {
            // No key: everything not already signed is reported unsigned.
            unsigned_transparent.extend(0..transparent_derivation_info.len());
            unsigned_sapling.extend(0..sapling_count);
            unsigned_orchard.extend((0..orchard_count).filter(|i| !presigned_orchard.contains(i)));
            unsigned_ironwood
                .extend((0..ironwood_count).filter(|i| !presigned_ironwood.contains(i)));
        }
        Some(usk) => {
            // Sign transparent inputs. An input we lack derivation info for, or
            // whose key derivation or signature fails, is recorded as unsigned:
            // it may belong to a different key.
            for (i, derivation_info) in transparent_derivation_info.iter().enumerate() {
                match derivation_info {
                    Some((scope, addr_idx)) => {
                        match usk.transparent().derive_secret_key(*scope, *addr_idx) {
                            Ok(sk) => match signer.sign_transparent(i, &sk) {
                                Ok(()) => transparent_signed += 1,
                                Err(e) => {
                                    tracing::debug!("Transparent input {i} left unsigned: {e:?}");
                                    unsigned_transparent.push(i);
                                }
                            },
                            Err(e) => {
                                tracing::debug!(
                                    "Transparent input {i} left unsigned: \
                                     key derivation failed: {e:?}"
                                );
                                unsigned_transparent.push(i);
                            }
                        }
                    }
                    None => unsigned_transparent.push(i),
                }
            }

            // Sign Sapling spends. A spend belonging to a different key returns
            // an error, which we record as unsigned.
            let sapling_ask = &usk.sapling().expsk.ask;
            for i in 0..sapling_count {
                match signer.sign_sapling(i, sapling_ask) {
                    Ok(()) => sapling_signed += 1,
                    Err(e) => {
                        tracing::debug!("Sapling spend {i} left unsigned: {e:?}");
                        unsigned_sapling.push(i);
                    }
                }
            }

            // Sign Orchard and Ironwood actions. Ironwood notes are
            // Orchard-shaped, so both pools sign under the same spend
            // authorizing key.
            let orchard_ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
            for i in (0..orchard_count).filter(|i| !presigned_orchard.contains(i)) {
                match signer.sign_orchard(i, &orchard_ask) {
                    Ok(()) => orchard_signed += 1,
                    Err(e) => {
                        tracing::debug!("Orchard action {i} left unsigned: {e:?}");
                        unsigned_orchard.push(i);
                    }
                }
            }
            for i in (0..ironwood_count).filter(|i| !presigned_ironwood.contains(i)) {
                match signer.sign_ironwood(i, &orchard_ask) {
                    Ok(()) => ironwood_signed += 1,
                    Err(e) => {
                        tracing::debug!("Ironwood action {i} left unsigned: {e:?}");
                        unsigned_ironwood.push(i);
                    }
                }
            }
        }
    }

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
