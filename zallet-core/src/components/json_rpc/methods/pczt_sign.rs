//! PCZT sign method — sign a PCZT with the wallet's keys.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use pczt::roles::signer::Signer;
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Serialize;
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zcash_keys::keys::UnifiedSpendingKey;
use zip32::{AccountId, fingerprint::SeedFingerprint};

use super::pczt_common::{decode_pczt_base64, encode_pczt_base64};
use crate::components::{database::DbHandle, json_rpc::server::LegacyCode, keystore::KeyStore};

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
    pub orchard_signed: usize,
    /// Indices of transparent inputs that could not be signed.
    pub unsigned_transparent: Vec<usize>,
    /// Indices of Sapling spends that could not be signed.
    pub unsigned_sapling: Vec<usize>,
    /// Indices of Orchard actions that could not be signed.
    pub unsigned_orchard: Vec<usize>,
}

pub(crate) type ResultType = SignResult;

pub(super) const PARAM_PCZT_DESC: &str = "The base64-encoded PCZT to sign.";
pub(super) const PARAM_STRICT_DESC: &str = "If true, fail if any inputs cannot be signed.";

/// Signs a PCZT with the wallet's keys.
///
/// Signs every input that the wallet holds keys for, using the account
/// identified by the `zallet.v1.*` signing hints that `pczt_create` records.
/// Inputs that do not belong to this wallet are left unsigned and reported.
pub(crate) async fn call(
    wallet: DbHandle,
    keystore: KeyStore,
    pczt_base64: &str,
    strict: Option<bool>,
) -> Response {
    let pczt = decode_pczt_base64(pczt_base64)?;

    // Read the account signing hints from the global proprietary fields.
    let seed_fp_bytes = pczt
        .global()
        .proprietary()
        .get("zallet.v1.seed_fingerprint")
        .ok_or_else(|| {
            LegacyCode::InvalidParameter
                .with_static("Missing signing hint: zallet.v1.seed_fingerprint")
        })?;

    let seed_fp =
        SeedFingerprint::from_bytes(seed_fp_bytes.as_slice().try_into().map_err(|_| {
            LegacyCode::InvalidParameter.with_static("Invalid seed fingerprint: expected 32 bytes")
        })?);

    let account_idx_bytes = pczt
        .global()
        .proprietary()
        .get("zallet.v1.account_index")
        .ok_or_else(|| {
            LegacyCode::InvalidParameter
                .with_static("Missing signing hint: zallet.v1.account_index")
        })?;

    let account_idx_u32 =
        u32::from_le_bytes(account_idx_bytes.as_slice().try_into().map_err(|_| {
            LegacyCode::InvalidParameter.with_static("Invalid account index: expected 4 bytes")
        })?);

    let account_idx = AccountId::try_from(account_idx_u32).map_err(|_| {
        LegacyCode::InvalidParameter.with_message(format!(
            "Invalid account index: {account_idx_u32} is out of range"
        ))
    })?;

    // Read the per-input transparent derivation hints before the Signer
    // consumes the PCZT.
    let transparent_derivation_info: Vec<Option<(TransparentKeyScope, NonHardenedChildIndex)>> =
        pczt.transparent()
            .inputs()
            .iter()
            .enumerate()
            .map(|(i, input)| {
                let scope_bytes = input.proprietary().get("zallet.v1.scope")?;
                let addr_idx_bytes = input.proprietary().get("zallet.v1.address_index")?;

                let scope_u32 = match scope_bytes.as_slice().try_into() {
                    Ok(bytes) => u32::from_le_bytes(bytes),
                    Err(_) => {
                        tracing::warn!("Malformed zallet.v1.scope for transparent input {i}");
                        return None;
                    }
                };
                let addr_idx_u32 = match addr_idx_bytes.as_slice().try_into() {
                    Ok(bytes) => u32::from_le_bytes(bytes),
                    Err(_) => {
                        tracing::warn!(
                            "Malformed zallet.v1.address_index for transparent input {i}"
                        );
                        return None;
                    }
                };

                let scope = match scope_u32 {
                    0 => TransparentKeyScope::EXTERNAL,
                    1 => TransparentKeyScope::INTERNAL,
                    2 => TransparentKeyScope::EPHEMERAL,
                    _ => {
                        tracing::warn!("Invalid scope {scope_u32} for transparent input {i}");
                        return None;
                    }
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

    // Count shielded inputs before the Signer consumes the PCZT.
    let sapling_count = pczt.sapling().spends().len();
    let orchard_count = pczt.orchard().actions().len();

    // Fetch the seed last, to avoid a keystore decryption if unnecessary.
    let seed = keystore
        .decrypt_seed(&seed_fp)
        .await
        .map_err(|e| match e.kind() {
            crate::error::ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
            }
            _ => LegacyCode::Database.with_message(e.to_string()),
        })?;

    let usk = UnifiedSpendingKey::from_seed(wallet.params(), seed.expose_secret(), account_idx)
        .map_err(|e| {
            LegacyCode::InvalidAddressOrKey
                .with_message(format!("Failed to derive spending key: {e}"))
        })?;

    let mut signer = Signer::new(pczt)
        .map_err(|_| LegacyCode::Verify.with_static("Failed to initialize signer"))?;

    // Sign transparent inputs. An input we lack derivation info for, or whose
    // key derivation or signature fails, is recorded as unsigned: it may belong
    // to a different key.
    let mut transparent_signed = 0;
    let mut unsigned_transparent = Vec::new();
    for (i, derivation_info) in transparent_derivation_info.iter().enumerate() {
        match derivation_info {
            Some((scope, addr_idx)) => {
                match usk.transparent().derive_secret_key(*scope, *addr_idx) {
                    Ok(sk) => match signer.sign_transparent(i, &sk) {
                        Ok(()) => transparent_signed += 1,
                        Err(_) => unsigned_transparent.push(i),
                    },
                    Err(_) => unsigned_transparent.push(i),
                }
            }
            None => unsigned_transparent.push(i),
        }
    }

    // Sign Sapling spends. A spend belonging to a different key returns an
    // error, which we record as unsigned.
    let mut sapling_signed = 0;
    let mut unsigned_sapling = Vec::new();
    let sapling_ask = &usk.sapling().expsk.ask;
    for i in 0..sapling_count {
        match signer.sign_sapling(i, sapling_ask) {
            Ok(()) => sapling_signed += 1,
            Err(_) => unsigned_sapling.push(i),
        }
    }

    // Sign Orchard actions.
    let mut orchard_signed = 0;
    let mut unsigned_orchard = Vec::new();
    let orchard_ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
    for i in 0..orchard_count {
        match signer.sign_orchard(i, &orchard_ask) {
            Ok(()) => orchard_signed += 1,
            Err(_) => unsigned_orchard.push(i),
        }
    }

    if strict.unwrap_or(false)
        && (!unsigned_transparent.is_empty()
            || !unsigned_sapling.is_empty()
            || !unsigned_orchard.is_empty())
    {
        return Err(LegacyCode::Verify.with_message(format!(
            "Strict mode: {} transparent, {} sapling, {} orchard inputs remain unsigned",
            unsigned_transparent.len(),
            unsigned_sapling.len(),
            unsigned_orchard.len()
        )));
    }

    Ok(SignResult {
        pczt: encode_pczt_base64(signer.finish())?,
        transparent_signed,
        sapling_signed,
        orchard_signed,
        unsigned_transparent,
        unsigned_sapling,
        unsigned_orchard,
    })
}
