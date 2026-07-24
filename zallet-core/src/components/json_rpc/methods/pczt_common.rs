//! Shared helpers for the PCZT RPC methods.

use std::sync::OnceLock;

use base64ct::{Base64, Encoding};
use jsonrpsee::types::ErrorObjectOwned;
use orchard::circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey};
use pczt::Pczt;
use sapling::circuit::{OutputVerifyingKey, SpendVerifyingKey};
use tokio::sync::Semaphore;
use transparent::keys::TransparentKeyScope;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BranchId, OrchardProtocolRevision};

use super::pczt_error::PcztError;
use crate::{components::json_rpc::server::LegacyCode, fl};

/// Maximum size, in bytes, accepted for a base64-encoded PCZT.
///
/// PCZTs grow with the number of inputs and outputs (and their proofs), but a
/// 10 MiB ceiling comfortably exceeds any realistic transaction while bounding
/// the work an unauthenticated decode can be made to do.
pub(super) const MAX_PCZT_BASE64_LEN: usize = 10 * 1024 * 1024;

/// Maximum number of PCZTs accepted by `pczt_combine` in a single call.
pub(super) const MAX_PCZTS_TO_COMBINE: usize = 20;

// Proprietary-field keys carrying Zallet's signing hints inside a PCZT.
//
// `pczt_create` writes these and `pczt_sign` reads them back — a private
// contract between the two methods. A PCZT does carry native ZIP 32 / BIP 32
// derivation metadata, but as of pczt 0.8.0-rc.1 it cannot be read back out:
// `Zip32Derivation` is crate-private, and the only public API touching the
// metadata is the Redactor, which clears it. So we stash our own copy.
// Defining these in one place keeps the writer and reader from drifting; the
// `v1` prefix leaves room for the format to evolve.

/// Global: the wallet seed fingerprint (32 bytes).
pub(super) const PROP_SEED_FINGERPRINT: &str = "zallet.v1.seed_fingerprint";

/// Global: the minimum privacy policy the transaction requires, as the UTF-8
/// name of the policy (e.g. `AllowRevealedAmounts`).
///
/// `pczt_create` computes this from the proposal and `pczt_sign` checks the
/// caller's acknowledgement against it. Living in the PCZT rather than in
/// server-side state, it survives restarts and travels with the PCZT to offline
/// signers. It is a guardrail against accidental disclosure, not tamper-proof
/// protection: a caller (or counterparty) editing the field could weaken the
/// recorded requirement, so a signer that did not create the PCZT should
/// inspect what it is signing regardless.
pub(super) const PROP_PRIVACY_POLICY: &str = "zallet.v1.privacy_policy";

/// Global: the ZIP 32 account index (`u32`, little-endian).
pub(super) const PROP_ACCOUNT_INDEX: &str = "zallet.v1.account_index";

/// Per transparent input: the key scope (`u32`, little-endian; see [`encode_key_scope`]).
pub(super) const PROP_SCOPE: &str = "zallet.v1.scope";

/// Per transparent input: the non-hardened address index (`u32`, little-endian).
pub(super) const PROP_ADDRESS_INDEX: &str = "zallet.v1.address_index";

/// Encodes a transparent key scope as the `u32` stored in the [`PROP_SCOPE`] hint.
///
/// Inverse of [`decode_key_scope`]. The stored value is the scope's BIP 32 child
/// number, so every scope — including custom ones — round-trips faithfully.
pub(super) fn encode_key_scope(scope: TransparentKeyScope) -> u32 {
    bip32::ChildNumber::from(scope).index()
}

/// Decodes a [`PROP_SCOPE`] `u32` back into a key scope, or `None` if the value
/// is out of range (scopes are BIP 32 child numbers, so they occupy 31 bits).
pub(super) fn decode_key_scope(value: u32) -> Option<TransparentKeyScope> {
    TransparentKeyScope::custom(value)
}

/// The proprietary-field key under which `zcash_client_backend` records its
/// proposal metadata when a PCZT is created via `create_pczt_from_proposal`.
///
/// Its presence marks a PCZT this wallet('s backend) created, which is the
/// precondition for `extract_and_store_transaction_from_pczt`. The upstream
/// constant is private, but the key is part of the PCZT's serialized format,
/// so it cannot change without breaking upstream's own compatibility.
pub(super) const PROP_BACKEND_PROPOSAL_INFO: &str = "zcash_client_backend:proposal_info";

/// Bounds the number of concurrently running proving/verification tasks.
///
/// Proof creation and Halo2 key generation are CPU-bound and take seconds to
/// minutes; they run on the blocking-thread pool, which tokio grows up to 512
/// threads. Without a bound, a client retrying a timed-out `pczt_prove` stacks
/// uncancellable proving tasks. Two permits let a prove and an extract overlap
/// without oversubscribing the machine.
pub(super) static PROVING_SLOTS: Semaphore = Semaphore::const_new(2);

/// The Orchard-family circuit version in force under the given consensus
/// branch, or `None` if the branch is unknown or predates Orchard.
///
/// The version is a function of the branch alone: under a given branch, an
/// Orchard bundle and an Ironwood bundle prove and verify against the same
/// circuit, so one proving/verifying key serves both bundles of a PCZT.
pub(super) fn circuit_version_for_branch(
    consensus_branch_id: u32,
) -> Option<OrchardCircuitVersion> {
    match BranchId::try_from(consensus_branch_id)
        .ok()?
        .orchard_protocol_revision()?
    {
        OrchardProtocolRevision::InsecureV1 => Some(OrchardCircuitVersion::InsecurePreNu6_2),
        OrchardProtocolRevision::V2 => Some(OrchardCircuitVersion::FixedPostNu6_2),
        OrchardProtocolRevision::V3 => Some(OrchardCircuitVersion::PostNu6_3),
    }
}

/// Returns the Orchard proving key for the given circuit version, building it
/// once and caching it for the lifetime of the process.
///
/// `ProvingKey::build` takes several seconds, so the first proving call under
/// each circuit version pays it and every later call reuses the key.
pub(super) fn orchard_proving_key(version: OrchardCircuitVersion) -> &'static ProvingKey {
    static INSECURE_PRE_NU6_2: OnceLock<ProvingKey> = OnceLock::new();
    static FIXED_POST_NU6_2: OnceLock<ProvingKey> = OnceLock::new();
    static POST_NU6_3: OnceLock<ProvingKey> = OnceLock::new();

    match version {
        OrchardCircuitVersion::InsecurePreNu6_2 => &INSECURE_PRE_NU6_2,
        OrchardCircuitVersion::FixedPostNu6_2 => &FIXED_POST_NU6_2,
        OrchardCircuitVersion::PostNu6_3 => &POST_NU6_3,
    }
    .get_or_init(|| ProvingKey::build(version))
}

/// Returns the Orchard verifying key for the given circuit version, building it
/// once and caching it for the lifetime of the process.
///
/// `VerifyingKey::build` runs a full Halo2 key generation (seconds of CPU), so
/// extraction must not rebuild it per call.
pub(super) fn orchard_verifying_key(version: OrchardCircuitVersion) -> &'static VerifyingKey {
    static INSECURE_PRE_NU6_2: OnceLock<VerifyingKey> = OnceLock::new();
    static FIXED_POST_NU6_2: OnceLock<VerifyingKey> = OnceLock::new();
    static POST_NU6_3: OnceLock<VerifyingKey> = OnceLock::new();

    match version {
        OrchardCircuitVersion::InsecurePreNu6_2 => &INSECURE_PRE_NU6_2,
        OrchardCircuitVersion::FixedPostNu6_2 => &FIXED_POST_NU6_2,
        OrchardCircuitVersion::PostNu6_3 => &POST_NU6_3,
    }
    .get_or_init(|| VerifyingKey::build(version))
}

/// Returns the bundled Sapling prover, parsing the parameters once and caching
/// them for the lifetime of the process.
pub(super) fn sapling_prover() -> &'static LocalTxProver {
    static PROVER: OnceLock<LocalTxProver> = OnceLock::new();
    PROVER.get_or_init(LocalTxProver::bundled)
}

/// Returns the bundled Sapling verifying keys, derived once from
/// [`sapling_prover`] and cached for the lifetime of the process.
pub(super) fn sapling_verifying_keys() -> &'static (SpendVerifyingKey, OutputVerifyingKey) {
    static KEYS: OnceLock<(SpendVerifyingKey, OutputVerifyingKey)> = OnceLock::new();
    KEYS.get_or_init(|| sapling_prover().verifying_keys())
}

/// Decodes a base64-encoded PCZT, rejecting oversized inputs before allocating.
pub(super) fn decode_pczt_base64(s: &str) -> Result<Pczt, ErrorObjectOwned> {
    if s.len() > MAX_PCZT_BASE64_LEN {
        return Err(LegacyCode::InvalidParameter.with_message(fl!("err-pczt-too-large")));
    }
    let pczt_bytes = Base64::decode_vec(s).map_err(|e| {
        LegacyCode::Deserialization
            .with_message(fl!("err-pczt-invalid-base64", error = e.to_string()))
    })?;
    // The parse error names which part of the encoding was malformed, which is
    // what a caller debugging a rejected PCZT needs.
    Ok(Pczt::parse(&pczt_bytes).map_err(PcztError::Parse)?)
}

/// Serializes a PCZT and base64-encodes it for a JSON-RPC response.
///
/// `Pczt::serialize` consumes the PCZT and can fail if it holds values that
/// exceed the wire format's bounds; that would be an internal inconsistency
/// rather than bad user input, so it maps to a generic error code, with the
/// cause carried in the message.
pub(super) fn encode_pczt_base64(pczt: Pczt) -> Result<String, ErrorObjectOwned> {
    let bytes = pczt.serialize().map_err(PcztError::Serialize)?;
    Ok(Base64::encode_string(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_scope_round_trips() {
        for scope in [
            TransparentKeyScope::EXTERNAL,
            TransparentKeyScope::INTERNAL,
            TransparentKeyScope::EPHEMERAL,
            // A custom scope must survive the codec, not be collapsed onto a
            // standard one.
            TransparentKeyScope::custom(0x7000_0007).expect("in range"),
        ] {
            assert_eq!(decode_key_scope(encode_key_scope(scope)), Some(scope));
        }

        // Values with the hardened bit set are not scopes.
        assert_eq!(decode_key_scope(1 << 31), None);
    }

    #[test]
    fn rejects_oversized_input() {
        crate::i18n::load_languages(&[]);

        let oversized = "A".repeat(MAX_PCZT_BASE64_LEN + 1);
        let err = decode_pczt_base64(&oversized).unwrap_err();
        assert!(err.message().contains("maximum size limit"));
    }

    #[test]
    fn rejects_invalid_base64() {
        crate::i18n::load_languages(&[]);

        let err = decode_pczt_base64("not valid base64 !!!").unwrap_err();
        assert!(err.message().contains("base64"));
    }

    #[test]
    fn rejects_valid_base64_that_is_not_a_pczt() {
        // These messages are localized, so the loader must be populated before
        // asserting on them; `fl!` is inert until a language is loaded. It also
        // disables the Unicode directionality isolation marks that would
        // otherwise surround the interpolated cause.
        crate::i18n::load_languages(&[]);

        // Valid base64, but not the PCZT magic/format.
        let err = decode_pczt_base64("AAAAAAAA").unwrap_err();
        let message = err.message();

        // The parse failure must name its cause, not just report that the PCZT
        // was invalid; this is the regression guard for surfacing the error
        // rather than discarding it.
        let prefix = "Invalid PCZT: ";
        let cause = message.strip_prefix(prefix).unwrap_or_else(|| {
            panic!("expected message to start with {prefix:?}, got {message:?}")
        });
        assert!(!cause.is_empty(), "expected a cause after {prefix:?}");
    }
}
