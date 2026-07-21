//! Failures from the PCZT RPC methods, and their mapping to legacy RPC codes.
//!
//! Each variant wraps the error reported by the `pczt` role that failed, so the
//! cause reaches the client instead of being discarded in favour of a fixed
//! string. The mapping from variant to [`LegacyCode`] lives in the
//! [`From<PcztError>`] impl below, which is the single place where a PCZT
//! failure acquires a wire-visible error code.
//!
//! None of the `pczt` role error types implement `Display` — they are all
//! `#[derive(Debug)]` — so the causes are formatted with `{:?}`. For these
//! enums that renders the variant name and any nested error, which is the
//! information an operator needs.

use jsonrpsee::types::ErrorObjectOwned;
use pczt::{
    EncodingError, ParseError,
    roles::{combiner, prover, signer, spend_finalizer, tx_extractor, updater},
};

use crate::{components::json_rpc::server::LegacyCode, fl};

/// Why a PCZT operation failed.
#[derive(Debug)]
pub(super) enum PcztError {
    /// The submitted bytes are not a well-formed PCZT.
    Parse(ParseError),
    /// The PCZT could not be re-encoded for the response.
    ///
    /// The PCZT holds values that exceed the wire format's bounds, which is an
    /// internal inconsistency rather than bad user input.
    Serialize(EncodingError),
    /// The submitted PCZTs do not describe the same transaction.
    Combine(combiner::Error),
    /// The Sapling proofs could not be created.
    SaplingProve(prover::SaplingError),
    /// The Orchard proof could not be created.
    OrchardProve(prover::OrchardError),
    /// The partial transparent signatures could not be folded into their
    /// `script_sig`s.
    FinalizeSpends(spend_finalizer::Error),
    /// The PCZT is not a complete, valid transaction.
    ///
    /// Extraction verifies every proof and signature, so this is the error a
    /// PCZT missing either of them fails with.
    Extract(tx_extractor::Error),
    /// The PCZT could not be prepared for signing.
    SignerInit(signer::Error),
    /// The transparent signing hints could not be recorded.
    RecordSigningHints(updater::TransparentError),
    /// A blocking task did not run to completion.
    ///
    /// The task either panicked or was cancelled; in both cases the PCZT
    /// operation itself never reported a result.
    TaskFailed {
        task: &'static str,
        source: tokio::task::JoinError,
    },
}

impl From<PcztError> for ErrorObjectOwned {
    fn from(e: PcztError) -> Self {
        match e {
            PcztError::Parse(e) => LegacyCode::Deserialization
                .with_message(fl!("err-pczt-parse", error = format!("{e:?}"))),
            PcztError::Serialize(e) => {
                LegacyCode::Misc.with_message(fl!("err-pczt-serialize", error = format!("{e:?}")))
            }
            PcztError::Combine(e) => {
                LegacyCode::Verify.with_message(fl!("err-pczt-combine", error = format!("{e:?}")))
            }
            PcztError::SaplingProve(e) => LegacyCode::Verify
                .with_message(fl!("err-pczt-prove-sapling", error = format!("{e:?}"))),
            PcztError::OrchardProve(e) => LegacyCode::Verify
                .with_message(fl!("err-pczt-prove-orchard", error = format!("{e:?}"))),
            PcztError::FinalizeSpends(e) => LegacyCode::Verify
                .with_message(fl!("err-pczt-finalize-spends", error = format!("{e:?}"))),
            PcztError::Extract(e) => {
                LegacyCode::Verify.with_message(fl!("err-pczt-extract", error = format!("{e:?}")))
            }
            PcztError::SignerInit(e) => LegacyCode::Verify
                .with_message(fl!("err-pczt-signer-init", error = format!("{e:?}"))),
            PcztError::RecordSigningHints(e) => LegacyCode::Wallet.with_message(fl!(
                "err-pczt-record-signing-hints",
                error = format!("{e:?}")
            )),
            PcztError::TaskFailed { task, source } => LegacyCode::Misc.with_message(fl!(
                "err-pczt-task-failed",
                task = task,
                error = source.to_string(),
            )),
        }
    }
}
