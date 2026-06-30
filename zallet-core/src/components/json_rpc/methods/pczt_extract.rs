//! PCZT extract method — extract the final transaction from a completed PCZT.
//!
//! Extraction finalizes the transparent spends and then verifies every proof
//! and signature before producing the transaction bytes. A PCZT that is missing
//! proofs (see [`super::pczt_prove`]) or signatures (see [`super::pczt_sign`])
//! will be rejected here rather than producing an invalid transaction.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use pczt::roles::spend_finalizer::SpendFinalizer;
use pczt::roles::tx_extractor::TransactionExtractor;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_proofs::prover::LocalTxProver;

use super::pczt_common::decode_pczt_base64;
use crate::components::json_rpc::server::LegacyCode;

pub(crate) type Response = RpcResult<ResultType>;

/// Result containing the extracted transaction.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ExtractResult {
    /// The hex-encoded raw transaction.
    pub hex: String,
}

pub(crate) type ResultType = ExtractResult;

pub(super) const PARAM_PCZT_DESC: &str =
    "The base64-encoded PCZT to extract a final transaction from.";

/// Extracts a final, network-ready transaction from a completed PCZT.
///
/// The PCZT must already have all required proofs and signatures in place;
/// extraction verifies them and fails otherwise.
pub(crate) async fn call(pczt_base64: &str) -> Response {
    let pczt = decode_pczt_base64(pczt_base64)?;

    // Spend finalization and proof verification are CPU-bound (and loading the
    // Sapling verifying keys is expensive), so run them off the async runtime.
    let tx_bytes: Vec<u8> =
        crate::spawn_blocking!("pczt_extract", move || -> Result<_, ErrorObjectOwned> {
            // Fold partial transparent signatures into their `script_sig`s. This
            // is a no-op when there are no transparent inputs.
            let pczt = SpendFinalizer::new(pczt)
                .finalize_spends()
                .map_err(|_| LegacyCode::Verify.with_static("Failed to finalize PCZT spends"))?;

            // Supplying the Sapling verifying keys is required to extract a PCZT
            // that has a Sapling bundle. The Orchard verifying key is generated
            // on the fly by the extractor when one is not provided.
            let (spend_vk, output_vk) = LocalTxProver::bundled().verifying_keys();
            let tx = TransactionExtractor::new(pczt)
                .with_sapling(&spend_vk, &output_vk)
                .extract()
                .map_err(|_| LegacyCode::Verify.with_static("Failed to extract transaction"))?;

            let mut tx_bytes = Vec::new();
            tx.write(&mut tx_bytes).map_err(|e| {
                LegacyCode::Deserialization
                    .with_message(format!("Failed to serialize transaction: {e}"))
            })?;
            Ok(tx_bytes)
        })
        .await
        .map_err(|_| LegacyCode::Misc.with_static("Extraction task failed"))??;

    Ok(ExtractResult {
        hex: hex::encode(tx_bytes),
    })
}
