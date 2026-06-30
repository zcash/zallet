//! PCZT prove method — create the zero-knowledge proofs for a PCZT.
//!
//! Proving is a prerequisite for extracting a transaction from any PCZT that
//! has shielded components: [`super::pczt_extract`] verifies proofs and will
//! reject a PCZT whose Sapling or Orchard proofs are missing.

use std::sync::OnceLock;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use pczt::Pczt;
use pczt::roles::prover::Prover;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_proofs::prover::LocalTxProver;

use super::pczt_common::{decode_pczt_base64, encode_pczt_base64};
use crate::components::json_rpc::server::LegacyCode;

pub(crate) type Response = RpcResult<ResultType>;

/// Result of proving a PCZT.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ProveResult {
    /// The base64-encoded PCZT with proofs added.
    pub pczt: String,
    /// Whether Sapling proofs were created.
    pub sapling_proven: bool,
    /// Whether the Orchard proof was created.
    pub orchard_proven: bool,
}

pub(crate) type ResultType = ProveResult;

pub(super) const PARAM_PCZT_DESC: &str = "The base64-encoded PCZT to add proofs to.";

/// Returns the Orchard proving key, building it once and caching it.
///
/// `ProvingKey::build` takes several seconds, so we avoid rebuilding it on
/// every call. The key is held for the lifetime of the process.
///
/// We build the `FixedPostNu6_2` circuit, which is the one used for all current
/// (non-Ironwood) network proving; `create_orchard_proof` proves the regular
/// Orchard bundle against it.
fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    static ORCHARD_PK: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();
    ORCHARD_PK.get_or_init(|| {
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2)
    })
}

/// Creates the Sapling and/or Orchard proofs required by a PCZT.
pub(crate) async fn call(pczt_base64: &str) -> Response {
    let prover = Prover::new(decode_pczt_base64(pczt_base64)?);

    let need_sapling = prover.requires_sapling_proofs();
    let need_orchard = prover.requires_orchard_proof();

    // Proving is CPU-bound (and loading the Sapling parameters is expensive), so
    // run it off the async runtime.
    let (pczt, sapling_proven, orchard_proven): (Pczt, bool, bool) =
        crate::spawn_blocking!("pczt_prove", move || -> Result<_, ErrorObjectOwned> {
            let mut prover = prover;

            if need_sapling {
                let local = LocalTxProver::bundled();
                prover = prover.create_sapling_proofs(&local, &local).map_err(|_| {
                    LegacyCode::Verify.with_static("Failed to create Sapling proofs")
                })?;
            }

            if need_orchard {
                prover = prover
                    .create_orchard_proof(orchard_proving_key())
                    .map_err(|_| {
                        LegacyCode::Verify.with_static("Failed to create Orchard proof")
                    })?;
            }

            Ok((prover.finish(), need_sapling, need_orchard))
        })
        .await
        .map_err(|_| LegacyCode::Misc.with_static("Proving task failed"))??;

    Ok(ProveResult {
        pczt: encode_pczt_base64(pczt)?,
        sapling_proven,
        orchard_proven,
    })
}
