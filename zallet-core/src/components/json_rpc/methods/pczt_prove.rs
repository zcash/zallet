//! PCZT prove method — create the zero-knowledge proofs for a PCZT.
//!
//! Proving is a prerequisite for extracting a transaction from any PCZT that
//! has shielded components: `pczt_extract` verifies proofs and will reject a
//! PCZT whose Sapling, Orchard, or Ironwood proofs are missing.
//!
//! The first call for each circuit version pays a one-time key-generation and
//! parameter-parsing cost of tens of seconds, which can exceed the RPC
//! timeout; the work continues and completes in the background, and a retry
//! reuses the cached keys. Concurrent proving is bounded, so retries queue
//! rather than stack. When the RPC server starts, the keys for the current
//! consensus branch are warmed in the background (see
//! [`super::pczt_common::spawn_proving_cache_warmer`]), so in steady state
//! this cost is paid before the first call arrives.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use pczt::Pczt;
use pczt::roles::prover::{OrchardError, Prover};
use schemars::JsonSchema;
use serde::Serialize;

use super::pczt_common::{
    PROVING_SLOTS, circuit_version_for_branch, decode_pczt_base64, encode_pczt_base64,
    orchard_proving_key, sapling_prover,
};
use super::pczt_error::PcztError;
use crate::{components::json_rpc::server::LegacyCode, fl};

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
    /// Whether the Ironwood proof was created.
    pub ironwood_proven: bool,
}

pub(crate) type ResultType = ProveResult;

pub(super) const PARAM_PCZT_DESC: &str = "The base64-encoded PCZT to add proofs to.";

/// Creates the Sapling, Orchard, and/or Ironwood proofs required by a PCZT.
pub(crate) async fn call(pczt_base64: &str) -> Response {
    let pczt = decode_pczt_base64(pczt_base64)?;

    // The circuit version is fixed by the PCZT's consensus branch, and is the
    // same for the Orchard and Ironwood bundles of a given PCZT.
    let circuit_version = circuit_version_for_branch(*pczt.global().consensus_branch_id());

    let prover = Prover::new(pczt);
    let need_sapling = prover.requires_sapling_proofs();
    let need_orchard = prover.requires_orchard_proof();
    let need_ironwood = prover.requires_ironwood_proof();

    let circuit_version = match (need_orchard || need_ironwood, circuit_version) {
        (true, None) => {
            // The same condition `create_orchard_proof` reports; surfaced here
            // because the proving key must be selected before calling it.
            return Err(PcztError::OrchardProve(OrchardError::UnsupportedConsensusBranchId).into());
        }
        (_, version) => version,
    };

    // Proving is CPU-bound (and generating the proving keys is expensive), so
    // run it off the async runtime, and at bounded concurrency.
    let _permit = PROVING_SLOTS
        .acquire()
        .await
        .expect("the proving semaphore is never closed");

    let (pczt, sapling_proven, orchard_proven, ironwood_proven): (Pczt, bool, bool, bool) =
        crate::spawn_blocking!("pczt_prove", move || -> Result<_, ErrorObjectOwned> {
            let mut prover = prover;

            if need_sapling {
                let local = sapling_prover();
                prover = prover
                    .create_sapling_proofs(local, local)
                    .map_err(PcztError::SaplingProve)?;
            }

            if let Some(version) = circuit_version {
                let pk = orchard_proving_key(version);

                if need_orchard {
                    prover = prover
                        .create_orchard_proof(pk)
                        .map_err(PcztError::OrchardProve)?;
                }

                if need_ironwood {
                    // The prover's `IronwoodError` is not publicly nameable at
                    // this `pczt` rev, so it is formatted here rather than
                    // carried in `PcztError`.
                    prover = prover.create_ironwood_proof(pk).map_err(|e| {
                        LegacyCode::Verify
                            .with_message(fl!("err-pczt-prove-ironwood", error = format!("{e:?}")))
                    })?;
                }
            }

            Ok((prover.finish(), need_sapling, need_orchard, need_ironwood))
        })
        .await
        .map_err(|source| PcztError::TaskFailed {
            task: "pczt_prove",
            source,
        })??;

    Ok(ProveResult {
        pczt: encode_pczt_base64(pczt)?,
        sapling_proven,
        orchard_proven,
        ironwood_proven,
    })
}
