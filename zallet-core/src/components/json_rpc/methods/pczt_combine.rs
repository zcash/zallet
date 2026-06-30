//! PCZT combine method — merge multiple PCZTs.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use pczt::roles::combiner::Combiner;
use schemars::JsonSchema;
use serde::Serialize;

use super::pczt_common::{MAX_PCZTS_TO_COMBINE, decode_pczt_base64, encode_pczt_base64};
use crate::components::json_rpc::server::LegacyCode;

pub(crate) type Response = RpcResult<ResultType>;

/// Result containing the combined PCZT.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct CombineResult {
    /// The base64-encoded combined PCZT.
    pub pczt: String,
}

pub(crate) type ResultType = CombineResult;

pub(super) const PARAM_PCZTS_DESC: &str = "An array of base64-encoded PCZTs to combine.";
pub(super) const PARAM_PCZTS_REQUIRED: bool = true;

/// Combines multiple PCZTs into a single PCZT.
pub(crate) fn call(pczts_base64: Vec<String>) -> Response {
    if pczts_base64.is_empty() {
        return Err(LegacyCode::InvalidParameter.with_static("At least one PCZT is required"));
    }

    if pczts_base64.len() > MAX_PCZTS_TO_COMBINE {
        return Err(LegacyCode::InvalidParameter.with_message(format!(
            "Too many PCZTs to combine: {} exceeds maximum of {MAX_PCZTS_TO_COMBINE}",
            pczts_base64.len(),
        )));
    }

    let pczts = pczts_base64
        .iter()
        .enumerate()
        .map(|(i, pczt_base64)| {
            decode_pczt_base64(pczt_base64).map_err(|e| {
                LegacyCode::Deserialization.with_message(format!("PCZT {i}: {}", e.message()))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let combined = Combiner::new(pczts)
        .combine()
        .map_err(|_| LegacyCode::Verify.with_static("Failed to combine PCZTs"))?;

    Ok(CombineResult {
        pczt: encode_pczt_base64(combined)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_input() {
        let err = call(vec![]).unwrap_err();
        assert!(err.message().contains("At least one PCZT"));
    }

    #[test]
    fn rejects_too_many() {
        // The cap is enforced before any decoding, so the contents are irrelevant.
        let too_many = vec!["AAAA".to_string(); MAX_PCZTS_TO_COMBINE + 1];
        let err = call(too_many).unwrap_err();
        assert!(err.message().contains("Too many PCZTs"));
    }
}
