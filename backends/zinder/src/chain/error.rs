//! Maps Zinder gRPC failures onto [`ChainError`].
//!
//! Classification keys on the `google.rpc.ErrorInfo.reason` string Zinder
//! attaches to every `Status` (decoded from the status detail bytes), falling
//! back to the gRPC status code. Message text is never matched. See the Zinder
//! error vocabulary (`docs/reference/error-vocabulary.md`).

use prost::Message as _;
use tonic::{Code, Status};

use zallet_core::components::chain::ChainError;

/// The `domain` Zinder stamps on its `ErrorInfo` details.
const ERROR_DOMAIN: &str = "zinder.dev";

/// Reasons that map to [`ChainError::Unavailable`]: transient dependency or
/// epoch-pin failures the wallet clears by retrying and re-pinning.
const UNAVAILABLE_REASONS: &[&str] = &[
    "CHAIN_EPOCH_PIN_UNAVAILABLE",
    "CHAIN_EPOCH_MISSING",
    "CHAIN_EPOCH_CONFLICT",
    "DERIVE_PROJECTION_LAGGING",
    "NODE_UNAVAILABLE",
    "STORAGE_UNAVAILABLE",
    "UPSTREAM_UNREACHABLE",
    "NO_VISIBLE_CHAIN_EPOCH",
    "BLOCKING_TASK_FAILED",
    "UNSUPPORTED_CHAIN_EVENT",
    "UNSUPPORTED_BLOCK_SELECTOR",
    "UNSUPPORTED_TRANSACTION_STATUS",
    // Paging/subscription cursors anchored ahead of, or outside, the retained
    // window: a benign race (e.g. an ingest restart mid-walk) that a fresh
    // snapshot walk clears, so the wallet re-pins rather than shutting down.
    "SNAPSHOT_PAGE_CURSOR_EXPIRED",
    "MEMPOOL_EVENT_CURSOR_EXPIRED",
    "CHAIN_EVENT_CURSOR_EXPIRED",
];

/// Reasons that map to [`ChainError::InvalidData`]: a persisted or upstream
/// payload could not be decoded.
const INVALID_DATA_REASONS: &[&str] = &["COMPACT_BLOCK_PAYLOAD_MALFORMED", "ARTIFACT_CORRUPT"];

/// Classifies a Zinder `Status` into a [`ChainError`].
pub(super) fn map_status(status: &Status) -> ChainError {
    if let Some(reason) = error_reason(status) {
        if UNAVAILABLE_REASONS.contains(&reason.as_str()) {
            return ChainError::unavailable(status.clone());
        }
        if INVALID_DATA_REASONS.contains(&reason.as_str()) {
            return ChainError::invalid_data(status.clone());
        }
        // Every other typed reason (invalid-argument request bugs,
        // deployment-gap failed-preconditions, internal faults) is a
        // backend-fatal condition retrying cannot clear.
        return ChainError::backend(status.clone());
    }

    // No typed reason: fall back to the coarse gRPC code.
    match status.code() {
        Code::Unavailable | Code::DeadlineExceeded | Code::ResourceExhausted | Code::Aborted => {
            ChainError::unavailable(status.clone())
        }
        Code::DataLoss => ChainError::invalid_data(status.clone()),
        _ => ChainError::backend(status.clone()),
    }
}

/// Extracts Zinder's `ErrorInfo.reason` from a `Status`'s detail bytes.
///
/// The detail bytes are a serialized `google.rpc.Status`; the reason lives in
/// its embedded `google.rpc.ErrorInfo`. Returns `None` when no Zinder-domain
/// `ErrorInfo` is present.
fn error_reason(status: &Status) -> Option<String> {
    let details = status.details();
    if details.is_empty() {
        return None;
    }
    let rpc_status = GoogleRpcStatus::decode(details).ok()?;
    for any in rpc_status.details {
        if any.type_url.ends_with("google.rpc.ErrorInfo") {
            if let Ok(info) = ErrorInfo::decode(any.value.as_slice()) {
                if info.domain == ERROR_DOMAIN {
                    return Some(info.reason);
                }
            }
        }
    }
    None
}

/// Minimal `google.rpc.Status`: only the `details` list is read.
#[derive(Clone, PartialEq, ::prost::Message)]
struct GoogleRpcStatus {
    #[prost(message, repeated, tag = "3")]
    details: ::prost::alloc::vec::Vec<::prost_types::Any>,
}

/// Minimal `google.rpc.ErrorInfo`: reason and domain (the `metadata` map is
/// skipped as an unknown field on decode).
#[derive(Clone, PartialEq, ::prost::Message)]
struct ErrorInfo {
    #[prost(string, tag = "1")]
    reason: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    domain: ::prost::alloc::string::String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `Status` carrying a Zinder-domain `ErrorInfo` with `reason`.
    fn status_with_reason(code: Code, reason: &str) -> Status {
        let info = ErrorInfo {
            reason: reason.to_owned(),
            domain: ERROR_DOMAIN.to_owned(),
        };
        let any = ::prost_types::Any {
            type_url: "type.googleapis.com/google.rpc.ErrorInfo".to_owned(),
            value: info.encode_to_vec(),
        };
        let rpc_status = GoogleRpcStatus { details: vec![any] };
        Status::with_details(code, "boom", rpc_status.encode_to_vec().into())
    }

    #[test]
    fn epoch_pin_unavailable_maps_to_unavailable() {
        let status = status_with_reason(Code::FailedPrecondition, "CHAIN_EPOCH_PIN_UNAVAILABLE");
        assert!(matches!(map_status(&status), ChainError::Unavailable(_)));
    }

    #[test]
    fn derive_lag_maps_to_unavailable() {
        let status = status_with_reason(Code::Unavailable, "DERIVE_PROJECTION_LAGGING");
        assert!(matches!(map_status(&status), ChainError::Unavailable(_)));
    }

    #[test]
    fn snapshot_page_cursor_expired_maps_to_unavailable() {
        let status = status_with_reason(Code::FailedPrecondition, "SNAPSHOT_PAGE_CURSOR_EXPIRED");
        assert!(matches!(map_status(&status), ChainError::Unavailable(_)));
    }

    #[test]
    fn mempool_event_cursor_expired_maps_to_unavailable() {
        let status = status_with_reason(Code::FailedPrecondition, "MEMPOOL_EVENT_CURSOR_EXPIRED");
        assert!(matches!(map_status(&status), ChainError::Unavailable(_)));
    }

    #[test]
    fn chain_event_cursor_expired_maps_to_unavailable() {
        let status = status_with_reason(Code::FailedPrecondition, "CHAIN_EVENT_CURSOR_EXPIRED");
        assert!(matches!(map_status(&status), ChainError::Unavailable(_)));
    }

    #[test]
    fn artifact_corrupt_maps_to_invalid_data() {
        let status = status_with_reason(Code::DataLoss, "ARTIFACT_CORRUPT");
        assert!(matches!(map_status(&status), ChainError::InvalidData(_)));
    }

    #[test]
    fn deployment_precondition_maps_to_backend() {
        let status = status_with_reason(Code::FailedPrecondition, "BROADCAST_DISABLED");
        assert!(matches!(map_status(&status), ChainError::Backend(_)));
    }

    #[test]
    fn invalid_argument_reason_maps_to_backend() {
        let status = status_with_reason(Code::InvalidArgument, "INVALID_ADDRESS");
        assert!(matches!(map_status(&status), ChainError::Backend(_)));
    }

    #[test]
    fn transport_unavailable_without_reason_maps_to_unavailable() {
        let status = Status::new(Code::Unavailable, "connection refused");
        assert!(matches!(map_status(&status), ChainError::Unavailable(_)));
    }

    #[test]
    fn not_found_without_reason_maps_to_backend() {
        // NOT_FOUND is a hard error at this layer; call sites that treat
        // absence as `Ok(None)` check the code before mapping.
        let status = Status::new(Code::NotFound, "missing");
        assert!(matches!(map_status(&status), ChainError::Backend(_)));
    }

    #[test]
    fn foreign_domain_reason_is_ignored() {
        // An ErrorInfo from a non-Zinder domain must not be trusted; fall back
        // to the code (FailedPrecondition -> Backend).
        let info = ErrorInfo {
            reason: "CHAIN_EPOCH_PIN_UNAVAILABLE".to_owned(),
            domain: "example.com".to_owned(),
        };
        let any = ::prost_types::Any {
            type_url: "type.googleapis.com/google.rpc.ErrorInfo".to_owned(),
            value: info.encode_to_vec(),
        };
        let rpc_status = GoogleRpcStatus { details: vec![any] };
        let status = Status::with_details(
            Code::FailedPrecondition,
            "boom",
            rpc_status.encode_to_vec().into(),
        );
        assert!(matches!(map_status(&status), ChainError::Backend(_)));
    }
}
