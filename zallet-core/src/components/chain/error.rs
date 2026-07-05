//! Errors surfaced by the chain-data abstraction.

use std::fmt;

/// A boxed, sendable error source.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// An error returned by a [`Chain`](super::Chain) or [`ChainView`](super::ChainView).
///
/// Absence of a requested item is **not** an error; methods return `Ok(None)` for that.
#[derive(Debug)]
#[non_exhaustive]
pub enum ChainError {
    /// The chain source is temporarily unable to serve the request; retrying later may
    /// succeed (transient transport failure, the backend is still syncing, work queue full).
    ///
    /// Constructed by alternative backends that can distinguish retryable failures; the
    /// Zaino backend currently classifies all opaque failures as [`ChainError::Backend`].
    #[allow(dead_code)]
    Unavailable(BoxError),
    /// The chain source returned data that could not be decoded, or that violated an
    /// invariant the wallet relies on (a non-canonical encoding, an unexpected response
    /// shape). Not retryable; indicates a bug, corruption, or a version mismatch.
    #[allow(dead_code)] // unused by whichever backend is not compiled
    InvalidData(BoxError),
    /// A backend-specific failure with no finer classification.
    Backend(BoxError),
}

impl ChainError {
    /// Wraps an arbitrary error as a [`ChainError::Backend`].
    pub fn backend(source: impl Into<BoxError>) -> Self {
        ChainError::Backend(source.into())
    }

    /// Wraps an arbitrary error as a [`ChainError::Unavailable`].
    #[allow(dead_code)]
    pub fn unavailable(source: impl Into<BoxError>) -> Self {
        ChainError::Unavailable(source.into())
    }

    /// Wraps an arbitrary error as a [`ChainError::InvalidData`].
    #[allow(dead_code)] // unused by whichever backend is not compiled
    pub fn invalid_data(source: impl Into<BoxError>) -> Self {
        ChainError::InvalidData(source.into())
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::Unavailable(e) => write!(f, "chain source unavailable: {e}"),
            ChainError::InvalidData(e) => write!(f, "chain source returned invalid data: {e}"),
            ChainError::Backend(e) => write!(f, "chain backend error: {e}"),
        }
    }
}

impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChainError::Unavailable(e) | ChainError::InvalidData(e) | ChainError::Backend(e) => {
                Some(e.as_ref())
            }
        }
    }
}

impl From<ChainError> for crate::error::Error {
    fn from(e: ChainError) -> Self {
        crate::error::ErrorKind::Chain.context(e).into()
    }
}
