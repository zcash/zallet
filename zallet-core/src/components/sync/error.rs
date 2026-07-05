use std::fmt;

use shardtree::error::ShardTreeError;
use zcash_client_backend::scanning::ScanError;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_protocol::consensus::BlockHeight;

use crate::components::chain::ChainError;

#[derive(Debug)]
pub(crate) enum SyncError {
    BatchDecryptorUnavailable,
    Chain(ChainError),
    Scan(ScanError),
    Tree(Box<ShardTreeError<zcash_client_sqlite::wallet::commitment_tree::Error>>),
    Other(Box<SqliteClientError>),
    /// The wallet's recorded chain history diverges from the backend's best chain below the
    /// wallet's birthday, so no common block can be found to rewind to. Syncing cannot
    /// safely continue.
    WalletDivergedBelowBirthday {
        birthday: BlockHeight,
    },
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::BatchDecryptorUnavailable => write!(f, "The batch decryptor has shut down"),
            SyncError::Chain(e) => write!(f, "{e:?}"),
            SyncError::Scan(e) => write!(f, "{e}"),
            SyncError::Tree(e) => write!(f, "{e}"),
            SyncError::Other(e) => write!(f, "{e}"),
            SyncError::WalletDivergedBelowBirthday { birthday } => write!(
                f,
                "the wallet's chain history diverges from the best chain below its birthday \
                 (height {birthday}); cannot continue syncing",
            ),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<ShardTreeError<zcash_client_sqlite::wallet::commitment_tree::Error>> for SyncError {
    fn from(e: ShardTreeError<zcash_client_sqlite::wallet::commitment_tree::Error>) -> Self {
        Self::Tree(Box::new(e))
    }
}

impl From<SqliteClientError> for SyncError {
    fn from(e: SqliteClientError) -> Self {
        Self::Other(Box::new(e))
    }
}
