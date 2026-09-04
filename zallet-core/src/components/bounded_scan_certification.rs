//! Unshippable certification of Zallet's bounded shielded-scan workflow.
//!
//! This module composes Zallet's real wallet database, subtree-root update, batch
//! decryptor, and block scanner for backend integration tests. It deliberately exposes
//! one single-attempt workflow instead of the production sync engine's retry loop.

use std::{
    fmt,
    ops::{ControlFlow, Range},
    path::PathBuf,
};

use serde::Serialize;
use tokio::task::JoinHandle;
use zcash_client_backend::data_api::{
    BlockMetadata, WalletRead, WalletWrite,
    scanning::{ScanPriority, ScanRange},
};
use zcash_protocol::consensus::BlockHeight;

use super::{
    chain::{Chain, ChainBlock, ChainError, ChainView},
    database::{Database, DbConnection},
    sync::{self, SyncError, WalletSync, steps},
};
use crate::{
    config::ZalletConfig,
    error::{Error, ErrorKind},
    network::Network,
};

const MIN_CERTIFICATION_BLOCK_COUNT: u32 = 2;
const MAX_CERTIFICATION_BLOCK_COUNT: u32 = 20;
const CERTIFICATION_WALLET_DATABASE_FILENAME: &str = "wallet.db";

/// Schema version of serialized bounded-scan certification evidence.
pub const BOUNDED_SCAN_CERTIFICATION_EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// Inputs for one bounded-scan certification attempt.
///
/// `certification_datadir` always replaces the data directory embedded in the cloned
/// [`ZalletConfig`], and certification always opens its fixed `wallet.db` child regardless
/// of the cloned database path. The requested range is start-inclusive and end-exclusive,
/// must contain between two and twenty blocks, and must start above height zero because
/// the scanner first requests the predecessor tree state.
#[derive(Clone, Debug)]
pub struct BoundedScanCertificationConfig {
    certification_datadir: PathBuf,
    zallet_config: ZalletConfig,
    requested_block_range: Range<u32>,
}

impl BoundedScanCertificationConfig {
    /// Validates and constructs the inputs for one bounded-scan certification attempt.
    pub fn new(
        certification_datadir: impl Into<PathBuf>,
        zallet_config: ZalletConfig,
        requested_block_range: Range<u32>,
    ) -> Result<Self, BoundedScanCertificationError> {
        let certification_datadir = certification_datadir.into();
        if !certification_datadir.is_absolute() {
            return Err(
                BoundedScanCertificationError::CertificationDatadirNotAbsolute {
                    certification_datadir,
                },
            );
        }
        validate_requested_block_range(&requested_block_range)?;

        Ok(Self {
            certification_datadir,
            zallet_config,
            requested_block_range,
        })
    }

    /// Returns the exact wallet database path that certification would open.
    ///
    /// Callers can use this before backend admission to prove that a rejected backend
    /// did not create or migrate the certification database.
    pub fn wallet_database_path(&self) -> PathBuf {
        self.effective_zallet_config().wallet_db_path()
    }

    fn effective_zallet_config(&self) -> ZalletConfig {
        let mut zallet_config = self.zallet_config.clone();
        zallet_config.datadir = Some(self.certification_datadir.clone());
        zallet_config.database.wallet = Some(PathBuf::from(CERTIFICATION_WALLET_DATABASE_FILENAME));
        zallet_config
    }
}

/// Primitive, serialization-friendly proof of a completed bounded scan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedScanCertificationEvidence {
    /// Version of this serialized evidence shape.
    pub schema_version: u32,
    /// First requested block height, included in the scan.
    pub requested_start_height_inclusive: u32,
    /// Height immediately after the last requested block.
    pub requested_end_height_exclusive: u32,
    /// Earliest block height relevant to any account in the wallet.
    pub wallet_birthday_height: u32,
    /// Height of the single chain view captured for this attempt.
    pub captured_tip_height: u32,
    /// Display-encoded hash of the single chain view's tip.
    pub captured_tip_hash: String,
    /// Number of Sapling subtree roots written before scanning.
    pub sapling_subtree_root_count: u64,
    /// Number of Orchard subtree roots written before scanning.
    pub orchard_subtree_root_count: u64,
    /// Number of Ironwood subtree roots written before scanning.
    pub ironwood_subtree_root_count: u64,
    /// Requested-range block metadata present before the attempt.
    pub block_metadata_before: Vec<BoundedScanBlockMetadataFingerprint>,
    /// Requested-range block metadata present after the attempt.
    pub block_metadata_after: Vec<BoundedScanBlockMetadataFingerprint>,
    /// Whether suggested scan work remained from the wallet birthday through the captured tip.
    pub has_outstanding_scan_work_from_wallet_birthday_through_captured_tip: bool,
}

/// Stable wallet-database metadata used to detect writes during a failed attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedScanBlockMetadataFingerprint {
    /// Recorded block height.
    pub block_height: u32,
    /// Display-encoded recorded block hash.
    pub block_hash: String,
    /// Recorded Sapling note-commitment tree size.
    pub sapling_tree_size: Option<u32>,
    /// Recorded Orchard note-commitment tree size.
    pub orchard_tree_size: Option<u32>,
    /// Recorded Ironwood note-commitment tree size.
    pub ironwood_tree_size: Option<u32>,
}

impl From<BlockMetadata> for BoundedScanBlockMetadataFingerprint {
    fn from(metadata: BlockMetadata) -> Self {
        Self {
            block_height: u32::from(metadata.block_height()),
            block_hash: metadata.block_hash().to_string(),
            sapling_tree_size: metadata.sapling_tree_size(),
            orchard_tree_size: metadata.orchard_tree_size(),
            ironwood_tree_size: metadata.ironwood_tree_size(),
        }
    }
}

/// Serializable evidence from an attempt whose captured chain view expired.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BoundedScanViewExpiryEvidence {
    /// Version of this serialized evidence shape.
    pub schema_version: u32,
    /// First requested block height, included in the scan.
    pub requested_start_height_inclusive: u32,
    /// Height immediately after the last requested block.
    pub requested_end_height_exclusive: u32,
    /// Earliest block height relevant to any account in the wallet.
    pub wallet_birthday_height: u32,
    /// Requested-range block metadata present before the attempt.
    pub block_metadata_before: Vec<BoundedScanBlockMetadataFingerprint>,
    /// Requested-range block metadata present after the attempt.
    pub block_metadata_after: Vec<BoundedScanBlockMetadataFingerprint>,
    /// Whether work remained from the wallet birthday through the last requested height.
    pub has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height: bool,
}

/// Typed result of one bounded-scan certification attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum BoundedScanCertificationOutcome {
    /// Every requested block was recorded, the final hash matched the captured tip, and
    /// no requested-range scan work remained.
    Certified(BoundedScanCertificationEvidence),
    /// The captured chain view expired without changing requested block metadata.
    ///
    /// The original [`ChainError`] is retained so integration tests can inspect its
    /// concrete source and then explicitly reacquire the complete workflow.
    ChainViewExpired {
        /// Original source-preserving chain-view expiry.
        chain_error: ChainError,
        /// Serializable database evidence retained independently of the chain error.
        evidence: BoundedScanViewExpiryEvidence,
    },
}

/// Failure to configure, run, or verify one bounded-scan certification attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum BoundedScanCertificationError {
    /// The certification data directory was relative.
    CertificationDatadirNotAbsolute {
        /// Rejected relative data directory.
        certification_datadir: PathBuf,
    },
    /// The requested half-open range was reversed, started at zero, or contained fewer
    /// than two or more than twenty blocks.
    InvalidRequestedBlockRange {
        /// Requested inclusive start height.
        start_height_inclusive: u32,
        /// Requested exclusive end height.
        end_height_exclusive: u32,
    },
    /// The certification wallet contained no account birthday.
    MissingWalletBirthday,
    /// The wallet birthday did not equal the requested start height.
    WalletBirthdayDoesNotMatchRequestedStart {
        /// Earliest block height relevant to any account in the wallet.
        wallet_birthday_height: u32,
        /// First requested block height.
        requested_start_height_inclusive: u32,
    },
    /// Opening or inspecting the certification wallet database failed.
    WalletDatabase(Error),
    /// Exclusively locking the certification data directory failed.
    CertificationDatadirLock(Error),
    /// The reused wallet-sync operation failed.
    WalletSync(Error),
    /// The backend returned a non-expiry chain error.
    Chain(ChainError),
    /// The last requested height did not equal the captured chain tip.
    RequestedRangeDoesNotEndAtCapturedTip {
        /// Last requested height.
        last_requested_height: u32,
        /// Captured chain-tip height.
        captured_tip_height: u32,
    },
    /// A chain view expired after requested block metadata changed.
    ChainViewExpiryChangedBlockMetadata {
        /// Original source-preserving chain-view expiry.
        chain_error: ChainError,
        /// Serializable evidence showing the metadata change.
        evidence: BoundedScanViewExpiryEvidence,
    },
    /// A completed scan did not record metadata for every requested height.
    MissingBlockMetadata {
        /// Requested heights that remained absent.
        missing_block_metadata_heights: Vec<u32>,
    },
    /// The final recorded block metadata belonged to a different same-height chain tip.
    FinalBlockMetadataHashDoesNotMatchCapturedTipHash {
        /// Final requested and captured-tip height.
        final_requested_height: u32,
        /// Hash recorded in the final block's wallet metadata.
        final_block_metadata_hash: String,
        /// Hash reported by the captured chain view.
        captured_tip_hash: String,
    },
    /// A completed scan left suggested work from the wallet birthday through the tip.
    OutstandingBirthdayThroughTipScanWork {
        /// Earliest block height relevant to any account in the wallet.
        wallet_birthday_height: u32,
        /// Captured chain-tip height.
        captured_tip_height: u32,
    },
    /// The batch decryptor failed after the scan itself completed successfully.
    BatchDecryptor(Error),
}

impl fmt::Display for BoundedScanCertificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CertificationDatadirNotAbsolute {
                certification_datadir,
            } => write!(
                formatter,
                "bounded-scan certification data directory must be absolute: \
                 {certification_datadir:?}",
            ),
            Self::InvalidRequestedBlockRange {
                start_height_inclusive,
                end_height_exclusive,
            } => write!(
                formatter,
                "bounded-scan certification range {start_height_inclusive}..\
                 {end_height_exclusive} must start above zero and contain \
                 {MIN_CERTIFICATION_BLOCK_COUNT}..=\
                 {MAX_CERTIFICATION_BLOCK_COUNT} blocks",
            ),
            Self::MissingWalletBirthday => {
                formatter.write_str("certification wallet contains no account birthday")
            }
            Self::WalletBirthdayDoesNotMatchRequestedStart {
                wallet_birthday_height,
                requested_start_height_inclusive,
            } => write!(
                formatter,
                "wallet birthday {wallet_birthday_height} must equal requested start height \
                 {requested_start_height_inclusive}",
            ),
            Self::WalletDatabase(error) => {
                write!(formatter, "certification wallet database failed: {error}")
            }
            Self::CertificationDatadirLock(error) => {
                write!(
                    formatter,
                    "locking the certification data directory failed: {error}"
                )
            }
            Self::WalletSync(error) => {
                write!(formatter, "certification wallet scan failed: {error}")
            }
            Self::Chain(error) => write!(formatter, "certification chain read failed: {error}"),
            Self::RequestedRangeDoesNotEndAtCapturedTip {
                last_requested_height,
                captured_tip_height,
            } => write!(
                formatter,
                "last requested height {last_requested_height} must equal captured tip \
                 {captured_tip_height}",
            ),
            Self::ChainViewExpiryChangedBlockMetadata { evidence, .. } => write!(
                formatter,
                "chain view expired after requested block metadata changed from \
                 {:?} to {:?}",
                evidence.block_metadata_before, evidence.block_metadata_after,
            ),
            Self::MissingBlockMetadata {
                missing_block_metadata_heights,
            } => write!(
                formatter,
                "completed scan left block metadata absent at heights \
                 {missing_block_metadata_heights:?}",
            ),
            Self::FinalBlockMetadataHashDoesNotMatchCapturedTipHash {
                final_requested_height,
                final_block_metadata_hash,
                captured_tip_hash,
            } => write!(
                formatter,
                "final block metadata hash {final_block_metadata_hash} at height \
                 {final_requested_height} does not match captured tip hash {captured_tip_hash}",
            ),
            Self::OutstandingBirthdayThroughTipScanWork {
                wallet_birthday_height,
                captured_tip_height,
            } => write!(
                formatter,
                "completed scan left suggested work from wallet birthday \
                 {wallet_birthday_height} through captured tip {captured_tip_height}",
            ),
            Self::BatchDecryptor(error) => {
                write!(formatter, "certification batch decryptor failed: {error}")
            }
        }
    }
}

impl std::error::Error for BoundedScanCertificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::WalletDatabase(error)
            | Self::CertificationDatadirLock(error)
            | Self::WalletSync(error)
            | Self::BatchDecryptor(error) => Some(error),
            Self::Chain(error)
            | Self::ChainViewExpiryChangedBlockMetadata {
                chain_error: error, ..
            } => Some(error),
            Self::CertificationDatadirNotAbsolute { .. }
            | Self::InvalidRequestedBlockRange { .. }
            | Self::MissingWalletBirthday
            | Self::WalletBirthdayDoesNotMatchRequestedStart { .. }
            | Self::RequestedRangeDoesNotEndAtCapturedTip { .. }
            | Self::MissingBlockMetadata { .. }
            | Self::FinalBlockMetadataHashDoesNotMatchCapturedTipHash { .. }
            | Self::OutstandingBirthdayThroughTipScanWork { .. } => None,
        }
    }
}

/// Runs one bounded-scan certification attempt against an admitted, constructed chain.
///
/// Backend construction and capability admission must complete before calling this
/// function. After validating [`BoundedScanCertificationConfig`], this function opens or
/// creates the wallet database immediately. A negative admission test should inspect
/// [`BoundedScanCertificationConfig::wallet_database_path`] and avoid this function
/// entirely.
///
/// The attempt holds Zallet's normal exclusive data-directory lock, requires the wallet
/// birthday to equal the requested start, fetches subtree roots, captures exactly one
/// [`ChainView`], requires the requested last height to equal that view's tip, and scans
/// the complete Historic range without retrying. Certification also requires the final
/// recorded block metadata hash to equal the captured tip hash. A caller that receives
/// [`BoundedScanCertificationOutcome::ChainViewExpired`] must explicitly invoke the
/// complete function again so roots, the view, and database evidence are reacquired as
/// one workflow.
pub async fn certify_bounded_scan<C: Chain>(
    chain: &C,
    certification_config: &BoundedScanCertificationConfig,
) -> Result<BoundedScanCertificationOutcome, BoundedScanCertificationError> {
    let zallet_config = certification_config.effective_zallet_config();
    let _certification_datadir_lock = zallet_config
        .lock_datadir()
        .map_err(BoundedScanCertificationError::CertificationDatadirLock)?;
    let database = Database::open(&zallet_config)
        .await
        .map_err(BoundedScanCertificationError::WalletDatabase)?;
    let mut db_data = database
        .handle()
        .await
        .map_err(BoundedScanCertificationError::WalletDatabase)?;
    let wallet_birthday_height = db_data
        .get_wallet_birthday()
        .map_err(|error| {
            BoundedScanCertificationError::WalletDatabase(Error::from(
                ErrorKind::Sync.context(error),
            ))
        })?
        .map(u32::from)
        .ok_or(BoundedScanCertificationError::MissingWalletBirthday)?;
    if wallet_birthday_height != certification_config.requested_block_range.start {
        return Err(
            BoundedScanCertificationError::WalletBirthdayDoesNotMatchRequestedStart {
                wallet_birthday_height,
                requested_start_height_inclusive: certification_config.requested_block_range.start,
            },
        );
    }
    let block_metadata_before = recorded_block_metadata(
        db_data.as_ref(),
        &certification_config.requested_block_range,
    )?;

    let scan_attempt = scan_requested_blocks_once(
        chain,
        &database,
        db_data.as_mut(),
        &zallet_config.consensus.network(),
        &certification_config.requested_block_range,
    )
    .await;

    let block_metadata_after = recorded_block_metadata(
        db_data.as_ref(),
        &certification_config.requested_block_range,
    );
    let has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height =
        has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height(
            db_data.as_ref(),
            &certification_config.requested_block_range,
        );

    match scan_attempt {
        Err(error @ BoundedScanCertificationError::Chain(ChainError::ViewExpired(_))) => {
            classify_bounded_scan_attempt(
                Err(error),
                certification_config,
                wallet_birthday_height,
                block_metadata_before,
                block_metadata_after?,
                has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height?,
            )
        }
        Err(error) => Err(error),
        Ok(completed_attempt) => {
            let outcome = classify_bounded_scan_attempt(
                Ok(completed_attempt.evidence),
                certification_config,
                wallet_birthday_height,
                block_metadata_before,
                block_metadata_after?,
                has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height?,
            )?;
            completed_attempt
                .decryptor_completion
                .map_err(BoundedScanCertificationError::BatchDecryptor)?;
            Ok(outcome)
        }
    }
}

struct BoundedScanAttemptEvidence {
    captured_tip: ChainBlock,
    subtree_root_counts: steps::SubtreeRootCounts,
}

struct CompletedBoundedScanAttempt {
    evidence: BoundedScanAttemptEvidence,
    decryptor_completion: Result<(), Error>,
}

struct BoundedScanDecryptorTask {
    task: JoinHandle<Result<(), SyncError>>,
}

impl BoundedScanDecryptorTask {
    fn new(task: JoinHandle<Result<(), SyncError>>) -> Self {
        Self { task }
    }

    async fn join(mut self) -> Result<(), Error> {
        let completion = (&mut self.task)
            .await
            .map_err(|error| Error::from(ErrorKind::Sync.context(error)))?;
        completion.map_err(Error::from)
    }
}

impl Drop for BoundedScanDecryptorTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn scan_requested_blocks_once<C: Chain>(
    chain: &C,
    database: &Database,
    db_data: &mut DbConnection,
    params: &Network,
    requested_block_range: &Range<u32>,
) -> Result<CompletedBoundedScanAttempt, BoundedScanCertificationError> {
    let subtree_root_counts = steps::update_subtree_roots(chain, db_data)
        .await
        .map_err(bounded_scan_sync_error)?;
    let chain_view = chain
        .snapshot()
        .await
        .map_err(BoundedScanCertificationError::Chain)?;
    let captured_tip = chain_view
        .tip()
        .await
        .map_err(BoundedScanCertificationError::Chain)?;
    let captured_tip_height = u32::from(captured_tip.height());
    validate_requested_range_ends_at_captured_tip(requested_block_range, captured_tip_height)?;

    db_data
        .update_chain_tip(captured_tip.height())
        .map_err(SyncError::from)
        .map_err(bounded_scan_sync_error)?;

    let (decryptor_handle, decryptor_engine) = WalletSync::build_decryptor();
    let mut decryptor_db_data = database
        .handle()
        .await
        .map_err(BoundedScanCertificationError::WalletDatabase)?;
    let params_for_decryptor = *params;
    let decryptor_task = BoundedScanDecryptorTask::new(tokio::spawn(async move {
        sync::batch_decryptor(
            params_for_decryptor,
            decryptor_db_data.as_mut(),
            decryptor_engine,
        )
        .await
    }));
    let scan_range = ScanRange::from_parts(
        BlockHeight::from_u32(requested_block_range.start)
            ..BlockHeight::from_u32(requested_block_range.end),
        ScanPriority::Historic,
    );
    let scan_attempt = steps::scan_blocks(
        chain_view,
        db_data,
        params,
        &scan_range,
        &decryptor_handle,
        None,
    )
    .await;

    drop(decryptor_handle);
    let decryptor_completion = decryptor_task.join().await;

    match scan_attempt {
        Err(error) => Err(bounded_scan_sync_error(error)),
        Ok(ControlFlow::Continue(())) => Ok(CompletedBoundedScanAttempt {
            evidence: BoundedScanAttemptEvidence {
                captured_tip,
                subtree_root_counts,
            },
            decryptor_completion,
        }),
        Ok(ControlFlow::Break(height)) => Err(BoundedScanCertificationError::WalletSync(
            Error::from(ErrorKind::Sync.context(format!(
                "bounded scan stopped unexpectedly at height {height}"
            ))),
        )),
    }
}

fn validate_requested_range_ends_at_captured_tip(
    requested_block_range: &Range<u32>,
    captured_tip_height: u32,
) -> Result<(), BoundedScanCertificationError> {
    let last_requested_height = requested_block_range.end - 1;
    if last_requested_height != captured_tip_height {
        return Err(
            BoundedScanCertificationError::RequestedRangeDoesNotEndAtCapturedTip {
                last_requested_height,
                captured_tip_height,
            },
        );
    }

    Ok(())
}

fn validate_requested_block_range(
    requested_block_range: &Range<u32>,
) -> Result<(), BoundedScanCertificationError> {
    let block_count = requested_block_range
        .end
        .checked_sub(requested_block_range.start);
    if requested_block_range.start == 0
        || block_count.is_none_or(|count| {
            !(MIN_CERTIFICATION_BLOCK_COUNT..=MAX_CERTIFICATION_BLOCK_COUNT).contains(&count)
        })
    {
        return Err(BoundedScanCertificationError::InvalidRequestedBlockRange {
            start_height_inclusive: requested_block_range.start,
            end_height_exclusive: requested_block_range.end,
        });
    }

    Ok(())
}

fn recorded_block_metadata(
    db_data: &DbConnection,
    requested_block_range: &Range<u32>,
) -> Result<Vec<BoundedScanBlockMetadataFingerprint>, BoundedScanCertificationError> {
    let mut recorded_metadata = Vec::new();
    for height in requested_block_range.clone() {
        if let Some(metadata) = db_data
            .block_metadata(BlockHeight::from_u32(height))
            .map_err(|error| {
                BoundedScanCertificationError::WalletDatabase(Error::from(
                    ErrorKind::Sync.context(error),
                ))
            })?
        {
            recorded_metadata.push(metadata.into());
        }
    }
    Ok(recorded_metadata)
}

fn has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height(
    db_data: &DbConnection,
    requested_block_range: &Range<u32>,
) -> Result<bool, BoundedScanCertificationError> {
    let requested_block_range = BlockHeight::from_u32(requested_block_range.start)
        ..BlockHeight::from_u32(requested_block_range.end);
    Ok(db_data
        .suggest_scan_ranges()
        .map_err(|error| {
            BoundedScanCertificationError::WalletDatabase(Error::from(
                ErrorKind::Sync.context(error),
            ))
        })?
        .iter()
        .any(|suggested| block_ranges_intersect(suggested.block_range(), &requested_block_range)))
}

fn block_ranges_intersect(left: &Range<BlockHeight>, right: &Range<BlockHeight>) -> bool {
    left.start < right.end && right.start < left.end
}

fn classify_bounded_scan_attempt(
    scan_attempt: Result<BoundedScanAttemptEvidence, BoundedScanCertificationError>,
    certification_config: &BoundedScanCertificationConfig,
    wallet_birthday_height: u32,
    block_metadata_before: Vec<BoundedScanBlockMetadataFingerprint>,
    block_metadata_after: Vec<BoundedScanBlockMetadataFingerprint>,
    has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height: bool,
) -> Result<BoundedScanCertificationOutcome, BoundedScanCertificationError> {
    match scan_attempt {
        Err(BoundedScanCertificationError::Chain(chain_error @ ChainError::ViewExpired(_))) => {
            let evidence = BoundedScanViewExpiryEvidence {
                schema_version: BOUNDED_SCAN_CERTIFICATION_EVIDENCE_SCHEMA_VERSION,
                requested_start_height_inclusive: certification_config.requested_block_range.start,
                requested_end_height_exclusive: certification_config.requested_block_range.end,
                wallet_birthday_height,
                block_metadata_before,
                block_metadata_after,
                has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height,
            };
            if evidence.block_metadata_before != evidence.block_metadata_after {
                return Err(
                    BoundedScanCertificationError::ChainViewExpiryChangedBlockMetadata {
                        chain_error,
                        evidence,
                    },
                );
            }

            Ok(BoundedScanCertificationOutcome::ChainViewExpired {
                chain_error,
                evidence,
            })
        }
        Err(error) => Err(error),
        Ok(attempt_evidence) => {
            let missing_block_metadata_heights = certification_config
                .requested_block_range
                .clone()
                .filter(|height| {
                    !block_metadata_after
                        .iter()
                        .any(|metadata| metadata.block_height == *height)
                })
                .collect::<Vec<_>>();
            if !missing_block_metadata_heights.is_empty() {
                return Err(BoundedScanCertificationError::MissingBlockMetadata {
                    missing_block_metadata_heights,
                });
            }
            if has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height {
                return Err(
                    BoundedScanCertificationError::OutstandingBirthdayThroughTipScanWork {
                        wallet_birthday_height,
                        captured_tip_height: u32::from(attempt_evidence.captured_tip.height()),
                    },
                );
            }
            let final_requested_height = certification_config.requested_block_range.end - 1;
            let Some(final_block_metadata) = block_metadata_after
                .iter()
                .find(|metadata| metadata.block_height == final_requested_height)
            else {
                return Err(BoundedScanCertificationError::MissingBlockMetadata {
                    missing_block_metadata_heights: vec![final_requested_height],
                });
            };
            let captured_tip_hash = attempt_evidence.captured_tip.hash().to_string();
            if final_block_metadata.block_hash != captured_tip_hash {
                return Err(
                    BoundedScanCertificationError::FinalBlockMetadataHashDoesNotMatchCapturedTipHash {
                        final_requested_height,
                        final_block_metadata_hash: final_block_metadata.block_hash.clone(),
                        captured_tip_hash,
                    },
                );
            }

            Ok(BoundedScanCertificationOutcome::Certified(
                BoundedScanCertificationEvidence {
                    schema_version: BOUNDED_SCAN_CERTIFICATION_EVIDENCE_SCHEMA_VERSION,
                    requested_start_height_inclusive: certification_config
                        .requested_block_range
                        .start,
                    requested_end_height_exclusive: certification_config.requested_block_range.end,
                    wallet_birthday_height,
                    captured_tip_height: u32::from(attempt_evidence.captured_tip.height()),
                    captured_tip_hash,
                    sapling_subtree_root_count: attempt_evidence.subtree_root_counts.sapling,
                    orchard_subtree_root_count: attempt_evidence.subtree_root_counts.orchard,
                    ironwood_subtree_root_count: attempt_evidence.subtree_root_counts.ironwood,
                    block_metadata_before,
                    block_metadata_after,
                    has_outstanding_scan_work_from_wallet_birthday_through_captured_tip:
                        has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height,
                },
            ))
        }
    }
}

fn bounded_scan_sync_error(error: SyncError) -> BoundedScanCertificationError {
    match error {
        SyncError::Chain(error) => BoundedScanCertificationError::Chain(error),
        error => BoundedScanCertificationError::WalletSync(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error as _, io, path::Path, time::Duration};

    use futures::{channel::oneshot, future};
    use secrecy::SecretVec;
    use zcash_client_backend::data_api::{AccountBirthday, chain::ChainState};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

    use super::*;
    use crate::components::chain::MockChain;

    fn certification_config(requested_block_range: Range<u32>) -> BoundedScanCertificationConfig {
        BoundedScanCertificationConfig::new(
            Path::new("/certification"),
            ZalletConfig::default(),
            requested_block_range,
        )
        .expect("test range is valid")
    }

    fn h(height: u32) -> BlockHeight {
        BlockHeight::from_u32(height)
    }

    fn completed_attempt() -> BoundedScanAttemptEvidence {
        BoundedScanAttemptEvidence {
            captured_tip: ChainBlock::new(h(2), BlockHash([2; 32])),
            subtree_root_counts: steps::SubtreeRootCounts {
                sapling: 3,
                orchard: 4,
                ironwood: 5,
            },
        }
    }

    fn recorded_metadata(height: u32, block_hash_byte: u8) -> BoundedScanBlockMetadataFingerprint {
        BoundedScanBlockMetadataFingerprint {
            block_height: height,
            block_hash: BlockHash([block_hash_byte; 32]).to_string(),
            sapling_tree_size: Some(height),
            orchard_tree_size: Some(height + 1),
            ironwood_tree_size: Some(height + 2),
        }
    }

    #[test]
    fn certification_range_accepts_two_through_twenty_blocks_above_height_zero() {
        assert!(
            BoundedScanCertificationConfig::new("/certification", ZalletConfig::default(), 1..3,)
                .is_ok()
        );
        assert!(
            BoundedScanCertificationConfig::new("/certification", ZalletConfig::default(), 7..27,)
                .is_ok()
        );
    }

    #[test]
    fn certification_range_rejects_height_zero_single_empty_reversed_and_oversized_ranges() {
        for requested_block_range in [0..2, 1..2, 7..7, Range { start: 8, end: 7 }, 7..28] {
            assert!(matches!(
                BoundedScanCertificationConfig::new(
                    "/certification",
                    ZalletConfig::default(),
                    requested_block_range,
                ),
                Err(BoundedScanCertificationError::InvalidRequestedBlockRange { .. })
            ));
        }
    }

    #[test]
    fn certification_datadir_must_be_absolute() {
        assert!(matches!(
            BoundedScanCertificationConfig::new(
                "relative-certification",
                ZalletConfig::default(),
                1..3,
            ),
            Err(
                BoundedScanCertificationError::CertificationDatadirNotAbsolute {
                    certification_datadir
                }
            ) if certification_datadir == Path::new("relative-certification")
        ));
    }

    #[test]
    fn certification_wallet_path_cannot_escape_the_explicit_datadir() {
        for configured_wallet_path in [
            PathBuf::from("/outside/absolute.db"),
            PathBuf::from("../outside-relative.db"),
        ] {
            let mut zallet_config = ZalletConfig {
                datadir: Some(PathBuf::from("/ignored")),
                ..Default::default()
            };
            zallet_config.database.wallet = Some(configured_wallet_path);
            let certification_config =
                BoundedScanCertificationConfig::new("/certification", zallet_config, 1..3)
                    .expect("certification config is valid");

            assert_eq!(
                certification_config.wallet_database_path(),
                PathBuf::from("/certification/wallet.db")
            );
        }
    }

    #[test]
    fn requested_range_must_end_at_the_captured_tip() {
        assert!(validate_requested_range_ends_at_captured_tip(&(1..21), 20).is_ok());
        assert!(matches!(
            validate_requested_range_ends_at_captured_tip(&(1..20), 20),
            Err(
                BoundedScanCertificationError::RequestedRangeDoesNotEndAtCapturedTip {
                    last_requested_height: 19,
                    captured_tip_height: 20,
                }
            )
        ));
        assert!(matches!(
            validate_requested_range_ends_at_captured_tip(&(2..22), 20),
            Err(
                BoundedScanCertificationError::RequestedRangeDoesNotEndAtCapturedTip {
                    last_requested_height: 21,
                    captured_tip_height: 20,
                }
            )
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certification_rejects_a_real_wallet_database_without_a_birthday() {
        crate::i18n::load_languages(&[]);
        let certification_datadir =
            tempfile::tempdir().expect("creates a certification data directory");
        let certification_config = BoundedScanCertificationConfig::new(
            certification_datadir.path(),
            ZalletConfig::default(),
            1..3,
        )
        .expect("certification config is valid");

        let error =
            certify_bounded_scan(&MockChain::reporting(Vec::new(), 1), &certification_config)
                .await
                .expect_err("wallet without an account birthday cannot be certified");

        assert!(matches!(
            error,
            BoundedScanCertificationError::MissingWalletBirthday
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn certification_rejects_a_real_wallet_birthday_that_differs_from_the_start() {
        crate::i18n::load_languages(&[]);
        let certification_datadir =
            tempfile::tempdir().expect("creates a certification data directory");
        let zallet_config = ZalletConfig::default();
        let wallet_birthday = zallet_config
            .consensus
            .network()
            .activation_height(NetworkUpgrade::Sapling)
            .expect("mainnet has a Sapling activation height");
        let wallet_birthday_height = u32::from(wallet_birthday);
        let certification_config = BoundedScanCertificationConfig::new(
            certification_datadir.path(),
            zallet_config,
            (wallet_birthday_height + 1)..(wallet_birthday_height + 3),
        )
        .expect("certification config is valid");
        let database = Database::open(&certification_config.effective_zallet_config())
            .await
            .expect("creates the certification wallet database");
        let mut wallet = database
            .handle()
            .await
            .expect("opens the certification wallet database");
        let birthday = AccountBirthday::from_parts(
            ChainState::empty(wallet_birthday - 1, BlockHash([0; 32])),
            None,
        );
        wallet
            .create_account(
                "Certification account",
                &SecretVec::new(vec![7; 32]),
                &birthday,
                None,
            )
            .expect("creates a real account at the Sapling activation height");
        assert_eq!(
            wallet
                .get_wallet_birthday()
                .expect("reads the real wallet birthday"),
            Some(wallet_birthday)
        );
        drop(wallet);
        drop(database);

        let error =
            certify_bounded_scan(&MockChain::reporting(Vec::new(), 1), &certification_config)
                .await
                .expect_err("wallet birthday must equal the requested start");

        assert!(matches!(
            error,
            BoundedScanCertificationError::WalletBirthdayDoesNotMatchRequestedStart {
                wallet_birthday_height: actual_birthday_height,
                requested_start_height_inclusive,
            }
            if actual_birthday_height == wallet_birthday_height
                && requested_start_height_inclusive == wallet_birthday_height + 1
        ));
    }

    #[test]
    fn half_open_scan_range_intersection_excludes_touching_boundaries() {
        assert!(block_ranges_intersect(&(h(5)..h(10)), &(h(9)..h(12))));
        assert!(block_ranges_intersect(&(h(5)..h(10)), &(h(5)..h(10))));
        assert!(!block_ranges_intersect(&(h(5)..h(10)), &(h(10)..h(12))));
        assert!(!block_ranges_intersect(&(h(5)..h(10)), &(h(1)..h(5))));
    }

    #[test]
    fn view_expiry_rejects_changed_block_metadata_at_the_same_height() {
        let certification_config = certification_config(1..3);
        let chain_error = ChainError::view_expired(io::Error::other("expired"));

        assert!(matches!(
            classify_bounded_scan_attempt(
                Err(BoundedScanCertificationError::Chain(chain_error)),
                &certification_config,
                1,
                vec![recorded_metadata(1, 1)],
                vec![recorded_metadata(1, 2)],
                true,
            ),
            Err(
                BoundedScanCertificationError::ChainViewExpiryChangedBlockMetadata {
                    evidence,
                    ..
                }
            ) if evidence.block_metadata_before == vec![recorded_metadata(1, 1)]
                && evidence.block_metadata_after == vec![recorded_metadata(1, 2)]
        ));
    }

    #[test]
    fn view_expiry_evidence_serializes_fingerprints_and_retains_the_chain_error_source() {
        #[derive(Debug)]
        struct ExpiredViewSource;

        impl fmt::Display for ExpiredViewSource {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("expired view source")
            }
        }

        impl std::error::Error for ExpiredViewSource {}

        let certification_config = certification_config(1..3);
        let chain_error = ChainError::view_expired(ExpiredViewSource);
        let outcome = classify_bounded_scan_attempt(
            Err(BoundedScanCertificationError::Chain(chain_error)),
            &certification_config,
            1,
            vec![recorded_metadata(1, 1)],
            vec![recorded_metadata(1, 1)],
            true,
        )
        .expect("unchanged metadata permits a typed expiry outcome");

        let BoundedScanCertificationOutcome::ChainViewExpired {
            chain_error,
            evidence,
        } = outcome
        else {
            panic!("view expiry must remain a typed outcome");
        };
        assert!(
            chain_error
                .source()
                .and_then(|source| source.downcast_ref::<ExpiredViewSource>())
                .is_some()
        );
        assert_eq!(
            serde_json::to_value(evidence).expect("view-expiry evidence serializes"),
            serde_json::json!({
                "schema_version": 1,
                "requested_start_height_inclusive": 1,
                "requested_end_height_exclusive": 3,
                "wallet_birthday_height": 1,
                "block_metadata_before": [{
                    "block_height": 1,
                    "block_hash": BlockHash([1; 32]).to_string(),
                    "sapling_tree_size": 1,
                    "orchard_tree_size": 2,
                    "ironwood_tree_size": 3,
                }],
                "block_metadata_after": [{
                    "block_height": 1,
                    "block_hash": BlockHash([1; 32]).to_string(),
                    "sapling_tree_size": 1,
                    "orchard_tree_size": 2,
                    "ironwood_tree_size": 3,
                }],
                "has_outstanding_scan_work_from_wallet_birthday_through_requested_last_height":
                    true,
            })
        );
    }

    #[test]
    fn unrelated_chain_error_is_not_classified_as_view_expiry() {
        let certification_config = certification_config(1..3);
        let chain_error = ChainError::unavailable(io::Error::other("temporarily unavailable"));

        assert!(matches!(
            classify_bounded_scan_attempt(
                Err(BoundedScanCertificationError::Chain(chain_error)),
                &certification_config,
                1,
                vec![],
                vec![],
                true,
            ),
            Err(BoundedScanCertificationError::Chain(
                ChainError::Unavailable(_)
            ))
        ));
    }

    #[test]
    fn certified_evidence_requires_complete_metadata_and_no_outstanding_work() {
        let certification_config = certification_config(1..3);

        assert!(matches!(
            classify_bounded_scan_attempt(
                Ok(completed_attempt()),
                &certification_config,
                1,
                vec![],
                vec![recorded_metadata(1, 1)],
                false,
            ),
            Err(BoundedScanCertificationError::MissingBlockMetadata {
                missing_block_metadata_heights
            }) if missing_block_metadata_heights == vec![2]
        ));
        assert!(matches!(
            classify_bounded_scan_attempt(
                Ok(completed_attempt()),
                &certification_config,
                1,
                vec![],
                vec![recorded_metadata(1, 1), recorded_metadata(2, 2)],
                true,
            ),
            Err(
                BoundedScanCertificationError::OutstandingBirthdayThroughTipScanWork {
                    wallet_birthday_height: 1,
                    captured_tip_height: 2,
                }
            )
        ));
    }

    #[test]
    fn same_height_different_tip_hash_cannot_be_certified() {
        let certification_config = certification_config(1..3);

        assert!(matches!(
            classify_bounded_scan_attempt(
                Ok(completed_attempt()),
                &certification_config,
                1,
                vec![],
                vec![recorded_metadata(1, 1), recorded_metadata(2, 7)],
                false,
            ),
            Err(
                BoundedScanCertificationError::FinalBlockMetadataHashDoesNotMatchCapturedTipHash {
                    final_requested_height: 2,
                    final_block_metadata_hash,
                    captured_tip_hash,
                }
            ) if final_block_metadata_hash == BlockHash([7; 32]).to_string()
                && captured_tip_hash == BlockHash([2; 32]).to_string()
        ));
    }

    #[test]
    fn certified_evidence_serializes_explicit_range_bounds_and_counts() {
        let certification_config = certification_config(1..3);
        let outcome = classify_bounded_scan_attempt(
            Ok(completed_attempt()),
            &certification_config,
            1,
            vec![recorded_metadata(1, 1)],
            vec![recorded_metadata(1, 1), recorded_metadata(2, 2)],
            false,
        )
        .expect("complete metadata and no outstanding work certify");
        let BoundedScanCertificationOutcome::Certified(evidence) = outcome else {
            panic!("successful attempt must return certification evidence");
        };

        assert_eq!(
            serde_json::to_value(evidence).expect("evidence serializes"),
            serde_json::json!({
                "schema_version": 1,
                "requested_start_height_inclusive": 1,
                "requested_end_height_exclusive": 3,
                "wallet_birthday_height": 1,
                "captured_tip_height": 2,
                "captured_tip_hash":
                    "0202020202020202020202020202020202020202020202020202020202020202",
                "sapling_subtree_root_count": 3,
                "orchard_subtree_root_count": 4,
                "ironwood_subtree_root_count": 5,
                "block_metadata_before": [{
                    "block_height": 1,
                    "block_hash": BlockHash([1; 32]).to_string(),
                    "sapling_tree_size": 1,
                    "orchard_tree_size": 2,
                    "ironwood_tree_size": 3,
                }],
                "block_metadata_after": [{
                    "block_height": 1,
                    "block_hash": BlockHash([1; 32]).to_string(),
                    "sapling_tree_size": 1,
                    "orchard_tree_size": 2,
                    "ironwood_tree_size": 3,
                }, {
                    "block_height": 2,
                    "block_hash": BlockHash([2; 32]).to_string(),
                    "sapling_tree_size": 2,
                    "orchard_tree_size": 3,
                    "ironwood_tree_size": 4,
                }],
                "has_outstanding_scan_work_from_wallet_birthday_through_captured_tip": false,
            })
        );
    }

    struct TaskDropNotifier(Option<oneshot::Sender<()>>);

    impl Drop for TaskDropNotifier {
        fn drop(&mut self) {
            if let Some(notifier) = self.0.take() {
                let _ = notifier.send(());
            }
        }
    }

    fn pending_decryptor_task(
        task_started: oneshot::Sender<()>,
        task_dropped: oneshot::Sender<()>,
    ) -> JoinHandle<Result<(), SyncError>> {
        tokio::spawn(async move {
            let _drop_notifier = TaskDropNotifier(Some(task_dropped));
            let _ = task_started.send(());
            future::pending::<Result<(), SyncError>>().await
        })
    }

    #[tokio::test]
    async fn decryptor_task_owner_aborts_the_task_when_dropped() {
        let (task_started, task_started_receiver) = oneshot::channel();
        let (task_dropped, task_dropped_receiver) = oneshot::channel();
        let decryptor_task =
            BoundedScanDecryptorTask::new(pending_decryptor_task(task_started, task_dropped));
        task_started_receiver
            .await
            .expect("pending task starts before its owner is dropped");

        drop(decryptor_task);

        tokio::time::timeout(Duration::from_secs(5), task_dropped_receiver)
            .await
            .expect("the pending task is dropped before the timeout")
            .expect("dropping the owner aborts and drops the pending task");
    }

    #[tokio::test]
    async fn cancelling_decryptor_join_aborts_the_owned_task() {
        let (task_started, task_started_receiver) = oneshot::channel();
        let (task_dropped, task_dropped_receiver) = oneshot::channel();
        let decryptor_task =
            BoundedScanDecryptorTask::new(pending_decryptor_task(task_started, task_dropped));
        task_started_receiver
            .await
            .expect("pending task starts before join is cancelled");
        let join_caller = tokio::spawn(decryptor_task.join());

        join_caller.abort();
        let _ = join_caller.await;

        tokio::time::timeout(Duration::from_secs(5), task_dropped_receiver)
            .await
            .expect("the pending task is dropped before the timeout")
            .expect("cancelling join drops the owner and aborts its task");
    }

    #[tokio::test]
    async fn decryptor_join_propagates_the_task_failure() {
        let decryptor_task = BoundedScanDecryptorTask::new(tokio::spawn(async {
            Err(SyncError::BatchDecryptorUnavailable)
        }));

        let error = decryptor_task
            .join()
            .await
            .expect_err("decryptor failure must propagate from join");

        assert_eq!(
            error
                .source()
                .expect("sync error is retained as the source")
                .to_string(),
            "The batch decryptor has shut down"
        );
    }
}
