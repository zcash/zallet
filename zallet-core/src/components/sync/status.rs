//! The sync engine's published status, and the gate that uses it.
//!
//! [`SyncStatus`] models the two conditions under which the wallet should not be used,
//! mirroring `zcashd`:
//!
//! - [`SyncStatus::CatchingUp`] — the wallet has not yet scanned up to the chain tip, so
//!   its balance is incomplete (analogous to initial block download).
//! - [`SyncStatus::Recovering`] — the sync engine detected that the wallet’s view had
//!   diverged from the chain (a reorg that occurred while Zallet was offline, or a live
//!   reorg) and is rolling back and rescanning (analogous to safe mode).
//!
//! The status is owned and published by the sync engine — the only component that can
//! observe a recovery in progress — and read by the JSON-RPC layer. It is published over
//! a [`watch`] channel, so reading it is a cheap, non-blocking borrow with no network
//! round-trip.

use std::sync::Arc;

use tokio::sync::watch;
use zcash_protocol::consensus::BlockHeight;

// `ensure_available` is only used by the wallet build’s balance and spend RPC methods.
#[cfg(zallet_build = "wallet")]
use {crate::components::json_rpc::server::LegacyCode, jsonrpsee::core::RpcResult};

/// Whether the wallet is usable, and if not, why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SyncStatus {
    /// The wallet has not yet scanned up to the chain tip; its balance is incomplete.
    CatchingUp {
        fully_synced: Option<BlockHeight>,
        tip: BlockHeight,
    },
    /// The wallet is synced to the chain tip and its view is trustworthy.
    Synced,
    /// A chain divergence was detected; the engine is rolling back and rescanning.
    Recovering { rolled_back_to: BlockHeight },
}

/// The raw signals the sync engine maintains, from which [`SyncStatus`] is derived.
#[derive(Clone, Debug)]
struct SyncSignals {
    /// The latest chain tip height observed from the indexer.
    tip: BlockHeight,
    /// The height to which the wallet is fully scanned (`block_fully_scanned`).
    fully_synced: Option<BlockHeight>,
    /// Whether steady-state sync has reached the chain tip at least once.
    tip_reached: bool,
    /// Set to the rollback target while a divergence is being repaired.
    recovering: Option<BlockHeight>,
}

impl SyncSignals {
    /// Derives the externally-visible status.
    ///
    /// `tolerance` is the maximum number of blocks the wallet may trail the tip while
    /// still counting as synced. A wallet that is still backfilling historical state has
    /// `fully_synced` far below the tip, so it derives [`SyncStatus::CatchingUp`].
    fn status(&self, tolerance: u32) -> SyncStatus {
        // A detected divergence takes priority: even if we happen to be near the tip, the
        // wallet's view is being repaired and must not be used.
        if let Some(rolled_back_to) = self.recovering {
            return SyncStatus::Recovering { rolled_back_to };
        }
        let within_tip = self
            .fully_synced
            .is_some_and(|fs| u32::from(self.tip).saturating_sub(u32::from(fs)) <= tolerance);
        if self.tip_reached && within_tip {
            SyncStatus::Synced
        } else {
            SyncStatus::CatchingUp {
                fully_synced: self.fully_synced,
                tip: self.tip,
            }
        }
    }
}

/// Writer half, held by the sync engine and shared across its tasks.
///
/// [`watch::Sender::send_modify`] takes `&self`, so the sync tasks can share this (via the
/// inner [`Arc`]) and update it concurrently; the channel serializes updates.
#[derive(Clone)]
pub(crate) struct SyncStatusWriter(Arc<watch::Sender<SyncSignals>>);

impl SyncStatusWriter {
    /// Records the latest observed chain tip height.
    pub(crate) fn set_tip(&self, tip: BlockHeight) {
        self.0.send_modify(|s| s.tip = tip);
    }

    /// Records the height to which the wallet is now fully scanned.
    pub(crate) fn set_fully_synced(&self, fully_synced: Option<BlockHeight>) {
        self.0.send_modify(|s| s.fully_synced = fully_synced);
    }

    /// Marks that steady-state sync has reached the chain tip.
    pub(crate) fn mark_tip_reached(&self) {
        self.0.send_modify(|s| s.tip_reached = true);
    }

    /// Engages the recovering (safe-mode) state while a divergence is repaired.
    pub(crate) fn begin_recovery(&self, rolled_back_to: BlockHeight) {
        self.0.send_modify(|s| s.recovering = Some(rolled_back_to));
    }

    /// Clears the recovering state once the wallet has caught back up.
    pub(crate) fn end_recovery(&self) {
        self.0.send_modify(|s| s.recovering = None);
    }
}

/// Reader half, held by the JSON-RPC layer.
#[derive(Clone)]
pub(crate) struct SyncStatusReader {
    rx: watch::Receiver<SyncSignals>,
    tolerance: u32,
}

impl SyncStatusReader {
    /// The current sync status.
    pub(crate) fn status(&self) -> SyncStatus {
        self.rx.borrow().status(self.tolerance)
    }

    /// Returns an error if the wallet is not synced enough to be used.
    ///
    /// Used to gate balance and spend methods: catching up maps to the "still in initial
    /// download" error, and recovering to the "forbidden by safe mode" error.
    #[cfg(zallet_build = "wallet")]
    pub(crate) fn ensure_available(&self) -> RpcResult<()> {
        match self.status() {
            SyncStatus::Synced => Ok(()),
            SyncStatus::CatchingUp { fully_synced, tip } => {
                let behind = fully_synced.map_or_else(
                    || u32::from(tip),
                    |fs| u32::from(tip).saturating_sub(u32::from(fs)),
                );
                Err(LegacyCode::ClientInInitialDownload.with_message(format!(
                    "Wallet is still catching up ({behind} blocks behind the chain tip); \
                     balance and spend operations are unavailable until it is synced"
                )))
            }
            SyncStatus::Recovering { rolled_back_to } => {
                Err(LegacyCode::ForbiddenBySafeMode.with_message(format!(
                    "Wallet is recovering from a chain reorganization (rolled back to \
                     {rolled_back_to}); balance and spend operations are unavailable until \
                     it has resynced"
                )))
            }
        }
    }
}

/// Creates a linked writer/reader pair, initially [`SyncStatus::CatchingUp`].
///
/// `tolerance` is the maximum number of blocks the wallet may trail the chain tip while
/// still being considered synced (the `sync.lock_threshold` config option).
pub(crate) fn channel(tolerance: u32) -> (SyncStatusWriter, SyncStatusReader) {
    let (tx, rx) = watch::channel(SyncSignals {
        tip: BlockHeight::from_u32(0),
        fully_synced: None,
        tip_reached: false,
        recovering: None,
    });
    (
        SyncStatusWriter(Arc::new(tx)),
        SyncStatusReader { rx, tolerance },
    )
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::BlockHeight;

    use super::{SyncSignals, SyncStatus};

    fn h(height: u32) -> BlockHeight {
        BlockHeight::from_u32(height)
    }

    fn signals() -> SyncSignals {
        SyncSignals {
            tip: h(1000),
            fully_synced: Some(h(1000)),
            tip_reached: true,
            recovering: None,
        }
    }

    #[test]
    fn synced_when_at_tip_and_reached() {
        assert_eq!(signals().status(100), SyncStatus::Synced);
        // Within tolerance still counts as synced.
        let s = SyncSignals {
            fully_synced: Some(h(950)),
            ..signals()
        };
        assert_eq!(s.status(100), SyncStatus::Synced);
    }

    #[test]
    fn catching_up_before_tip_reached() {
        let s = SyncSignals {
            tip_reached: false,
            ..signals()
        };
        assert!(matches!(s.status(100), SyncStatus::CatchingUp { .. }));
    }

    #[test]
    fn catching_up_when_backfilling_history() {
        // Tip reached, but historical state is unscanned, so `fully_synced` trails far
        // behind the tip.
        let s = SyncSignals {
            fully_synced: Some(h(200)),
            ..signals()
        };
        assert!(matches!(s.status(100), SyncStatus::CatchingUp { .. }));
    }

    #[test]
    fn catching_up_when_never_synced() {
        let s = SyncSignals {
            fully_synced: None,
            ..signals()
        };
        assert!(matches!(s.status(100), SyncStatus::CatchingUp { .. }));
    }

    #[test]
    fn recovering_takes_priority_over_being_at_tip() {
        let s = SyncSignals {
            recovering: Some(h(900)),
            ..signals()
        };
        assert_eq!(
            s.status(100),
            SyncStatus::Recovering {
                rolled_back_to: h(900)
            }
        );
    }

    #[test]
    fn synced_at_exact_tolerance_boundary_but_not_one_past() {
        // Trailing the tip by exactly `tolerance` still counts as synced (tip 1000,
        // fully_synced 900, tolerance 100).
        let at = SyncSignals {
            fully_synced: Some(h(900)),
            ..signals()
        };
        assert_eq!(at.status(100), SyncStatus::Synced);
        // One block further behind tips over into catching up.
        let past = SyncSignals {
            fully_synced: Some(h(899)),
            ..signals()
        };
        assert!(matches!(past.status(100), SyncStatus::CatchingUp { .. }));
    }

    #[test]
    fn channel_starts_catching_up() {
        let (_writer, reader) = super::channel(100);
        assert!(matches!(reader.status(), SyncStatus::CatchingUp { .. }));
    }

    #[test]
    fn writer_updates_flow_through_to_the_reader() {
        let (writer, reader) = super::channel(100);

        writer.set_tip(h(1000));
        writer.set_fully_synced(Some(h(1000)));
        writer.mark_tip_reached();
        assert_eq!(reader.status(), SyncStatus::Synced);

        // A recovery overrides the synced view until it is cleared.
        writer.begin_recovery(h(900));
        assert_eq!(
            reader.status(),
            SyncStatus::Recovering {
                rolled_back_to: h(900)
            }
        );

        writer.end_recovery();
        assert_eq!(reader.status(), SyncStatus::Synced);
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn ensure_available_maps_each_state_to_its_error_code() {
        let (writer, reader) = super::channel(100);

        // Initial state is catching up → `ClientInInitialDownload`.
        assert_eq!(reader.ensure_available().unwrap_err().code(), -10);

        // Synced → available.
        writer.set_tip(h(1000));
        writer.set_fully_synced(Some(h(1000)));
        writer.mark_tip_reached();
        assert!(reader.ensure_available().is_ok());

        // Recovering → `ForbiddenBySafeMode`.
        writer.begin_recovery(h(900));
        assert_eq!(reader.ensure_available().unwrap_err().code(), -2);
    }
}
