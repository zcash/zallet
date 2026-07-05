//! Components of Zallet.
//!
//! These are not [`abscissa_core::Component`]s because Abscissa's dependency injection is
//! [buggy](https://github.com/iqlusioninc/abscissa/issues/989).

use tokio::task::JoinHandle;

use crate::error::Error;

pub mod chain;
pub(crate) mod database;
pub(crate) mod json_rpc;
pub(crate) mod sync;
pub(crate) mod tracing;

#[cfg(zallet_build = "wallet")]
pub(crate) mod keystore;

/// A handle to a background task spawned by a component.
///
/// Background tasks in Zallet are either one-shot (expected to terminate before Zallet),
/// or ongoing (Zallet shuts down if the task finishes). The tasks are monitored by
/// [`StartCmd::run`].
///
/// [`StartCmd::run`]: crate::commands::AsyncRunnable::run
pub type TaskHandle = JoinHandle<Result<(), Error>>;
