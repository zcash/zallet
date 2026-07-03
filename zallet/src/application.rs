//! Zallet Abscissa Application

use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use abscissa_core::{
    Application, Component, FrameworkError, FrameworkErrorKind, StandardPaths,
    application::{self, AppCell},
    config::{self, CfgCell},
    terminal::component::Terminal,
};
use abscissa_tokio::TokioComponent;
use i18n_embed::unic_langid::LanguageIdentifier;

use crate::{
    cli::EntryPoint,
    components::{chain::ChainRuntime, tracing::Tracing},
    config::ZalletConfig,
    fl, i18n,
};

/// Application state
pub static APP: AppCell<ZalletApp> = AppCell::new();

/// The chain backend registered for this process.
static CHAIN_RUNTIME: OnceLock<&'static dyn ChainRuntime> = OnceLock::new();

/// Returns the chain backend registered at boot.
///
/// Panics if called before [`boot`]; commands only run inside a booted application,
/// so this is unreachable in practice.
pub(crate) fn chain_runtime() -> &'static dyn ChainRuntime {
    CHAIN_RUNTIME
        .get()
        .copied()
        .expect("chain backend is registered before commands run")
}

/// When Zallet is shutting down, wait at most this long for Tokio tasks to finish.
const TOKIO_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

/// Zallet Application
#[derive(Debug)]
pub struct ZalletApp {
    /// Application configuration.
    config: CfgCell<ZalletConfig>,

    /// Application state.
    state: application::State<Self>,
}

/// Initializes a new application instance.
///
/// By default no configuration is loaded, and the framework state is initialized to a
/// default, empty state (no components, threads, etc).
impl Default for ZalletApp {
    fn default() -> Self {
        Self {
            config: CfgCell::default(),
            state: application::State::default(),
        }
    }
}

impl Application for ZalletApp {
    type Cmd = EntryPoint;
    type Cfg = ZalletConfig;
    type Paths = StandardPaths;

    fn config(&self) -> config::Reader<ZalletConfig> {
        self.config.read()
    }

    /// Overridden so config errors name the file: a missing config reports
    /// `err-config-file-not-found`, and a parse error reports
    /// `err-config-file-invalid` with the offending path (the framework
    /// otherwise omits it).
    fn load_config(&mut self, path: &Path) -> Result<Self::Cfg, FrameworkError> {
        let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());

        if !path.exists() {
            return Err(FrameworkErrorKind::ConfigError
                .context(fl!(
                    "err-config-file-not-found",
                    path = abs.display().to_string()
                ))
                .into());
        }

        let contents =
            std::fs::read_to_string(path).map_err(|e| FrameworkErrorKind::IoError.context(e))?;
        toml::from_str(&contents).map_err(|e| {
            FrameworkErrorKind::ConfigError
                .context(fl!(
                    "err-config-file-invalid",
                    path = abs.display().to_string(),
                    error = e.to_string()
                ))
                .into()
        })
    }

    fn state(&self) -> &application::State<Self> {
        &self.state
    }

    // Overridden to leave out framework components.
    fn framework_components(
        &mut self,
        command: &Self::Cmd,
    ) -> Result<Vec<Box<dyn Component<Self>>>, FrameworkError> {
        let terminal = Terminal::new(self.term_colors(command));
        // Don't use the framework's `Tracing` component.

        Ok(vec![Box::new(terminal)])
    }

    fn register_components(&mut self, command: &Self::Cmd) -> Result<(), FrameworkError> {
        let mut components = self.framework_components(command)?;
        components.push(Box::new(
            Tracing::new(self.term_colors(command))
                .expect("tracing subsystem failed to initialize"),
        ));
        components.push(Box::new(
            TokioComponent::from(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name_fn(|| {
                        static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
                        let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
                        format!("tokio-worker-{id}")
                    })
                    .build()
                    .expect("failed to build Tokio runtime"),
            )
            .with_shutdown_timeout(TOKIO_SHUTDOWN_TIMEOUT),
        ));
        self.state.components_mut().register(components)
    }

    fn after_config(&mut self, config: Self::Cfg) -> Result<(), FrameworkError> {
        // Configure components
        let mut components = self.state.components_mut();
        components.after_config(&config)?;
        self.config.set_once(config);
        Ok(())
    }
}

/// Boots the Zallet application, parsing subcommand and options from command-line
/// arguments, and terminating when complete.
pub fn boot(requested_languages: Vec<LanguageIdentifier>) {
    // We load languages here so that the app's CLI usage text can be localized.
    i18n::load_languages(&requested_languages);

    // Register the compile-time-selected chain backend. Once the backends move to
    // their own crates (zcash/zallet#540), each backend binary registers its own
    // factory here instead.
    let _ = CHAIN_RUNTIME.set(crate::components::chain::DEFAULT_CHAIN_RUNTIME);

    // Now do the normal Abscissa boot.
    abscissa_core::boot(&APP);
}

#[cfg(test)]
mod tests {
    /// Registration hands back the registered backend through `chain_runtime`.
    ///
    /// (A full boot isn't runnable in a unit test; registration is the part this
    /// module owns.)
    #[test]
    fn chain_runtime_registration() {
        let _ = super::CHAIN_RUNTIME.set(crate::components::chain::DEFAULT_CHAIN_RUNTIME);
        // Must not panic:
        let _rt = super::chain_runtime();
    }
}
