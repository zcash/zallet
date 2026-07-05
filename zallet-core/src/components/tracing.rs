use std::io;

use tracing::level_filters::LevelFilter;
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt};

use abscissa_core::{Component, FrameworkError, FrameworkErrorKind, terminal::ColorChoice};

/// Abscissa component for initializing the `tracing` subsystem
#[derive(Component, Debug)]
#[component(core)]
pub(crate) struct Tracing {}

impl Tracing {
    pub(crate) fn new(color_choice: ColorChoice) -> Result<Self, FrameworkError> {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        // Configure log/tracing interoperability by setting a `LogTracer` as
        // the global logger for the log crate, which converts all log events
        // into tracing events.
        LogTracer::init().map_err(|e| FrameworkErrorKind::ComponentError.context(e))?;

        // Construct a tracing subscriber with the supplied filter and enable reloading.
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(io::stderr)
            .with_ansi(match color_choice {
                ColorChoice::Always => true,
                ColorChoice::AlwaysAnsi => true,
                ColorChoice::Auto => true,
                ColorChoice::Never => false,
            })
            .with_filter(env_filter);

        let subscriber = tracing_subscriber::registry().with(fmt_layer);

        // Spawn the console server in the background, and apply the console layer.
        #[cfg(all(feature = "tokio-console", tokio_unstable))]
        let subscriber = subscriber.with(console_subscriber::spawn());

        // Now set it as the global tracing subscriber and save the handle.
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| FrameworkErrorKind::ComponentError.context(e))?;

        Ok(Self {})
    }
}
