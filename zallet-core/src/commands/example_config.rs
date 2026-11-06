//! `example-config` subcommand

use abscissa_core::Runnable;

use crate::{
    cli::ExampleConfigCmd,
    commands::{AsyncRunnable, overwrite_allowed, resolve_output_target, write_config_output},
    config::ZalletConfig,
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

impl AsyncRunnable for ExampleConfigCmd {
    async fn run(&self) -> Result<(), Error> {
        if !self.this_is_beta_code_and_you_will_need_to_recreate_the_example_later {
            return Err(ErrorKind::Generic.context(fl!("example-beta-code")).into());
        }

        // Serialize the example config.
        let output = ZalletConfig::generate_example();

        // Write the Zallet config file. `--force` may overwrite only a target named
        // explicitly with `-o`; the inferred default path is the live config, which
        // is never overwritten.
        let output_path = resolve_output_target(APP.config().datadir(), self.output.as_deref());
        if let Some(path) = output_path {
            write_config_output(
                &path,
                overwrite_allowed(self.force, self.output.is_some()),
                &output,
            )?;
            println!(
                "{}",
                fl!("migrate-config-written", conf = path.display().to_string())
            );
        } else {
            println!("{output}")
        }

        Ok(())
    }
}

impl Runnable for ExampleConfigCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
