use abscissa_core::Runnable;
use secrecy::{ExposeSecret, SecretString};

use crate::{
    cli::AddRpcUserCmd,
    commands::AsyncRunnable,
    components::json_rpc::server::{authorization::PasswordHash, cookie},
    error::{Error, ErrorKind},
    fl,
};

impl AsyncRunnable for AddRpcUserCmd {
    async fn run(&self) -> Result<(), Error> {
        // Refuse to emit a config block that Zallet would reject at startup.
        if self.username == cookie::COOKIE_USER {
            return Err(ErrorKind::Generic
                .context(fl!("cmd-add-rpc-user-reserved", user = cookie::COOKIE_USER))
                .into());
        }

        let password = SecretString::new(
            rpassword::prompt_password(fl!("cmd-add-rpc-user-prompt"))
                .map_err(|e| ErrorKind::Generic.context(e))?,
        );

        if password.expose_secret().is_empty() {
            return Err(ErrorKind::Generic
                .context(fl!("cmd-add-rpc-user-password-empty"))
                .into());
        }

        let pwhash = PasswordHash::from_bare(password.expose_secret());

        eprintln!("{}", fl!("cmd-add-rpc-user-instructions"));
        eprintln!();
        println!("[[rpc.auth]]");
        println!("user = \"{}\"", self.username);
        println!("pwhash = \"{pwhash}\"");

        Ok(())
    }
}

impl Runnable for AddRpcUserCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}
