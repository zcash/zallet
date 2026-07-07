use abscissa_core::Runnable;
use secrecy::{ExposeSecret, SecretString};

use crate::{
    cli::AddRpcUserCmd,
    commands::AsyncRunnable,
    components::json_rpc::server::authorization::PasswordHash,
    error::{Error, ErrorKind},
    fl,
};

impl AsyncRunnable for AddRpcUserCmd {
    async fn run(&self) -> Result<(), Error> {
        let password = SecretString::new(
            rpassword::prompt_password(fl!("cmd-add-rpc-user-prompt"))
                .map_err(|e| ErrorKind::Generic.context(e))?,
        );

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
