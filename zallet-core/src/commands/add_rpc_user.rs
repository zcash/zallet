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

        // Emitting this snippet on stdout is the entire point of the command: the
        // user pastes it into their `zallet.toml`. It is a deliverable, not a log —
        // Zallet's only tracing subscriber writes to stderr, and there is no log
        // file. `username` is the positional argument the user just supplied, so it
        // is already in argv, and the password itself never leaves `SecretString`:
        // only its salted hash is printed. CodeQL's `rust/cleartext-logging` still
        // flags the `user` line, because it treats `println!` as a logging sink.
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
