use age::secrecy::SecretString;
use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use crate::components::{
    json_rpc::server::LegacyCode,
    keystore::{KeyStore, KeystoreError},
};

/// Response to a `walletpassphrase` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// Empty result indicating success.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(());

pub(super) const PARAM_PASSPHRASE_DESC: &str =
    "The passphrase for decrypting the wallet's age identity.";
pub(super) const PARAM_TIMEOUT_DESC: &str = "Time in seconds after which the wallet will relock.";

pub(crate) async fn call(keystore: &KeyStore, passphrase: SecretString, timeout: u64) -> Response {
    if !keystore.uses_encrypted_identities() {
        return Err(LegacyCode::WalletWrongEncState.with_static(
            "Error: running with an unencrypted wallet, but walletpassphrase was called.",
        ));
    }

    match keystore.unlock(passphrase, timeout).await {
        Ok(()) => Ok(ResultType(())),
        Err(KeystoreError::IncorrectPassphrase) => Err(LegacyCode::WalletPassphraseIncorrect
            .with_static("Error: The wallet passphrase entered was incorrect.")),
        Err(KeystoreError::TimeoutTooLarge) => Err(LegacyCode::InvalidParameter
            .with_static("Error: timeout is too large; please choose a smaller value.")),
        Err(KeystoreError::MissingRecipients) => Err(LegacyCode::WalletWrongEncState.with_static(
            "Error: running with an unencrypted wallet, but walletpassphrase was called.",
        )),
    }
}
