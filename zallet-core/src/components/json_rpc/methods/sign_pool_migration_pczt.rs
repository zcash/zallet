//! `z_signpoolmigrationpczt`: sign a migration PCZT with the account's spend authorization.
//!
//! For offline / air-gapped signing (build the migration on one wallet, sign on another holding the
//! key), and the software stand-in a hardware device performs on-device: it takes an unsigned
//! migration PCZT (from `z_startpoolmigration` with `external_signer`, or
//! `z_buildpoolmigrationtransfers`), adds only the account's Orchard spend-authorization signature (the
//! Signer role), and returns the signed PCZT to apply with `z_applypoolmigrationsignature`. It does not
//! prove, extract, or broadcast. A hardware wallet performs the equivalent signing on the device
//! instead of calling this.

use base64ct::{Base64, Encoding};
use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use schemars::JsonSchema;
use serde::Serialize;

use super::pool_migration::decrypt_account_usk;
use crate::components::database::DbConnection;
use crate::components::json_rpc::server::LegacyCode;
use crate::components::json_rpc::utils::parse_account_parameter;
use crate::components::keystore::KeyStore;
use crate::migrate::sign_migration_pczt;

/// Response to a `z_signpoolmigrationpczt` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = SignPoolMigrationPczt;

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "Either the UUID or ZIP 32 account index of the account whose spend key signs the PCZT.";
pub(super) const PARAM_PCZT_DESC: &str = "The unsigned migration PCZT to sign, base64 encoded (from z_startpoolmigration with \
     external_signer, or z_buildpoolmigrationtransfers).";

/// The result of signing a migration PCZT.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct SignPoolMigrationPczt {
    /// The signed PCZT, base64 encoded, to apply with z_applypoolmigrationsignature.
    pczt: String,
}

pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account: JsonValue,
    pczt: &str,
) -> Response {
    let account_id = parse_account_parameter(wallet, keystore, &account).await?;
    let usk = decrypt_account_usk(wallet, keystore, account_id).await?;

    let bytes = Base64::decode_vec(pczt)
        .map_err(|_| LegacyCode::InvalidParameter.with_static("Malformed base64 PCZT"))?;
    // Signing is CPU-light and touches no wallet database, so it needs no blocking section.
    let signed = sign_migration_pczt(&usk, &bytes)
        .map_err(|e| LegacyCode::Misc.with_message(e.to_string()))?;

    Ok(SignPoolMigrationPczt {
        pczt: Base64::encode_string(&signed),
    })
}
