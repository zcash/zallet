//! `z_getmultisigkeyinfo` — export this wallet's ZIP 48 cosigner key.
//!
//! A ZIP 48 multisig account is defined by the set of its cosigners' extended public
//! keys, which each participant derives independently and then shares with the others.
//! This exports one such key: the one this wallet contributes.
//!
//! The key is reported as a [BIP 388 `KEY_INFO` expression] rather than a bare xpub,
//! because the key origin is part of what the other cosigners need — reconstructing the
//! account requires knowing the path each key was derived at, and an xpub alone does not
//! carry it. It is also the form hardware wallets consume.
//!
//! Exporting a key is not itself an account: nothing is recorded here, and the wallet
//! learns nothing about who the other cosigners are. That happens when every
//! participant's key is collected and the account is registered.
//!
//! [BIP 388 `KEY_INFO` expression]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki#key-information-vector

use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Serialize;
use transparent::zip48;
use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_protocol::consensus::{NetworkConstants, Parameters};

use crate::components::{
    database::DbConnection,
    json_rpc::{
        server::LegacyCode,
        utils::{ensure_wallet_is_unlocked, parse_account_parameter},
    },
    keystore::KeyStore,
};

/// Response to a `z_getmultisigkeyinfo` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// This wallet's ZIP 48 cosigner key, for sharing with the other cosigners.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// The account's UUID within this Zallet instance.
    account_uuid: String,

    /// The ZIP 48 path the key was derived at, as `m/48'/<coin_type>'/<account>'/133000'`.
    ///
    /// This is also carried inside `key_info`; it is reported separately so that the
    /// response can be read without parsing the expression.
    derivation_path: String,

    /// The BIP 388 `KEY_INFO` expression naming this wallet's cosigner key.
    ///
    /// Give this to the other cosigners, and collect theirs in turn: registering the
    /// multisig account requires the whole set. It is public key material, so it needs
    /// no more protection in transit than an address does — but a substituted key
    /// silently changes every address the account derives, so verify the collected set
    /// out of band.
    key_info: String,
}

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "Either the UUID or ZIP 32 account index of the account to derive the cosigner key from.";

/// The ZIP 48 `script_type` path element for Zcash P2SH multisig.
///
/// Named here only to report the derivation path; the derivation itself is
/// [`zip48::AccountPrivKey`]'s, which fixes the same value. [`derivation_path`] is
/// checked against a derived key in the tests below, so the two cannot drift apart
/// silently.
const ZCASH_P2SH_SCRIPT_TYPE: u32 = 133_000;

/// The ZIP 48 path a cosigner key for `account_index` is derived at.
///
/// Rendered with a leading `m/`, as derivation paths conventionally are; the same path
/// appears without it inside the `KEY_INFO` expression, after the key's fingerprint.
fn derivation_path<P: Parameters>(params: &P, account_index: zip32::AccountId) -> String {
    format!(
        "m/48'/{}'/{}'/{ZCASH_P2SH_SCRIPT_TYPE}'",
        params.coin_type(),
        u32::from(account_index),
    )
}

/// Derives this wallet's ZIP 48 cosigner key from `seed`, as a `KEY_INFO` expression.
///
/// The ZIP 48 account index is the Zallet account's own ZIP 32 index, so the key a given
/// account contributes is stable and re-exporting reproduces it.
fn cosigner_key_info<P: Parameters>(
    params: &P,
    seed: &[u8],
    account_index: zip32::AccountId,
) -> RpcResult<String> {
    let account_key =
        zip48::AccountPrivKey::from_seed(params, seed, account_index).map_err(|e| {
            LegacyCode::Wallet.with_message(format!("Failed to derive the ZIP 48 account key: {e}"))
        })?;

    Ok(account_key.to_account_pubkey().key_info_expression(params))
}

pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account: JsonValue,
) -> Response {
    ensure_wallet_is_unlocked(keystore).await?;

    let account_id = parse_account_parameter(wallet, keystore, &account).await?;

    let account = wallet
        .get_account(account_id)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        // This would be a race condition between this and account deletion.
        .ok_or_else(|| {
            LegacyCode::Wallet.with_static("Error: the account no longer exists in this wallet")
        })?;

    // ZIP 48 derives from a seed, so an account that has none has no cosigner key to
    // export. An account imported from a viewing key is the case that reaches here.
    let derivation = account.source().key_derivation().ok_or_else(|| {
        LegacyCode::Wallet.with_static(
            "Error: cannot derive a ZIP 48 cosigner key for an account that was imported \
             from a viewing key, as it has no seed to derive from",
        )
    })?;

    let seed = keystore
        .decrypt_seed(derivation.seed_fingerprint())
        .await
        .map_err(|e| match e.kind() {
            // TODO: Improve internal error types.
            //       https://github.com/zcash/zallet/issues/256
            crate::error::ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
            }
            _ => LegacyCode::Database.with_message(e.to_string()),
        })?;

    let account_index = derivation.account_index();

    Ok(ResultType {
        account_uuid: account_id.expose_uuid().to_string(),
        derivation_path: derivation_path(wallet.params(), account_index),
        key_info: cosigner_key_info(wallet.params(), seed.expose_secret(), account_index)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus;

    use crate::network::Network;

    fn mainnet() -> Network {
        Network::Consensus(consensus::Network::MainNetwork)
    }

    fn testnet() -> Network {
        Network::Consensus(consensus::Network::TestNetwork)
    }

    fn account(index: u32) -> zip32::AccountId {
        zip32::AccountId::try_from(index).expect("valid account index")
    }

    /// The first cosigner key of the worked example in ZIP 48, which
    /// `zcash_transparent`'s own `zip_48_example` test also pins.
    ///
    /// Having it here as well is what makes this module's derivation — the seed and
    /// account index it feeds in, not just the arithmetic it delegates — a fixed
    /// quantity rather than whatever the upstream call happens to return.
    const ZIP_48_EXAMPLE_SEED: [u8; 32] = [1; 32];
    const ZIP_48_EXAMPLE_KEY_INFO: &str = "[4ba43603/48'/133'/0'/133000']xpub6E96VHgq8MKkYGuNLDjxLxH3LH93NGJX5xSufVjnh7zM8bKehGr3iekJLyc8WJiMemYWuXLPKwygt3j9nfJCapPkYRfCc5YFvzb3aMLsQdV";

    #[test]
    fn matches_the_zip_48_example_vector() {
        let key_info = cosigner_key_info(&mainnet(), &ZIP_48_EXAMPLE_SEED, account(0)).unwrap();

        assert_eq!(key_info, ZIP_48_EXAMPLE_KEY_INFO);
    }

    /// The reported path must be the path the key was actually derived at. They are
    /// produced by different code — one formatted here, one embedded by the derivation —
    /// so this is the check that keeps them honest.
    #[test]
    fn reported_path_is_the_path_the_key_was_derived_at() {
        for (params, name) in [(mainnet(), "mainnet"), (testnet(), "testnet")] {
            for index in [0, 1, 42] {
                let path = derivation_path(&params, account(index));
                let key_info =
                    cosigner_key_info(&params, &ZIP_48_EXAMPLE_SEED, account(index)).unwrap();

                let embedded = path
                    .strip_prefix("m/")
                    .expect("derivation_path renders a leading m/");
                assert!(
                    key_info.contains(embedded),
                    "{name} account {index}: {key_info} does not contain {embedded}",
                );
            }
        }
    }

    /// A cosigner has to be able to hand the expression to the others and have them
    /// parse it back, so the export must satisfy the parser it will meet.
    #[test]
    fn exported_key_info_parses_back() {
        let params = mainnet();
        let key_info = cosigner_key_info(&params, &ZIP_48_EXAMPLE_SEED, account(0)).unwrap();

        assert!(
            zip48::AccountPubKey::parse_key_info_expression(&key_info, &params).is_some(),
            "exported expression did not parse: {key_info}",
        );
    }

    /// The coin type is part of the ZIP 48 path, so a key exported by a mainnet wallet
    /// must not be accepted into a testnet account, or vice versa. Registering across
    /// networks would produce an account nobody can spend from.
    #[test]
    fn key_info_does_not_parse_on_the_other_network() {
        let mainnet_key = cosigner_key_info(&mainnet(), &ZIP_48_EXAMPLE_SEED, account(0)).unwrap();
        let testnet_key = cosigner_key_info(&testnet(), &ZIP_48_EXAMPLE_SEED, account(0)).unwrap();

        assert!(
            zip48::AccountPubKey::parse_key_info_expression(&mainnet_key, &testnet()).is_none(),
            "a mainnet cosigner key parsed as testnet",
        );
        assert!(
            zip48::AccountPubKey::parse_key_info_expression(&testnet_key, &mainnet()).is_none(),
            "a testnet cosigner key parsed as mainnet",
        );
    }

    /// Re-exporting must reproduce the key, or a cosigner who exports twice would hand
    /// out two different keys for one account.
    #[test]
    fn export_is_deterministic() {
        let params = mainnet();
        let first = cosigner_key_info(&params, &ZIP_48_EXAMPLE_SEED, account(7)).unwrap();
        let second = cosigner_key_info(&params, &ZIP_48_EXAMPLE_SEED, account(7)).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn distinct_accounts_and_seeds_give_distinct_keys() {
        let params = mainnet();
        let account_0 = cosigner_key_info(&params, &ZIP_48_EXAMPLE_SEED, account(0)).unwrap();
        let account_1 = cosigner_key_info(&params, &ZIP_48_EXAMPLE_SEED, account(1)).unwrap();
        let other_seed = cosigner_key_info(&params, &[2; 32], account(0)).unwrap();

        assert_ne!(account_0, account_1);
        assert_ne!(account_0, other_seed);
    }
}
