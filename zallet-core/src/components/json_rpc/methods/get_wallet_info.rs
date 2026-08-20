use std::time::UNIX_EPOCH;

use documented::Documented;
use jsonrpsee::{core::RpcResult, tracing::warn};
use schemars::JsonSchema;
use serde::Serialize;
use zcash_protocol::value::Zatoshis;

use crate::components::{
    json_rpc::utils::{JsonZec, value_from_zatoshis},
    keystore::KeyStore,
};

/// Response to a `getwalletinfo` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = GetWalletInfo;

/// The wallet state information.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct GetWalletInfo {
    /// The wallet version, in its "Bitcoin client version" form.
    walletversion: u64,

    /// The total confirmed transparent balance of the wallet in ZEC.
    balance: JsonZec,

    /// The total unconfirmed transparent balance of the wallet in ZEC.
    ///
    /// Not included if `asOfHeight` is specified.
    unconfirmed_balance: Option<JsonZec>,

    /// The total immature transparent balance of the wallet in ZEC.
    immature_balance: JsonZec,

    /// The total confirmed shielded balance of the wallet in ZEC.
    shielded_balance: String,

    /// The total unconfirmed shielded balance of the wallet in ZEC.
    ///
    /// Not included if `asOfHeight` is specified.
    shielded_unconfirmed_balance: Option<String>,

    /// The total number of transactions in the wallet
    txcount: u64,

    /// The timestamp (seconds since GMT epoch) of the oldest pre-generated key in the
    /// key pool.
    keypoololdest: u64,

    /// How many new keys are pre-generated.
    keypoolsize: u32,

    /// The timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is
    /// unlocked for transfers, or 0 if the wallet is locked.
    #[serde(skip_serializing_if = "Option::is_none")]
    unlocked_until: Option<u64>,

    /// The ZIP 32 seed fingerprint of the wallet's mnemonic phrase.
    ///
    /// Present only when the wallet holds exactly one mnemonic phrase, so that this
    /// `zcashd`-inherited field always means what `zcashd` meant by it: `zcashd` had at
    /// most one phrase per wallet, and omitted this field when it had none. A Zallet
    /// wallet may hold any number, so see `mnemonic_seedfps` for the general case.
    #[serde(skip_serializing_if = "Option::is_none")]
    mnemonic_seedfp: Option<String>,

    /// Every ZIP 32 seed fingerprint the wallet holds, in lexicographic order.
    ///
    /// Empty if the wallet holds no mnemonic phrases. Omitted, along with
    /// `mnemonic_seedfp`, only if the key store could not be queried.
    ///
    /// Use `z_listaccounts` to learn which phrase an individual account derives from.
    #[serde(skip_serializing_if = "Option::is_none")]
    mnemonic_seedfps: Option<Vec<String>>,
}

pub(crate) async fn call(keystore: &KeyStore) -> Response {
    // https://github.com/zcash/zallet/issues/620
    warn!(
        "TODO: getwalletinfo still reports placeholders for walletversion, balance, \
         unconfirmed_balance, immature_balance, shielded_balance, \
         shielded_unconfirmed_balance, txcount, keypoololdest, and keypoolsize"
    );

    let mnemonic_seedfps = match keystore.list_seed_fingerprints().await {
        Ok(seed_fps) => {
            let mut seed_fps = seed_fps
                .into_iter()
                .map(|seed_fp| seed_fp.to_string())
                .collect::<Vec<_>>();
            // `list_seed_fingerprints` returns a `HashSet`, whose iteration order varies
            // between calls; sort so that repeated calls agree.
            seed_fps.sort();
            Some(seed_fps)
        }
        Err(e) => {
            // Degrade rather than failing the whole method: every other field here is
            // computable without the key store database, and omitting these two is
            // unambiguous because `mnemonic_seedfps` is otherwise always present.
            warn!("Failed to list the wallet's seed fingerprints: {e}");
            None
        }
    };

    // `zcashd` omitted this field when the wallet had no mnemonic, rather than reporting
    // a placeholder. Zallet additionally omits it when the wallet holds several, since
    // there is no one fingerprint to report; `mnemonic_seedfps` covers that case.
    let mnemonic_seedfp = match mnemonic_seedfps.as_deref() {
        Some([seed_fp]) => Some(seed_fp.clone()),
        _ => None,
    };

    let unlocked_until = if keystore.uses_encrypted_identities() {
        Some(
            keystore
                .unlocked_until()
                .await
                .map(|i| i.duration_since(UNIX_EPOCH).expect("valid").as_secs())
                .unwrap_or(0),
        )
    } else {
        None
    };

    Ok(GetWalletInfo {
        walletversion: 0,
        balance: value_from_zatoshis(Zatoshis::ZERO),
        unconfirmed_balance: Some(value_from_zatoshis(Zatoshis::ZERO)),
        immature_balance: value_from_zatoshis(Zatoshis::ZERO),
        shielded_balance: "0.00".into(),
        shielded_unconfirmed_balance: Some("0.00".into()),
        txcount: 0,
        keypoololdest: 0,
        keypoolsize: 0,
        unlocked_until,
        mnemonic_seedfp,
        mnemonic_seedfps,
    })
}
