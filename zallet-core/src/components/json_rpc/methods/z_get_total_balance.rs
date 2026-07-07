use std::num::NonZeroU32;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{WalletRead, wallet::ConfirmationsPolicy};
use zcash_protocol::value::Zatoshis;

use crate::components::{
    database::DbConnection,
    json_rpc::{server::LegacyCode, utils::value_from_zatoshis},
};

/// Response to a `z_gettotalbalance` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = TotalBalance;

/// The total value of funds stored in the wallet.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct TotalBalance {
    /// The total value of unspent transparent outputs, in ZEC
    transparent: String,

    /// The total value of unspent Sapling and Orchard outputs, in ZEC
    private: String,

    /// The total value of unspent shielded and transparent outputs, in ZEC
    total: String,
}

pub(super) const PARAM_MINCONF_DESC: &str =
    "Only include notes in transactions confirmed at least this many times.";
pub(super) const PARAM_INCLUDE_WATCHONLY_DESC: &str =
    "Also include balance in watchonly addresses.";

pub(crate) fn call(
    wallet: &DbConnection,
    minconf: Option<u32>,
    include_watchonly: Option<bool>,
) -> Response {
    match include_watchonly {
        Some(true) => Ok(()),
        None | Some(false) => Err(LegacyCode::Misc
            .with_message("include_watchonly argument must be set to true (for now)")),
    }?;

    let confirmations_policy = match minconf {
        Some(minconf) => match NonZeroU32::new(minconf) {
            Some(c) => ConfirmationsPolicy::new_symmetrical(c, false),
            None => ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
        },
        None => ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false),
    };

    let (transparent, private) = if let Some(summary) = wallet
        .get_wallet_summary(confirmations_policy)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
    {
        // TODO: support `include_watch_only = false`
        summary.account_balances().iter().fold(
            (Some(Zatoshis::ZERO), Some(Zatoshis::ZERO)),
            |(transparent, private), (_, balance)| {
                (
                    transparent + balance.unshielded_balance().total(),
                    private + balance.sapling_balance().total() + balance.orchard_balance().total(),
                )
            },
        )
    } else {
        (Some(Zatoshis::ZERO), Some(Zatoshis::ZERO))
    };

    transparent
        .zip(private)
        .and_then(|(transparent, private)| {
            (transparent + private).map(|total| TotalBalance {
                transparent: value_from_zatoshis(transparent).to_string(),
                private: value_from_zatoshis(private).to_string(),
                total: value_from_zatoshis(total).to_string(),
            })
        })
        .ok_or_else(|| LegacyCode::Wallet.with_static("balance overflow"))
}
