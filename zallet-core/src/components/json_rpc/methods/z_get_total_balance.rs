use std::num::NonZeroU32;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{AccountBalance, WalletRead, wallet::ConfirmationsPolicy};
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

    /// The total value of unspent Sapling, Orchard, and Ironwood outputs, in ZEC
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

    match wallet
        .get_wallet_summary(confirmations_policy)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
    {
        // TODO: support `include_watch_only = false`
        Some(summary) => total_balance(summary.account_balances().values()),
        None => total_balance(std::iter::empty::<&AccountBalance>()),
    }
}

/// Computes the wallet-wide totals from the per-account balances.
///
/// The transparent total is the combined total of the regular (non-coinbase) and
/// coinbase transparent buckets; each bucket's total spans its spendable and pending
/// values, so immature coinbase funds are included.
fn total_balance<'a>(balances: impl IntoIterator<Item = &'a AccountBalance>) -> Response {
    let (transparent, private) = balances.into_iter().fold(
        (Some(Zatoshis::ZERO), Some(Zatoshis::ZERO)),
        |(transparent, private), balance| {
            (
                transparent + balance.unshielded_balance().total(),
                private
                    + balance.sapling_balance().total()
                    + balance.orchard_balance().total()
                    + balance.ironwood_balance().total(),
            )
        },
    );

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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use zcash_client_backend::data_api::AccountBalance;
    use zcash_protocol::value::{BalanceError, COIN, Zatoshis};

    use super::total_balance;
    use crate::components::json_rpc::utils::value_from_zatoshis;

    fn zat(value: u64) -> Zatoshis {
        Zatoshis::const_from_u64(value)
    }

    /// Renders the ZEC-denominated string for a zatoshi amount, exactly as the RPC
    /// response does.
    fn zec(value: u64) -> String {
        value_from_zatoshis(zat(value)).to_string()
    }

    fn rendered<'a>(balances: impl IntoIterator<Item = &'a AccountBalance>) -> serde_json::Value {
        serde_json::to_value(total_balance(balances).unwrap()).unwrap()
    }

    // An empty wallet reports zero in every field.
    #[test]
    fn empty_wallet_is_all_zero() {
        assert_eq!(
            rendered([]),
            json!({
                "transparent": zec(0),
                "private": zec(0),
                "total": zec(0),
            }),
        );
    }

    // The transparent total is the sum of the regular and coinbase transparent bucket
    // totals, including immature (pending) coinbase funds.
    #[test]
    fn transparent_includes_regular_and_coinbase() {
        let mut balance = AccountBalance::ZERO;
        balance
            .with_unshielded_regular_balance_mut::<_, BalanceError>(|b| {
                b.add_spendable_value(zat(2 * COIN))
            })
            .unwrap();
        balance
            .with_unshielded_coinbase_balance_mut::<_, BalanceError>(|b| {
                // Mature (spendable) coinbase...
                b.add_spendable_value(zat(3 * COIN))?;
                // ...and immature (pending) coinbase both count towards the total.
                b.add_pending_spendable_value(zat(5 * COIN))
            })
            .unwrap();

        assert_eq!(
            rendered([&balance]),
            json!({
                "transparent": zec(10 * COIN),
                "private": zec(0),
                "total": zec(10 * COIN),
            }),
        );
    }

    // The overall total is the transparent total plus the private (shielded) total,
    // summed across accounts.
    #[test]
    fn total_is_transparent_plus_private() {
        let mut account1 = AccountBalance::ZERO;
        account1
            .with_unshielded_regular_balance_mut::<_, BalanceError>(|b| {
                b.add_spendable_value(zat(COIN))
            })
            .unwrap();
        account1
            .with_sapling_balance_mut::<_, BalanceError>(|b| b.add_spendable_value(zat(2 * COIN)))
            .unwrap();

        let mut account2 = AccountBalance::ZERO;
        account2
            .with_unshielded_coinbase_balance_mut::<_, BalanceError>(|b| {
                b.add_spendable_value(zat(4 * COIN))
            })
            .unwrap();
        account2
            .with_orchard_balance_mut::<_, BalanceError>(|b| b.add_spendable_value(zat(8 * COIN)))
            .unwrap();
        account2
            .with_ironwood_balance_mut::<_, BalanceError>(|b| b.add_spendable_value(zat(16 * COIN)))
            .unwrap();

        assert_eq!(
            rendered([&account1, &account2]),
            json!({
                "transparent": zec(5 * COIN),
                "private": zec(26 * COIN),
                "total": zec(31 * COIN),
            }),
        );
    }
}
