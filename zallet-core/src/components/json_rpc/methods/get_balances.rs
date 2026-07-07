use std::num::NonZeroU32;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{WalletRead, wallet::ConfirmationsPolicy};
use zcash_protocol::value::Zatoshis;

use crate::components::{database::DbConnection, json_rpc::server::LegacyCode};

/// Response to a `z_getbalances` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = Balances;

/// The balances available for each independent spending authority held by the wallet.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct Balances {
    /// The balances held by each Unified Account spending authority in the wallet.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    accounts: Vec<AccountBalance>,

    /// The balance of transparent funds held by legacy transparent keys.
    ///
    /// All funds held in legacy transparent addresses are treated as though they are
    /// associated with a single spending authority.
    ///
    /// Omitted if `features.legacy_pool_seed_fingerprint` is unset in the Zallet config,
    /// or no legacy transparent funds are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    legacy_transparent: Option<TransparentBalance>,

    /// The balance of transparent funds held by legacy watch-only transparent addresses.
    ///
    /// All funds held in legacy transparent addresses are treated as though they are
    /// associated with a single spending authority.
    ///
    /// Omitted if `features.legacy_pool_seed_fingerprint` is unset in the Zallet config,
    /// or no legacy transparent funds are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    legacy_transparent_watchonly: Option<TransparentBalance>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct AccountBalance {
    /// The account's UUID within this Zallet instance.
    account_uuid: String,

    /// The balance held by the account in the transparent pool.
    ///
    /// This includes all funds held by transparent addresses derived from the account's
    /// viewing key, and excludes all funds held by watch-only standalone transparent
    /// addresses imported into the account.
    ///
    /// Omitted if no transparent funds are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    transparent: Option<TransparentBalance>,

    /// The balance held by each watch-only standalone transparent address imported into
    /// the account.
    ///
    /// Omitted if the account has no standalone transparent addresses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    transparent_watchonly: Vec<StandaloneTransparentAddressBalance>,

    /// The balance held by the account in the Sapling shielded pool.
    ///
    /// Omitted if no Sapling funds are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    sapling: Option<Balance>,

    /// The balance held by the account in the Orchard shielded pool.
    ///
    /// Omitted if no Orchard funds are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    orchard: Option<Balance>,

    /// The total funds in all pools held by the account.
    total: Balance,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct StandaloneTransparentAddressBalance {
    /// The standalone transparent address.
    address: String,

    #[serde(flatten)]
    balance: TransparentBalance,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct TransparentBalance {
    /// The transparent balance excluding coinbase outputs.
    ///
    /// Omitted if no non-coinbase funds are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    regular: Option<Balance>,

    /// The transparent balance in coinbase outputs.
    ///
    /// Omitted if no coinbase funds are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    coinbase: Option<Balance>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct Balance {
    /// Balance that is spendable at the requested number of confirmations.
    spendable: Value,

    /// Balance that is spendable at the requested number of confirmations, but currently
    /// locked by some other spend operation.
    ///
    /// Omitted if zero.
    // TODO: Support locked outputs.
    // https://github.com/zcash/librustzcash/issues/2161
    #[serde(skip_serializing_if = "Option::is_none")]
    locked: Option<Value>,

    /// Pending balance that is not currently spendable at the requested number of
    /// confirmations, but will become spendable later.
    ///
    /// Omitted if zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pending: Option<Value>,

    /// Unspendable balance due to individual note values being too small.
    ///
    /// The wallet might on occasion be able to sweep some of these notes into spendable
    /// outputs (for example, when a transaction it is creating would otherwise have
    /// already-paid-for Orchard dummy spends), but these values should never be counted
    /// as part of the wallet's spendable balance because they cannot be spent on demand.
    ///
    /// Omitted if zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    dust: Option<Value>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct Value {
    /// The balance in zatoshis.
    #[serde(rename = "valueZat")]
    value_zat: u64,
}

pub(super) const PARAM_MINCONF_DESC: &str =
    "Only include unspent outputs in transactions confirmed at least this many times.";

pub(crate) fn call(wallet: &DbConnection, minconf: Option<u32>) -> Response {
    let confirmations_policy = match minconf {
        Some(minconf) => match NonZeroU32::new(minconf) {
            Some(c) => ConfirmationsPolicy::new_symmetrical(c, false),
            // `minconf = 0` currently cannot be represented accurately with
            // `ConfirmationsPolicy` (in particular it cannot represent zero-conf
            // fully-transparent spends), so for now we use "minimum possible".
            None => ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, true),
        },
        None => ConfirmationsPolicy::new_symmetrical(NonZeroU32::MIN, false),
    };

    let summary = match wallet
        .get_wallet_summary(confirmations_policy)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
    {
        Some(summary) => summary,
        None => return Err(LegacyCode::InWarmup.with_static("Wallet sync required")),
    };

    let accounts = summary
        .account_balances()
        .iter()
        .map(|(account_uuid, account)| {
            // TODO: Separate out transparent coinbase and standalone balances.
            let transparent_regular = account.unshielded_balance();

            Ok(AccountBalance {
                account_uuid: account_uuid.expose_uuid().to_string(),
                transparent: opt_transparent_balance(transparent_regular)?,
                transparent_watchonly: vec![],
                sapling: opt_balance_from(account.sapling_balance())?,
                orchard: opt_balance_from(account.orchard_balance())?,
                total: balance_from(account)?,
            })
        })
        .collect::<RpcResult<_>>()?;

    Ok(Balances {
        accounts,
        // TODO: Fetch legacy transparent balance once supported.
        // https://github.com/zcash/zallet/issues/384
        legacy_transparent: None,
        legacy_transparent_watchonly: None,
    })
}

fn opt_transparent_balance(
    regular: &zcash_client_backend::data_api::Balance,
) -> RpcResult<Option<TransparentBalance>> {
    if regular.total().is_zero() && regular.uneconomic_value().is_zero() {
        Ok(None)
    } else {
        Ok(Some(TransparentBalance {
            regular: opt_balance_from(regular)?,
            coinbase: None,
        }))
    }
}

fn balance_from(b: &zcash_client_backend::data_api::AccountBalance) -> RpcResult<Balance> {
    Ok(balance(
        b.spendable_value(),
        (b.change_pending_confirmation() + b.value_pending_spendability()).ok_or(
            LegacyCode::Database
                .with_static("Wallet database is corrupt: storing more than MAX_MONEY"),
        )?,
        b.uneconomic_value(),
    ))
}

fn opt_balance_from(b: &zcash_client_backend::data_api::Balance) -> RpcResult<Option<Balance>> {
    Ok(opt_balance(
        b.spendable_value(),
        (b.change_pending_confirmation() + b.value_pending_spendability()).ok_or(
            LegacyCode::Database
                .with_static("Wallet database is corrupt: storing more than MAX_MONEY"),
        )?,
        b.uneconomic_value(),
    ))
}

fn balance(spendable: Zatoshis, pending: Zatoshis, dust: Zatoshis) -> Balance {
    Balance {
        spendable: value(spendable),
        locked: None,
        pending: opt_value(pending),
        dust: opt_value(dust),
    }
}

fn opt_balance(spendable: Zatoshis, pending: Zatoshis, dust: Zatoshis) -> Option<Balance> {
    (!(spendable.is_zero() && pending.is_zero() && dust.is_zero())).then(|| Balance {
        spendable: value(spendable),
        locked: None,
        pending: opt_value(pending),
        dust: opt_value(dust),
    })
}

fn value(value: Zatoshis) -> Value {
    Value {
        value_zat: value.into_u64(),
    }
}

fn opt_value(value: Zatoshis) -> Option<Value> {
    (!value.is_zero()).then(|| Value {
        value_zat: value.into_u64(),
    })
}
