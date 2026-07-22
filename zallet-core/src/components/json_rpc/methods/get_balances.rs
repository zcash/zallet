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

    /// The balance held by the account in the Ironwood shielded pool.
    ///
    /// Ironwood (NU6.3, ZIP 2005) notes are Orchard-shaped but tracked as a
    /// distinct pool. Omitted if no Ironwood funds are present.
    #[serde(skip_serializing_if = "Option::is_none")]
    ironwood: Option<Balance>,

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
    /// Locked value is excluded from `spendable` while the operation that locked it is in
    /// flight, and returns to `spendable` when the operation completes, fails, or its
    /// lock expires. Omitted if zero.
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
            account_balance_response(account_uuid.expose_uuid().to_string(), account)
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

/// Builds the balance report for a single account.
fn account_balance_response(
    account_uuid: String,
    account: &zcash_client_backend::data_api::AccountBalance,
) -> RpcResult<AccountBalance> {
    Ok(AccountBalance {
        account_uuid,
        transparent: opt_transparent_balance(
            account.unshielded_regular_balance(),
            account.unshielded_coinbase_balance(),
        )?,
        // TODO: Fetch balances for standalone/watch-only transparent addresses.
        transparent_watchonly: vec![],
        sapling: opt_balance_from(account.sapling_balance())?,
        orchard: opt_balance_from(account.orchard_balance())?,
        ironwood: opt_balance_from(account.ironwood_balance())?,
        total: balance_from(account)?,
    })
}

fn opt_transparent_balance(
    regular: &zcash_client_backend::data_api::Balance,
    coinbase: &zcash_client_backend::data_api::Balance,
) -> RpcResult<Option<TransparentBalance>> {
    let is_empty = |b: &zcash_client_backend::data_api::Balance| {
        b.total().is_zero() && b.uneconomic_value().is_zero()
    };
    if is_empty(regular) && is_empty(coinbase) {
        Ok(None)
    } else {
        Ok(Some(TransparentBalance {
            regular: opt_balance_from(regular)?,
            coinbase: opt_balance_from(coinbase)?,
        }))
    }
}

fn balance_from(b: &zcash_client_backend::data_api::AccountBalance) -> RpcResult<Balance> {
    let regular = b.unshielded_regular_balance();
    let coinbase = b.unshielded_coinbase_balance();

    Ok(balance(
        // `AccountBalance::spendable_value` covers the shielded pools only.
        (b.spendable_value() + regular.spendable_value() + coinbase.spendable_value()).ok_or(
            LegacyCode::Database
                .with_static("Wallet database is corrupt: storing more than MAX_MONEY"),
        )?,
        // `AccountBalance::locked_value` covers every pool (shielded and both
        // transparent buckets), so it must be used exactly once here.
        b.locked_value(),
        // `AccountBalance::change_pending_confirmation` and
        // `AccountBalance::value_pending_spendability` cover the shielded pools only.
        // Immature transparent coinbase funds are reported by the coinbase bucket's
        // pending fields.
        (b.change_pending_confirmation()
            + b.value_pending_spendability()
            + regular.change_pending_confirmation()
            + regular.value_pending_spendability()
            + coinbase.change_pending_confirmation()
            + coinbase.value_pending_spendability())
        .ok_or(
            LegacyCode::Database
                .with_static("Wallet database is corrupt: storing more than MAX_MONEY"),
        )?,
        // `AccountBalance::uneconomic_value` already includes both transparent buckets,
        // so it must be used exactly once here.
        b.uneconomic_value(),
    ))
}

fn opt_balance_from(b: &zcash_client_backend::data_api::Balance) -> RpcResult<Option<Balance>> {
    Ok(opt_balance(
        b.spendable_value(),
        b.locked_value(),
        (b.change_pending_confirmation() + b.value_pending_spendability()).ok_or(
            LegacyCode::Database
                .with_static("Wallet database is corrupt: storing more than MAX_MONEY"),
        )?,
        b.uneconomic_value(),
    ))
}

fn balance(spendable: Zatoshis, locked: Zatoshis, pending: Zatoshis, dust: Zatoshis) -> Balance {
    Balance {
        spendable: value(spendable),
        locked: opt_value(locked),
        pending: opt_value(pending),
        dust: opt_value(dust),
    }
}

fn opt_balance(
    spendable: Zatoshis,
    locked: Zatoshis,
    pending: Zatoshis,
    dust: Zatoshis,
) -> Option<Balance> {
    (!(spendable.is_zero() && locked.is_zero() && pending.is_zero() && dust.is_zero())).then(|| {
        Balance {
            spendable: value(spendable),
            locked: opt_value(locked),
            pending: opt_value(pending),
            dust: opt_value(dust),
        }
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

#[cfg(test)]
mod tests {
    use serde_json::json;
    use zcash_client_backend::data_api::{self, AccountBalance};
    use zcash_protocol::value::{BalanceError, Zatoshis};

    use super::account_balance_response;

    const UUID: &str = "test-uuid";

    fn zat(value: u64) -> Zatoshis {
        Zatoshis::const_from_u64(value)
    }

    /// Adds the given values (in zatoshis) to each bucket of a pool's [`data_api::Balance`].
    fn fill(
        balance: &mut data_api::Balance,
        spendable: u64,
        pending_change: u64,
        pending_spendable: u64,
        dust: u64,
    ) -> Result<(), BalanceError> {
        balance.add_spendable_value(zat(spendable))?;
        balance.add_pending_change_value(zat(pending_change))?;
        balance.add_pending_spendable_value(zat(pending_spendable))?;
        balance.add_uneconomic_value(zat(dust))
    }

    /// Renders the response for an account balance to its JSON representation (the
    /// actual RPC output contract).
    fn rendered(account: &AccountBalance) -> serde_json::Value {
        serde_json::to_value(account_balance_response(UUID.into(), account).unwrap()).unwrap()
    }

    // An account with no funds anywhere omits the `transparent` key entirely (along
    // with all shielded pool keys), and reports a zero spendable total.
    #[test]
    fn empty_account_omits_transparent() {
        assert_eq!(
            rendered(&AccountBalance::ZERO),
            json!({
                "account_uuid": UUID,
                "total": {"spendable": {"valueZat": 0}},
            }),
        );
    }

    // Regular-only transparent funds render under `transparent.regular`, with the
    // `coinbase` key omitted.
    #[test]
    fn regular_only_omits_coinbase() {
        let mut account = AccountBalance::ZERO;
        account
            .with_unshielded_regular_balance_mut::<_, BalanceError>(|b| {
                b.add_spendable_value(zat(10_000))
            })
            .unwrap();

        assert_eq!(
            rendered(&account),
            json!({
                "account_uuid": UUID,
                "transparent": {"regular": {"spendable": {"valueZat": 10_000}}},
                "total": {"spendable": {"valueZat": 10_000}},
            }),
        );
    }

    // Coinbase-only transparent funds render under `transparent.coinbase`, with the
    // `regular` key omitted. Mature (spendable) coinbase appears in both
    // `coinbase.spendable` and `total.spendable`.
    #[test]
    fn mature_coinbase_only_is_spendable_and_omits_regular() {
        let mut account = AccountBalance::ZERO;
        account
            .with_unshielded_coinbase_balance_mut::<_, BalanceError>(|b| {
                b.add_spendable_value(zat(625_000_000))
            })
            .unwrap();

        assert_eq!(
            rendered(&account),
            json!({
                "account_uuid": UUID,
                "transparent": {"coinbase": {"spendable": {"valueZat": 625_000_000u64}}},
                "total": {"spendable": {"valueZat": 625_000_000u64}},
            }),
        );
    }

    // Immature coinbase funds are pending, not spendable: they appear in
    // `coinbase.pending` and are included in `total.pending`.
    #[test]
    fn immature_coinbase_is_pending() {
        let mut account = AccountBalance::ZERO;
        account
            .with_unshielded_coinbase_balance_mut::<_, BalanceError>(|b| {
                b.add_pending_spendable_value(zat(625_000_000))
            })
            .unwrap();

        assert_eq!(
            rendered(&account),
            json!({
                "account_uuid": UUID,
                "transparent": {
                    "coinbase": {
                        "spendable": {"valueZat": 0},
                        "pending": {"valueZat": 625_000_000u64},
                    },
                },
                "total": {
                    "spendable": {"valueZat": 0},
                    "pending": {"valueZat": 625_000_000u64},
                },
            }),
        );
    }

    // When both buckets hold funds, `regular` and `coinbase` render side by side and
    // both contribute to the account total.
    #[test]
    fn regular_and_coinbase_render_side_by_side() {
        let mut account = AccountBalance::ZERO;
        account
            .with_unshielded_regular_balance_mut::<_, BalanceError>(|b| {
                b.add_spendable_value(zat(10_000))
            })
            .unwrap();
        account
            .with_unshielded_coinbase_balance_mut::<_, BalanceError>(|b| {
                b.add_spendable_value(zat(625_000_000))
            })
            .unwrap();

        assert_eq!(
            rendered(&account),
            json!({
                "account_uuid": UUID,
                "transparent": {
                    "regular": {"spendable": {"valueZat": 10_000}},
                    "coinbase": {"spendable": {"valueZat": 625_000_000u64}},
                },
                "total": {"spendable": {"valueZat": 625_010_000u64}},
            }),
        );
    }

    // `AccountBalance::uneconomic_value` already includes the transparent buckets, so
    // dust spread across shielded and both transparent buckets must be counted exactly
    // once in `total.dust`.
    #[test]
    fn dust_across_pools_is_counted_once() {
        let mut account = AccountBalance::ZERO;
        account
            .with_sapling_balance_mut::<_, BalanceError>(|b| b.add_uneconomic_value(zat(100)))
            .unwrap();
        account
            .with_unshielded_regular_balance_mut::<_, BalanceError>(|b| {
                b.add_uneconomic_value(zat(200))
            })
            .unwrap();
        account
            .with_unshielded_coinbase_balance_mut::<_, BalanceError>(|b| {
                b.add_uneconomic_value(zat(300))
            })
            .unwrap();

        assert_eq!(account.uneconomic_value(), zat(600));
        assert_eq!(
            rendered(&account),
            json!({
                "account_uuid": UUID,
                "transparent": {
                    "regular": {"spendable": {"valueZat": 0}, "dust": {"valueZat": 200}},
                    "coinbase": {"spendable": {"valueZat": 0}, "dust": {"valueZat": 300}},
                },
                "sapling": {"spendable": {"valueZat": 0}, "dust": {"valueZat": 100}},
                "total": {"spendable": {"valueZat": 0}, "dust": {"valueZat": 600}},
            }),
        );
    }

    // With every bucket of every pool nonzero, the account total's spendable, pending,
    // and dust fields each equal the exact sum of the per-pool parts.
    #[test]
    fn total_is_sum_of_parts_across_all_pools() {
        let mut account = AccountBalance::ZERO;
        // Distinct powers of two so that every sum is unambiguous.
        account
            .with_sapling_balance_mut(|b| fill(b, 1, 2, 4, 8))
            .unwrap();
        account
            .with_orchard_balance_mut(|b| fill(b, 16, 32, 64, 128))
            .unwrap();
        account
            .with_ironwood_balance_mut(|b| fill(b, 256, 512, 1024, 2048))
            .unwrap();
        account
            .with_unshielded_regular_balance_mut(|b| fill(b, 4096, 8192, 16384, 32768))
            .unwrap();
        account
            .with_unshielded_coinbase_balance_mut(|b| fill(b, 65536, 131072, 262144, 524288))
            .unwrap();

        // Expected sums, computed by hand:
        // spendable = 1 + 16 + 256 + 4096 + 65536
        let spendable = 69_905u64;
        // pending = (2+4) + (32+64) + (512+1024) + (8192+16384) + (131072+262144)
        let pending = 6 + 96 + 1536 + 24576 + 393216u64;
        // dust = 8 + 128 + 2048 + 32768 + 524288
        let dust = 559_240u64;

        assert_eq!(
            rendered(&account),
            json!({
                "account_uuid": UUID,
                "transparent": {
                    "regular": {
                        "spendable": {"valueZat": 4096},
                        "pending": {"valueZat": 8192 + 16384},
                        "dust": {"valueZat": 32768},
                    },
                    "coinbase": {
                        "spendable": {"valueZat": 65536},
                        "pending": {"valueZat": 131072 + 262144},
                        "dust": {"valueZat": 524288},
                    },
                },
                "sapling": {
                    "spendable": {"valueZat": 1},
                    "pending": {"valueZat": 6},
                    "dust": {"valueZat": 8},
                },
                "orchard": {
                    "spendable": {"valueZat": 16},
                    "pending": {"valueZat": 96},
                    "dust": {"valueZat": 128},
                },
                "ironwood": {
                    "spendable": {"valueZat": 256},
                    "pending": {"valueZat": 1536},
                    "dust": {"valueZat": 2048},
                },
                "total": {
                    "spendable": {"valueZat": spendable},
                    "pending": {"valueZat": pending},
                    "dust": {"valueZat": dust},
                },
            }),
        );
    }
}
