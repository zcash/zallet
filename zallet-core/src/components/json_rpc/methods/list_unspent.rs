use std::num::NonZeroU32;

use documented::Documented;
use jsonrpsee::{
    core::RpcResult,
    types::{ErrorCode as RpcErrorCode, ErrorObjectOwned as RpcError},
};
use schemars::JsonSchema;
use serde::Serialize;

use transparent::keys::TransparentKeyScope;
use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::{
        Account, AccountPurpose, CoinbaseFilter, InputSource, WalletRead,
        wallet::{ConfirmationsPolicy, TargetHeight, input_selection::LockFilter},
    },
    encoding::AddressCodec,
    fees::{orchard::InputView as _, sapling::InputView as _},
    wallet::NoteId,
};
use zcash_keys::address::Address;
use zcash_protocol::{
    ShieldedPool,
    consensus::{BlockHeight, COINBASE_MATURITY_BLOCKS},
    value::Zatoshis,
};
use zip32::Scope;

use crate::components::{
    database::DbConnection,
    json_rpc::{
        server::LegacyCode,
        utils::{JsonZec, parse_as_of_height, parse_minconf, value_from_zatoshis},
    },
};

/// Response to a `z_listunspent` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// A list of unspent notes.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(Vec<UnspentOutput>);

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct UnspentOutput {
    /// The ID of the transaction that created this output.
    txid: String,

    /// The shielded value pool.
    ///
    /// One of `["sapling", "orchard", "ironwood", "transparent"]`.
    pool: String,

    /// The Transparent UTXO, Sapling output or Orchard action index.
    outindex: u32,

    /// The number of confirmations.
    confirmations: u32,

    /// `true` if the account that received the output is watch-only
    is_watch_only: bool,

    /// The Zcash address that received the output.
    ///
    /// Omitted if this output was received on an account-internal address (for example, change
    /// and shielding outputs).
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,

    /// The UUID of the wallet account that received this output.
    account_uuid: String,

    /// `true` if the output was received by the account's internal viewing key.
    ///
    /// The `address` field is guaranteed be absent when this field is set to `true`, in which case
    /// it indicates that this may be a change output, an output of a wallet-internal shielding
    /// transaction, an output of a wallet-internal cross-account transfer, or otherwise is the
    /// result of some wallet-internal operation.
    #[serde(rename = "walletInternal")]
    wallet_internal: bool,

    /// `true` if the output was produced by a coinbase transaction.
    ///
    /// Omitted if this is a shielded output.
    #[serde(skip_serializing_if = "Option::is_none")]
    generated: Option<bool>,

    /// Number of blocks remaining until this coinbase output reaches maturity
    /// and becomes spendable. `0` if already mature.
    ///
    /// Omitted for non-coinbase transparent outputs and all shielded outputs.
    #[serde(rename = "blockstomaturity")]
    #[serde(skip_serializing_if = "Option::is_none")]
    blocks_to_maturity: Option<u32>,

    /// The value of the output in ZEC.
    value: JsonZec,

    /// The value of the output in zatoshis.
    #[serde(rename = "valueZat")]
    value_zat: u64,

    /// Hexadecimal string representation of the memo field.
    ///
    /// Omitted if this is a transparent output.
    #[serde(skip_serializing_if = "Option::is_none")]
    memo: Option<String>,

    /// UTF-8 string representation of memo field (if it contains valid UTF-8).
    #[serde(rename = "memoStr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    memo_str: Option<String>,
}

pub(super) const PARAM_MINCONF_DESC: &str =
    "Only include outputs of transactions confirmed at least this many times.";
pub(super) const PARAM_MAXCONF_DESC: &str =
    "Only include outputs of transactions confirmed at most this many times.";
pub(super) const PARAM_INCLUDE_WATCHONLY_DESC: &str =
    "Also include outputs received at watch-only addresses.";
pub(super) const PARAM_ADDRESSES_DESC: &str =
    "If non-empty, only outputs received by the provided addresses will be returned.";
pub(super) const PARAM_AS_OF_HEIGHT_DESC: &str = "Execute the query as if it were run when the blockchain was at the height specified by this argument.";

/// The number of confirmations that an output of a transaction mined at `mined_height` has as
/// of `target_height`.
///
/// An output of a transaction that is not mined in the main chain has zero confirmations. Such
/// an output can be reported by this RPC when its transaction is in the mempool, or when a
/// transaction that had been mined has been un-mined by a reorg and its containing block has
/// not yet been re-scanned.
fn confirmation_count(target_height: TargetHeight, mined_height: Option<BlockHeight>) -> u32 {
    // Subtraction of block heights saturates at zero, which correctly reports a transaction
    // mined at or above the target height (possible when `asOfHeight` places the target below
    // the chain tip) as having no confirmations as of that height.
    mined_height.map_or(0, |h| target_height - h)
}

/// Whether an output with the given number of confirmations is within the range of
/// confirmations requested for this query.
///
/// Both bounds are inclusive: an output with exactly `minconf` (or exactly `maxconf`)
/// confirmations is reported. Because an unmined transaction's outputs have zero
/// confirmations, they are in range only for `minconf = 0`, which this RPC permits whenever
/// `asOfHeight` is absent.
fn confirmations_in_range(confirmations: u32, minconf: u32, maxconf: Option<u32>) -> bool {
    confirmations >= minconf && maxconf.is_none_or(|c| confirmations <= c)
}

// FIXME: the following parameters are not yet properly supported
// * include_watchonly
pub(crate) fn call(
    wallet: &DbConnection,
    minconf: Option<u32>,
    maxconf: Option<u32>,
    _include_watchonly: Option<bool>,
    addresses: Option<Vec<String>>,
    as_of_height: Option<i64>,
) -> Response {
    let as_of_height = parse_as_of_height(as_of_height)?;
    let minconf = parse_minconf(minconf, 1, as_of_height)?;

    let confirmations_policy = match NonZeroU32::new(minconf) {
        Some(c) => ConfirmationsPolicy::new_symmetrical(c, false),
        None => ConfirmationsPolicy::new_symmetrical(NonZeroU32::new(1).unwrap(), true),
    };

    //let include_watchonly = include_watchonly.unwrap_or(false);
    let addresses = addresses
        .unwrap_or_default()
        .iter()
        .map(|addr| {
            Address::decode(wallet.params(), addr).ok_or_else(|| {
                RpcError::owned(
                    LegacyCode::InvalidParameter.into(),
                    "Not a valid Zcash address",
                    Some(addr),
                )
            })
        })
        .collect::<Result<Vec<Address>, _>>()?;

    let target_height = match as_of_height.map_or_else(
        || {
            wallet.chain_height().map_err(|e| {
                RpcError::owned(
                    LegacyCode::Database.into(),
                    "WalletDb::chain_height failed",
                    Some(format!("{e}")),
                )
            })
        },
        |h| Ok(Some(h)),
    )? {
        Some(h) => TargetHeight::from(h + 1),
        None => {
            return Ok(ResultType(vec![]));
        }
    };

    let mut unspent_outputs = vec![];

    for account_id in wallet.get_account_ids().map_err(|e| {
        RpcError::owned(
            LegacyCode::Database.into(),
            "WalletDb::get_account_ids failed",
            Some(format!("{e}")),
        )
    })? {
        let account = wallet
            .get_account(account_id)
            .map_err(|e| {
                RpcError::owned(
                    LegacyCode::Database.into(),
                    "WalletDb::get_account failed",
                    Some(format!("{e}")),
                )
            })?
            // This would be a race condition between this and account deletion.
            .ok_or(RpcErrorCode::InternalError)?;

        let is_watch_only = !matches!(account.purpose(), AccountPurpose::Spending { .. });

        let utxos = wallet
            .get_transparent_receivers(account_id, true, true)
            .map_err(|e| {
                RpcError::owned(
                    LegacyCode::Database.into(),
                    "WalletDb::get_transparent_receivers failed",
                    Some(format!("{e}")),
                )
            })?
            .iter()
            .try_fold(vec![], |mut acc, (addr, _)| {
                // Query non-coinbase and coinbase outputs separately so that each UTXO
                // can be tagged with its coinbase origin. The two filters partition the
                // full set of spendable outputs: outputs with an unknown transaction
                // index are treated as non-coinbase by `NonCoinbaseOnly` and excluded
                // by `CoinbaseOnly`, so nothing is dropped or duplicated.
                for (coinbase_filter, generated) in [
                    (CoinbaseFilter::NonCoinbaseOnly, false),
                    (CoinbaseFilter::CoinbaseOnly, true),
                ] {
                    let outputs = wallet
                        .get_spendable_transparent_outputs(
                            addr,
                            target_height,
                            confirmations_policy,
                            coinbase_filter,
                            // A locked output is still an unspent output belonging to the
                            // wallet, and this RPC reports the wallet's holdings rather than
                            // selecting inputs, so lock state is not a filter here.
                            LockFilter::Unfiltered,
                        )
                        .map_err(|e| {
                            RpcError::owned(
                                LegacyCode::Database.into(),
                                "WalletDb::get_spendable_transparent_outputs failed",
                                Some(format!("{e}")),
                            )
                        })?;

                    acc.extend(outputs.into_iter().map(|utxo| (utxo, generated)));
                }
                Ok::<_, RpcError>(acc)
            })?;

        for (utxo, generated) in utxos {
            let confirmations = confirmation_count(target_height, utxo.mined_height());

            // `get_spendable_transparent_outputs` applies `minconf` itself, but not `maxconf`;
            // both bounds are checked here so that every pool reports the same range.
            if !confirmations_in_range(confirmations, minconf, maxconf) {
                continue;
            }

            let wallet_internal = wallet
                .get_transparent_address_metadata(account_id, utxo.recipient_address())
                .map_err(|e| {
                    RpcError::owned(
                        LegacyCode::Database.into(),
                        "WalletDb::get_transparent_address_metadata failed",
                        Some(format!("{e}")),
                    )
                })?
                .is_some_and(|m| m.scope() == Some(TransparentKeyScope::INTERNAL));

            unspent_outputs.push(transparent_unspent_output(
                utxo.outpoint().txid().to_string(),
                utxo.outpoint().n(),
                confirmations,
                is_watch_only,
                utxo.txout()
                    .recipient_address()
                    .map(|addr| addr.encode(wallet.params())),
                account_id.expose_uuid().to_string(),
                wallet_internal,
                utxo.value(),
                generated,
            ))
        }

        let notes = wallet
            .select_unspent_notes(
                account_id,
                &[
                    ShieldedPool::Sapling,
                    ShieldedPool::Orchard,
                    ShieldedPool::Ironwood,
                ],
                target_height,
                &[],
                LockFilter::Unfiltered,
            )
            .map_err(|e| {
                RpcError::owned(
                    LegacyCode::Database.into(),
                    "WalletDb::select_unspent_notes failed",
                    Some(format!("{e}")),
                )
            })?;

        let get_memo = |txid, protocol, output_index| -> RpcResult<_> {
            Ok(wallet
                .get_memo(NoteId::new(txid, protocol, output_index))
                .map_err(|e| {
                    RpcError::owned(
                        LegacyCode::Database.into(),
                        "WalletDb::get_memo failed",
                        Some(format!("{e}")),
                    )
                })?
                .map(|memo| {
                    (
                        hex::encode(memo.encode().as_array()),
                        match memo {
                            zcash_protocol::memo::Memo::Text(text_memo) => Some(text_memo.into()),
                            _ => None,
                        },
                    )
                })
                .unwrap_or(("TODO: Always enhance every note".into(), None)))
        };

        let get_mined_height = |txid| {
            wallet.get_tx_height(txid).map_err(|e| {
                RpcError::owned(
                    LegacyCode::Database.into(),
                    "WalletDb::get_tx_height failed",
                    Some(format!("{e}")),
                )
            })
        };

        for note in notes.sapling().iter().filter(|n| {
            addresses
                .iter()
                .all(|addr| addr.to_sapling_address() == Some(n.note().recipient()))
        }) {
            let confirmations = confirmation_count(target_height, get_mined_height(*note.txid())?);

            // Skip notes that do not have sufficient confirmations according to `minconf`, or
            // that have too many confirmations according to `maxconf`.
            if !confirmations_in_range(confirmations, minconf, maxconf) {
                continue;
            }

            let is_internal = note.spending_key_scope() == Scope::Internal;

            let (memo, memo_str) =
                get_memo(*note.txid(), ShieldedPool::Sapling, note.output_index())?;

            unspent_outputs.push(UnspentOutput {
                txid: note.txid().to_string(),
                pool: "sapling".into(),
                outindex: note.output_index().into(),
                confirmations,
                is_watch_only,
                account_uuid: account_id.expose_uuid().to_string(),
                // TODO: Ensure we generate the same kind of shielded address as `zcashd`.
                address: (!is_internal).then(|| note.note().recipient().encode(wallet.params())),
                value: value_from_zatoshis(note.value()),
                value_zat: u64::from(note.value()),
                memo: Some(memo),
                memo_str,
                wallet_internal: is_internal,
                generated: None,
                blocks_to_maturity: None,
            })
        }

        for note in notes.orchard().iter().filter(|n| {
            addresses.iter().all(|addr| {
                addr.as_understood_unified_receivers()
                    .iter()
                    .any(|r| match r {
                        zcash_keys::address::Receiver::Orchard(address) => {
                            address == &n.note().recipient()
                        }
                        _ => false,
                    })
            })
        }) {
            let confirmations = confirmation_count(target_height, get_mined_height(*note.txid())?);

            // Skip notes that do not have sufficient confirmations according to `minconf`, or
            // that have too many confirmations according to `maxconf`.
            if !confirmations_in_range(confirmations, minconf, maxconf) {
                continue;
            }

            let wallet_internal = note.spending_key_scope() == Scope::Internal;

            let (memo, memo_str) =
                get_memo(*note.txid(), ShieldedPool::Orchard, note.output_index())?;

            unspent_outputs.push(UnspentOutput {
                txid: note.txid().to_string(),
                pool: "orchard".into(),
                outindex: note.output_index().into(),
                confirmations,
                is_watch_only,
                account_uuid: account_id.expose_uuid().to_string(),
                // TODO: Ensure we generate the same kind of shielded address as `zcashd`.
                address: (!wallet_internal).then(|| {
                    UnifiedAddress::from_receivers(Some(note.note().recipient()), None, None)
                        .expect("valid")
                        .encode(wallet.params())
                }),
                value: value_from_zatoshis(note.value()),
                value_zat: u64::from(note.value()),
                memo: Some(memo),
                memo_str,
                wallet_internal,
                generated: None,
                blocks_to_maturity: None,
            })
        }

        // Ironwood notes are Orchard-shaped (their recipient is an Orchard
        // address and they live behind an Orchard receiver), so this mirrors
        // the Orchard block above; only the reported pool and the memo lookup
        // protocol differ.
        for note in notes.ironwood().iter().filter(|n| {
            addresses.iter().all(|addr| {
                addr.as_understood_unified_receivers()
                    .iter()
                    .any(|r| match r {
                        zcash_keys::address::Receiver::Orchard(address) => {
                            address == &n.note().recipient()
                        }
                        _ => false,
                    })
            })
        }) {
            let confirmations = confirmation_count(target_height, get_mined_height(*note.txid())?);

            // Skip notes that do not have sufficient confirmations according to `minconf`, or
            // that have too many confirmations according to `maxconf`.
            if !confirmations_in_range(confirmations, minconf, maxconf) {
                continue;
            }

            let wallet_internal = note.spending_key_scope() == Scope::Internal;

            let (memo, memo_str) =
                get_memo(*note.txid(), ShieldedPool::Ironwood, note.output_index())?;

            unspent_outputs.push(UnspentOutput {
                txid: note.txid().to_string(),
                pool: "ironwood".into(),
                outindex: note.output_index().into(),
                confirmations,
                is_watch_only,
                account_uuid: account_id.expose_uuid().to_string(),
                // TODO: Ensure we generate the same kind of shielded address as `zcashd`.
                address: (!wallet_internal).then(|| {
                    UnifiedAddress::from_receivers(Some(note.note().recipient()), None, None)
                        .expect("valid")
                        .encode(wallet.params())
                }),
                value: value_from_zatoshis(note.value()),
                value_zat: u64::from(note.value()),
                memo: Some(memo),
                memo_str,
                wallet_internal,
                generated: None,
                blocks_to_maturity: None,
            })
        }
    }

    Ok(ResultType(unspent_outputs))
}

/// Builds the `z_listunspent` entry for a transparent UTXO.
///
/// Transparent outputs always report their coinbase origin via the `generated` field,
/// have no memo, and belong to the `transparent` pool. This is a pure function over
/// values already extracted from the wallet, so that its JSON rendering can be
/// unit-tested without a database.
#[allow(clippy::too_many_arguments)]
fn transparent_unspent_output(
    txid: String,
    outindex: u32,
    confirmations: u32,
    is_watch_only: bool,
    address: Option<String>,
    account_uuid: String,
    wallet_internal: bool,
    value: Zatoshis,
    generated: bool,
) -> UnspentOutput {
    UnspentOutput {
        txid,
        pool: "transparent".into(),
        outindex,
        confirmations,
        is_watch_only,
        address,
        account_uuid,
        wallet_internal,
        generated: Some(generated),
        blocks_to_maturity: if generated {
            Some(COINBASE_MATURITY_BLOCKS.saturating_sub(confirmations))
        } else {
            None
        },
        value: value_from_zatoshis(value),
        value_zat: u64::from(value),
        memo: None,
        memo_str: None,
    }
}

#[cfg(test)]
mod tests {
    use zcash_client_backend::data_api::wallet::TargetHeight;
    use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

    use super::{
        UnspentOutput, confirmation_count, confirmations_in_range, transparent_unspent_output,
    };
    use crate::components::json_rpc::utils::value_from_zatoshis;

    /// The height of the next block to be mined, as used by the RPC. An output mined in block
    /// 99 therefore has one confirmation, and one mined in block 90 has ten.
    const TARGET: u32 = 100;

    fn target() -> TargetHeight {
        TargetHeight::from(BlockHeight::from_u32(TARGET))
    }

    fn mined_in(height: u32) -> Option<BlockHeight> {
        Some(BlockHeight::from_u32(height))
    }

    #[test]
    fn unmined_transaction_has_zero_confirmations() {
        assert_eq!(confirmation_count(target(), None), 0);
    }

    #[test]
    fn confirmations_count_the_mining_block() {
        assert_eq!(confirmation_count(target(), mined_in(TARGET - 1)), 1);
        assert_eq!(confirmation_count(target(), mined_in(TARGET - 10)), 10);
    }

    // An `asOfHeight` in the past places the target height below the chain tip, so a
    // transaction known to the wallet may be mined at or above it. Such a transaction has no
    // confirmations as of the target height, rather than a negative or wrapped count.
    #[test]
    fn transaction_mined_at_or_above_target_has_zero_confirmations() {
        assert_eq!(confirmation_count(target(), mined_in(TARGET)), 0);
        assert_eq!(confirmation_count(target(), mined_in(TARGET + 5)), 0);
    }

    // Regression: an output of an unmined transaction has zero confirmations, and so must be
    // excluded whenever at least one confirmation is required. This previously tested the
    // mined height with `Option::iter().any(..)`, which is vacuously false for an unmined
    // transaction, so such outputs were reported at every `minconf`.
    #[test]
    fn unmined_output_is_excluded_at_minconf_1() {
        assert!(!confirmations_in_range(
            confirmation_count(target(), None),
            1,
            None
        ));
    }

    // ... but `minconf = 0` is permitted when `asOfHeight` is absent, and admits exactly those
    // zero-confirmation outputs.
    #[test]
    fn unmined_output_is_included_at_minconf_0() {
        assert!(confirmations_in_range(
            confirmation_count(target(), None),
            0,
            None
        ));
    }

    #[test]
    fn minconf_bound_is_inclusive() {
        let confirmations = confirmation_count(target(), mined_in(TARGET - 10));
        assert!(!confirmations_in_range(confirmations, 11, None));
        assert!(confirmations_in_range(confirmations, 10, None));
        assert!(confirmations_in_range(confirmations, 9, None));
    }

    // Regression: `maxconf` was applied only to shielded notes, so transparent outputs with
    // more than `maxconf` confirmations were reported regardless. Both bounds now come from
    // this single predicate, which every pool consults.
    #[test]
    fn maxconf_bound_is_inclusive() {
        let confirmations = confirmation_count(target(), mined_in(TARGET - 10));
        assert!(!confirmations_in_range(confirmations, 1, Some(9)));
        assert!(confirmations_in_range(confirmations, 1, Some(10)));
        assert!(confirmations_in_range(confirmations, 1, Some(11)));
    }

    #[test]
    fn absent_maxconf_imposes_no_upper_bound() {
        assert!(confirmations_in_range(
            confirmation_count(target(), mined_in(0)),
            1,
            None
        ));
    }

    /// Renders a transparent UTXO entry with the given coinbase origin to its JSON
    /// representation (the actual RPC output contract).
    fn rendered_transparent(generated: bool) -> serde_json::Value {
        serde_json::to_value(transparent_unspent_output(
            "3ec4c1b4b1e61a13c11ec5b0ba1240cca66f0e0d5b1e0303403d0a44ae7d0219".into(),
            0,
            10,
            false,
            Some("t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs".into()),
            "3ad46f88-8f11-407b-b768-a2d587e971c9".into(),
            false,
            Zatoshis::const_from_u64(625_000_000),
            generated,
        ))
        .unwrap()
    }

    #[test]
    fn transparent_coinbase_output_is_generated() {
        let rendered = rendered_transparent(true);
        assert_eq!(rendered["generated"], serde_json::json!(true));
        assert_eq!(rendered["pool"], serde_json::json!("transparent"));
    }

    #[test]
    fn transparent_coinbase_output_reports_blocks_to_maturity() {
        // 10 confirmations, 90 blocks remaining until mature (100 - 10).
        let rendered = rendered_transparent(true);
        assert_eq!(rendered["blockstomaturity"], serde_json::json!(90));
    }

    #[test]
    fn transparent_mature_coinbase_output_reports_zero_blocks_to_maturity() {
        let rendered = serde_json::to_value(transparent_unspent_output(
            "3ec4c1b4b1e61a13c11ec5b0ba1240cca66f0e0d5b1e0303403d0a44ae7d0219".into(),
            0,
            100, // exactly at maturity
            false,
            Some("t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs".into()),
            "3ad46f88-8f11-407b-b768-a2d587e971c9".into(),
            false,
            Zatoshis::const_from_u64(625_000_000),
            true,
        ))
        .unwrap();
        assert_eq!(rendered["blockstomaturity"], serde_json::json!(0));
    }

    #[test]
    fn transparent_non_coinbase_output_is_not_generated() {
        let rendered = rendered_transparent(false);
        assert_eq!(rendered["generated"], serde_json::json!(false));
    }

    #[test]
    fn transparent_non_coinbase_output_omits_blocks_to_maturity() {
        let rendered = rendered_transparent(false);
        assert!(rendered.get("blockstomaturity").is_none());
    }

    #[test]
    fn shielded_output_omits_generated_and_blocks_to_maturity() {
        // Shielded notes never set `generated` or `blockstomaturity`; the fields
        // must be omitted entirely rather than rendered as `null`.
        let output = UnspentOutput {
            txid: "3ec4c1b4b1e61a13c11ec5b0ba1240cca66f0e0d5b1e0303403d0a44ae7d0219".into(),
            pool: "sapling".into(),
            outindex: 0,
            confirmations: 10,
            is_watch_only: false,
            address: None,
            account_uuid: "3ad46f88-8f11-407b-b768-a2d587e971c9".into(),
            wallet_internal: true,
            generated: None,
            blocks_to_maturity: None,
            value: value_from_zatoshis(Zatoshis::const_from_u64(100_000)),
            value_zat: 100_000,
            memo: Some("f600".into()),
            memo_str: None,
        };

        let rendered = serde_json::to_value(output).unwrap();
        assert!(rendered.get("generated").is_none());
        assert!(rendered.get("blockstomaturity").is_none());
    }
}
