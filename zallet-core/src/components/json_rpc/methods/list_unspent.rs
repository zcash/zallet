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
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    encoding::AddressCodec,
    fees::{orchard::InputView as _, sapling::InputView as _},
    wallet::NoteId,
};
use zcash_keys::address::Address;
use zcash_protocol::ShieldedPool;
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
    /// One of `["sapling", "orchard", "transparent"]`.
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
                let mut outputs = wallet
                    .get_spendable_transparent_outputs(
                        addr,
                        target_height,
                        confirmations_policy,
                        CoinbaseFilter::AllTransparentOutputs,
                    )
                    .map_err(|e| {
                        RpcError::owned(
                            LegacyCode::Database.into(),
                            "WalletDb::get_spendable_transparent_outputs failed",
                            Some(format!("{e}")),
                        )
                    })?;

                acc.append(&mut outputs);
                Ok::<_, RpcError>(acc)
            })?;

        for utxo in utxos {
            let confirmations = utxo.mined_height().map(|h| target_height - h).unwrap_or(0);

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

            unspent_outputs.push(UnspentOutput {
                txid: utxo.outpoint().txid().to_string(),
                pool: "transparent".into(),
                outindex: utxo.outpoint().n(),
                confirmations,
                is_watch_only,
                account_uuid: account_id.expose_uuid().to_string(),
                address: utxo
                    .txout()
                    .recipient_address()
                    .map(|addr| addr.encode(wallet.params())),
                value: value_from_zatoshis(utxo.value()),
                value_zat: u64::from(utxo.value()),
                memo: None,
                memo_str: None,
                wallet_internal,
            })
        }

        let notes = wallet
            .select_unspent_notes(
                account_id,
                &[ShieldedPool::Sapling, ShieldedPool::Orchard],
                target_height,
                &[],
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
            let tx_mined_height = get_mined_height(*note.txid())?;
            let confirmations = tx_mined_height
                .map_or(0, |h| u32::from(target_height.saturating_sub(u32::from(h))));

            // skip notes that do not have sufficient confirmations according to minconf,
            // or that have too many confirmations according to maxconf
            if tx_mined_height
                .iter()
                .any(|h| *h > target_height.saturating_sub(minconf))
                || maxconf.iter().any(|c| confirmations > *c)
            {
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
            let tx_mined_height = get_mined_height(*note.txid())?;
            let confirmations = tx_mined_height
                .map_or(0, |h| u32::from(target_height.saturating_sub(u32::from(h))));

            // skip notes that do not have sufficient confirmations according to minconf,
            // or that have too many confirmations according to maxconf
            if tx_mined_height
                .iter()
                .any(|h| *h > target_height.saturating_sub(minconf))
                || maxconf.iter().any(|c| confirmations > *c)
            {
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
            })
        }
    }

    Ok(ResultType(unspent_outputs))
}
