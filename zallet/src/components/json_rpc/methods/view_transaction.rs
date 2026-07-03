use std::collections::BTreeMap;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use orchard::note_encryption::OrchardDomain;
use rusqlite::{OptionalExtension, named_params};
use schemars::JsonSchema;
use serde::Serialize;
use transparent::keys::TransparentKeyScope;
use zcash_address::{
    ToAddress, ZcashAddress,
    unified::{self, Encoding},
};
use zcash_client_backend::data_api::WalletRead;
use zcash_client_sqlite::{AccountUuid, error::SqliteClientError};
use zcash_keys::encoding::AddressCodec;
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};
use zcash_protocol::{
    ShieldedPool, TxId,
    consensus::{BlockHeight, Parameters},
    memo::Memo,
    value::{BalanceError, Zatoshis},
};

use crate::components::{
    chain::{Chain, ChainView},
    database::DbConnection,
    json_rpc::{
        server::LegacyCode,
        utils::{JsonZec, parse_txid, value_from_zatoshis},
    },
};

#[cfg(zallet_build = "wallet")]
use {
    crate::components::json_rpc::utils::{JsonZecBalance, value_from_zat_balance},
    zcash_protocol::value::ZatBalance,
};

const POOL_TRANSPARENT: &str = "transparent";
const POOL_SAPLING: &str = "sapling";
const POOL_ORCHARD: &str = "orchard";

/// The number of blocks within expiry height when a tx is considered to be expiring soon.
const TX_EXPIRING_SOON_THRESHOLD: u32 = 3;

/// Response to a `z_viewtransaction` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = Transaction;

/// Detailed information about an in-wallet transaction.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct Transaction {
    /// The transaction ID.
    txid: String,

    /// The transaction status.
    ///
    /// One of 'mined', 'waiting', 'expiringsoon' or 'expired'.
    status: &'static str,

    /// The number of confirmations.
    ///
    /// - A positive value is the number of blocks that have been mined including the
    ///   transaction in the chain. For example, 1 confirmation means the transaction is
    ///   in the block currently at the chain tip.
    /// - 0 means the transaction is in the mempool. If `asOfHeight` was set, this case
    ///   will not occur.
    /// - -1 means the transaction cannot be mined.
    confirmations: i64,

    /// The hash of the main chain block that this transaction is mined in.
    ///
    /// Omitted if this transaction is not mined within a block in the current best chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    blockhash: Option<String>,

    /// The index of the transaction within its block's `vtx` field.
    ///
    /// Omitted if this transaction is not mined within a block in the current best chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    blockindex: Option<u32>,

    /// The time in seconds since epoch (1 Jan 1970 GMT) that the main chain block
    /// containing this transaction was mined.
    ///
    /// Omitted if this transaction is not mined within a block in the current best chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    blocktime: Option<u64>,

    /// The transaction version.
    version: u32,

    /// The greatest height at which this transaction can be mined, or 0 if this
    /// transaction does not expire.
    expiryheight: u64,

    /// The fee paid by the transaction.
    ///
    /// Omitted if this is a coinbase transaction, or if the fee cannot be determined
    /// because one or more transparent inputs of the transaction cannot be found.
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<JsonZec>,

    /// Set to `true` if this is a coinbase transaction, omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    generated: Option<bool>,

    /// The inputs to the transaction that the wallet is capable of viewing.
    spends: Vec<Spend>,

    /// The outputs of the transaction that the wallet is capable of viewing.
    outputs: Vec<Output>,

    /// A map from an involved account's UUID to the effects of this transaction on it.
    #[cfg(zallet_build = "wallet")]
    accounts: BTreeMap<String, AccountEffect>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct Spend {
    /// The value pool.
    ///
    /// One of `["transparent", "sapling", "orchard"]`.
    pool: &'static str,

    /// (transparent) the index of the spend within `vin`.
    #[serde(rename = "tIn")]
    #[serde(skip_serializing_if = "Option::is_none")]
    t_in: Option<u16>,

    /// (sapling) the index of the spend within `vShieldedSpend`.
    #[serde(skip_serializing_if = "Option::is_none")]
    spend: Option<u16>,

    /// (orchard) the index of the action within orchard bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<u16>,

    /// The id for the transaction this note was created in.
    #[serde(rename = "txidPrev")]
    txid_prev: String,

    /// (transparent) the index of the corresponding output within the previous
    /// transaction's `vout`.
    #[serde(rename = "tOutPrev")]
    #[serde(skip_serializing_if = "Option::is_none")]
    t_out_prev: Option<u32>,

    /// (sapling) the index of the corresponding output within the previous transaction's
    /// `vShieldedOutput`.
    #[serde(rename = "outputPrev")]
    #[serde(skip_serializing_if = "Option::is_none")]
    output_prev: Option<u16>,

    /// (orchard) the index of the corresponding action within the previous transaction's
    /// Orchard bundle.
    #[serde(rename = "actionPrev")]
    #[serde(skip_serializing_if = "Option::is_none")]
    action_prev: Option<u16>,

    /// The UUID of the Zallet account that received the corresponding output.
    ///
    /// Omitted if the output is not for an account in the wallet (which always means that
    /// `pool` is `"transparent"`; external shielded spends are never included because
    /// they are unviewable).
    #[serde(skip_serializing_if = "Option::is_none")]
    account_uuid: Option<String>,

    /// The Zcash address involved in the transaction.
    ///
    /// Omitted if this note was received on an account-internal address (e.g. change
    /// notes).
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,

    /// The amount in ZEC.
    value: JsonZec,

    /// The amount in zatoshis.
    #[serde(rename = "valueZat")]
    value_zat: u64,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct Output {
    /// The value pool.
    ///
    /// One of `["transparent", "sapling", "orchard"]`.
    pool: &'static str,

    /// (transparent) the index of the output within the `vout`.
    #[serde(rename = "tOut")]
    #[serde(skip_serializing_if = "Option::is_none")]
    t_out: Option<u16>,

    /// (sapling) the index of the output within the `vShieldedOutput`.
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<u16>,

    /// (orchard) the index of the action within the orchard bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<u16>,

    /// The UUID of the Zallet account that received the output.
    ///
    /// Omitted if the output is not for an account in the wallet (`outgoing != false`).
    #[serde(skip_serializing_if = "Option::is_none")]
    account_uuid: Option<String>,

    /// The Zcash address that received the output.
    ///
    /// Omitted if this output was received on an account-internal address (e.g. change outputs),
    /// or is a transparent output to a script that is not either P2PKH or P2SH (and thus doesn't
    /// have an address encoding).
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,

    /// Whether or not the output is outgoing from this wallet.
    ///
    /// - `true` if the output is not for an account in the wallet, and the transaction
    ///   was funded by the wallet.
    /// - `false` if the output is for an account in the wallet.
    ///
    /// Omitted if the output is not for an account in the wallet, and the transaction was
    /// not funded by the wallet.
    outgoing: Option<bool>,

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
    ///
    /// Omitted if this is a transparent output.
    #[serde(rename = "memoStr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    memo_str: Option<String>,
}

/// The effect of a transaction on an account's balance.
#[cfg(zallet_build = "wallet")]
#[derive(Clone, Debug, Serialize, JsonSchema)]
struct AccountEffect {
    /// The net change of the account's balance, in ZEC.
    ///
    /// This includes any contribution by this account to the transaction fee.
    delta: JsonZecBalance,

    /// The net change of the account's balance, in zatoshis.
    ///
    /// This includes any contribution by this account to the transaction fee.
    #[serde(rename = "deltaZat")]
    delta_zat: i64,
}

pub(super) const PARAM_TXID_DESC: &str = "The ID of the transaction to view.";

pub(crate) async fn call<C: Chain>(wallet: &DbConnection, chain: C, txid_str: &str) -> Response {
    let txid = parse_txid(txid_str)?;

    let chain_view = chain
        .snapshot()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let tx = wallet
        .get_transaction(txid)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or(
            LegacyCode::InvalidAddressOrKey.with_static("Invalid or non-wallet transaction id"),
        )?;

    // TODO: Should we enforce ZIP 212 when viewing outputs of a transaction that is
    //       already in the wallet?
    //       https://github.com/zcash/wallet/issues/254
    let zip212_enforcement = sapling::note_encryption::Zip212Enforcement::GracePeriod;

    let mut spends = vec![];
    let mut outputs = vec![];

    let mut transparent_input_values = BTreeMap::new();

    // Collect account IDs for transparent coin relevance detection.
    let account_ids = wallet
        .get_account_ids()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    // Collect viewing keys for recovering output information.
    // - OVKs are used cross-protocol and thus are collected as byte arrays.
    let mut sapling_ivks = vec![];
    let mut orchard_ivks = vec![];
    let mut ovks = vec![];
    for (account_id, ufvk) in wallet
        .get_unified_full_viewing_keys()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
    {
        if let Some(t) = ufvk.transparent() {
            let (internal_ovk, external_ovk) = t.ovks_for_shielding();
            ovks.push((internal_ovk.as_bytes(), zip32::Scope::Internal));
            ovks.push((external_ovk.as_bytes(), zip32::Scope::External));
        }
        for scope in [zip32::Scope::External, zip32::Scope::Internal] {
            if let Some(dfvk) = ufvk.sapling() {
                sapling_ivks.push((
                    account_id,
                    sapling::keys::PreparedIncomingViewingKey::new(&dfvk.to_ivk(scope)),
                    scope,
                ));
                ovks.push((dfvk.to_ovk(scope).0, scope));
            }
            if let Some(fvk) = ufvk.orchard() {
                orchard_ivks.push((
                    account_id,
                    orchard::keys::PreparedIncomingViewingKey::new(&fvk.to_ivk(scope)),
                    scope,
                ));
                ovks.push((*fvk.to_ovk(scope).as_ref(), scope));
            }
        }
    }

    // TODO: Add `WalletRead::get_note_with_nullifier`
    type OutputInfo = (TxId, u16, AccountUuid, Option<String>, Zatoshis);
    fn output_with_nullifier(
        wallet: &DbConnection,
        pool: ShieldedPool,
        nf: [u8; 32],
    ) -> RpcResult<Option<OutputInfo>> {
        let (pool_prefix, output_prefix) = match pool {
            ShieldedPool::Sapling => ("sapling", "output"),
            ShieldedPool::Orchard => ("orchard", "action"),
            // Ironwood is not yet supported; elide such spends rather than failing the call.
            ShieldedPool::Ironwood => return Ok(None),
        };

        wallet
            .with_raw(|conn, _| {
                conn.query_row(
                    &format!(
                        "SELECT txid, {output_prefix}_index, accounts.uuid, address, value
                        FROM {pool_prefix}_received_notes rn
                        JOIN transactions ON transaction_id = id_tx
                        JOIN accounts ON accounts.id = rn.account_id
                        LEFT OUTER JOIN addresses ON address_id = addresses.id
                        WHERE nf = :nf"
                    ),
                    named_params! {
                        ":nf": nf,
                    },
                    |row| {
                        Ok((
                            TxId::from_bytes(row.get("txid")?),
                            row.get(format!("{output_prefix}_index").as_str())?,
                            AccountUuid::from_uuid(row.get("uuid")?),
                            row.get("address")?,
                            Zatoshis::const_from_u64(row.get("value")?),
                        ))
                    },
                )
            })
            .optional()
            .map_err(|e| {
                LegacyCode::Database.with_message(format!("Failed to fetch spent note: {e:?}"))
            })
    }

    /// Fetches the address that was cached at transaction construction as the recipient.
    // TODO: Move this into `WalletRead`.
    fn sent_to_address(
        wallet: &DbConnection,
        txid: &TxId,
        pool: ShieldedPool,
        idx: u16,
        fallback_addr: impl FnOnce() -> Option<String>,
    ) -> RpcResult<Option<String>> {
        let output_pool = match pool {
            ShieldedPool::Sapling => 2,
            ShieldedPool::Orchard => 3,
            // Ironwood is not yet supported; elide the sent-to address rather than failing.
            ShieldedPool::Ironwood => return Ok(None),
        };
        Ok(wallet
            .with_raw(|conn, _| {
                conn.query_row(
                    "SELECT to_address
                            FROM sent_notes
                            JOIN transactions ON transaction_id = id_tx
                            WHERE txid = :txid
                            AND   output_pool = :output_pool
                            AND   output_index = :output_index",
                    named_params! {
                        ":txid": txid.as_ref(),
                        ":output_pool": output_pool,
                        ":output_index": idx,
                    },
                    |row| row.get("to_address"),
                )
            })
            // Allow the `sent_notes` table to not be populated.
            .optional()
            .map_err(|e| {
                LegacyCode::Database.with_message(format!("Failed to fetch sent-to address: {e}"))
            })?
            // If we don't have a cached recipient, fall back on an address that
            // corresponds to the actual receiver.
            .unwrap_or_else(fallback_addr))
    }

    // Process spends first, so we can use them to determine whether this transaction was
    // funded by the wallet.

    if let Some(bundle) = tx.transparent_bundle() {
        // Skip transparent inputs for coinbase transactions (as they are not spends).
        if !bundle.is_coinbase() {
            // Transparent inputs
            for (input, idx) in bundle.vin.iter().zip(0u16..) {
                let txid_prev = input.prevout().txid().to_string();

                let (account_uuid, address, value) =
                    match chain_view.get_transaction(*input.prevout().txid()).await {
                        Ok(Some(prev_tx)) => {
                            let output = prev_tx
                                .inner
                                .transparent_bundle()
                                .and_then(|b| {
                                    b.vout.get(
                                        usize::try_from(input.prevout().n()).expect("should fit"),
                                    )
                                })
                                .expect("Zaino should have rejected this earlier");
                            let address = output.recipient_address();

                            let account_id = address.as_ref().and_then(|address| {
                                account_ids.iter().find(|account| {
                                    wallet
                                        .get_transparent_address_metadata(**account, address)
                                        .transpose()
                                        .is_some()
                                })
                            });

                            (
                                account_id.map(|account| account.expose_uuid().to_string()),
                                address.map(|addr| addr.encode(wallet.params())),
                                output.value(),
                            )
                        }
                        Ok(None) => unreachable!(),
                        Err(_) => todo!(),
                    };

                transparent_input_values.insert(input.prevout(), value);

                spends.push(Spend {
                    pool: POOL_TRANSPARENT,
                    t_in: Some(idx),
                    spend: None,
                    action: None,
                    txid_prev,
                    t_out_prev: Some(input.prevout().n()),
                    output_prev: None,
                    action_prev: None,
                    account_uuid,
                    address,
                    value: value_from_zatoshis(value),
                    value_zat: value.into_u64(),
                });
            }
        }
    }

    if let Some(bundle) = tx.sapling_bundle() {
        // Sapling spends
        for (spend, idx) in bundle.shielded_spends().iter().zip(0..) {
            let spent_note =
                output_with_nullifier(wallet, ShieldedPool::Sapling, spend.nullifier().0)?;

            if let Some((txid_prev, output_prev, account_id, address, value)) = spent_note {
                spends.push(Spend {
                    pool: POOL_SAPLING,
                    t_in: None,
                    spend: Some(idx),
                    action: None,
                    txid_prev: txid_prev.to_string(),
                    t_out_prev: None,
                    output_prev: Some(output_prev),
                    action_prev: None,
                    account_uuid: Some(account_id.expose_uuid().to_string()),
                    address,
                    value: value_from_zatoshis(value),
                    value_zat: value.into_u64(),
                });
            }
        }
    }

    if let Some(bundle) = tx.orchard_bundle() {
        for (action, idx) in bundle.actions().iter().zip(0..) {
            let spent_note = output_with_nullifier(
                wallet,
                ShieldedPool::Orchard,
                action.nullifier().to_bytes(),
            )?;

            if let Some((txid_prev, action_prev, account_id, address, value)) = spent_note {
                spends.push(Spend {
                    pool: POOL_ORCHARD,
                    t_in: None,
                    spend: None,
                    action: Some(idx),
                    txid_prev: txid_prev.to_string(),
                    t_out_prev: None,
                    output_prev: None,
                    action_prev: Some(action_prev),
                    account_uuid: Some(account_id.expose_uuid().to_string()),
                    address,
                    value: value_from_zatoshis(value),
                    value_zat: value.into_u64(),
                });
            }
        }
    }

    let funded_by_this_wallet = spends.iter().any(|spend| spend.account_uuid.is_some());

    if let Some(bundle) = tx.transparent_bundle() {
        // Transparent outputs
        for (output, idx) in bundle.vout.iter().zip(0..) {
            let (account_uuid, address, outgoing, wallet_internal) =
                match output.recipient_address() {
                    None => (None, None, None, false),
                    Some(address) => {
                        let (account_uuid, wallet_scope) = account_ids
                            .iter()
                            .find_map(|account| {
                                match wallet.get_transparent_address_metadata(*account, &address) {
                                    Ok(Some(metadata)) => {
                                        Some((account.expose_uuid().to_string(), metadata.scope()))
                                    }
                                    _ => None,
                                }
                            })
                            .unzip();

                        let outgoing = match (&account_uuid, funded_by_this_wallet) {
                            (None, true) => Some(true),
                            (Some(_), _) => Some(false),
                            (None, false) => None,
                        };

                        (
                            account_uuid,
                            Some(address.encode(wallet.params())),
                            outgoing,
                            // The outer `Some` indicates that we have address metadata; the inner
                            // `Option` is `None` for addresses associated with imported transparent
                            // spending keys.
                            wallet_scope == Some(Some(TransparentKeyScope::INTERNAL)),
                        )
                    }
                };

            outputs.push(Output {
                pool: POOL_TRANSPARENT,
                t_out: Some(idx),
                output: None,
                action: None,
                account_uuid,
                address,
                outgoing,
                wallet_internal,
                value: value_from_zatoshis(output.value()),
                value_zat: output.value().into_u64(),
                memo: None,
                memo_str: None,
            });
        }
    }

    if let Some(bundle) = tx.sapling_bundle() {
        let incoming: BTreeMap<
            u16,
            (
                sapling::Note,
                AccountUuid,
                Option<sapling::PaymentAddress>,
                [u8; 512],
            ),
        > = bundle
            .shielded_outputs()
            .iter()
            .zip(0..)
            .filter_map(|(output, idx)| {
                sapling_ivks.iter().find_map(|(account_id, ivk, scope)| {
                    sapling::note_encryption::try_sapling_note_decryption(
                        ivk,
                        output,
                        zip212_enforcement,
                    )
                    .map(|(n, a, m)| {
                        (
                            idx,
                            (
                                n,
                                *account_id,
                                matches!(scope, zip32::Scope::External).then_some(a),
                                m,
                            ),
                        )
                    })
                })
            })
            .collect();

        let outgoing: BTreeMap<u16, (sapling::Note, Option<sapling::PaymentAddress>, [u8; 512])> =
            bundle
                .shielded_outputs()
                .iter()
                .zip(0..)
                .filter_map(|(output, idx)| {
                    ovks.iter().find_map(|(ovk, scope)| {
                        sapling::note_encryption::try_sapling_output_recovery(
                            &sapling::keys::OutgoingViewingKey(*ovk),
                            output,
                            zip212_enforcement,
                        )
                        .map(|(n, a, m)| {
                            (
                                idx,
                                (n, matches!(scope, zip32::Scope::External).then_some(a), m),
                            )
                        })
                    })
                })
                .collect();

        // Sapling outputs
        for (_, idx) in bundle.shielded_outputs().iter().zip(0..) {
            if let Some((note, account_uuid, addr, memo)) = incoming
                .get(&idx)
                .map(|(n, account_id, addr, memo)| {
                    (n, Some(account_id.expose_uuid().to_string()), addr, memo)
                })
                .or_else(|| {
                    outgoing
                        .get(&idx)
                        .map(|(n, addr, memo)| (n, None, addr, memo))
                })
            {
                let address = sent_to_address(wallet, &txid, ShieldedPool::Sapling, idx, || {
                    addr.map(|address| {
                        ZcashAddress::from_sapling(
                            wallet.params().network_type(),
                            address.to_bytes(),
                        )
                        .encode()
                    })
                })?;
                // Don't need to check `funded_by_this_wallet` because we only reach this
                // line if the output was decryptable by an IVK (so it doesn't matter) or
                // an OVK (so it is by definition outgoing, even if we can't currently
                // detect a spent nullifier due to non-linear scanning).
                let outgoing = Some(account_uuid.is_none());
                let wallet_internal = address.is_none();

                let value = Zatoshis::const_from_u64(note.value().inner());

                let memo_str = match Memo::from_bytes(memo) {
                    Ok(Memo::Text(text_memo)) => Some(text_memo.into()),
                    _ => None,
                };
                let memo = Some(hex::encode(memo));

                outputs.push(Output {
                    pool: POOL_SAPLING,
                    t_out: None,
                    output: Some(idx),
                    action: None,
                    account_uuid,
                    address,
                    outgoing,
                    wallet_internal,
                    value: value_from_zatoshis(value),
                    value_zat: value.into_u64(),
                    memo,
                    memo_str,
                });
            }
        }
    }

    if let Some(bundle) = tx.orchard_bundle() {
        let incoming: BTreeMap<
            u16,
            (
                orchard::Note,
                AccountUuid,
                Option<orchard::Address>,
                [u8; 512],
            ),
        > = bundle
            .actions()
            .iter()
            .zip(0..)
            .filter_map(|(action, idx)| {
                let domain = OrchardDomain::for_action(action);
                orchard_ivks.iter().find_map(|(account_id, ivk, scope)| {
                    try_note_decryption(&domain, ivk, action).map(|(n, a, m)| {
                        (
                            idx,
                            (
                                n,
                                *account_id,
                                matches!(scope, zip32::Scope::External).then_some(a),
                                m,
                            ),
                        )
                    })
                })
            })
            .collect();

        let outgoing: BTreeMap<u16, (orchard::Note, Option<orchard::Address>, [u8; 512])> = bundle
            .actions()
            .iter()
            .zip(0..)
            .filter_map(|(action, idx)| {
                let domain = OrchardDomain::for_action(action);
                ovks.iter().find_map(move |(ovk, scope)| {
                    try_output_recovery_with_ovk(
                        &domain,
                        &orchard::keys::OutgoingViewingKey::from(*ovk),
                        action,
                        action.cv_net(),
                        &action.encrypted_note().out_ciphertext,
                    )
                    .map(|(n, a, m)| {
                        (
                            idx,
                            (n, matches!(scope, zip32::Scope::External).then_some(a), m),
                        )
                    })
                })
            })
            .collect();

        for (_, idx) in bundle.actions().iter().zip(0..) {
            if let Some((note, account_uuid, addr, memo)) = incoming
                .get(&idx)
                .map(|(n, account_id, addr, memo)| {
                    (n, Some(account_id.expose_uuid().to_string()), addr, memo)
                })
                .or_else(|| {
                    outgoing
                        .get(&idx)
                        .map(|(n, addr, memo)| (n, None, addr, memo))
                })
            {
                let address = sent_to_address(wallet, &txid, ShieldedPool::Orchard, idx, || {
                    addr.map(|address| {
                        ZcashAddress::from_unified(
                            wallet.params().network_type(),
                            unified::Address::try_from_items(vec![unified::Receiver::Orchard(
                                address.to_raw_address_bytes(),
                            )])
                            .expect("valid"),
                        )
                        .encode()
                    })
                })?;
                // Don't need to check `funded_by_this_wallet` because we only reach this
                // line if the output was decryptable by an IVK (so it doesn't matter) or
                // an OVK (so it is by definition outgoing, even if we can't currently
                // detect a spent nullifier due to non-linear scanning).
                let outgoing = Some(account_uuid.is_none());
                let wallet_internal = address.is_none();

                let value = Zatoshis::const_from_u64(note.value().inner());

                let memo_str = match Memo::from_bytes(memo) {
                    Ok(Memo::Text(text_memo)) => Some(text_memo.into()),
                    _ => None,
                };
                let memo = Some(hex::encode(memo));

                outputs.push(Output {
                    pool: POOL_ORCHARD,
                    t_out: None,
                    output: None,
                    action: Some(idx),
                    account_uuid,
                    address,
                    outgoing,
                    wallet_internal,
                    value: value_from_zatoshis(value),
                    value_zat: value.into_u64(),
                    memo,
                    memo_str,
                });
            }
        }
    }

    let chain_tip = chain_view
        .tip()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let wallet_tx_info = WalletTxInfo::fetch(wallet, &chain_view, &tx, chain_tip.height)
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let fee = tx
        .fee_paid(|prevout| Ok::<_, BalanceError>(transparent_input_values.get(prevout).copied()))
        // This should never occur, as a transaction that violated balance would be
        // rejected by the backing full node.
        .map_err(|e| LegacyCode::Database.with_message(format!("Failed to compute fee: {e}")))?;

    #[cfg(zallet_build = "wallet")]
    let accounts = wallet.with_raw(|conn, _| {
        let mut stmt = conn
            .prepare(
                "SELECT account_uuid, account_balance_delta
                FROM v_transactions
                WHERE txid = :txid",
            )
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
        stmt.query_map(
            named_params! {
                ":txid": txid.as_ref(),
            },
            |row| {
                Ok((
                    AccountUuid::from_uuid(row.get("account_uuid")?),
                    row.get("account_balance_delta")?,
                ))
            },
        )
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .map(|res| {
            res.map_err(|e| LegacyCode::Database.with_message(e.to_string()))
                .and_then(|(account_id, delta_zat)| {
                    let delta = ZatBalance::from_i64(delta_zat)
                        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
                    Ok((
                        account_id.expose_uuid().to_string(),
                        AccountEffect {
                            delta: value_from_zat_balance(delta),
                            delta_zat,
                        },
                    ))
                })
        })
        .collect::<Result<_, _>>()
    })?;

    Ok(Transaction {
        txid: txid_str.to_ascii_lowercase(),
        status: wallet_tx_info.status,
        confirmations: wallet_tx_info.confirmations,
        blockhash: wallet_tx_info.blockhash,
        blockindex: wallet_tx_info.blockindex,
        blocktime: wallet_tx_info.blocktime,
        version: tx.version().header() & 0x7FFFFFFF,
        expiryheight: wallet_tx_info.expiryheight,
        fee: fee.map(value_from_zatoshis),
        generated: wallet_tx_info.generated,
        spends,
        outputs,
        #[cfg(zallet_build = "wallet")]
        accounts,
    })
}

struct WalletTxInfo {
    status: &'static str,
    confirmations: i64,
    generated: Option<bool>,
    blockhash: Option<String>,
    blockindex: Option<u32>,
    blocktime: Option<u64>,
    expiryheight: u64,
}

impl WalletTxInfo {
    /// Logic adapted from `WalletTxToJSON` in `zcashd`, to match the semantics of the `gettransaction` fields.
    async fn fetch<V: ChainView>(
        wallet: &DbConnection,
        chain_view: &V,
        tx: &zcash_primitives::transaction::Transaction,
        chain_height: BlockHeight,
    ) -> Result<Self, SqliteClientError> {
        let mined_height = wallet.get_tx_height(tx.txid())?;

        let confirmations = {
            match mined_height {
                Some(mined_height) => i64::from(chain_height + 1 - mined_height),
                None => {
                    // TODO: Also check if the transaction is in the mempool.
                    //       https://github.com/zcash/wallet/issues/237
                    -1
                }
            }
        };

        let generated = if tx
            .transparent_bundle()
            .is_some_and(|bundle| bundle.is_coinbase())
        {
            Some(true)
        } else {
            None
        };

        let mut status = "waiting";

        let (blockhash, blockindex, blocktime) = if let Some(height) = mined_height {
            status = "mined";

            let block = chain_view
                .get_block(height)
                .await
                .map_err(|_| SqliteClientError::ChainHeightUnknown)?
                .ok_or(SqliteClientError::ChainHeightUnknown)?;

            let tx_index = block
                .vtx()
                .iter()
                .zip(0..)
                .find_map(|(ctx, index)| (ctx.txid() == tx.txid()).then_some(index));

            (
                Some(block.header().hash().to_string()),
                tx_index,
                Some(block.header().time.into()),
            )
        } else {
            match (
                is_expired_tx(tx, chain_height),
                is_expiring_soon_tx(tx, chain_height + 1),
            ) {
                (false, true) => status = "expiringsoon",
                (true, _) => status = "expired",
                _ => (),
            }
            (None, None, None)
        };

        Ok(Self {
            status,
            confirmations,
            generated,
            blockhash,
            blockindex,
            blocktime,
            expiryheight: tx.expiry_height().into(),
        })
    }
}

fn is_expired_tx(tx: &zcash_primitives::transaction::Transaction, height: BlockHeight) -> bool {
    if tx.expiry_height() == 0.into()
        || tx
            .transparent_bundle()
            .is_some_and(|bundle| bundle.is_coinbase())
    {
        false
    } else {
        height > tx.expiry_height()
    }
}

fn is_expiring_soon_tx(
    tx: &zcash_primitives::transaction::Transaction,
    next_height: BlockHeight,
) -> bool {
    is_expired_tx(tx, next_height + TX_EXPIRING_SOON_THRESHOLD)
}
