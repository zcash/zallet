use documented::Documented;
use jsonrpsee::core::RpcResult;
use rusqlite::named_params;
use schemars::JsonSchema;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use zcash_client_sqlite::error::SqliteClientError;
use zcash_protocol::{
    PoolType, ShieldedPool, TxId,
    memo::{Memo, MemoBytes},
    value::{ZatBalance, Zatoshis},
};

use crate::components::{database::DbConnection, json_rpc::server::LegacyCode};

const POOL_TRANSPARENT: &str = "transparent";
const POOL_SAPLING: &str = "sapling";
const POOL_ORCHARD: &str = "orchard";
const POOL_IRONWOOD: &str = "ironwood";

/// Response to a `z_viewtransaction` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// A list of transactions involving the wallet.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(Vec<WalletTx>);

pub(super) const PARAM_ACCOUNT_UUID_DESC: &str =
    "The UUID of the account to list transactions for.";
pub(super) const PARAM_START_HEIGHT_DESC: &str =
    "The (inclusive) lower bound on block heights for which transactions should be retrieved";
pub(super) const PARAM_END_HEIGHT_DESC: &str =
    "The (exclusive) upper bound on block heights for which transactions should be retrieved";
pub(super) const PARAM_OFFSET_DESC: &str =
    "The number of results to skip before returning a page of results.";
pub(super) const PARAM_LIMIT_DESC: &str =
    "The maximum number of results to return from a single call.";

/// Basic information about a transaction output that was either created or received by this
/// wallet.
#[derive(Clone, Debug, Serialize, JsonSchema)]
struct WalletTxOutput {
    pool: String,
    output_index: u32,
    from_account: Option<String>,
    to_account: Option<String>,
    to_address: Option<String>,
    value: u64,
    is_change: bool,
    memo: Option<String>,
}

impl WalletTxOutput {
    fn parse_pool_code(pool_code: i64) -> Option<PoolType> {
        match pool_code {
            0 => Some(PoolType::Transparent),
            2 => Some(PoolType::SAPLING),
            3 => Some(PoolType::ORCHARD),
            4 => Some(PoolType::Shielded(ShieldedPool::Ironwood)),
            _ => None,
        }
    }

    /// Builds the output detail for a `v_tx_outputs` row.
    ///
    /// Returns `None` only if the pool code is one Zallet cannot render (there is
    /// currently no such case; every known pool, including Ironwood, is surfaced).
    #[allow(clippy::too_many_arguments)]
    fn new(
        pool_code: i64,
        output_index: u32,
        from_account: Option<Uuid>,
        to_account: Option<Uuid>,
        to_address: Option<String>,
        value: i64,
        is_change: bool,
        memo: Option<Vec<u8>>,
    ) -> Result<Option<Self>, SqliteClientError> {
        let pool = match Self::parse_pool_code(pool_code).ok_or(
            SqliteClientError::CorruptedData(format!("Invalid pool code: {pool_code}")),
        )? {
            PoolType::Transparent => POOL_TRANSPARENT,
            PoolType::Shielded(ShieldedPool::Sapling) => POOL_SAPLING,
            PoolType::Shielded(ShieldedPool::Orchard) => POOL_ORCHARD,
            // Ironwood notes are Orchard-shaped but tracked as a distinct pool.
            PoolType::Shielded(ShieldedPool::Ironwood) => POOL_IRONWOOD,
        }
        .to_string();

        Ok(Some(Self {
            pool,
            output_index,
            from_account: from_account.map(|u| u.to_string()),
            to_account: to_account.map(|u| u.to_string()),
            to_address,
            value: u64::from(Zatoshis::from_nonnegative_i64(value).map_err(|e| {
                SqliteClientError::CorruptedData(format!("Invalid output value {value}: {e:?}"))
            })?),
            is_change,
            memo: render_memo(memo.as_deref()),
        }))
    }
}

/// Renders a stored memo as the `memo` field of a `z_listtransactions` output.
///
/// Text memos render as text and empty memos are omitted. Anything else (arbitrary
/// data, a future memo type, or text that is not valid UTF-8) renders as the hex of
/// the full 512-byte memo, the same value `z_viewtransaction` reports for the output.
/// This cannot fail: the sender chooses the memo, and one undecodable memo must not
/// take down the whole history (#794). A stored blob too long to be a memo renders as
/// the hex of the stored bytes, with a warning so the operator can see it.
fn render_memo(memo: Option<&[u8]>) -> Option<String> {
    let bytes = memo?;
    let memo_bytes = match MemoBytes::from_bytes(bytes) {
        Ok(memo_bytes) => memo_bytes,
        Err(e) => {
            tracing::warn!(
                "Stored memo of {} bytes is not a valid memo ({e}); rendering as hex",
                bytes.len()
            );
            return Some(hex::encode(bytes));
        }
    };
    match Memo::try_from(memo_bytes.clone()) {
        Ok(Memo::Empty) => None,
        Ok(Memo::Text(text_memo)) => Some(text_memo.into()),
        Ok(Memo::Future(_) | Memo::Arbitrary(_)) | Err(_) => {
            Some(hex::encode(memo_bytes.as_array()))
        }
    }
}

/// A transaction that affects an account in a wallet.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct WalletTx {
    /// The UUID of the account that this transaction entry is acting on.
    ///
    /// A transaction that has effects on multiple accounts will have multiple rows in the result.
    account_uuid: String,
    /// The height at which the transaction was mined
    mined_height: Option<u32>,
    /// The transaction identifier
    txid: String,
    /// The expiry height of the transaction
    expiry_height: Option<u32>,
    /// The delta to the account produced by the transaction
    account_balance_delta: i64,
    /// The fee paid by the transaction, if known.
    fee_paid: Option<u64>,
    /// The number of outputs produced by the transaction.
    sent_note_count: usize,
    /// The number of outputs received by the transaction.
    received_note_count: usize,
    /// The timestamp at which the block was mined.
    block_time: Option<i64>,
    /// The human-readable datetime at which the block was mined.
    block_datetime: Option<String>,
    /// Whether or not the transaction expired without having been mined.
    expired_unmined: bool,
    /// The outputs of the transaction received by the wallet.
    outputs: Vec<WalletTxOutput>,
}

impl WalletTx {
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        account_uuid: Vec<u8>,
        mined_height: Option<u32>,
        txid: Vec<u8>,
        expiry_height: Option<u32>,
        account_balance_delta: i64,
        fee_paid: Option<u64>,
        sent_note_count: usize,
        received_note_count: usize,
        block_time: Option<i64>,
        expired_unmined: bool,
        outputs: Vec<WalletTxOutput>,
    ) -> Result<Self, SqliteClientError> {
        Ok(WalletTx {
            account_uuid: Uuid::from_bytes(<[u8; 16]>::try_from(account_uuid).map_err(|e| {
                SqliteClientError::CorruptedData(format!("Invalid account uuid: {}", e.len()))
            })?)
            .to_string(),
            mined_height,
            txid: TxId::from_bytes(<[u8; 32]>::try_from(txid).map_err(|e| {
                SqliteClientError::CorruptedData(format!("Invalid txid: {}", e.len()))
            })?)
            .to_string(),
            expiry_height,
            account_balance_delta: i64::from(ZatBalance::from_i64(account_balance_delta).map_err(
                |e| {
                    SqliteClientError::CorruptedData(format!(
                        "Invalid balance delta {account_balance_delta}: {e:?}"
                    ))
                },
            )?),
            fee_paid: fee_paid
                .map(|v| {
                    Zatoshis::from_u64(v)
                        .map_err(|e| {
                            SqliteClientError::CorruptedData(format!(
                                "Invalid fee value {v}: {e:?}"
                            ))
                        })
                        .map(u64::from)
                })
                .transpose()?,
            sent_note_count,
            received_note_count,
            block_time,
            block_datetime: block_time
                .map(|t| {
                    let datetime = time::OffsetDateTime::from_unix_timestamp(t).map_err(|e| {
                        SqliteClientError::CorruptedData(format!("Invalid unix timestamp {t}: {e}"))
                    })?;
                    Ok::<_, SqliteClientError>(
                        datetime
                            .format(&Rfc3339)
                            .expect("datetime can be formatted"),
                    )
                })
                .transpose()?,
            expired_unmined,
            outputs,
        })
    }
}

fn query_transactions(
    conn: &rusqlite::Transaction<'_>,
    account_uuid: Option<Uuid>,
    start_height: Option<u32>,
    end_height: Option<u32>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<Vec<WalletTx>, SqliteClientError> {
    let mut stmt_txs = conn.prepare(
        "SELECT account_uuid,
                mined_height,
                txid,
                expiry_height,
                account_balance_delta,
                fee_paid,
                sent_note_count,
                received_note_count,
                block_time,
                expired_unmined,
                -- Fallback order for transaction history ordering:
                COALESCE(
                    -- Block height the transaction was mined at (if mined and known).
                    mined_height,
                    -- Expiry height for the transaction (if non-zero, which is always the
                    -- case for transactions we create).
                    CASE WHEN expiry_height == 0 THEN NULL ELSE expiry_height END
                    -- Mempool height (i.e. chain height + 1, so it appears most recently
                    -- in history). We represent this with NULL.
                ) AS sort_height
            FROM v_transactions
            WHERE (:account_uuid IS NULL OR account_uuid = :account_uuid)
              AND (
                -- ignore the start height if the provided value is None
                :start_height IS NULL OR
                -- the transaction is mined in the desired range
                mined_height >= :start_height OR
                -- the start height is non-null, but we permit mempool transactions
                (mined_height IS NULL AND :end_height IS NULL)
              )
              AND (
                -- ignore the end height & allow mempool txs if the provided value is None
                :end_height IS NULL OR 
                -- if an end height is provided, then the tx is required to be mined
                mined_height < :end_height
              )
            ORDER BY sort_height ASC NULLS LAST
            LIMIT :limit
            OFFSET :offset",
    )?;

    let mut stmt_outputs = conn.prepare(
        "SELECT
                output_pool,
                output_index,
                from_account_uuid,
                to_account_uuid,
                to_address,
                value,
                is_change,
                memo
             FROM v_tx_outputs
             WHERE txid = :txid",
    )?;

    stmt_txs
        .query_and_then::<_, SqliteClientError, _, _>(
            named_params! {
                ":account_uuid": account_uuid,
                ":start_height": start_height,
                ":end_height": end_height,
                ":limit": limit.map_or(-1, i64::from),
                ":offset": offset.unwrap_or(0)
            },
            |row| {
                let txid = row
                    .get::<_, Vec<u8>>("txid")
                    .map_err(|e| SqliteClientError::CorruptedData(format!("{e}")))?;

                let tx_outputs = stmt_outputs
                    .query_and_then::<_, SqliteClientError, _, _>(
                        named_params![":txid": txid],
                        |out_row| {
                            WalletTxOutput::new(
                                out_row.get("output_pool")?,
                                out_row.get("output_index")?,
                                out_row.get("from_account_uuid")?,
                                out_row.get("to_account_uuid")?,
                                out_row.get("to_address")?,
                                out_row.get("value")?,
                                out_row.get("is_change")?,
                                out_row.get("memo")?,
                            )
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();

                WalletTx::from_parts(
                    row.get("account_uuid")?,
                    row.get("mined_height")?,
                    txid,
                    row.get("expiry_height")?,
                    row.get("account_balance_delta")?,
                    row.get("fee_paid")?,
                    row.get("sent_note_count")?,
                    row.get("received_note_count")?,
                    row.get("block_time")?,
                    row.get("expired_unmined")?,
                    tx_outputs,
                )
            },
        )?
        .collect::<Result<Vec<WalletTx>, _>>()
}

pub(crate) async fn call(
    wallet: &DbConnection,
    account_uuid: Option<String>,
    start_height: Option<u32>,
    end_height: Option<u32>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Response {
    let account_uuid = account_uuid
        .map(|s| {
            Uuid::try_parse(&s).map_err(|_| {
                LegacyCode::InvalidParameter.with_message(format!("not a valid UUID: {s}"))
            })
        })
        .transpose()?;

    wallet.with_raw_mut(|conn, _| {
        let db_tx = conn
            .transaction()
            .map_err(|e| LegacyCode::Database.with_message(format!("{e}")))?;

        Ok(ResultType(
            query_transactions(
                &db_tx,
                account_uuid,
                start_height,
                end_height,
                offset,
                limit,
            )
            .map_err(|e| LegacyCode::Database.with_message(format!("{e}")))?,
        ))
    })
}

#[cfg(test)]
mod tests {
    use zcash_protocol::memo::{Memo, MemoBytes};

    use super::{POOL_IRONWOOD, WalletTxOutput, render_memo};

    /// The `v_tx_outputs` pool code for Ironwood (see `WalletTxOutput::parse_pool_code`).
    const IRONWOOD_POOL_CODE: i64 = 4;
    const OUTPUT_INDEX: u32 = 1;
    const OUTPUT_VALUE: i64 = 10_000_000;
    const TEXT_MEMO: &str = "hello";
    /// 0xAB is a UTF-8 continuation byte, so this is a text-type memo that is not valid
    /// UTF-8: the #794 trigger.
    const INVALID_UTF8_MEMO: [u8; 10] = [0xab; 10];
    /// Type byte of an arbitrary (non-text) memo.
    const ARBITRARY_MEMO_PREFIX: u8 = 0xff;

    /// Hex of the full 512-byte memo, as the other RPC methods report `memo`.
    fn full_memo_hex(bytes: &[u8]) -> String {
        hex::encode(MemoBytes::from_bytes(bytes).unwrap().as_array())
    }

    #[test]
    fn no_stored_memo_renders_as_absent() {
        assert_eq!(render_memo(None), None);
    }

    #[test]
    fn empty_memo_renders_as_absent() {
        assert_eq!(render_memo(Some(MemoBytes::empty().as_slice())), None);
    }

    #[test]
    fn text_memo_renders_as_its_text() {
        let full = Memo::from_bytes(TEXT_MEMO.as_bytes()).unwrap().encode();
        assert_eq!(
            render_memo(Some(full.as_slice())),
            Some(TEXT_MEMO.to_string())
        );
        // Unpadded stored bytes decode the same way.
        assert_eq!(
            render_memo(Some(TEXT_MEMO.as_bytes())),
            Some(TEXT_MEMO.to_string())
        );
    }

    #[test]
    fn arbitrary_memo_renders_as_full_hex() {
        let mut bytes = vec![ARBITRARY_MEMO_PREFIX];
        bytes.extend_from_slice(TEXT_MEMO.as_bytes());
        assert!(matches!(
            Memo::from_bytes(&bytes).unwrap(),
            Memo::Arbitrary(_)
        ));
        assert_eq!(render_memo(Some(&bytes)), Some(full_memo_hex(&bytes)));
    }

    #[test]
    fn invalid_utf8_text_memo_renders_as_full_hex_instead_of_failing() {
        assert!(matches!(
            Memo::from_bytes(&INVALID_UTF8_MEMO),
            Err(zcash_protocol::memo::Error::InvalidUtf8(_))
        ));
        assert_eq!(
            render_memo(Some(&INVALID_UTF8_MEMO)),
            Some(full_memo_hex(&INVALID_UTF8_MEMO))
        );
    }

    #[test]
    fn over_long_stored_memo_renders_as_hex_of_the_stored_bytes() {
        let bytes = vec![ARBITRARY_MEMO_PREFIX; MemoBytes::empty().as_array().len() + 1];
        assert!(matches!(
            MemoBytes::from_bytes(&bytes),
            Err(zcash_protocol::memo::Error::TooLong(_))
        ));
        assert_eq!(render_memo(Some(&bytes)), Some(hex::encode(&bytes)));
    }

    #[test]
    fn output_with_invalid_utf8_memo_is_rendered_rather_than_rejected() {
        let output = WalletTxOutput::new(
            IRONWOOD_POOL_CODE,
            OUTPUT_INDEX,
            None,
            None,
            None,
            OUTPUT_VALUE,
            false,
            Some(INVALID_UTF8_MEMO.to_vec()),
        )
        .expect("an undecodable memo must not fail the output")
        .expect("every known pool is rendered");
        assert_eq!(output.pool, POOL_IRONWOOD);
        assert_eq!(output.memo, Some(full_memo_hex(&INVALID_UTF8_MEMO)));
        assert_eq!(output.value, OUTPUT_VALUE as u64);
    }
}
