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

    /// Builds the output detail for a `v_tx_outputs` row, or `None` if the output
    /// belongs to a pool that Zallet does not yet surface (Ironwood), so that the
    /// output is elided from `listtransactions` rather than failing the whole call.
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
            // Ironwood is not yet supported; elide such outputs from the results.
            PoolType::Shielded(ShieldedPool::Ironwood) => return Ok(None),
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
            memo: memo
                .as_ref()
                .and_then(|b| {
                    MemoBytes::from_bytes(b)
                        .and_then(Memo::try_from)
                        .map(|m| match m {
                            Memo::Empty => None,
                            Memo::Text(text_memo) => Some(text_memo.to_string()),
                            Memo::Future(memo_bytes) => Some(hex::encode(memo_bytes.as_slice())),
                            Memo::Arbitrary(m) => Some(hex::encode(&m[..])),
                        })
                        .transpose()
                })
                .transpose()
                .map_err(|e| {
                    SqliteClientError::CorruptedData(format!("Invalid memo data: {e:?}"))
                })?,
        }))
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
