use std::num::NonZeroU32;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{
    Account, AccountPurpose, AccountReceivedOutput, MinedStateFilter, ReceivedOutputsQuery,
    WalletRead, wallet::TargetHeight,
};
use zcash_keys::address::Address;
use zcash_protocol::{PoolType, ShieldedPool, consensus::BlockHeight, memo::Memo};

use crate::components::{
    database::DbConnection,
    json_rpc::{
        payments,
        server::LegacyCode,
        utils::{
            JsonZec, confirmation_count, parse_as_of_height, parse_minconf, value_from_zatoshis,
        },
    },
};

/// Response to a `z_listreceivedbyaddress` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// A list of outputs received by an address.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(Vec<ReceivedOutput>);

/// An output received by the wallet, whether or not it has been spent.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct ReceivedOutput {
    /// The value pool in which the output was received.
    ///
    /// One of `["transparent", "sapling", "orchard", "ironwood"]`.
    pool: String,

    /// The ID of the transaction that created this output.
    txid: String,

    /// The value of the output in ZEC.
    amount: JsonZec,

    /// The value of the output in zatoshis.
    #[serde(rename = "amountZat")]
    amount_zat: u64,

    /// The hexadecimal string representation of the memo field.
    ///
    /// Absent for transparent outputs, and for shielded outputs whose memo has not yet
    /// been downloaded from the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    memo: Option<String>,

    /// UTF-8 string representation of the memo field, if it represents a valid UTF-8
    /// string.
    #[serde(rename = "memoStr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    memo_str: Option<String>,

    /// The transparent output index, Sapling output index, or Orchard or Ironwood action
    /// index of the output within its transaction.
    outindex: u32,

    /// The number of confirmations.
    confirmations: u32,

    /// The height of the block containing the transaction, or `0` if the transaction is
    /// unmined.
    blockheight: u32,

    /// The index of the transaction within the block containing it, or `-1` if the
    /// transaction is unmined.
    blockindex: i64,

    /// The time of the block containing the transaction, in seconds since the POSIX
    /// epoch, or `0` if the transaction is unmined.
    blocktime: i64,

    /// `true` if the output was received as change.
    ///
    /// Omitted for outputs received by accounts for which the wallet does not have
    /// spending authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    change: Option<bool>,
}

pub(super) const PARAM_ADDRESS_DESC: &str = "The address that received the outputs to list.";
pub(super) const PARAM_MINCONF_DESC: &str =
    "Only include outputs of transactions confirmed at least this many times.";
pub(super) const PARAM_AS_OF_HEIGHT_DESC: &str = "Execute the query as if it were run when the blockchain was at the height specified by this argument.";
pub(super) const PARAM_OFFSET_DESC: &str =
    "An optional number of outputs to skip over before a page of results is returned.";
pub(super) const PARAM_LIMIT_DESC: &str =
    "An optional upper bound on the number of results that should be returned in a page.";

/// The mined-height bound and unmined-inclusion filter equivalent to requiring at least
/// `minconf` confirmations as of `query_height` (the chain tip, or the `asOfHeight`
/// parameter when given).
///
/// An output mined at height `h` has `query_height + 1 - h` confirmations, so requiring
/// at least `minconf` of them is the bound `h <= query_height + 1 - minconf`. Unmined
/// outputs have zero confirmations, and so are included exactly when `minconf` is zero
/// (which `parse_minconf` permits only when `asOfHeight` is absent).
fn mined_bounds(
    minconf: u32,
    query_height: BlockHeight,
) -> (Option<BlockHeight>, MinedStateFilter) {
    if minconf == 0 {
        (Some(query_height + 1), MinedStateFilter::All)
    } else {
        // Subtraction of block heights saturates at zero; a `minconf` larger than the
        // chain height yields a bound that no mined output satisfies.
        (
            Some(query_height + 1 - minconf),
            MinedStateFilter::MinedOnly,
        )
    }
}

/// The JSON name of the value pool in which an output was received.
fn pool_name(pool_type: PoolType) -> &'static str {
    match pool_type {
        PoolType::Transparent => "transparent",
        PoolType::Shielded(ShieldedPool::Sapling) => "sapling",
        PoolType::Shielded(ShieldedPool::Orchard) => "orchard",
        PoolType::Shielded(ShieldedPool::Ironwood) => "ironwood",
    }
}

/// Renders a received output as a `z_listreceivedbyaddress` result entry.
///
/// The `change` field is rendered only when `include_change` is set; the wallet omits it
/// for accounts without spending authority, for which change detection is unreliable.
fn received_output(
    output: &AccountReceivedOutput,
    target_height: TargetHeight,
    include_change: bool,
) -> RpcResult<ReceivedOutput> {
    let (memo, memo_str) = match output.memo() {
        Some(memo_bytes) => (
            Some(hex::encode(memo_bytes.as_array())),
            match Memo::try_from(memo_bytes.clone()) {
                Ok(Memo::Text(text)) => Some(text.to_string()),
                _ => None,
            },
        ),
        None => (None, None),
    };

    let mined = output.mined_position();

    Ok(ReceivedOutput {
        pool: pool_name(output.pool_type()).into(),
        txid: output.txid().to_string(),
        amount: value_from_zatoshis(output.value()),
        amount_zat: output.value().into(),
        memo,
        memo_str,
        outindex: u32::try_from(output.output_index())
            .map_err(|_| LegacyCode::Database.with_static("output index out of range"))?,
        confirmations: confirmation_count(target_height, mined.map(|p| p.height())),
        blockheight: mined.map_or(0, |p| p.height().into()),
        blockindex: mined
            .and_then(|p| p.tx_index())
            .map_or(-1, |i| i64::from(u32::from(i))),
        blocktime: mined.and_then(|p| p.block_time()).map_or(0, i64::from),
        change: include_change.then_some(output.is_change()),
    })
}

pub(crate) fn call(
    wallet: &DbConnection,
    address: &str,
    minconf: Option<u32>,
    as_of_height: Option<i64>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Response {
    let as_of_height = parse_as_of_height(as_of_height)?;
    let minconf = parse_minconf(minconf, 1, as_of_height)?;
    let limit = limit
        .map(|l| {
            NonZeroU32::new(l)
                .ok_or_else(|| LegacyCode::InvalidParameter.with_static("limit must be positive"))
        })
        .transpose()?;

    let addr = Address::decode(wallet.params(), address)
        .ok_or_else(|| LegacyCode::InvalidAddressOrKey.with_static("Invalid zaddr."))?;

    // ZIP 320 (TEX) addresses direct the *sender* to use transparent funds; they are not
    // addresses that a wallet receives on, and zcashd predates them.
    if matches!(addr, Address::Tex(_)) {
        return Err(LegacyCode::InvalidParameter.with_static(
            "TEX addresses cannot receive outputs; provide the transparent address instead.",
        ));
    }

    let account = payments::get_account_for_address(wallet, &addr).map_err(|e| {
        let db_code: i32 = LegacyCode::Database.into();
        if e.code() == db_code {
            e
        } else {
            LegacyCode::InvalidAddressOrKey.with_static(
                "From address does not belong to this node, zaddr spending key or viewing key not found.",
            )
        }
    })?;

    // Reject an address that is a bare receiver of a "larger" unified address of the
    // account, mirroring zcashd. An address whose receivers are exactly the receivers of
    // a wallet address is that address in another encoding (for example, the Sapling
    // address of an account created by importing a Sapling key, whose wallet address is
    // the sapling-only unified re-encoding of it), and is accepted.
    if !matches!(addr, Address::Unified(_)) {
        let receivers = addr.as_understood_unified_receivers();
        let addresses = wallet
            .list_addresses(account.id())
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

        let exact = addresses.iter().any(|info| info.address() == &addr);
        if !exact
            && addresses.iter().any(|info| {
                let stored = info.address();
                matches!(stored, Address::Unified(_))
                    && stored.as_understood_unified_receivers().len() > receivers.len()
                    && {
                        let stored_addr = stored.to_zcash_address(wallet.params());
                        receivers.iter().all(|r| r.corresponds(&stored_addr))
                    }
            })
        {
            return Err(LegacyCode::InvalidParameter.with_static(
                "The provided address is a bare receiver from a Unified Address in this wallet. Provide the full UA instead.",
            ));
        }
    }

    let query_height = match as_of_height {
        Some(h) => h,
        None => match wallet
            .chain_height()
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        {
            Some(h) => h,
            None => return Ok(ResultType(vec![])),
        },
    };
    let target_height = TargetHeight::from(query_height + 1);
    let (max_mined_height, mined_state_filter) = mined_bounds(minconf, query_height);

    // A transparent address selects only its own outputs: the account synthesized by
    // zcashd wallet.dat migration aggregates many otherwise-unrelated imported
    // transparent addresses, which zcashd would never list together. A shielded or
    // unified address selects all of the account's outputs, so that this listing of
    // what the account has received covers notes received at its other diversifiers
    // along with the change notes received on its internal addresses: an address
    // filter resolves to an `addresses` row, and internal shielded receivers are
    // never stored as addresses, so a per-address filter could not report change.
    // This is deliberately broader than `z_listunspent`, which matches shielded
    // notes against the exact address it is given.
    let address_filter = matches!(addr, Address::Transparent(_)).then(|| addr.clone());

    let query = ReceivedOutputsQuery::from_parts(
        address_filter,
        max_mined_height,
        mined_state_filter,
        offset.unwrap_or(0),
        limit,
    );

    let include_change = matches!(account.purpose(), AccountPurpose::Spending { .. });

    let outputs = wallet
        .get_account_received_outputs(account.id(), &query)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    Ok(ResultType(
        outputs
            .iter()
            .map(|output| received_output(output, target_height, include_change))
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

#[cfg(test)]
mod tests {
    use zcash_client_backend::data_api::{
        AccountReceivedOutput, MinedPosition, MinedStateFilter, wallet::TargetHeight,
    };
    use zcash_protocol::{
        PoolType, ShieldedPool, TxId,
        consensus::{BlockHeight, TxIndex},
        memo::MemoBytes,
        value::Zatoshis,
    };

    use super::{mined_bounds, received_output};

    /// The height of the next block to be mined, as used by the RPC. An output mined in
    /// block 99 therefore has one confirmation, and one mined in block 90 has ten.
    const TARGET: u32 = 100;

    fn target() -> TargetHeight {
        TargetHeight::from(BlockHeight::from(TARGET))
    }

    /// The chain height corresponding to [`target`], as passed to [`mined_bounds`].
    fn query_height() -> BlockHeight {
        BlockHeight::from(TARGET - 1)
    }

    #[test]
    fn minconf_zero_includes_unmined_outputs_and_bounds_nothing() {
        let (bound, filter) = mined_bounds(0, query_height());
        assert_eq!(bound, Some(BlockHeight::from(TARGET)));
        assert_eq!(filter, MinedStateFilter::All);
    }

    #[test]
    fn positive_minconf_bounds_mined_height_and_excludes_unmined_outputs() {
        // An output mined in the top block has exactly one confirmation, so it is the
        // highest block that `minconf = 1` admits.
        assert_eq!(
            mined_bounds(1, query_height()),
            (Some(query_height()), MinedStateFilter::MinedOnly),
        );
        assert_eq!(
            mined_bounds(10, query_height()),
            (
                Some(BlockHeight::from(TARGET - 10)),
                MinedStateFilter::MinedOnly
            ),
        );
    }

    #[test]
    fn excessive_minconf_bound_saturates_at_the_genesis_height() {
        let (bound, _) = mined_bounds(TARGET + 50, query_height());
        assert_eq!(bound, Some(BlockHeight::from(0)));
    }

    fn entry(
        pool_type: PoolType,
        memo: Option<MemoBytes>,
        mined: Option<MinedPosition>,
        include_change: bool,
    ) -> serde_json::Value {
        serde_json::to_value(
            received_output(
                &AccountReceivedOutput::from_parts(
                    pool_type,
                    TxId::from_bytes([1u8; 32]),
                    3,
                    Zatoshis::const_from_u64(625_000_000),
                    false,
                    None,
                    memo,
                    mined,
                ),
                target(),
                include_change,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn mined_at_90() -> Option<MinedPosition> {
        Some(MinedPosition::from_parts(
            BlockHeight::from(90),
            Some(TxIndex::from(2u16)),
            Some(1_700_000_000),
        ))
    }

    #[test]
    fn shielded_text_memo_entry_renders_all_fields() {
        let rendered = entry(
            PoolType::Shielded(ShieldedPool::Sapling),
            Some(MemoBytes::from_bytes(b"Hello memo").unwrap()),
            mined_at_90(),
            true,
        );

        assert_eq!(rendered["pool"], serde_json::json!("sapling"));
        assert_eq!(
            rendered["txid"],
            serde_json::json!(TxId::from_bytes([1u8; 32]).to_string()),
        );
        assert_eq!(rendered["amountZat"], serde_json::json!(625_000_000u64));
        // `JsonZec` renders ZEC values with eight decimal places, as zcashd does.
        assert_eq!(
            rendered["amount"],
            serde_json::to_value(crate::components::json_rpc::utils::value_from_zatoshis(
                Zatoshis::const_from_u64(625_000_000)
            ))
            .unwrap(),
        );
        assert_eq!(rendered["amount"].to_string(), "6.25000000");
        assert_eq!(rendered["outindex"], serde_json::json!(3));
        assert_eq!(rendered["confirmations"], serde_json::json!(10));
        assert_eq!(rendered["blockheight"], serde_json::json!(90));
        assert_eq!(rendered["blockindex"], serde_json::json!(2));
        assert_eq!(rendered["blocktime"], serde_json::json!(1_700_000_000i64));
        assert_eq!(rendered["change"], serde_json::json!(false));
        assert_eq!(rendered["memoStr"], serde_json::json!("Hello memo"));

        // The memo is the full 512-byte memo field, hex-encoded.
        let memo_hex = rendered["memo"].as_str().unwrap();
        assert_eq!(memo_hex.len(), 512 * 2);
        assert!(memo_hex.starts_with(&hex::encode(b"Hello memo")));
        assert!(memo_hex.ends_with("00"));
    }

    #[test]
    fn empty_memo_renders_hex_but_no_memo_str() {
        let rendered = entry(
            PoolType::Shielded(ShieldedPool::Orchard),
            Some(MemoBytes::empty()),
            mined_at_90(),
            true,
        );

        assert_eq!(rendered["pool"], serde_json::json!("orchard"));
        assert!(rendered["memo"].as_str().unwrap().starts_with("f6"));
        assert!(rendered.get("memoStr").is_none());
    }

    #[test]
    fn arbitrary_memo_renders_hex_but_no_memo_str() {
        let mut memo_bytes = [0u8; 512];
        memo_bytes[0] = 0xff;
        memo_bytes[1] = 0x42;
        let rendered = entry(
            PoolType::Shielded(ShieldedPool::Ironwood),
            Some(MemoBytes::from_bytes(&memo_bytes).unwrap()),
            mined_at_90(),
            true,
        );

        assert_eq!(rendered["pool"], serde_json::json!("ironwood"));
        assert!(rendered["memo"].as_str().unwrap().starts_with("ff42"));
        assert!(rendered.get("memoStr").is_none());
    }

    #[test]
    fn absent_memo_omits_both_memo_fields() {
        // Transparent outputs have no memo, and a shielded output whose memo has not yet
        // been downloaded renders the same way; the keys must be omitted entirely rather
        // than rendered as `null`.
        let rendered = entry(PoolType::Transparent, None, mined_at_90(), true);

        assert_eq!(rendered["pool"], serde_json::json!("transparent"));
        assert!(rendered.get("memo").is_none());
        assert!(rendered.get("memoStr").is_none());
    }

    #[test]
    fn unmined_entry_renders_zcashd_placeholder_block_fields() {
        let rendered = entry(
            PoolType::Shielded(ShieldedPool::Sapling),
            Some(MemoBytes::empty()),
            None,
            true,
        );

        assert_eq!(rendered["confirmations"], serde_json::json!(0));
        assert_eq!(rendered["blockheight"], serde_json::json!(0));
        assert_eq!(rendered["blockindex"], serde_json::json!(-1));
        assert_eq!(rendered["blocktime"], serde_json::json!(0));
    }

    #[test]
    fn change_field_is_omitted_for_accounts_without_spending_authority() {
        let rendered = entry(
            PoolType::Shielded(ShieldedPool::Sapling),
            Some(MemoBytes::empty()),
            mined_at_90(),
            false,
        );

        assert!(rendered.get("change").is_none());
    }
}
