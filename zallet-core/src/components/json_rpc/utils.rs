use std::fmt;

use jsonrpsee::{
    core::{JsonValue, RpcResult},
    types::{ErrorCode as RpcErrorCode, ErrorObjectOwned},
};
use rust_decimal::Decimal;
use schemars::{JsonSchema, json_schema};
use serde::Serialize;
use zcash_client_sqlite::AccountUuid;
use zcash_encoding::ReverseHex;
use zcash_protocol::{
    TxId,
    consensus::BlockHeight,
    value::{COIN, ZatBalance, Zatoshis},
};
use zip32::DiversifierIndex;

use super::server::LegacyCode;

#[cfg(zallet_build = "wallet")]
use {
    crate::components::{
        chain::{Chain, ChainView},
        database::DbConnection,
        keystore::KeyStore,
    },
    std::collections::HashSet,
    zcash_client_backend::data_api::{Account, AccountBirthday, WalletRead, chain::ChainState},
    zcash_primitives::block::BlockHash,
    zcash_protocol::value::BalanceError,
    zip32::fingerprint::SeedFingerprint,
};

#[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
use {
    crate::error::ErrorKind,
    std::collections::HashMap,
    transparent::address::TransparentAddress,
    zcash_client_backend::{
        fees::StandardFeeRule, proposal::Proposal, wallet::TransparentAddressSource,
    },
    zcash_script::script,
};

/// The account identifier used for HD derivation of transparent and Sapling addresses via
/// the legacy `getnewaddress` and `z_getnewaddress` code paths.
#[cfg(zallet_build = "wallet")]
const ZCASH_LEGACY_ACCOUNT: u32 = 0x7fff_ffff;

#[cfg(zallet_build = "wallet")]
pub(super) async fn ensure_wallet_is_unlocked(keystore: &KeyStore) -> RpcResult<()> {
    // TODO: Consider returning some kind of unlock guard to ensure the caller doesn't
    // need to race against the relock timeout.
    if keystore.is_locked().await {
        Err(LegacyCode::WalletUnlockNeeded
            .with_static("Error: Please enter the wallet passphrase with walletpassphrase first."))
    } else {
        Ok(())
    }
}

/// Collects the standalone (non-HD) transparent spending keys required to sign the
/// transparent inputs of `proposal`.
///
/// Determines which transparent receivers in this account were imported standalone
/// (vs. HD-derived). Only those have an associated entry in the keystore's
/// standalone-key table; HD-derived receivers are signed for using `usk` and must not
/// be looked up via `decrypt_standalone_transparent_key` (which would error with
/// `QueryReturnedNoRows`).
///
/// Gated on `zcashd-import` because the keystore's standalone-key table (and the
/// `decrypt_standalone_transparent_key` accessor) only exists under that feature.
/// Also gated on the `wallet` build because its only callers (`z_send_many` and
/// `z_shieldcoinbase`) are wallet-only, and the `DbConnection`/`KeyStore` types it
/// uses are only imported in that build.
#[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
pub(super) async fn collect_standalone_transparent_keys<NoteRef>(
    wallet: &DbConnection,
    keystore: &KeyStore,
    account_id: AccountUuid,
    proposal: &Proposal<StandardFeeRule, NoteRef>,
) -> RpcResult<HashMap<TransparentAddress, Vec<secp256k1::SecretKey>>> {
    let standalone_addrs: HashSet<TransparentAddress> = wallet
        .get_transparent_receivers(account_id, true, true)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .into_iter()
        .filter_map(|(addr, metadata)| match metadata.source() {
            TransparentAddressSource::StandalonePubkey(_)
            | TransparentAddressSource::StandaloneScript(_) => Some(addr),
            TransparentAddressSource::Derived { .. } => None,
        })
        .collect();

    let mut keys: HashMap<TransparentAddress, Vec<secp256k1::SecretKey>> = HashMap::new();
    for step in proposal.steps() {
        for input in step.transparent_inputs() {
            if let Some(address) = script::FromChain::parse(&input.txout().script_pubkey().0)
                .ok()
                .as_ref()
                .and_then(TransparentAddress::from_script_from_chain)
            {
                if !standalone_addrs.contains(&address) {
                    continue;
                }
                let secret_key = keystore
                    .decrypt_standalone_transparent_key(&address)
                    .await
                    .map_err(|e| match e.kind() {
                        // TODO: Improve internal error types.
                        ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                            LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
                        }
                        _ => LegacyCode::Database.with_message(e.to_string()),
                    })?;
                keys.entry(address).or_default().push(secret_key);
            }
        }
    }
    Ok(keys)
}

/// Builds an [`AccountBirthday`] by fetching the treestate at the given height.
///
/// For height 0 (genesis), returns a birthday with an empty chain state since the
/// commitment trees are empty. For non-zero heights, fetches the real treestate from
/// the chain indexer so the sync engine can validate note commitment tree continuity.
#[cfg(zallet_build = "wallet")]
pub(super) async fn fetch_account_birthday<C: Chain>(
    chain: &C,
    height: BlockHeight,
) -> RpcResult<AccountBirthday> {
    if height == BlockHeight::from_u32(0) {
        // The chain state is the state of the note commitment trees *as of the block
        // preceding* the birthday. There is no block before genesis, and the conventional
        // hash of genesis's (nonexistent) parent is all-zeros, so an empty chain state with
        // a zero block hash is the correct anchor here. (Using the real genesis block hash
        // would be wrong: that is the hash of block 0 itself, not of the block before it.)
        return Ok(AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash([0; 32])),
            None,
        ));
    }

    // The chain state anchoring the birthday is the note commitment tree state as of the
    // block *preceding* the birthday height.
    let treestate_height = height.saturating_sub(1);
    let chain_view = chain.snapshot().await.map_err(|e| {
        ErrorObjectOwned::owned(
            RpcErrorCode::InternalError.code(),
            format!("Failed to obtain a chain snapshot: {e}"),
            None::<()>,
        )
    })?;
    let chain_state = chain_view
        .tree_state_as_of(treestate_height)
        .await
        .map_err(|e| {
            // A failure to fetch the treestate from the chain indexer is an internal
            // error, not a problem with the caller's parameters.
            ErrorObjectOwned::owned(
                RpcErrorCode::InternalError.code(),
                format!("Failed to get treestate at height {treestate_height}: {e}"),
                None::<()>,
            )
        })?
        .ok_or_else(|| {
            ErrorObjectOwned::owned(
                RpcErrorCode::InternalError.code(),
                format!("No treestate available at height {treestate_height}"),
                None::<()>,
            )
        })?;

    Ok(AccountBirthday::from_parts(chain_state, None))
}

pub(crate) fn parse_txid(txid_str: &str) -> RpcResult<TxId> {
    ReverseHex::decode(txid_str)
        .map(TxId::from_bytes)
        .ok_or_else(|| LegacyCode::InvalidParameter.with_static("invalid txid"))
}

/// Parses the `seedfp` parameter present in many wallet RPCs.
#[cfg(zallet_build = "wallet")]
pub(super) fn parse_seedfp_parameter(seedfp: &str) -> RpcResult<SeedFingerprint> {
    parse_seedfp(seedfp).map_err(|e| {
        LegacyCode::InvalidParameter.with_message(format!("Invalid seed fingerprint: {e:?}"))
    })
}

#[cfg(zallet_build = "wallet")]
pub(crate) fn parse_seedfp(
    seedfp: &str,
) -> Result<SeedFingerprint, zip32::fingerprint::ParseError> {
    seedfp.parse::<SeedFingerprint>().or_else(|e| {
        // Fall back on the old hex encoding generated by `zcashd`. If this fails for any
        // reason, return the error from the modern format parser.
        let mut hash = [0; 32];
        hex::decode_to_slice(seedfp, &mut hash).map_err(|_| e)?;

        // `zcashd` used `uint256` so the canonical hex byte ordering is "reverse".
        hash.reverse();

        Ok(SeedFingerprint::from_bytes(hash))
    })
}

/// Parses the `account` parameter present in many wallet RPCs.
pub(super) async fn parse_account_parameter(
    #[cfg(zallet_build = "wallet")] wallet: &DbConnection,
    #[cfg(zallet_build = "wallet")] keystore: &KeyStore,
    account: &JsonValue,
) -> RpcResult<AccountUuid> {
    match account {
        // This might be a ZIP 32 account index (how zcashd accepted it).
        // Disallowed for merchant terminals (no need to inherit this cruft).
        #[cfg(zallet_build = "wallet")]
        JsonValue::Number(n) => {
            let zip32_account_index = n
                .as_u64()
                .filter(|n| n < &u64::from(ZCASH_LEGACY_ACCOUNT))
                .ok_or_else(|| {
                    LegacyCode::InvalidParameter
                        .with_static("Invalid account number, must be 0 <= account <= (2^31)-2.")
                })?;

            let mut distinct_seeds = HashSet::new();
            let mut account_id = None;

            let legacy_seeds = keystore
                .list_legacy_seed_fingerprints()
                .await
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

            for candidate_account_id in wallet
                .get_account_ids()
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            {
                let account = wallet
                    .get_account(candidate_account_id)
                    .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
                    // This would be a race condition between this and account deletion.
                    .ok_or(RpcErrorCode::InternalError)?;

                // Ignore accounts from imported keys. `zcashd` did not support importing
                // UFVKs as "accounts"; the latter always descended from the single seed.
                if let Some(derivation) = account.source().key_derivation() {
                    let seed_fp = derivation.seed_fingerprint();

                    // Ignore accounts using a legacy non-mnemonic seed. `zcashd` only
                    // ever used this to derive a new Sapling spend authority for each
                    // call to `z_getnewaddress`, and these were never accessible via
                    // JSON-RPCs that took ZIP 32 account indices.
                    if !legacy_seeds.contains(seed_fp) {
                        distinct_seeds.insert(*seed_fp);
                        if u64::from(u32::from(derivation.account_index())) == zip32_account_index {
                            account_id = Some(candidate_account_id);
                        }
                    }
                }
            }

            if distinct_seeds.len() == 1 {
                account_id.ok_or_else(|| {
                    LegacyCode::Wallet.with_message(format!(
                        "Error: account {zip32_account_index} has not been generated by z_getnewaccount."
                    ))
                })
            } else {
                Err(LegacyCode::Wallet.with_static("Account numbers are not supported in wallets with multiple seeds. Use the account UUID instead."))
            }
        }
        // This might be an account UUID.
        JsonValue::String(s) => s
            .parse()
            .map(AccountUuid::from_uuid)
            .map_err(|_| RpcErrorCode::InvalidParams.into()),
        _ => Err(RpcErrorCode::InvalidParams.into()),
    }
}

/// Parses the `diversifier_index` parameter present in many wallet RPCs.
pub(super) fn parse_diversifier_index(diversifier_index: u128) -> RpcResult<DiversifierIndex> {
    diversifier_index
        .try_into()
        .map_err(|_| LegacyCode::InvalidParameter.with_static("diversifier index is too large."))
}

/// Parses the `as_of_height` parameter present in many wallet RPCs.
pub(super) fn parse_as_of_height(as_of_height: Option<i64>) -> RpcResult<Option<BlockHeight>> {
    match as_of_height {
        None | Some(-1) => Ok(None),
        Some(..0) => Err(LegacyCode::InvalidParameter
            .with_static("Can not perform the query as of a negative block height")),
        Some(0) => Err(LegacyCode::InvalidParameter
            .with_static("Can not perform the query as of the genesis block")),
        Some(h) => u32::try_from(h).map_or_else(
            |_| {
                Err(LegacyCode::InvalidParameter
                    .with_static("`as_of_height` parameter out of range"))
            },
            |h| Ok(Some(BlockHeight::from(h))),
        ),
    }
}

/// Parses the `minconf` parameter present in many wallet RPCs.
pub(super) fn parse_minconf(
    minconf: Option<u32>,
    default: u32,
    as_of_height: Option<BlockHeight>,
) -> RpcResult<u32> {
    match minconf {
        None => Ok(default),
        Some(0) if as_of_height.is_some() => Err(LegacyCode::InvalidParameter
            .with_static("Require a minimum of 1 confirmation when `asOfHeight` is provided")),
        Some(d) => Ok(d),
    }
}

/// Equivalent of `AmountFromValue` in `zcashd`, permitting the same input formats.
#[cfg(zallet_build = "wallet")]
pub(super) fn zatoshis_from_value(value: &JsonValue) -> RpcResult<Zatoshis> {
    let amount_str = match value {
        JsonValue::String(s) => Ok(s.as_str()),
        JsonValue::Number(n) => Ok(n.as_str()),
        _ => Err(LegacyCode::Type.with_static("Amount is not a number or string")),
    }?;

    let amount = parse_fixed_point(amount_str, 8)
        .ok_or_else(|| LegacyCode::Type.with_static("Invalid amount"))?;

    Zatoshis::from_nonnegative_i64(amount).map_err(|e| match e {
        BalanceError::Underflow => {
            LegacyCode::InvalidParameter.with_static("Invalid parameter, amount must be positive")
        }
        BalanceError::Overflow => LegacyCode::Type.with_static("Amount out of range"),
    })
}

pub(super) fn value_from_zatoshis(value: Zatoshis) -> JsonZec {
    JsonZec(value_from_zat_balance(value.into()).0)
}

/// Equivalent of `ValueFromAmount` in `zcashd`
pub(super) fn value_from_zat_balance(value: ZatBalance) -> JsonZecBalance {
    JsonZecBalance(
        (Decimal::from(i64::from(value)) / Decimal::from(COIN))
            // Matches the truncated-remainder rounding that `zcashd` used.
            .trunc_with_scale(8),
    )
}

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub(super) struct JsonZec(Decimal);

impl fmt::Display for JsonZec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl JsonSchema for JsonZec {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ZEC".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        json_schema!({
            "type": "number",
            "minimum": 0,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub(super) struct JsonZecBalance(Decimal);

impl fmt::Display for JsonZecBalance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl JsonSchema for JsonZecBalance {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ZECBalance".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        json_schema!({
            "type": "number",
        })
    }
}

/// Upper bound for mantissa.
///
/// 10^18-1 is the largest arbitrary decimal that will fit in a signed 64-bit integer.
/// Larger integers cannot consist of arbitrary combinations of 0-9:
///
/// ```text
///   999999999999999999  (10^18)-1
///  9223372036854775807  (1<<63)-1  (max int64_t)
///  9999999999999999999  (10^19)-1  (would overflow)
/// ```
#[cfg(zallet_build = "wallet")]
const UPPER_BOUND: i64 = 1000000000000000000 - 1;

/// Helper function for [`parse_fixed_point`].
#[cfg(zallet_build = "wallet")]
fn process_mantissa_digit(ch: char, mantissa: &mut i64, mantissa_tzeros: &mut i64) -> bool {
    if ch == '0' {
        *mantissa_tzeros += 1;
    } else {
        for _ in 0..=*mantissa_tzeros {
            if *mantissa > (UPPER_BOUND / 10) {
                return false; // overflow
            }
            *mantissa *= 10;
        }
        *mantissa += i64::from(ch.to_digit(10).expect("caller checked this"));
        *mantissa_tzeros = 0;
    }
    true
}

/// Equivalent to [`ParseFixedPoint`] in `zcashd`. Bleh.
///
/// [`ParseFixedPoint`]: https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/util/strencodings.cpp#L418
#[cfg(zallet_build = "wallet")]
fn parse_fixed_point(mut val: &str, decimals: i64) -> Option<i64> {
    let mut mantissa = 0i64;
    let mut exponent = 0i64;
    let mut mantissa_tzeros = 0i64;
    let mut exponent_sign = false;
    let mut point_ofs = 0;

    let mantissa_sign = match val.split_at_checked(1) {
        Some(("-", rest)) => {
            val = rest;
            true
        }
        _ => false,
    };
    match val.split_at_checked(1) {
        Some(("0", rest)) => val = rest, // pass single 0
        Some(("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9", _)) => {
            let mut chars = val.char_indices();
            loop {
                match chars.next() {
                    Some((_, ch)) if ch.is_ascii_digit() => {
                        if !process_mantissa_digit(ch, &mut mantissa, &mut mantissa_tzeros) {
                            return None; // overflow
                        }
                    }
                    Some((i, _)) => {
                        val = val.split_at(i).1;
                        break;
                    }
                    None => {
                        val = "";
                        break;
                    }
                }
            }
        }
        Some(_) => return None, // missing expected digit
        None => return None,    // empty string or loose '-'
    }
    if let Some((".", rest)) = val.split_at_checked(1) {
        val = rest;
        match val.split_at_checked(1) {
            Some(("0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9", _)) => {
                let mut chars = val.char_indices();
                loop {
                    match chars.next() {
                        Some((_, ch)) if ch.is_ascii_digit() => {
                            if !process_mantissa_digit(ch, &mut mantissa, &mut mantissa_tzeros) {
                                return None; // overflow
                            }
                            point_ofs += 1;
                        }
                        Some((i, _)) => {
                            val = val.split_at(i).1;
                            break;
                        }
                        None => {
                            val = "";
                            break;
                        }
                    }
                }
            }
            _ => return None, // missing expected digit
        }
    }
    if let Some(("e" | "E", rest)) = val.split_at_checked(1) {
        val = rest;
        match val.split_at_checked(1) {
            Some(("+", rest)) => val = rest,
            Some(("-", rest)) => {
                exponent_sign = true;
                val = rest;
            }
            _ => (),
        }
        match val.split_at_checked(1) {
            Some(("0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9", _)) => {
                let mut chars = val.char_indices();
                loop {
                    match chars.next() {
                        Some((_, ch)) if ch.is_ascii_digit() => {
                            if exponent > (UPPER_BOUND / 10) {
                                return None; // overflow
                            }
                            exponent = exponent * 10 + i64::from(ch.to_digit(10).expect("checked"));
                        }
                        Some((i, _)) => {
                            val = val.split_at(i).1;
                            break;
                        }
                        None => {
                            val = "";
                            break;
                        }
                    }
                }
            }
            _ => return None, // missing expected digit
        }
    }
    if !val.is_empty() {
        return None; // trailing garbage
    }

    // finalize exponent
    if exponent_sign {
        exponent = -exponent;
    }
    exponent = exponent - point_ofs + mantissa_tzeros;

    // finalize mantissa
    if mantissa_sign {
        mantissa = -mantissa;
    }

    // convert to one 64-bit fixed-point value
    exponent += decimals;
    if exponent < 0 {
        return None; // cannot represent values smaller than 10^-decimals
    }
    if exponent >= 18 {
        return None; // cannot represent values larger than or equal to 10^(18-decimals)
    }

    for _ in 0..exponent {
        if !(-(UPPER_BOUND / 10)..=(UPPER_BOUND / 10)).contains(&mantissa) {
            return None; // overflow
        }
        mantissa *= 10;
    }
    if !(-UPPER_BOUND..=UPPER_BOUND).contains(&mantissa) {
        return None; // overflow
    }

    Some(mantissa)
}

/// Formats an integer number of zatoshis as a decimal ZEC string (8 fractional digits).
///
/// The formatting inverse of [`zatoshis_from_value`], for constructing amount fixtures in
/// tests.
#[cfg(test)]
pub(crate) fn zec_str(zatoshis: u64) -> String {
    format!("{}.{:08}", zatoshis / 100_000_000, zatoshis % 100_000_000)
}

#[cfg(test)]
mod tests {
    use zcash_protocol::value::{COIN, ZatBalance};

    use crate::components::json_rpc::utils::value_from_zat_balance;

    #[cfg(zallet_build = "wallet")]
    use {
        super::{parse_fixed_point, zatoshis_from_value},
        crate::components::json_rpc::utils::parse_seedfp_parameter,
        zcash_protocol::value::Zatoshis,
        zip32::fingerprint::SeedFingerprint,
    };

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn seed_fingerprint_roundtrip() {
        let seedfp = SeedFingerprint::from_seed(&[0; 32]).unwrap();

        assert_eq!(parse_seedfp_parameter(&seedfp.to_string()), Ok(seedfp),);
    }

    #[test]
    fn rpc_format_monetary_values() {
        let format = |v| value_from_zat_balance(ZatBalance::const_from_i64(v)).to_string();
        let coin = i64::try_from(COIN).expect("fits");

        assert_eq!(format(0), "0.00000000");
        assert_eq!(format(1), "0.00000001");
        assert_eq!(format(17622195), "0.17622195");
        assert_eq!(format(50000000), "0.50000000");
        assert_eq!(format(89898989), "0.89898989");
        assert_eq!(format(100000000), "1.00000000");
        assert_eq!(format(2099999999999990), "20999999.99999990");
        assert_eq!(format(2099999999999999), "20999999.99999999");

        assert_eq!(format((coin / 10000) * 123456789), "12345.67890000");
        assert_eq!(format(-coin), "-1.00000000");
        assert_eq!(format(-coin / 10), "-0.10000000");

        // We can't test this `zcashd` case because it exceeds `MAX_MONEY`, but we won't
        // ever encounter it for `value_from_zat_balance`.
        //assert_eq!(format(coin * 100000000), "100000000.00000000");
        assert_eq!(format(coin * 10000000), "10000000.00000000");
        assert_eq!(format(coin * 1000000), "1000000.00000000");
        assert_eq!(format(coin * 100000), "100000.00000000");
        assert_eq!(format(coin * 10000), "10000.00000000");
        assert_eq!(format(coin * 1000), "1000.00000000");
        assert_eq!(format(coin * 100), "100.00000000");
        assert_eq!(format(coin * 10), "10.00000000");
        assert_eq!(format(coin), "1.00000000");
        assert_eq!(format(coin / 10), "0.10000000");
        assert_eq!(format(coin / 100), "0.01000000");
        assert_eq!(format(coin / 1000), "0.00100000");
        assert_eq!(format(coin / 10000), "0.00010000");
        assert_eq!(format(coin / 100000), "0.00001000");
        assert_eq!(format(coin / 1000000), "0.00000100");
        assert_eq!(format(coin / 10000000), "0.00000010");
        assert_eq!(format(coin / 100000000), "0.00000001");
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn rpc_parse_monetary_values() {
        let zat = |v| Ok(Zatoshis::const_from_u64(v));

        assert!(zatoshis_from_value(&"-0.00000001".into()).is_err());
        assert_eq!(zatoshis_from_value(&"0".into()), zat(0));
        assert_eq!(zatoshis_from_value(&"0.00000000".into()), zat(0));
        assert_eq!(zatoshis_from_value(&"0.00000001".into()), zat(1));
        assert_eq!(zatoshis_from_value(&"0.17622195".into()), zat(17622195));
        assert_eq!(zatoshis_from_value(&"0.5".into()), zat(50000000));
        assert_eq!(zatoshis_from_value(&"0.50000000".into()), zat(50000000));
        assert_eq!(zatoshis_from_value(&"0.89898989".into()), zat(89898989));
        assert_eq!(zatoshis_from_value(&"1.00000000".into()), zat(100000000));
        assert_eq!(
            zatoshis_from_value(&"20999999.9999999".into()),
            zat(2099999999999990)
        );
        assert_eq!(
            zatoshis_from_value(&"20999999.99999999".into()),
            zat(2099999999999999)
        );

        assert_eq!(zatoshis_from_value(&"1e-8".into()), zat(COIN / 100000000));
        assert_eq!(zatoshis_from_value(&"0.1e-7".into()), zat(COIN / 100000000));
        assert_eq!(
            zatoshis_from_value(&"0.01e-6".into()),
            zat(COIN / 100000000)
        );
        assert_eq!(
            zatoshis_from_value(&
                "0.0000000000000000000000000000000000000000000000000000000000000000000000000001e+68"
            .into()),
            zat(COIN / 100000000)
        );
        assert_eq!(
            zatoshis_from_value(
                &"10000000000000000000000000000000000000000000000000000000000000000e-64".into()
            ),
            zat(COIN)
        );
        assert_eq!(
            zatoshis_from_value(&
                "0.000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000e64"
                .into()),
            zat(COIN)
        );

        assert!(zatoshis_from_value(&"1e-9".into()).is_err()); //should fail
        assert!(zatoshis_from_value(&"0.000000019".into()).is_err()); //should fail
        assert_eq!(zatoshis_from_value(&"0.00000001000000".into()), zat(1)); //should pass, cut trailing 0
        assert!(zatoshis_from_value(&"19e-9".into()).is_err()); //should fail
        assert_eq!(zatoshis_from_value(&"0.19e-6".into()), zat(19)); //should pass, leading 0 is present

        assert!(zatoshis_from_value(&"92233720368.54775808".into()).is_err()); //overflow error
        assert!(zatoshis_from_value(&"1e+11".into()).is_err()); //overflow error
        assert!(zatoshis_from_value(&"1e11".into()).is_err()); //overflow error signless
        assert!(zatoshis_from_value(&"93e+9".into()).is_err()); //overflow error
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn test_parse_fixed_point() {
        assert_eq!(parse_fixed_point("0", 8), Some(0));
        assert_eq!(parse_fixed_point("1", 8), Some(100000000));
        assert_eq!(parse_fixed_point("0.0", 8), Some(0));
        assert_eq!(parse_fixed_point("-0.1", 8), Some(-10000000));
        assert_eq!(parse_fixed_point("1.1", 8), Some(110000000));
        assert_eq!(parse_fixed_point("1.10000000000000000", 8), Some(110000000));
        assert_eq!(parse_fixed_point("1.1e1", 8), Some(1100000000));
        assert_eq!(parse_fixed_point("1.1e-1", 8), Some(11000000));
        assert_eq!(parse_fixed_point("1000", 8), Some(100000000000));
        assert_eq!(parse_fixed_point("-1000", 8), Some(-100000000000));
        assert_eq!(parse_fixed_point("0.00000001", 8), Some(1));
        assert_eq!(parse_fixed_point("0.0000000100000000", 8), Some(1));
        assert_eq!(parse_fixed_point("-0.00000001", 8), Some(-1));
        assert_eq!(
            parse_fixed_point("1000000000.00000001", 8),
            Some(100000000000000001)
        );
        assert_eq!(
            parse_fixed_point("9999999999.99999999", 8),
            Some(999999999999999999)
        );
        assert_eq!(
            parse_fixed_point("-9999999999.99999999", 8),
            Some(-999999999999999999)
        );

        assert_eq!(parse_fixed_point("", 8), None);
        assert_eq!(parse_fixed_point("-", 8), None);
        assert_eq!(parse_fixed_point("a-1000", 8), None);
        assert_eq!(parse_fixed_point("-a1000", 8), None);
        assert_eq!(parse_fixed_point("-1000a", 8), None);
        assert_eq!(parse_fixed_point("-01000", 8), None);
        assert_eq!(parse_fixed_point("00.1", 8), None);
        assert_eq!(parse_fixed_point(".1", 8), None);
        assert_eq!(parse_fixed_point("--0.1", 8), None);
        assert_eq!(parse_fixed_point("0.000000001", 8), None);
        assert_eq!(parse_fixed_point("-0.000000001", 8), None);
        assert_eq!(parse_fixed_point("0.00000001000000001", 8), None);
        assert_eq!(parse_fixed_point("-10000000000.00000000", 8), None);
        assert_eq!(parse_fixed_point("10000000000.00000000", 8), None);
        assert_eq!(parse_fixed_point("-10000000000.00000001", 8), None);
        assert_eq!(parse_fixed_point("10000000000.00000001", 8), None);
        assert_eq!(parse_fixed_point("-10000000000.00000009", 8), None);
        assert_eq!(parse_fixed_point("10000000000.00000009", 8), None);
        assert_eq!(parse_fixed_point("-99999999999.99999999", 8), None);
        assert_eq!(parse_fixed_point("99999909999.09999999", 8), None);
        assert_eq!(parse_fixed_point("92233720368.54775807", 8), None);
        assert_eq!(parse_fixed_point("92233720368.54775808", 8), None);
        assert_eq!(parse_fixed_point("-92233720368.54775808", 8), None);
        assert_eq!(parse_fixed_point("-92233720368.54775809", 8), None);
        assert_eq!(parse_fixed_point("1.1e", 8), None);
        assert_eq!(parse_fixed_point("1.1e-", 8), None);
        assert_eq!(parse_fixed_point("1.", 8), None);
    }
}
