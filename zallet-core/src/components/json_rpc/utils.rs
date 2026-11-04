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
use crate::components::database::{Database, DbHandle};

#[cfg(zallet_build = "wallet")]
use {
    crate::components::{chain::ChainView, keystore::KeyStore},
    std::collections::HashSet,
    zcash_client_backend::data_api::{Account, AccountBirthday, WalletRead, chain::ChainState},
    zcash_primitives::block::BlockHash,
    zcash_protocol::value::BalanceError,
    zip32::fingerprint::SeedFingerprint,
};

#[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
use {
    crate::components::database::DbConnection,
    crate::error::ErrorKind,
    std::collections::HashMap,
    transparent::address::TransparentAddress,
    zcash_client_backend::{
        fees::StandardFeeRule, proposal::Proposal, wallet::TransparentAddressSource,
    },
    zcash_script::{script, solver, solver::ScriptKind},
};

/// The account identifier used for HD derivation of transparent and Sapling addresses via
/// the legacy `getnewaddress` and `z_getnewaddress` code paths.
#[cfg(zallet_build = "wallet")]
pub(super) const ZCASH_LEGACY_ACCOUNT: u32 = 0x7fff_ffff;

/// Acquires a wallet database connection, mapping a pool failure to the internal-error
/// RPC code.
///
/// The deadlock-avoidance rule on [`Database::handle`] applies: do not call this (or any
/// keystore method that touches key material) while already holding a [`DbHandle`].
pub(super) async fn wallet_handle(wallet: &Database) -> RpcResult<DbHandle> {
    wallet
        .handle()
        .await
        .map_err(|_| RpcErrorCode::InternalError.into())
}

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

/// Returns an error if new spend authority must not be derived from the given seed
/// because the operator has not confirmed that they hold its mnemonic phrase.
///
/// A phrase Zallet generated exists nowhere but this wallet until the operator records it
/// somewhere durable, so funds sent to addresses derived from it before then are lost with
/// the wallet. `keystore.require_backup` governs whether that is refused or merely true.
#[cfg(zallet_build = "wallet")]
pub(super) async fn ensure_seed_is_backed_up(
    keystore: &KeyStore,
    seed_fp: &SeedFingerprint,
) -> RpcResult<()> {
    let required = keystore
        .backup_required(seed_fp)
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    if required {
        Err(LegacyCode::WalletBackupRequired.with_static(
            "Error: Please acknowledge that you have backed up the wallet's emergency recovery phrase \
             by using the zallet confirm-backup command first.",
        ))
    } else {
        Ok(())
    }
}

/// Maps standalone transparent receivers in this account to their member public keys.
///
/// This is the database half of collecting the standalone (non-HD) transparent spending
/// keys needed to sign a proposal's transparent inputs; run it while a wallet connection
/// is held, then release that connection and pass the result to
/// [`decrypt_standalone_transparent_keys`] (which acquires its own connection via the
/// keystore, and so must not run while the caller still holds one; see
/// [`Database::handle`]).
///
/// Gated on `zcashd-import` because its only callers (`z_send_many` and
/// `z_shieldcoinbase`) sign for standalone keys under that feature, and on the
/// `wallet` build because those callers are wallet-only and the
/// `DbConnection`/`KeyStore` types it uses are only imported in that build.
#[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
pub(super) fn standalone_transparent_receivers(
    wallet: &DbConnection,
    account_id: AccountUuid,
) -> RpcResult<HashMap<TransparentAddress, Vec<secp256k1::PublicKey>>> {
    Ok(wallet
        .get_transparent_receivers(account_id, true, true)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .into_iter()
        .filter_map(|(addr, metadata)| {
            standalone_address_pubkeys(metadata.source()).map(|pubkeys| (addr, pubkeys))
        })
        .collect())
}

/// Decrypts the standalone transparent spending keys required to sign the transparent
/// inputs of `proposal`.
///
/// `standalone_pubkeys` is the output of [`standalone_transparent_receivers`]: a P2PKH
/// import supplies its own public key, and a P2SH import supplies its multisig members.
/// Keys the keystore does not hold are omitted; whether the available keys reach the
/// signature threshold is determined when the proposal is signed. HD-derived receivers
/// are signed for using the account's unified spending key and are absent from the result.
#[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
pub(super) async fn decrypt_standalone_transparent_keys<NoteRef>(
    keystore: &KeyStore,
    standalone_pubkeys: &HashMap<TransparentAddress, Vec<secp256k1::PublicKey>>,
    proposal: &Proposal<StandardFeeRule, NoteRef>,
) -> RpcResult<HashMap<TransparentAddress, Vec<secp256k1::SecretKey>>> {
    let mut keys: HashMap<TransparentAddress, Vec<secp256k1::SecretKey>> = HashMap::new();
    for step in proposal.steps() {
        for input in step.transparent_inputs() {
            let Some(address) = script::FromChain::parse(&input.txout().script_pubkey().0)
                .ok()
                .as_ref()
                .and_then(TransparentAddress::from_script_from_chain)
            else {
                continue;
            };

            // Look each address up once, no matter how many inputs it contributes.
            if keys.contains_key(&address) {
                continue;
            }

            if let Some(pubkeys) = standalone_pubkeys.get(&address) {
                let secret_keys = keystore
                    .decrypt_standalone_transparent_keys(pubkeys)
                    .await
                    .map_err(|e| match e.kind() {
                        // TODO: Improve internal error types.
                        ErrorKind::Generic if e.to_string() == "Wallet is locked" => {
                            LegacyCode::WalletUnlockNeeded.with_message(e.to_string())
                        }
                        _ => LegacyCode::Database.with_message(e.to_string()),
                    })?;
                keys.insert(address, secret_keys);
            }
        }
    }
    Ok(keys)
}

/// Returns the public keys whose keystore entries can spend from an address with the given
/// source, or `None` if the source carries no standalone key material.
#[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
fn standalone_address_pubkeys(
    source: &TransparentAddressSource,
) -> Option<Vec<secp256k1::PublicKey>> {
    match source {
        TransparentAddressSource::StandalonePubkey(pubkey) => Some(vec![*pubkey]),
        TransparentAddressSource::StandaloneScript(redeem) => Some(multisig_pubkeys(redeem)),
        // No key material exists for an address-only import, so there is no standalone key
        // to collect; spends from it are rejected upstream.
        TransparentAddressSource::StandaloneAddress => None,
        TransparentAddressSource::Derived { .. } => None,
    }
}

/// Returns the member public keys of a multisig redeem script, or an empty list if the
/// script is not multisig.
#[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
fn multisig_pubkeys(redeem: &script::Redeem) -> Vec<secp256k1::PublicKey> {
    match solver::standard(redeem) {
        Some(ScriptKind::MultiSig { pubkeys, .. }) => pubkeys
            .iter()
            .filter_map(|pubkey| secp256k1::PublicKey::from_slice(pubkey.as_slice()).ok())
            .collect(),
        _ => Vec::new(),
    }
}

/// Builds an [`AccountBirthday`] by fetching the treestate at the given height.
///
/// For height 0 (genesis), returns a birthday with an empty chain state since the
/// commitment trees are empty. For non-zero heights, fetches the real treestate from
/// the chain indexer so the sync engine can validate note commitment tree continuity.
///
/// `recover_until`, when provided, tells the sync engine to scan forward from the
/// birthday until (and including) that height before switching to steady-state mode.
#[cfg(zallet_build = "wallet")]
pub(super) async fn fetch_account_birthday<V: ChainView>(
    chain_view: &V,
    height: BlockHeight,
    recover_until: Option<BlockHeight>,
) -> RpcResult<AccountBirthday> {
    if height == BlockHeight::from_u32(0) {
        // The chain state is the state of the note commitment trees *as of the block
        // preceding* the birthday. There is no block before genesis, and the conventional
        // hash of genesis's (nonexistent) parent is all-zeros, so an empty chain state with
        // a zero block hash is the correct anchor here. (Using the real genesis block hash
        // would be wrong: that is the hash of block 0 itself, not of the block before it.)
        return Ok(AccountBirthday::from_parts(
            ChainState::empty(BlockHeight::from_u32(0), BlockHash([0; 32])),
            recover_until,
        ));
    }

    // The chain state anchoring the birthday is the note commitment tree state as of the
    // block *preceding* the birthday height.
    let treestate_height = height.saturating_sub(1);
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

    Ok(AccountBirthday::from_parts(chain_state, recover_until))
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
///
/// Takes the database rather than a connection, acquiring one itself only for the
/// numeric (ZIP 32 account index) form: callers must not already hold a [`DbHandle`],
/// per the deadlock-avoidance rule on [`Database::handle`].
pub(super) async fn parse_account_parameter(
    #[cfg(zallet_build = "wallet")] wallet: &Database,
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

            // Query the keystore before acquiring a wallet connection: the keystore
            // takes its own connection from the same pool.
            let legacy_seeds = keystore
                .list_legacy_seed_fingerprints()
                .await
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

            let wallet = wallet_handle(wallet).await?;

            for candidate_account_id in wallet
                .as_ref()
                .get_account_ids()
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            {
                let account = wallet
                    .as_ref()
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
        super::{ensure_seed_is_backed_up, parse_fixed_point, zatoshis_from_value},
        crate::components::{
            json_rpc::{server::LegacyCode, utils::parse_seedfp_parameter},
            keystore::{
                BackupStatus,
                testing::{keystore_with_config, phrase, run_async},
            },
        },
        tempfile::tempdir,
        zcash_protocol::value::Zatoshis,
        zip32::fingerprint::SeedFingerprint,
    };

    /// The gate must report exactly `zcashd`'s `RPC_WALLET_BACKUP_REQUIRED`, since
    /// integrators inherited that code from `zcashd`.
    #[cfg(zallet_build = "wallet")]
    #[test]
    fn unconfirmed_backup_is_refused_with_the_legacy_error_code() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = keystore_with_config(&datadir, |config| {
                config.keystore.require_backup = Some(true);
            })
            .await;

            let seed_fp = keystore
                .encrypt_and_store_mnemonic(phrase([1; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();

            let err = ensure_seed_is_backed_up(&keystore, &seed_fp)
                .await
                .expect_err("an unconfirmed seed must be refused");
            assert_eq!(err.code(), LegacyCode::WalletBackupRequired as i32);

            keystore.confirm_backup(&seed_fp).await.unwrap();
            ensure_seed_is_backed_up(&keystore, &seed_fp)
                .await
                .expect("a confirmed seed must be permitted");
        });
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn the_gate_is_bypassed_when_require_backup_is_off() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = keystore_with_config(&datadir, |config| {
                config.keystore.require_backup = Some(false);
            })
            .await;

            let seed_fp = keystore
                .encrypt_and_store_mnemonic(phrase([2; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();

            ensure_seed_is_backed_up(&keystore, &seed_fp)
                .await
                .expect("require_backup = false must permit an unconfirmed seed");
        });
    }

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

    /// A standalone P2PKH import supplies its own public key, and a P2SH import supplies
    /// the members of its multisig redeem script. A source without key material supplies
    /// none.
    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    #[test]
    fn standalone_address_pubkeys_covers_every_key_source() {
        use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
        use zcash_client_backend::wallet::TransparentAddressSource;
        use zcash_script::{Opcode, pattern::check_multisig, pv, script::Component};

        use super::standalone_address_pubkeys;

        let key = |seed: u8| {
            secp256k1::SecretKey::from_secret_bytes([seed; 32])
                .expect("a non-zero seed is a valid secret key")
                .public_key()
        };
        let members = [key(1), key(2), key(3)];

        // A P2PKH import carries its own public key.
        assert_eq!(
            standalone_address_pubkeys(&TransparentAddressSource::StandalonePubkey(members[0])),
            Some(vec![members[0]]),
        );

        // A P2SH import carries the members of its redeem script.
        let serialized = members.map(|pk| pk.serialize());
        assert_eq!(
            standalone_address_pubkeys(&TransparentAddressSource::StandaloneScript(Component(
                check_multisig(2, &serialized.each_ref().map(|pk| &pk[..]), false).unwrap()
            ),)),
            Some(members.to_vec()),
        );

        // A redeem script that is not multisig has no member keys to look up.
        assert_eq!(
            standalone_address_pubkeys(&TransparentAddressSource::StandaloneScript(Component(
                vec![Opcode::PushValue(pv::_1)],
            ))),
            Some(vec![]),
        );

        // Address-only imports and HD-derived addresses have no standalone key material.
        assert_eq!(
            standalone_address_pubkeys(&TransparentAddressSource::StandaloneAddress),
            None,
        );
        assert_eq!(
            standalone_address_pubkeys(&TransparentAddressSource::Derived {
                scope: TransparentKeyScope::EXTERNAL,
                address_index: NonHardenedChildIndex::from_index(0)
                    .expect("zero is a valid non-hardened index"),
            }),
            None,
        );
    }

    /// Fifteen compressed public keys fit within the 520-byte P2SH redeem-script limit.
    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    const MAX_COMPRESSED_P2SH_MEMBERS: usize = 15;

    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    proptest::proptest! {
        #[test]
        fn multisig_members_preserve_order_and_normalize_encoding(
            seeds in proptest::collection::vec(
                proptest::prelude::any::<[u8; 32]>(), 1..=MAX_COMPRESSED_P2SH_MEMBERS,
            ),
            uncompressed in proptest::prelude::any::<bool>(),
        ) {
            use zcash_script::{pattern::check_multisig, script::Component};

            let secrets = seeds.into_iter().map(secp256k1::SecretKey::from_secret_bytes)
                .collect::<Result<Vec<_>, _>>();
            proptest::prop_assume!(secrets.is_ok());
            let pubkeys = secrets.unwrap().into_iter().map(|sk| sk.public_key()).collect::<Vec<_>>();
            let encoded = pubkeys.iter().map(|pk| if uncompressed {
                pk.serialize_uncompressed().to_vec()
            } else {
                pk.serialize().to_vec()
            }).collect::<Vec<_>>();
            let script = Component(check_multisig(
                1, &encoded.iter().map(Vec::as_slice).collect::<Vec<_>>(), false,
            ).unwrap());
            proptest::prop_assert_eq!(super::multisig_pubkeys(&script), pubkeys);
        }
    }

    /// Synthetic proposal inputs exercise key collection without chain state or proving.
    #[cfg(all(zallet_build = "wallet", feature = "zcashd-import"))]
    #[test]
    fn standalone_proposal_keys_are_complete_and_not_duplicated_per_input() {
        use std::{collections::BTreeMap, num::NonZeroUsize};
        use transparent::{
            address::TransparentAddress,
            builder::{SpendInfo, TransparentBuilder, TransparentInputInfo, TransparentSigningSet},
            bundle::{OutPoint, TxOut},
        };
        use zcash_client_backend::{
            data_api::{
                AccountBirthday, WalletRead, WalletWrite,
                chain::ChainState,
                wallet::{ConfirmationsPolicy, TargetHeight},
            },
            fees::{StandardFeeRule, TransactionBalance},
            proposal::Proposal,
            wallet::WalletTransparentOutput,
            zip321::TransactionRequest,
        };
        use zcash_keys::keys::transparent::Key;
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::consensus::BlockHeight;
        use zcash_script::{
            pattern::{check_multisig, pay_to_script_hash},
            script::Component,
        };

        use super::{decrypt_standalone_transparent_keys, standalone_transparent_receivers};
        use crate::components::keystore::testing::keystore_and_database_with_config;

        let datadir = tempdir().unwrap();
        run_async(|| async {
            let (keystore, database) =
                keystore_and_database_with_config(&datadir, Some(NonZeroUsize::MIN), |_| {}).await;
            let secrets = [1, 2, 3].map(|byte| {
                secp256k1::SecretKey::from_secret_bytes([byte; 32]).expect("valid secret key")
            });
            for secret in &secrets[..2] {
                keystore
                    .encrypt_and_store_standalone_transparent_key(&Key::new(*secret, true))
                    .await
                    .unwrap();
            }
            let pubkeys = secrets.map(|sk| sk.public_key());
            let serialized = pubkeys.map(|pk| pk.serialize());
            let redeem = Component(
                check_multisig(2, &serialized.each_ref().map(|pk| &pk[..]), false).unwrap(),
            );
            let p2sh =
                TransparentAddress::from_script_pubkey(&Component(pay_to_script_hash(&redeem)))
                    .unwrap();
            let p2pkh = TransparentAddress::from_pubkey(&pubkeys[0]);
            let birthday = AccountBirthday::from_parts(
                ChainState::empty(BlockHeight::from_u32(0), BlockHash([0; 32])),
                None,
            );
            let (account, standalone) = {
                let mut wallet = database.handle().await.unwrap();
                let (account, _) = wallet
                    .create_account(
                        "test",
                        &secrecy::SecretVec::new(vec![0; 32]),
                        &birthday,
                        None,
                    )
                    .unwrap();
                wallet
                    .import_standalone_transparent_script(account, redeem.clone())
                    .unwrap();
                wallet
                    .import_standalone_transparent_pubkey(account, pubkeys[0])
                    .unwrap();
                (
                    account,
                    standalone_transparent_receivers(wallet.as_ref(), account).unwrap(),
                )
            };
            let derived = database
                .handle()
                .await
                .unwrap()
                .get_transparent_receivers(account, true, true)
                .unwrap()
                .into_iter()
                .find_map(|(address, metadata)| metadata.source().scope().map(|_| address))
                .expect("the account has an HD receiver");
            let addresses = [p2sh, p2sh, p2pkh, derived];
            let inputs: Vec<_> = addresses
                .into_iter()
                .enumerate()
                .map(|(index, address)| {
                    WalletTransparentOutput::from_parts(
                        OutPoint::new([0; 32], u32::try_from(index).unwrap()),
                        TxOut::new(Zatoshis::const_from_u64(COIN), address.script().into()),
                        None,
                        Some(()),
                        None,
                        None,
                    )
                    .unwrap()
                })
                .collect();
            let proposal: Proposal<_, ()> = Proposal::single_step(
                TransactionRequest::empty(),
                BTreeMap::new(),
                inputs,
                None,
                BlockHeight::from_u32(0),
                TransactionBalance::new(
                    vec![],
                    Zatoshis::from_u64(COIN * addresses.len() as u64).unwrap(),
                )
                .unwrap(),
                StandardFeeRule::Zip317,
                TargetHeight::from(BlockHeight::from_u32(1)),
                ConfirmationsPolicy::default(),
                false,
                false,
            )
            .unwrap();
            let keys = decrypt_standalone_transparent_keys(&keystore, &standalone, &proposal)
                .await
                .unwrap();
            assert_eq!(
                keys,
                std::collections::HashMap::from([
                    (p2sh, secrets[..2].to_vec()),
                    (p2pkh, vec![secrets[0]]),
                ])
            );

            // The collected two keys meet this 2-of-3 threshold; one key does not.
            let mut builder = TransparentBuilder::empty();
            for input in &proposal.steps().head.transparent_inputs()[..2] {
                builder.add_input(
                    TransparentInputInfo::from_parts(
                        input.outpoint().clone(),
                        input.txout().clone(),
                        SpendInfo::P2sh {
                            redeem_script: redeem.weaken(),
                        },
                    )
                    .unwrap(),
                );
            }
            let bundle = builder.build().unwrap();
            let mut signing_set = TransparentSigningSet::new();
            signing_set.add_key(keys[&p2sh][0]);
            assert_eq!(
                bundle
                    .clone()
                    .apply_signatures(|_| [0; 32], &signing_set)
                    .unwrap_err(),
                transparent::builder::Error::MissingSigningKey
            );
            signing_set.add_key(keys[&p2sh][1]);
            bundle.apply_signatures(|_| [0; 32], &signing_set).unwrap();
        });
    }
}
