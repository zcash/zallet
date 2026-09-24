//! `z_getmultisigaccountinfo` — describe the account a set of cosigner keys defines.
//!
//! The inverse of [`z_getmultisigkeyinfo`]: that method exports this wallet's own
//! cosigner key, and this one takes the collected set back and reports what it
//! describes. Nothing is recorded — this is the verification step, not registration.
//!
//! ZIP 48 requires that cosigners confirm they built the same account before any of
//! them uses it to receive, because every address depends on every key and a single
//! substituted one silently redirects funds. Comparing key material by eye does not
//! scale past a couple of participants; comparing a derived address does. Both values
//! reported here are independent of the order the keys are given in, so cosigners who
//! collected the same set in different orders still agree.
//!
//! [`z_getmultisigkeyinfo`]: super::z_get_multisig_key_info

use std::num::NonZeroU8;

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::Serialize;
use transparent::{keys::NonHardenedChildIndex, zip48};
use zcash_client_backend::encoding::AddressCodec;
use zcash_protocol::consensus::Parameters;

use crate::components::{
    database::DbConnection,
    json_rpc::{server::LegacyCode, utils::ensure_wallet_is_unlocked},
    keystore::KeyStore,
};

/// Response to a `z_getmultisigaccountinfo` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// What a set of ZIP 48 cosigner keys describes.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// The BIP 388 wallet descriptor template for the account, e.g.
    /// `sh(sortedmulti(2,@0/**,@1/**,@2/**))`.
    ///
    /// The placeholders stand for the cosigner keys rather than naming them, so this
    /// states the account's shape — threshold and participant count — and nothing
    /// about which keys fill it.
    descriptor_template: String,

    /// The number of cosigners that must sign to spend.
    threshold: u8,

    /// The number of cosigners the account has.
    cosigners: usize,

    /// The first address the account derives, as every cosigner should also derive it.
    ///
    /// This is the value to compare out of band. It depends on all of the keys, so
    /// agreement here is evidence that the collected sets match; disagreement means at
    /// least one key differs, and the account must not be used until that is resolved.
    first_address: String,

    /// Which cosigner this wallet is, as an index into the submitted key set, or `null`
    /// if none of this wallet's seeds derives any key in it.
    ///
    /// `null` is not necessarily an error — a watch-only participant is a legitimate
    /// use — but it does mean this wallet cannot contribute a signature, so it is worth
    /// checking when you expected to be a cosigner.
    our_index: Option<usize>,
}

pub(super) const PARAM_KEY_INFO_DESC: &str = "The BIP 388 `KEY_INFO` expressions of every cosigner, including this wallet's own, \
     as returned by `z_getmultisigkeyinfo`.";
pub(super) const PARAM_KEY_INFO_REQUIRED: bool = true;

pub(super) const PARAM_THRESHOLD_DESC: &str = "The number of cosigners that must sign to spend. Must be at least 1 and at most \
     the number of cosigners.";

/// Parses the submitted cosigner keys, preserving the order they were given in.
///
/// Rejects an entry that is not a ZIP 48 `KEY_INFO` expression for this network, naming
/// its position so the caller can tell which one to look at, and rejects a repeated key:
/// `FullViewingKey::standard` accepts one, but an account where a single participant
/// silently occupies two slots is not the m-of-n its threshold advertises.
fn parse_cosigners<P: Parameters>(
    params: &P,
    key_info: &[String],
) -> RpcResult<Vec<zip48::AccountPubKey>> {
    let mut keys = Vec::with_capacity(key_info.len());

    for (i, expression) in key_info.iter().enumerate() {
        let key = zip48::AccountPubKey::parse_key_info_expression(expression, params).ok_or_else(
            || {
                LegacyCode::InvalidParameter.with_message(format!(
                    "Error: cosigner key {i} is not a ZIP 48 KEY_INFO expression for this network",
                ))
            },
        )?;

        if let Some(first) = keys.iter().position(|seen| seen == &key) {
            return Err(LegacyCode::InvalidParameter.with_message(format!(
                "Error: cosigner keys {first} and {i} are the same key; each cosigner must \
                     contribute a distinct key",
            )));
        }

        keys.push(key);
    }

    Ok(keys)
}

/// Builds the ZIP 48 full viewing key for the collected cosigner set.
fn full_viewing_key(
    threshold: u8,
    keys: Vec<zip48::AccountPubKey>,
) -> RpcResult<zip48::FullViewingKey> {
    let threshold = NonZeroU8::new(threshold).ok_or_else(|| {
        LegacyCode::InvalidParameter.with_static("Error: threshold must be at least 1")
    })?;

    zip48::FullViewingKey::standard(threshold, keys).map_err(|e| {
        use zip48::FullViewingKeyError::*;
        match e {
            NoPubKeys => LegacyCode::InvalidParameter
                .with_static("Error: a multisig account needs at least one cosigner key"),
            TooManyPubKeys => LegacyCode::InvalidParameter
                .with_static("Error: a ZIP 48 multisig account may have at most 15 cosigners"),
            InvalidThreshold => LegacyCode::InvalidParameter
                .with_static("Error: threshold exceeds the number of cosigners"),
            IncompatiblePubKeys => LegacyCode::InvalidParameter.with_static(
                "Error: the cosigner keys were not all derived at the same ZIP 48 path; every \
                 cosigner must use the same coin type and account index",
            ),
        }
    })
}

/// Identifies which cosigner `seed` makes this wallet, by index into `keys`.
///
/// `derive_matching_account_priv_key` re-derives a candidate at the ZIP 48 path the key
/// set itself names, and reports whether it matches any member. Recovering the position
/// then takes one more step, because the match is reported as a key rather than an
/// index, and `FullViewingKey` does not expose the set it was built from.
fn cosigner_index_for_seed(
    fvk: &zip48::FullViewingKey,
    keys: &[zip48::AccountPubKey],
    seed: &[u8],
) -> RpcResult<Option<usize>> {
    let matching = fvk.derive_matching_account_priv_key(seed).map_err(|e| {
        LegacyCode::Wallet.with_message(format!("Failed to derive a candidate cosigner key: {e}"))
    })?;

    Ok(matching.and_then(|account_key| {
        let ours = account_key.to_account_pubkey();
        keys.iter().position(|key| key == &ours)
    }))
}

/// Identifies which cosigner this wallet is, by index into `keys`.
///
/// Every seed the wallet holds is tried, because being a cosigner is a property of the
/// wallet rather than of any one seed. Nothing stops one wallet from holding two slots
/// of the same account, so the lowest matching index is reported rather than whichever
/// seed happened to be tried first — `list_seed_fingerprints` returns a set, and its
/// iteration order is not stable. Returns `None` if no seed derives a key in the set.
async fn our_cosigner_index(
    keystore: &KeyStore,
    fvk: &zip48::FullViewingKey,
    keys: &[zip48::AccountPubKey],
) -> RpcResult<Option<usize>> {
    let seed_fps = keystore
        .list_seed_fingerprints()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let mut ours = None;

    for seed_fp in seed_fps {
        let seed = keystore
            .decrypt_seed(&seed_fp)
            .await
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

        if let Some(index) = cosigner_index_for_seed(fvk, keys, seed.expose_secret())? {
            ours = Some(ours.map_or(index, |lowest: usize| lowest.min(index)));
        }
    }

    Ok(ours)
}

/// Everything the response reports that does not depend on the wallet's own seeds.
///
/// `our_index` is left `None` for [`call`] to fill in, because determining it needs the
/// keystore. Keeping the rest here means the order-independence property can be tested
/// against what is actually reported rather than against a reconstruction of it.
///
/// The parsed keys are returned alongside, because the cosigner index is a position in
/// them and `zip48::FullViewingKey` does not expose the vector it was built from.
fn describe<P: Parameters>(
    params: &P,
    key_info: &[String],
    threshold: u8,
) -> RpcResult<(Vec<zip48::AccountPubKey>, zip48::FullViewingKey, ResultType)> {
    let keys = parse_cosigners(params, key_info)?;
    let cosigners = keys.len();
    let fvk = full_viewing_key(threshold, keys.clone())?;

    let (address, _redeem_script) =
        fvk.derive_address(zip32::Scope::External, NonHardenedChildIndex::ZERO);

    let described = ResultType {
        descriptor_template: fvk.wallet_descriptor_template(),
        threshold,
        cosigners,
        first_address: address.encode(params),
        our_index: None,
    };

    Ok((keys, fvk, described))
}

pub(crate) async fn call(
    wallet: &DbConnection,
    keystore: &KeyStore,
    key_info: Vec<String>,
    threshold: u8,
) -> Response {
    ensure_wallet_is_unlocked(keystore).await?;

    let (keys, fvk, mut described) = describe(wallet.params(), &key_info, threshold)?;
    described.our_index = our_cosigner_index(keystore, &fvk, &keys).await?;

    Ok(described)
}

#[cfg(test)]
mod tests {
    use super::super::z_get_multisig_key_info::cosigner_key_info;
    use super::*;
    use zcash_protocol::consensus;

    use crate::network::Network;

    fn mainnet() -> Network {
        Network::Consensus(consensus::Network::MainNetwork)
    }

    fn testnet() -> Network {
        Network::Consensus(consensus::Network::TestNetwork)
    }

    fn account(index: u32) -> zip32::AccountId {
        zip32::AccountId::try_from(index).expect("valid account index")
    }

    /// A cosigner key-info expression, produced by the very code `z_getmultisigkeyinfo`
    /// exports with, so these tests cannot drift from what a cosigner is actually handed.
    fn cosigner<P: Parameters>(params: &P, seed: &[u8; 32], account_index: u32) -> String {
        cosigner_key_info(params, seed, account(account_index)).expect("valid ZIP 48 derivation")
    }

    /// Three cosigners of one account, derived from the distinct seeds 1, 2 and 3.
    fn three_cosigners<P: Parameters>(params: &P) -> Vec<String> {
        [[1; 32], [2; 32], [3; 32]]
            .iter()
            .map(|seed| cosigner(params, seed, 0))
            .collect()
    }

    /// The reported fields that do not depend on the wallet's seeds.
    fn reported<P: Parameters>(params: &P, key_info: &[String], threshold: u8) -> (String, String) {
        let (_, _, described) = describe(params, key_info, threshold).expect("valid cosigner set");

        (described.descriptor_template, described.first_address)
    }

    /// The whole point of the method: cosigners who collected the same keys in different
    /// orders must still agree. `sortedmulti` sorts the derived keys per address, so the
    /// address is order-independent upstream; the template names placeholders rather than
    /// keys, so it is too. This pins both, because a later change to what is reported
    /// could easily reintroduce order dependence without any other test noticing.
    #[test]
    fn order_does_not_change_what_is_reported() {
        let params = mainnet();
        let key_info = three_cosigners(&params);
        let expected = reported(&params, &key_info, 2);

        for permutation in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            let permuted = permutation
                .iter()
                .map(|&i| key_info[i].clone())
                .collect::<Vec<_>>();

            assert_eq!(reported(&params, &permuted, 2), expected, "{permutation:?}");
        }
    }

    /// `FullViewingKey::standard` accepts a repeated key, but an account where one
    /// participant holds two of the three slots is not the 2-of-3 it claims to be.
    #[test]
    fn rejects_a_repeated_cosigner_key() {
        let params = mainnet();
        let mut key_info = three_cosigners(&params);
        key_info[2] = key_info[0].clone();

        let err = parse_cosigners(&params, &key_info).expect_err("duplicate is rejected");
        assert!(
            err.message().contains("distinct key"),
            "unexpected message: {}",
            err.message(),
        );
    }

    /// The coin type is part of the ZIP 48 path, so a key exported on one network must
    /// not be accepted on the other — an account built from a mixed set would be one
    /// that no participant can reproduce.
    #[test]
    fn rejects_a_key_from_another_network() {
        let mainnet = mainnet();
        let testnet = testnet();
        let mut key_info = three_cosigners(&mainnet);
        key_info[1] = cosigner(&testnet, &[2; 32], 0);

        assert!(parse_cosigners(&mainnet, &key_info).is_err());

        let mut key_info = three_cosigners(&testnet);
        key_info[1] = cosigner(&mainnet, &[2; 32], 0);

        assert!(parse_cosigners(&testnet, &key_info).is_err());
    }

    /// Every way a cosigner set can be invalid reaches the caller as its own message,
    /// rather than as one generic failure.
    #[test]
    fn each_invalid_set_reports_what_is_wrong() {
        let params = mainnet();
        let key_info = three_cosigners(&params);
        let keys = |info: &[String]| parse_cosigners(&params, info).expect("cosigners parse");

        let cases: &[(Vec<String>, u8, &str)] = &[
            (key_info.clone(), 0, "at least 1"),
            (vec![], 1, "at least one cosigner key"),
            (key_info.clone(), 4, "exceeds the number of cosigners"),
            (
                (0u8..16)
                    .map(|i| cosigner(&params, &[i + 1; 32], 0))
                    .collect(),
                2,
                "at most 15 cosigners",
            ),
            (
                vec![
                    cosigner(&params, &[1; 32], 0),
                    cosigner(&params, &[2; 32], 1),
                ],
                2,
                "same ZIP 48 path",
            ),
        ];

        for (info, threshold, expected) in cases {
            // `zip48::FullViewingKey` derives nothing, not even `Debug`, so the `Ok`
            // value has to go before `expect_err` can report on it.
            let err = full_viewing_key(*threshold, keys(info))
                .map(|_| ())
                .expect_err("invalid cosigner set is rejected");

            assert!(
                err.message().contains(expected),
                "threshold {threshold} over {} keys: expected {expected:?}, got {:?}",
                info.len(),
                err.message(),
            );
        }
    }

    /// The wallet must be able to tell which cosigner it is, and must not claim to be
    /// one when it is not — a wallet that mistakes its slot would sign for the wrong
    /// key, and one that wrongly reports `null` would look watch-only to its operator.
    #[test]
    fn identifies_this_wallets_slot_or_reports_none() {
        let params = mainnet();
        let key_info = three_cosigners(&params);
        let keys = parse_cosigners(&params, &key_info).expect("cosigners parse");
        let fvk = full_viewing_key(2, keys.clone()).expect("valid cosigner set");

        for (i, seed) in [[1; 32], [2; 32], [3; 32]].iter().enumerate() {
            assert_eq!(
                cosigner_index_for_seed(&fvk, &keys, seed).unwrap(),
                Some(i),
                "seed {i} should be cosigner {i}",
            );
        }

        assert_eq!(
            cosigner_index_for_seed(&fvk, &keys, &[9; 32]).unwrap(),
            None
        );
    }

    /// The slot reported is an index into the set as submitted, so it must follow the
    /// keys when they move.
    #[test]
    fn the_reported_slot_follows_the_submitted_order() {
        let params = mainnet();
        let key_info = three_cosigners(&params);
        let reversed = key_info.iter().rev().cloned().collect::<Vec<_>>();
        let keys = parse_cosigners(&params, &reversed).expect("cosigners parse");
        let fvk = full_viewing_key(2, keys.clone()).expect("valid cosigner set");

        assert_eq!(
            cosigner_index_for_seed(&fvk, &keys, &[1; 32]).unwrap(),
            Some(2),
        );
    }
}
