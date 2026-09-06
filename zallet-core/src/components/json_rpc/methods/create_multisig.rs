//! `createmultisig` — build an m-of-n multisig redeem script and its P2SH address.
//!
//! This is the read-only half of the pair it forms with `addmultisigaddress`: it
//! computes the script and address and returns them, without recording anything in
//! the wallet. `zcashd` derived both from one helper, and so does Zallet — see
//! [`build_multisig`], which `add_multisig_address` also uses.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use secp256k1::PublicKey;
use serde::Serialize;
use transparent::{address::TransparentAddress, util::hash160};
use zcash_keys::encoding::AddressCodec;
use zcash_script::{
    pattern,
    script::{Code, Component, Redeem},
    solver::{self, ScriptKind},
};

use crate::{
    components::{database::DbConnection, json_rpc::server::LegacyCode},
    network::Network,
};

#[cfg(zallet_build = "wallet")]
use {
    crate::components::json_rpc::payments::get_account_for_address,
    zcash_client_backend::{
        data_api::{Account, WalletRead},
        wallet::TransparentAddressSource,
    },
    zcash_keys::address::Address,
};

pub(crate) type Response = RpcResult<ResultType>;

/// The multisig redeem script, and the P2SH address that commits to it.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// The P2SH address of the multisig redeem script.
    address: String,

    /// The hex-encoded multisig redeem script.
    ///
    /// This is required to spend any funds sent to `address`, and is not recoverable
    /// from the address itself, which commits only to its hash. Record it.
    #[serde(rename = "redeemScript")]
    redeem_script: String,
}

pub(super) const PARAM_NREQUIRED_DESC: &str =
    "The number of the supplied keys that must sign to spend.";
pub(super) const PARAM_KEYS_DESC: &str = "The keys the multisig address is composed of, each either a hex-encoded public key \
     or a transparent address this wallet holds the public key for.";
pub(super) const PARAM_KEYS_REQUIRED: bool = true;

/// The maximum number of keys a multisig script may name.
///
/// Both counts in the script are pushed as a single opcode in the `OP_1`..`OP_16`
/// range, so 16 is the ceiling. `zcashd` enforced the same limit.
const MAX_MULTISIG_KEYS: usize = 16;

/// The maximum serialized size of a P2SH redeem script, in bytes.
///
/// A redeem script is supplied as a single stack element when the P2SH output is
/// spent, so it is bounded by the interpreter's maximum push size. A script larger
/// than this hashes to a perfectly good address that nothing can ever spend from,
/// which is why the limit is checked here rather than left to the spender.
const MAX_REDEEM_SCRIPT_SIZE: usize = 520;

/// Builds the `OP_m <pubkey>… OP_n OP_CHECKMULTISIG` redeem script of an m-of-n
/// multisig, validating the arguments the way `zcashd` did, and returns it with its
/// serialization.
///
/// The serialization is returned rather than left to be derived again by each caller
/// that needs it: the size limit, the address, and the hex `createmultisig` reports
/// must all be the same bytes, and serializing afresh for each is another chance for
/// them not to be.
///
/// `pubkeys` holds each key already serialized, because the encoding is part of what
/// the address commits to: `zcashd` pushed a key exactly as it was given, so a script
/// naming an uncompressed key hashes to a different address than the same key
/// compressed. Recreating a known multisig address requires reproducing that choice,
/// so the caller's encoding is carried through rather than canonicalized here.
fn build_multisig_redeem_script(
    nrequired: u8,
    pubkeys: &[Vec<u8>],
) -> RpcResult<(Redeem, Vec<u8>)> {
    if nrequired < 1 {
        return Err(LegacyCode::InvalidParameter
            .with_static("a multisignature address must require at least one key to redeem"));
    }
    if pubkeys.len() < usize::from(nrequired) {
        return Err(LegacyCode::InvalidParameter.with_message(format!(
            "not enough keys supplied (got {} keys, but need at least {nrequired} to redeem)",
            pubkeys.len(),
        )));
    }
    if pubkeys.len() > MAX_MULTISIG_KEYS {
        return Err(LegacyCode::InvalidParameter.with_message(format!(
            "number of keys involved in the multisignature address creation > {MAX_MULTISIG_KEYS}",
        )));
    }

    // Both counts are in `1..=16` by the checks above, so `check_multisig` pushes each
    // as a single `OP_1`..`OP_16`. It does not enforce either limit itself — its own
    // errors cover only an unpushable key and a count too large for `i64` — so the
    // checks above are what keep the result a standard multisig.
    let keys: Vec<&[u8]> = pubkeys.iter().map(Vec::as_slice).collect();
    let redeem: Redeem = Component(
        pattern::check_multisig(nrequired, &keys, false)
            .map_err(|e| LegacyCode::InvalidParameter.with_message(e.to_string()))?,
    );

    let bytes = Code::serialize(&redeem.0);
    if bytes.len() > MAX_REDEEM_SCRIPT_SIZE {
        return Err(LegacyCode::InvalidParameter.with_message(format!(
            "redeemScript exceeds size limit: {} > {MAX_REDEEM_SCRIPT_SIZE}",
            bytes.len(),
        )));
    }

    check_reads_back_as_intended(&redeem, nrequired, pubkeys)?;

    Ok((redeem, bytes))
}

/// Checks that `redeem` reads back as the multisig it was built to be: the same
/// threshold, and the same keys in the same order, byte for byte.
///
/// This catches any drift between how we build a script and how the rest of the stack
/// (`decodescript`, the solver, a spending wallet) interprets one. Comparing the keys
/// and not merely counting them is what makes the check cover the encoding, which is
/// the part of the script the address most easily disagrees about.
fn check_reads_back_as_intended(
    redeem: &Redeem,
    nrequired: u8,
    pubkeys: &[Vec<u8>],
) -> RpcResult<()> {
    match solver::standard(redeem) {
        Some(ScriptKind::MultiSig {
            required,
            pubkeys: parsed,
        }) if required == nrequired
            && parsed.len() == pubkeys.len()
            && parsed
                .iter()
                .zip(pubkeys)
                .all(|(parsed, given)| parsed.as_slice() == given.as_slice()) =>
        {
            Ok(())
        }
        _ => Err(LegacyCode::Misc.with_static("constructed script is not a standard multisig")),
    }
}

/// The P2SH address committing to a serialized redeem script.
fn p2sh_address(params: &Network, bytes: &[u8]) -> String {
    TransparentAddress::ScriptHash(hash160::hash(bytes)).encode(params)
}

/// Resolves one entry of the `keys` argument to a public key.
///
/// An entry is either a hex-encoded public key, or a transparent address this wallet
/// holds the public key for; `zcashd` accepted both.
///
/// The key is returned already serialized, in the encoding the script should name;
/// see [`build_multisig_redeem_script`] for why that is preserved rather than
/// normalized.
fn resolve_key(wallet: &DbConnection, key: &str) -> RpcResult<Vec<u8>> {
    // A hex-encoded public key needs no wallet at all. `from_slice` accepts both the
    // compressed and uncompressed encodings, as `zcashd` did, and validates the point;
    // the bytes are then used as given so the caller's encoding survives into the
    // script.
    if let Some(bytes) = hex::decode(key)
        .ok()
        .filter(|bytes| PublicKey::from_slice(bytes).is_ok())
    {
        return Ok(bytes);
    }

    let address = TransparentAddress::decode(wallet.params(), key).map_err(|_| {
        LegacyCode::InvalidAddressOrKey
            .with_message(format!("Invalid public key or transparent address: {key}"))
    })?;

    match address {
        TransparentAddress::PublicKeyHash(_) => resolve_address_pubkey(wallet, &address),
        // A P2SH address commits to a script, not to a key, so there is no public key
        // to put in the multisig. (Nesting P2SH inside P2SH is not spendable anyway.)
        TransparentAddress::ScriptHash(_) => Err(LegacyCode::InvalidAddressOrKey
            .with_message(format!("{key} is a P2SH address, which has no public key"))),
    }
}

/// The public key this wallet holds for a P2PKH address it knows.
///
/// Always the compressed encoding: a P2PKH address that Zallet derived or imported is
/// the hash of the compressed key, and `secp256k1::PublicKey` does not retain the
/// encoding it was parsed from. Name the key in hex to control that.
#[cfg(zallet_build = "wallet")]
fn resolve_address_pubkey(
    wallet: &DbConnection,
    address: &TransparentAddress,
) -> RpcResult<Vec<u8>> {
    let encoded = address.encode(wallet.params());

    let account = get_account_for_address(wallet, &Address::Transparent(*address))?;
    let metadata = wallet
        .get_transparent_address_metadata(account.id(), address)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or_else(|| {
            LegacyCode::InvalidAddressOrKey
                .with_message(format!("No public key is known for address {encoded}"))
        })?;

    match metadata.source() {
        // An imported key is stored as the public key itself. The standalone variants
        // only exist under `transparent-key-import`; without it an address can only
        // have been derived, and the match below is exhaustive without them.
        #[cfg(feature = "transparent-key-import")]
        TransparentAddressSource::StandalonePubkey(pubkey) => Ok(pubkey.serialize().to_vec()),

        // An address imported on its own, with no key material behind it. The wallet
        // watches it for incoming funds but holds nothing the address is the hash of,
        // so there is no key to name in the script until that material is imported.
        #[cfg(feature = "transparent-key-import")]
        TransparentAddressSource::StandaloneAddress => Err(LegacyCode::InvalidAddressOrKey
            .with_message(format!(
                "{encoded} was imported as an address alone, so no public key is known for it"
            ))),

        // A derived receiver's public key is re-derived from the account's key rather
        // than read from the address record, which is not integrity-protected.
        TransparentAddressSource::Derived {
            scope,
            address_index,
        } => account
            .ufvk()
            .and_then(|ufvk| ufvk.transparent())
            .ok_or_else(|| {
                LegacyCode::InvalidAddressOrKey.with_message(format!(
                    "The account holding {encoded} has no transparent key",
                ))
            })?
            .derive_address_pubkey(*scope, *address_index)
            .map(|pubkey| pubkey.serialize().to_vec())
            .map_err(|_| {
                LegacyCode::InvalidAddressOrKey
                    .with_message(format!("Could not derive the public key for {encoded}"))
            }),

        // Reached only for a P2SH address, which `resolve_key` rejects before here.
        #[cfg(feature = "transparent-key-import")]
        TransparentAddressSource::StandaloneScript(_) => Err(LegacyCode::InvalidAddressOrKey
            .with_message(format!(
                "{encoded} is a P2SH address, which has no public key"
            ))),
    }
}

/// Without a wallet there is nothing to resolve an address against, so this build
/// accepts hex-encoded public keys only.
#[cfg(not(zallet_build = "wallet"))]
fn resolve_address_pubkey(
    wallet: &DbConnection,
    address: &TransparentAddress,
) -> RpcResult<Vec<u8>> {
    Err(LegacyCode::InvalidAddressOrKey.with_message(format!(
        "{} cannot be resolved to a public key in this build; supply a hex-encoded public key",
        address.encode(wallet.params()),
    )))
}

/// The multisig a `keys` argument describes.
pub(super) struct Multisig {
    /// The redeem script itself, to record in the wallet.
    pub(super) redeem: Redeem,
    /// Its serialization, to report in hex.
    pub(super) bytes: Vec<u8>,
    /// The P2SH address committing to it.
    pub(super) address: String,
}

/// Resolves the `keys` argument and builds the multisig it describes.
///
/// This is the whole of `createmultisig`, and everything `addmultisigaddress` does
/// before recording the script. Sharing it is what makes the two report the same
/// address for the same arguments, rather than merely intend to.
pub(super) fn build_multisig(
    wallet: &DbConnection,
    nrequired: u8,
    keys: &[String],
) -> RpcResult<Multisig> {
    let pubkeys = keys
        .iter()
        .map(|key| resolve_key(wallet, key))
        .collect::<RpcResult<Vec<_>>>()?;
    let (redeem, bytes) = build_multisig_redeem_script(nrequired, &pubkeys)?;
    let address = p2sh_address(wallet.params(), &bytes);

    Ok(Multisig {
        redeem,
        bytes,
        address,
    })
}

/// Creates a multisig redeem script and reports its P2SH address.
pub(crate) fn call(wallet: &DbConnection, nrequired: u8, keys: &[String]) -> Response {
    let multisig = build_multisig(wallet, nrequired, keys)?;

    Ok(ResultType {
        address: multisig.address,
        redeem_script: hex::encode(multisig.bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus;

    fn mainnet() -> Network {
        Network::Consensus(consensus::Network::MainNetwork)
    }

    // Compressed public key from zcashd qa/rpc-tests/decodescript.py:17
    const COMPRESSED_PUBKEY: &str =
        "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2";

    fn pubkey() -> Vec<u8> {
        hex::decode(COMPRESSED_PUBKEY).unwrap()
    }

    fn pubkeys(n: usize) -> Vec<Vec<u8>> {
        vec![pubkey(); n]
    }

    /// `<len> <key>`: the direct push of a serialized public key, as a script names it.
    ///
    /// The length byte doubles as the opcode for any push of 1..=75 bytes, which covers
    /// both key encodings, so it is taken from the key rather than written out.
    fn push(key: &[u8]) -> String {
        format!("{:02x}{}", key.len(), hex::encode(key))
    }

    /// The same key in its 65-byte uncompressed encoding.
    fn uncompressed_pubkey() -> Vec<u8> {
        PublicKey::from_slice(&pubkey())
            .unwrap()
            .serialize_uncompressed()
            .to_vec()
    }

    /// The 2-of-3 script from zcashd qa/rpc-tests/decodescript.py:74-79:
    /// `<m> <A pubkey> <B pubkey> <C pubkey> <n> OP_CHECKMULTISIG`.
    #[test]
    fn builds_the_zcashd_2_of_3_script() {
        let (_, bytes) = build_multisig_redeem_script(2, &pubkeys(3)).unwrap();

        let expected = format!("52{}53ae", push(&pubkey()).repeat(3));
        assert_eq!(hex::encode(bytes), expected);
    }

    /// What we build must read back as what we meant, through the same solver
    /// `decodescript` uses.
    #[test]
    fn round_trips_through_the_solver() {
        let (_, bytes) = build_multisig_redeem_script(2, &pubkeys(3)).unwrap();

        let parsed = Redeem::parse(&Code(bytes.clone())).unwrap();
        match solver::standard(&parsed) {
            Some(ScriptKind::MultiSig { required, pubkeys }) => {
                assert_eq!(required, 2);
                assert_eq!(pubkeys.len(), 3);
                for parsed_pubkey in pubkeys {
                    assert_eq!(parsed_pubkey.as_slice(), &pubkey()[..]);
                }
            }
            // `ScriptKind` does not implement `Debug`, so report the script instead.
            _ => panic!("expected a multisig script, got {}", hex::encode(&bytes)),
        }
    }

    /// The address is the P2SH address of the script, which on mainnet is a `t3`.
    #[test]
    fn address_is_the_p2sh_of_the_script() {
        let (_, bytes) = build_multisig_redeem_script(2, &pubkeys(3)).unwrap();

        let expected = TransparentAddress::ScriptHash(hash160::hash(&bytes)).encode(&mainnet());
        let address = p2sh_address(&mainnet(), &bytes);

        assert_eq!(address, expected);
        assert!(
            address.starts_with("t3"),
            "expected a mainnet P2SH address, got {address}"
        );
    }

    /// The opcode range allows 16 keys, but the 520-byte redeem script limit binds
    /// first: a compressed key costs 34 bytes to push, so 15 keys fit in 513 bytes and
    /// 16 need 547. Fifteen is the real ceiling for a compressed-key multisig.
    #[test]
    fn fifteen_compressed_keys_fit_and_sixteen_do_not() {
        assert!(build_multisig_redeem_script(15, &pubkeys(15)).is_ok());

        let err = build_multisig_redeem_script(16, &pubkeys(16)).unwrap_err();
        assert_eq!(err.code(), LegacyCode::InvalidParameter as i32);
        assert!(
            err.message().contains("exceeds size limit"),
            "got: {}",
            err.message(),
        );
    }

    /// Past 16 the count is not pushable as a single opcode at all, which is a
    /// different rejection from the size limit above.
    #[test]
    fn rejects_more_than_sixteen_keys() {
        let err = build_multisig_redeem_script(1, &pubkeys(17)).unwrap_err();

        assert_eq!(err.code(), LegacyCode::InvalidParameter as i32);
        assert!(err.message().contains("> 16"), "got: {}", err.message());
    }

    /// A key is pushed in the encoding it was given, so an uncompressed one costs 66
    /// bytes rather than 34 — which is what makes recreating a `zcashd` address that
    /// names uncompressed keys possible, and what makes 8 of them too large.
    #[test]
    fn preserves_the_given_key_encoding() {
        let (_, bytes) = build_multisig_redeem_script(1, &[uncompressed_pubkey()]).unwrap();

        let expected = format!("51{}51ae", push(&uncompressed_pubkey()));
        assert_eq!(hex::encode(bytes), expected);
    }

    #[test]
    fn rejects_zero_required() {
        let err = build_multisig_redeem_script(0, &pubkeys(3)).unwrap_err();

        assert_eq!(err.code(), LegacyCode::InvalidParameter as i32);
        assert_eq!(
            err.message(),
            "a multisignature address must require at least one key to redeem",
        );
    }

    #[test]
    fn rejects_more_required_than_supplied() {
        let err = build_multisig_redeem_script(3, &pubkeys(2)).unwrap_err();

        assert_eq!(err.code(), LegacyCode::InvalidParameter as i32);
        assert_eq!(
            err.message(),
            "not enough keys supplied (got 2 keys, but need at least 3 to redeem)",
        );
    }

    /// An uncompressed key costs 66 bytes to push, so 7 fit in 465 bytes and 8 need
    /// 531 — over the limit, well below the 16-key ceiling.
    #[test]
    fn rejects_oversized_script() {
        assert!(build_multisig_redeem_script(1, &vec![uncompressed_pubkey(); 7]).is_ok());

        let err = build_multisig_redeem_script(1, &vec![uncompressed_pubkey(); 8]).unwrap_err();
        assert_eq!(err.code(), LegacyCode::InvalidParameter as i32);
        assert!(
            err.message().contains("exceeds size limit"),
            "got: {}",
            err.message(),
        );
    }
}
