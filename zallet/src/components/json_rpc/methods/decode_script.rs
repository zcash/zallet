use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use secp256k1::PublicKey;
use serde::Serialize;
use transparent::{address::TransparentAddress, util::hash160};
use zcash_keys::encoding::AddressCodec;
use zcash_script::{
    script::{Asm, Code},
    solver::{self, ScriptKind},
};

use crate::{components::json_rpc::server::LegacyCode, network::Network};

pub(crate) type Response = RpcResult<ResultType>;

/// The result of decoding a script.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    #[serde(flatten)]
    inner: TransparentScript,

    /// The P2SH address for this script.
    p2sh: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct TransparentScript {
    /// The assembly string representation of the script.
    asm: String,

    /// The required number of signatures to spend this output.
    ///
    /// Omitted for scripts that don't contain identifiable addresses (such as
    /// non-standard or null-data scripts).
    #[serde(rename = "reqSigs", skip_serializing_if = "Option::is_none")]
    req_sigs: Option<u8>,

    /// The type of script.
    ///
    /// One of `["pubkey", "pubkeyhash", "scripthash", "multisig", "nulldata", "nonstandard"]`.
    #[serde(rename = "type")]
    kind: &'static str,

    /// Array of the transparent addresses involved in the script.
    ///
    /// Omitted for scripts that don't contain identifiable addresses (such as
    /// non-standard or null-data scripts).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
}

pub(super) const PARAM_HEXSTRING_DESC: &str = "The hex-encoded script.";

/// Decodes a hex-encoded script.
///
/// # Arguments
/// - `params`: Network parameters for address encoding.
/// - `hexstring`: The hex-encoded script.
pub(crate) fn call(params: &Network, hexstring: &str) -> Response {
    let script_bytes = hex::decode(hexstring)
        .map_err(|_| LegacyCode::Deserialization.with_static("Hex decoding failed"))?;

    let script_code = Code(script_bytes);

    let p2sh = calculate_p2sh_address(&script_code.0, params);

    Ok(ResultType {
        inner: script_to_json(params, &script_code),
        p2sh,
    })
}

/// Equivalent of `ScriptPubKeyToJSON` in `zcashd` with `fIncludeHex = false`.
pub(super) fn script_to_json(params: &Network, script_code: &Code) -> TransparentScript {
    let asm = script_code.to_asm(false);

    let (kind, req_sigs, addresses) = detect_script_info(script_code, params);

    TransparentScript {
        asm,
        kind,
        req_sigs,
        addresses,
    }
}

/// Converts a raw public key to its P2PKH address.
fn pubkey_to_p2pkh_address(pubkey_bytes: &[u8], params: &Network) -> Option<String> {
    let pubkey = PublicKey::from_slice(pubkey_bytes).ok()?;
    let addr = TransparentAddress::from_pubkey(&pubkey);
    Some(addr.encode(params))
}

/// Calculates the P2SH address for a given script.
fn calculate_p2sh_address(script_bytes: &[u8], params: &Network) -> String {
    let hash = hash160::hash(script_bytes);
    TransparentAddress::ScriptHash(hash).encode(params)
}

/// Detects the script type and extracts associated information.
///
/// Returns a tuple of (type_name, required_sigs, addresses).
//
// TODO: Replace match arms with `ScriptKind::as_str()` and `ScriptKind::req_sigs()`
//       once zcash_script is upgraded past 0.4.x.
//       See https://github.com/ZcashFoundation/zcash_script/pull/291
// TODO: zcashd relied on initialization behaviour for the default value
//       for null-data or non-standard outputs. Figure out what it is.
//       https://github.com/zcash/wallet/issues/236
fn detect_script_info(
    script_code: &Code,
    params: &Network,
) -> (&'static str, Option<u8>, Vec<String>) {
    script_code
        .to_component()
        .ok()
        .and_then(|c| c.refine().ok())
        .and_then(|component| solver::standard(&component))
        .map(|script_kind| match script_kind {
            ScriptKind::PubKeyHash { hash } => {
                let addr = TransparentAddress::PublicKeyHash(hash);
                ("pubkeyhash", Some(1), vec![addr.encode(params)])
            }
            ScriptKind::ScriptHash { hash } => {
                let addr = TransparentAddress::ScriptHash(hash);
                ("scripthash", Some(1), vec![addr.encode(params)])
            }
            ScriptKind::PubKey { data } => {
                let addresses: Vec<String> = pubkey_to_p2pkh_address(data.as_slice(), params)
                    .into_iter()
                    .collect();
                let req_sigs = if addresses.is_empty() { None } else { Some(1) };
                ("pubkey", req_sigs, addresses)
            }
            ScriptKind::MultiSig { required, pubkeys } => {
                let addresses: Vec<String> = pubkeys
                    .iter()
                    .filter_map(|pk| pubkey_to_p2pkh_address(pk.as_slice(), params))
                    .collect();
                let req_sigs = if addresses.is_empty() {
                    None
                } else {
                    Some(required)
                };
                ("multisig", req_sigs, addresses)
            }
            ScriptKind::NullData { .. } => ("nulldata", None, vec![]),
        })
        .unwrap_or(("nonstandard", None, vec![]))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use zcash_protocol::consensus;

    // From zcashd qa/rpc-tests/decodescript.py:17-22
    const ZCASHD_PUBLIC_KEY: &str =
        "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2";
    const ZCASHD_PUBLIC_KEY_HASH: &str = "11695b6cd891484c2d49ec5aa738ec2b2f897777";

    fn mainnet() -> Network {
        Network::Consensus(consensus::Network::MainNetwork)
    }

    fn testnet() -> Network {
        Network::Consensus(consensus::Network::TestNetwork)
    }

    #[test]
    fn decode_p2pkh_script() {
        // From zcashd qa/rpc-tests/decodescript.py:65
        // P2PKH: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        let script_hex = format!("76a914{ZCASHD_PUBLIC_KEY_HASH}88ac");
        let result = call(&mainnet(), &script_hex).unwrap().inner;

        assert_eq!(result.kind, "pubkeyhash");
        assert_eq!(result.req_sigs, Some(1));
        assert_eq!(result.addresses.len(), 1);
        assert!(result.addresses[0].starts_with("t1"));
        assert_eq!(
            result.asm,
            format!("OP_DUP OP_HASH160 {ZCASHD_PUBLIC_KEY_HASH} OP_EQUALVERIFY OP_CHECKSIG")
        );
    }

    #[test]
    fn decode_p2sh_script() {
        // From zcashd qa/rpc-tests/decodescript.py:73
        // P2SH: OP_HASH160 <script_hash> OP_EQUAL
        let script_hex = format!("a914{ZCASHD_PUBLIC_KEY_HASH}87");
        let result = call(&mainnet(), &script_hex).unwrap().inner;

        assert_eq!(result.kind, "scripthash");
        assert_eq!(result.req_sigs, Some(1));
        assert_eq!(result.addresses.len(), 1);
        assert!(result.addresses[0].starts_with("t3"));
        assert_eq!(
            result.asm,
            format!("OP_HASH160 {ZCASHD_PUBLIC_KEY_HASH} OP_EQUAL")
        );
    }

    #[test]
    fn decode_p2pk_script() {
        // From zcashd qa/rpc-tests/decodescript.py:57
        // P2PK: <pubkey> OP_CHECKSIG
        // 0x21 = 33 bytes push opcode
        let script_hex = format!("21{ZCASHD_PUBLIC_KEY}ac");
        let result = call(&mainnet(), &script_hex).unwrap().inner;

        assert_eq!(result.kind, "pubkey");
        assert_eq!(result.req_sigs, Some(1));
        assert_eq!(result.addresses.len(), 1);
        assert!(result.addresses[0].starts_with("t1"));
        assert_eq!(result.asm, format!("{ZCASHD_PUBLIC_KEY} OP_CHECKSIG"));
    }

    #[test]
    fn decode_multisig_script() {
        // From zcashd qa/rpc-tests/decodescript.py:69
        // 2-of-3 Multisig: OP_2 <pubkey> <pubkey> <pubkey> OP_3 OP_CHECKMULTISIG
        // Uses the same pubkey repeated 3 times (valid for testing)
        let script_hex = format!(
            "52\
             21{ZCASHD_PUBLIC_KEY}\
             21{ZCASHD_PUBLIC_KEY}\
             21{ZCASHD_PUBLIC_KEY}\
             53ae"
        );
        let result = call(&mainnet(), &script_hex).unwrap().inner;

        assert_eq!(result.kind, "multisig");
        assert_eq!(result.req_sigs, Some(2));
        assert_eq!(result.addresses.len(), 3);
        // All addresses should be the same since we used the same pubkey
        assert_eq!(result.addresses.iter().collect::<HashSet<_>>().len(), 1);
        // Verify ASM uses decimal numbers for OP_2 and OP_3
        assert!(result.asm.starts_with("2 "));
        assert!(result.asm.contains(" 3 OP_CHECKMULTISIG"));
    }

    #[test]
    fn decode_nulldata_script() {
        // From zcashd qa/rpc-tests/decodescript.py:77
        // OP_RETURN with signature-like data (crafted to resemble a DER signature)
        let script_hex = "6a48304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e\
            3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee31\
            3d741ad0cfbc0c509001";
        let result = call(&mainnet(), script_hex).unwrap().inner;

        assert_eq!(result.kind, "nulldata");
        assert_eq!(result.req_sigs, None);
        assert!(result.addresses.is_empty());
        assert!(result.asm.starts_with("OP_RETURN"));
    }

    #[test]
    fn decode_nonstandard_script() {
        // OP_TRUE (0x51)
        let script_hex = "51";
        let result = call(&mainnet(), script_hex).unwrap().inner;

        assert_eq!(result.kind, "nonstandard");
        assert_eq!(result.req_sigs, None);
        assert!(result.addresses.is_empty());
        // ASM should show "1" for OP_1/OP_TRUE
        assert_eq!(result.asm, "1");
    }

    #[test]
    fn decode_empty_script() {
        let result = call(&mainnet(), "").unwrap();

        assert_eq!(result.inner.kind, "nonstandard");
        assert_eq!(result.inner.req_sigs, None);
        assert!(result.inner.addresses.is_empty());
        assert!(result.inner.asm.is_empty());
        // P2SH should still be computed (hash of empty script)
        assert!(result.p2sh.starts_with("t3"));
    }

    #[test]
    fn decode_invalid_hex() {
        let result = call(&mainnet(), "not_hex");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), LegacyCode::Deserialization as i32);
        assert_eq!(err.message(), "Hex decoding failed");
    }

    #[test]
    fn decode_p2pkh_testnet() {
        // Same P2PKH script from zcashd test vectors but on testnet
        let script_hex = format!("76a914{ZCASHD_PUBLIC_KEY_HASH}88ac");
        let result = call(&testnet(), &script_hex).unwrap();

        assert_eq!(result.inner.kind, "pubkeyhash");
        // Testnet addresses start with "tm" for P2PKH
        assert!(result.inner.addresses[0].starts_with("tm"));
        // P2SH testnet addresses start with "t2"
        assert!(result.p2sh.starts_with("t2"));
    }

    #[test]
    fn p2sh_address_calculation() {
        // Verify P2SH address is correctly calculated for a P2PKH script
        let script_hex = format!("76a914{ZCASHD_PUBLIC_KEY_HASH}88ac");
        let result = call(&mainnet(), &script_hex).unwrap();

        // P2SH address should be computed for any script type
        let script_bytes = hex::decode(&script_hex).unwrap();
        let expected_p2sh = calculate_p2sh_address(&script_bytes, &mainnet());
        assert_eq!(result.p2sh, expected_p2sh);
    }

    /// P2PKH scriptPubKey asm output.
    ///
    /// Test vector from zcashd `qa/rpc-tests/decodescript.py:134`.
    #[test]
    fn scriptpubkey_asm_p2pkh() {
        let script =
            Code(hex::decode("76a914dc863734a218bfe83ef770ee9d41a27f824a6e5688ac").unwrap());
        let asm = script.to_asm(false);
        assert_eq!(
            asm,
            "OP_DUP OP_HASH160 dc863734a218bfe83ef770ee9d41a27f824a6e56 OP_EQUALVERIFY OP_CHECKSIG"
        );

        // Verify script type detection
        let (kind, req_sigs, _) = detect_script_info(&script, &mainnet());
        assert_eq!(kind, "pubkeyhash");
        assert_eq!(req_sigs, Some(1));
    }

    /// P2SH scriptPubKey asm output.
    ///
    /// Test vector from zcashd `qa/rpc-tests/decodescript.py:135`.
    #[test]
    fn scriptpubkey_asm_p2sh() {
        let script = Code(hex::decode("a9142a5edea39971049a540474c6a99edf0aa4074c5887").unwrap());
        let asm = script.to_asm(false);
        assert_eq!(
            asm,
            "OP_HASH160 2a5edea39971049a540474c6a99edf0aa4074c58 OP_EQUAL"
        );

        let (kind, req_sigs, _) = detect_script_info(&script, &mainnet());
        assert_eq!(kind, "scripthash");
        assert_eq!(req_sigs, Some(1));
    }

    /// OP_RETURN nulldata scriptPubKey.
    ///
    /// Test vector from zcashd `qa/rpc-tests/decodescript.py:142`.
    #[test]
    fn scriptpubkey_asm_nulldata() {
        let script = Code(hex::decode("6a09300602010002010001").unwrap());
        let asm = script.to_asm(false);
        assert_eq!(asm, "OP_RETURN 300602010002010001");

        let (kind, req_sigs, addresses) = detect_script_info(&script, &mainnet());
        assert_eq!(kind, "nulldata");
        assert_eq!(req_sigs, None);
        assert!(addresses.is_empty());
    }

    /// P2PK scriptPubKey (uncompressed pubkey).
    ///
    /// Pubkey extracted from zcashd `qa/rpc-tests/decodescript.py:122-125` scriptSig,
    /// wrapped in P2PK format (OP_PUSHBYTES_65 <pubkey> OP_CHECKSIG).
    #[test]
    fn scriptpubkey_asm_p2pk() {
        let script = Code(hex::decode(
            "4104d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544fc7088d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536ac"
        ).unwrap());
        let asm = script.to_asm(false);
        assert_eq!(
            asm,
            "04d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544fc7088d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536 OP_CHECKSIG"
        );

        let (kind, req_sigs, _) = detect_script_info(&script, &mainnet());
        assert_eq!(kind, "pubkey");
        assert_eq!(req_sigs, Some(1));
    }

    /// Nonstandard script detection.
    ///
    /// Tests fallback behavior for scripts that don't match standard patterns.
    #[test]
    fn scriptpubkey_nonstandard() {
        // Just OP_TRUE (0x51) - a valid but nonstandard script
        let script = Code(hex::decode("51").unwrap());

        let (kind, req_sigs, addresses) = detect_script_info(&script, &mainnet());
        assert_eq!(kind, "nonstandard");
        assert_eq!(req_sigs, None);
        assert!(addresses.is_empty());
    }
}
