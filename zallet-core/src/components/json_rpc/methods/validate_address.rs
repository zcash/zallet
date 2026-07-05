use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use transparent::address::TransparentAddress;
use zcash_keys::encoding::AddressCodec;
use zcash_script::script::Evaluable;

use crate::network::Network;

pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = ValidateAddress;

/// The result of validating a transparent Zcash address.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ValidateAddress {
    /// Whether the address is valid.
    isvalid: bool,

    /// The normalized address string.
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,

    /// The hex-encoded scriptPubKey generated for the address.
    #[serde(rename = "scriptPubKey", skip_serializing_if = "Option::is_none")]
    script_pub_key: Option<String>,

    /// Whether the address is a P2SH (script) address.
    #[serde(skip_serializing_if = "Option::is_none")]
    isscript: Option<bool>,
}

pub(super) const PARAM_ADDRESS_DESC: &str = "The transparent address to validate.";

/// Validates a transparent Zcash address.
///
/// # Arguments
/// - `params`: Network parameters for address encoding/decoding.
/// - `address`: The address string to validate.
pub(crate) fn call(params: &Network, address: &str) -> Response {
    let transparent_addr = match TransparentAddress::decode(params, address) {
        Ok(addr) => addr,
        Err(_) => {
            return Ok(ValidateAddress {
                isvalid: false,
                address: None,
                script_pub_key: None,
                isscript: None,
            });
        }
    };

    let script_pubkey = transparent_addr.script();
    let script_hex = hex::encode(script_pubkey.to_bytes());

    let isscript = matches!(transparent_addr, TransparentAddress::ScriptHash(_));

    Ok(ValidateAddress {
        isvalid: true,
        address: Some(transparent_addr.encode(params)),
        script_pub_key: Some(script_hex),
        isscript: Some(isscript),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus;

    fn mainnet() -> Network {
        Network::Consensus(consensus::Network::MainNetwork)
    }

    fn testnet() -> Network {
        Network::Consensus(consensus::Network::TestNetwork)
    }

    // Address reused from verify_message.rs tests.
    const MAINNET_P2PKH: &str = "t1VydNnkjBzfL1iAMyUbwGKJAF7PgvuCfMY";

    // Address reused from verify_message.rs:192 test.
    const MAINNET_P2SH: &str = "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd";

    #[test]
    fn valid_p2pkh_mainnet() {
        let result = call(&mainnet(), MAINNET_P2PKH).unwrap();
        assert!(result.isvalid);
        assert_eq!(result.address.as_deref(), Some(MAINNET_P2PKH));
        assert!(!result.isscript.unwrap());
        // P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        let spk = result.script_pub_key.unwrap();
        assert!(
            spk.starts_with("76a914"),
            "P2PKH script should start with 76a914"
        );
        assert!(spk.ends_with("88ac"), "P2PKH script should end with 88ac");
    }

    #[test]
    fn valid_p2sh_mainnet() {
        let result = call(&mainnet(), MAINNET_P2SH).unwrap();
        assert!(result.isvalid);
        assert_eq!(result.address.as_deref(), Some(MAINNET_P2SH));
        assert!(result.isscript.unwrap());
        // P2SH scriptPubKey: OP_HASH160 <20-byte-hash> OP_EQUAL
        let spk = result.script_pub_key.unwrap();
        assert!(
            spk.starts_with("a914"),
            "P2SH script should start with a914"
        );
        assert!(spk.ends_with("87"), "P2SH script should end with 87");
    }

    #[test]
    fn invalid_address() {
        let result = call(&mainnet(), "notanaddress").unwrap();
        assert!(!result.isvalid);
        assert!(result.address.is_none());
        assert!(result.script_pub_key.is_none());
        assert!(result.isscript.is_none());
    }

    #[test]
    fn empty_string() {
        let result = call(&mainnet(), "").unwrap();
        assert!(!result.isvalid);
        assert!(result.address.is_none());
        assert!(result.script_pub_key.is_none());
        assert!(result.isscript.is_none());
    }

    // https://github.com/zcash/zcash/blob/v6.11.0/qa/rpc-tests/disablewallet.py#L29
    #[test]
    fn wrong_network_mainnet_p2sh_on_testnet() {
        let result = call(&testnet(), "t3b1jtLvxCstdo1pJs9Tjzc5dmWyvGQSZj8").unwrap();
        assert!(!result.isvalid);
    }

    // https://github.com/zcash/zcash/blob/v6.11.0/qa/rpc-tests/disablewallet.py#L31
    #[test]
    fn testnet_addr_on_testnet() {
        let result = call(&testnet(), "tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86").unwrap();
        assert!(result.isvalid);
    }

    // Network mismatch test similar to disablewallet.py:29 above.
    #[test]
    fn mainnet_p2pkh_on_testnet() {
        let result = call(&testnet(), MAINNET_P2PKH).unwrap();
        assert!(!result.isvalid);
    }

    // https://github.com/zcash/zcash/blob/v6.11.0/src/wallet/test/rpc_wallet_tests.cpp#L523
    // (valid for z_validateaddress, not validateaddress)
    #[test]
    fn shielded_sapling_address_is_invalid() {
        let result = call(
            &mainnet(),
            "zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9slya",
        )
        .unwrap();
        assert!(!result.isvalid);
    }

    #[test]
    fn truncated_address() {
        let result = call(&mainnet(), "t1VydNnkjBzfL1iAMyUbwGKJAF7Pgvu").unwrap();
        assert!(!result.isvalid);
    }

    // https://github.com/zcash/zcash/blob/v6.11.0/src/rpc/misc.cpp#L199-L200
    #[test]
    fn serialization_invalid_only_has_isvalid() {
        let result = call(&mainnet(), "invalid").unwrap();
        let json = serde_json::to_value(&result).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(
            obj.len(),
            1,
            "Invalid address should only have isvalid field"
        );
        assert!(obj.contains_key("isvalid"));
    }

    // https://github.com/zcash/zcash/blob/v6.11.0/src/rpc/misc.cpp#L200-L216
    #[test]
    fn serialization_valid_has_all_fields() {
        let result = call(&mainnet(), MAINNET_P2PKH).unwrap();
        let json = serde_json::to_value(&result).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 4, "Valid address should have exactly 4 fields");
        assert!(obj.contains_key("isvalid"));
        assert!(obj.contains_key("address"));
        assert!(obj.contains_key("scriptPubKey"));
        assert!(obj.contains_key("isscript"));
    }
}
