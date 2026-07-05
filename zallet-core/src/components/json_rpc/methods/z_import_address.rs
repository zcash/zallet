use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;

use crate::components::{chain::Chain, database::DbConnection, json_rpc::server::LegacyCode};

#[cfg(feature = "transparent-key-import")]
use {
    crate::components::chain::ChainView,
    crate::network::Network,
    jsonrpsee::types::ErrorCode as RpcErrorCode,
    secp256k1::PublicKey,
    std::collections::HashSet,
    transparent::{address::TransparentAddress, util::hash160},
    zcash_client_backend::data_api::{WalletRead, WalletWrite},
    zcash_client_sqlite::AccountUuid,
    zcash_keys::encoding::AddressCodec,
    zcash_script::script::{Code, Redeem},
};

/// Response to a z_importaddress request
pub(crate) type Response = RpcResult<ResultType>;

/// The result of importing an address.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// The type of address imported: "p2pkh" or "p2sh".
    #[serde(rename = "type")]
    kind: &'static str,
    /// The transparent address corresponding to the imported data.
    address: String,
}

pub(super) const PARAM_ACCOUNT_DESC: &str = "The account UUID to import the address into.";
pub(super) const PARAM_HEX_DATA_DESC: &str =
    "Hex-encoded public key (P2PKH) or redeem script (P2SH).";
pub(super) const PARAM_RESCAN_DESC: &str =
    "If true (default), rescan the chain for UTXOs belonging to all wallet transparent addresses.";

#[cfg(feature = "transparent-key-import")]
pub(crate) async fn call<C: Chain>(
    wallet: &mut DbConnection,
    chain: C,
    account: &str,
    hex_data: &str,
    rescan: Option<bool>,
) -> Response {
    let account_id = account
        .parse()
        .map(AccountUuid::from_uuid)
        .map_err(|_| RpcErrorCode::InvalidParams)?;

    // Parse the address import data, and call the appropriate import handler
    let result = match parse_import(wallet.params(), hex_data)? {
        ParsedImport::P2pkh { pubkey, result } => {
            wallet
                .import_standalone_transparent_pubkey(account_id, pubkey)
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
            result
        }
        ParsedImport::P2sh { script, result } => {
            wallet
                .import_standalone_transparent_script(account_id, script)
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
            result
        }
    };

    if rescan.unwrap_or(true) {
        // Trigger a re-scan from the account's existing birthday so the sync engine
        // re-scans the already-synced range with the newly imported address tracked,
        // discovering its transparent (and any shielded) history with correct block
        // positions — including `tx_index = 0` for coinbase outputs, which the scanner
        // records directly. This replaces the previous address-index UTXO fetch and its
        // coinbase `tx_index` fix-up pass.
        //
        // We rewind the scan queue to the block before the account's birthday WITHOUT
        // lowering any account's birthday (an empty `reset_account_birthdays`): the rewind
        // target is the account's birthday floor, so no reset is required. The actual
        // scanning then happens asynchronously in the background sync tasks.
        let birthday = wallet
            .get_account_birthday(account_id)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
        let chain_view = chain
            .snapshot()
            .await
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
        let prior_chain_state = chain_view
            .tree_state_as_of(birthday - 1)
            .await
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            .ok_or_else(|| {
                LegacyCode::Database.with_static("chain state unavailable for rescan")
            })?;
        wallet
            .rewind_to_chain_state(prior_chain_state, HashSet::new())
            .map_err(|e| LegacyCode::Misc.with_message(format!("Rescan failed: {e}")))?;
    }

    Ok(result)
}

#[cfg(not(feature = "transparent-key-import"))]
pub(crate) async fn call<C: Chain>(
    _wallet: &mut DbConnection,
    _chain: C,
    _account: &str,
    _hex_data: &str,
    _rescan: Option<bool>,
) -> Response {
    Err(LegacyCode::Misc.with_static("z_importaddress requires the transparent-key-import feature"))
}

/// Intermediate result of parsing hex-encoded import data.
#[cfg(feature = "transparent-key-import")]
enum ParsedImport {
    /// A compressed or uncompressed public key (P2PKH import).
    P2pkh {
        pubkey: PublicKey,
        result: ResultType,
    },
    /// A redeem script (P2SH import).
    P2sh { script: Redeem, result: ResultType },
}

/// Parses hex-encoded data and classifies it as a public key (P2PKH) or redeem
/// script (P2SH), computing the corresponding transparent address.
#[cfg(feature = "transparent-key-import")]
fn parse_import(params: &Network, hex_data: &str) -> RpcResult<ParsedImport> {
    let bytes = hex::decode(hex_data)
        .map_err(|_| LegacyCode::InvalidParameter.with_static("Invalid hex encoding"))?;

    // Try to parse as a public key (P2PKH import).
    if let Ok(pubkey) = PublicKey::from_slice(&bytes) {
        let address = TransparentAddress::from_pubkey(&pubkey).encode(params);
        Ok(ParsedImport::P2pkh {
            pubkey,
            result: ResultType {
                kind: "p2pkh",
                address,
            },
        })
    } else {
        // Otherwise treat as a redeem script (P2SH import).
        let address = TransparentAddress::ScriptHash(hash160::hash(&bytes)).encode(params);
        let code = Code(bytes);
        let script = Redeem::parse(&code).map_err(|_| {
            LegacyCode::InvalidParameter.with_message(format!(
                "Unrecognized input (not a valid pubkey or redeem script): {hex_data}"
            ))
        })?;
        Ok(ParsedImport::P2sh {
            script,
            result: ResultType {
                kind: "p2sh",
                address,
            },
        })
    }
}

#[cfg(all(test, feature = "transparent-key-import"))]
mod tests {
    use super::*;
    use zcash_protocol::consensus;

    fn mainnet() -> Network {
        Network::Consensus(consensus::Network::MainNetwork)
    }

    fn testnet() -> Network {
        Network::Consensus(consensus::Network::TestNetwork)
    }

    // Compressed public key from zcashd qa/rpc-tests/decodescript.py:17
    const COMPRESSED_PUBKEY: &str =
        "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2";

    // P2PKH scriptPubKey (a valid script, but not a valid public key):
    // OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    const P2PKH_REDEEM_SCRIPT: &str = "76a91411695b6cd891484c2d49ec5aa738ec2b2f89777788ac";

    #[test]
    fn compressed_pubkey_classified_as_p2pkh() {
        let parsed = parse_import(&mainnet(), COMPRESSED_PUBKEY).unwrap();
        match parsed {
            ParsedImport::P2pkh { result, .. } => {
                assert_eq!(result.kind, "p2pkh");
                assert!(
                    result.address.starts_with("t1"),
                    "P2PKH mainnet address should start with t1, got {}",
                    result.address,
                );
            }
            ParsedImport::P2sh { .. } => panic!("Expected P2PKH, got P2SH"),
        }
    }

    #[test]
    fn compressed_pubkey_p2pkh_on_testnet() {
        let parsed = parse_import(&testnet(), COMPRESSED_PUBKEY).unwrap();
        match parsed {
            ParsedImport::P2pkh { result, .. } => {
                assert_eq!(result.kind, "p2pkh");
                assert!(
                    result.address.starts_with("tm"),
                    "P2PKH testnet address should start with tm, got {}",
                    result.address,
                );
            }
            ParsedImport::P2sh { .. } => panic!("Expected P2PKH, got P2SH"),
        }
    }

    #[test]
    fn redeem_script_classified_as_p2sh() {
        let parsed = parse_import(&mainnet(), P2PKH_REDEEM_SCRIPT).unwrap();
        match parsed {
            ParsedImport::P2sh { result, .. } => {
                assert_eq!(result.kind, "p2sh");
                assert!(
                    result.address.starts_with("t3"),
                    "P2SH mainnet address should start with t3, got {}",
                    result.address,
                );
            }
            ParsedImport::P2pkh { .. } => panic!("Expected P2SH, got P2PKH"),
        }
    }

    #[test]
    fn redeem_script_p2sh_on_testnet() {
        let parsed = parse_import(&testnet(), P2PKH_REDEEM_SCRIPT).unwrap();
        match parsed {
            ParsedImport::P2sh { result, .. } => {
                assert_eq!(result.kind, "p2sh");
                assert!(
                    result.address.starts_with("t2"),
                    "P2SH testnet address should start with t2, got {}",
                    result.address,
                );
            }
            ParsedImport::P2pkh { .. } => panic!("Expected P2SH, got P2PKH"),
        }
    }

    #[test]
    fn p2sh_address_is_hash160_of_script() {
        let script_bytes = hex::decode(P2PKH_REDEEM_SCRIPT).unwrap();
        let expected_address =
            TransparentAddress::ScriptHash(hash160::hash(&script_bytes)).encode(&mainnet());

        let parsed = parse_import(&mainnet(), P2PKH_REDEEM_SCRIPT).unwrap();
        match parsed {
            ParsedImport::P2sh { result, .. } => {
                assert_eq!(result.address, expected_address);
            }
            ParsedImport::P2pkh { .. } => panic!("Expected P2SH, got P2PKH"),
        }
    }

    #[test]
    fn p2pkh_address_matches_pubkey() {
        let pubkey_bytes = hex::decode(COMPRESSED_PUBKEY).unwrap();
        let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
        let expected_address = TransparentAddress::from_pubkey(&pubkey).encode(&mainnet());

        let parsed = parse_import(&mainnet(), COMPRESSED_PUBKEY).unwrap();
        match parsed {
            ParsedImport::P2pkh { result, .. } => {
                assert_eq!(result.address, expected_address);
            }
            ParsedImport::P2sh { .. } => panic!("Expected P2PKH, got P2SH"),
        }
    }

    #[test]
    fn invalid_hex_returns_error() {
        let Err(err) = parse_import(&mainnet(), "not_valid_hex") else {
            panic!("Expected error for invalid hex");
        };
        assert_eq!(err.code(), LegacyCode::InvalidParameter as i32);
        assert_eq!(err.message(), "Invalid hex encoding");
    }

    #[test]
    fn odd_length_hex_returns_error() {
        let Err(err) = parse_import(&mainnet(), "abc") else {
            panic!("Expected error for odd-length hex");
        };
        assert_eq!(err.code(), LegacyCode::InvalidParameter as i32);
        assert_eq!(err.message(), "Invalid hex encoding");
    }
}
