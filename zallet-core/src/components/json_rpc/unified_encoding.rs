//! ZIP 316 encodings of unified addresses and viewing keys for JSON-RPC responses.
//!
//! JSON-RPC responses give each unified address or viewing key in its ZIP 316 Revision 0
//! form (`u1…`, `uview1…`, `uivk1…`), as `zcashd` did, so that software that understands
//! only Revision 0 can parse them. A value that Revision 0 cannot represent (no shielded
//! component, metadata such as an expiry, or a P2SH viewing key item) is given in its
//! Revision 2 form (`zu…`/`tu…`, `uvf…`, `uvi…`) instead.

#[cfg(zallet_build = "wallet")]
use jsonrpsee::core::RpcResult;
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::Parameters;

#[cfg(zallet_build = "wallet")]
use {
    super::server::LegacyCode,
    zcash_keys::{
        encoding::UnifiedEncodingError,
        keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey},
    },
};

/// Encodes a unified address with every one of its receivers.
///
/// A transparent receiver is retained, as in `zcashd`'s Revision 0 addresses.
pub(super) fn encode_unified_address(ua: &UnifiedAddress, params: &impl Parameters) -> String {
    ua.encode_receiver_preserving(params)
}

/// Encodes a unified full viewing key.
///
/// Returns an RPC error if the key has no encoding at either revision.
#[cfg(zallet_build = "wallet")]
pub(super) fn encode_ufvk(
    ufvk: &UnifiedFullViewingKey,
    params: &impl Parameters,
) -> RpcResult<String> {
    ufvk.encode(params).map_err(encoding_error)
}

/// Encodes a unified incoming viewing key.
///
/// Returns an RPC error if the key has no encoding at either revision.
#[cfg(zallet_build = "wallet")]
pub(super) fn encode_uivk(
    uivk: &UnifiedIncomingViewingKey,
    params: &impl Parameters,
) -> RpcResult<String> {
    uivk.encode(params).map_err(encoding_error)
}

#[cfg(zallet_build = "wallet")]
fn encoding_error(e: UnifiedEncodingError) -> jsonrpsee::types::ErrorObjectOwned {
    LegacyCode::Misc.with_message(format!("Cannot encode the viewing key: {e}"))
}

#[cfg(test)]
mod tests {
    use zcash_address::unified::{self, Container, Encoding, Revision};
    use zcash_keys::{
        address::UnifiedAddress,
        keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    };
    use zcash_protocol::{
        consensus::{BlockHeight, MAIN_NETWORK, NetworkType, TEST_NETWORK},
        constants,
    };

    use super::encode_unified_address;
    #[cfg(zallet_build = "wallet")]
    use super::{encode_ufvk, encode_uivk};

    /// Height used as an address expiry in tests.
    const EXPIRY_HEIGHT: u32 = 3_000_000;

    fn test_ufvk() -> UnifiedFullViewingKey {
        UnifiedSpendingKey::from_seed(&MAIN_NETWORK, &[7; 32], zip32::AccountId::ZERO)
            .expect("test seed derives a spending key")
            .to_unified_full_viewing_key()
    }

    fn test_address() -> UnifiedAddress {
        test_ufvk()
            .default_address(UnifiedAddressRequest::ALLOW_ALL)
            .expect("the test key has a default address")
            .0
    }

    fn hrp_prefix(hrp: &str) -> String {
        format!("{hrp}1")
    }

    #[test]
    fn unified_address_is_revision_0_with_every_receiver() {
        let ua = test_address();
        assert!(ua.transparent().is_some() && ua.orchard().is_some());

        let encoded = encode_unified_address(&ua, &MAIN_NETWORK);
        assert!(encoded.starts_with(&hrp_prefix(constants::mainnet::HRP_UNIFIED_ADDRESS)));

        let (network, revision, decoded) =
            unified::Address::decode(&encoded).expect("the encoding decodes");
        assert_eq!(network, NetworkType::Main);
        assert_eq!(revision, Revision::R0);
        assert_eq!(decoded.items().len(), ua.receiver_types().len());

        let testnet = encode_unified_address(&ua, &TEST_NETWORK);
        assert!(testnet.starts_with(&hrp_prefix(constants::testnet::HRP_UNIFIED_ADDRESS)));
    }

    #[test]
    fn address_with_expiry_keeps_revision_2() {
        let ua = test_address();
        let ua = UnifiedAddress::from_receivers(
            ua.orchard().copied(),
            ua.sapling().copied(),
            ua.transparent().copied(),
            Some(BlockHeight::from_u32(EXPIRY_HEIGHT)),
            None,
        )
        .expect("the test address has receivers");

        let encoded = encode_unified_address(&ua, &MAIN_NETWORK);
        let (_, revision, _) = unified::Address::decode(&encoded).expect("the encoding decodes");
        assert_eq!(revision, Revision::R2);
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn ufvk_is_revision_0_and_round_trips() {
        let ufvk = test_ufvk();
        let encoded = encode_ufvk(&ufvk, &MAIN_NETWORK).expect("the test UFVK has an encoding");
        assert!(encoded.starts_with(&hrp_prefix(constants::mainnet::HRP_UNIFIED_FVK)));

        let decoded = UnifiedFullViewingKey::decode(&MAIN_NETWORK, &encoded)
            .expect("the Revision 0 encoding decodes");
        assert_eq!(
            decoded
                .encode(&MAIN_NETWORK)
                .expect("the decoded UFVK has an encoding"),
            encoded,
        );

        let testnet = encode_ufvk(&ufvk, &TEST_NETWORK).expect("the test UFVK has an encoding");
        assert!(testnet.starts_with(&hrp_prefix(constants::testnet::HRP_UNIFIED_FVK)));
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn uivk_is_revision_0_and_round_trips() {
        let uivk = test_ufvk().to_unified_incoming_viewing_key();
        let encoded = encode_uivk(&uivk, &MAIN_NETWORK).expect("the test UIVK has an encoding");
        assert!(encoded.starts_with(&hrp_prefix(constants::mainnet::HRP_UNIFIED_IVK)));

        let (_, revision, _) = unified::Uivk::decode(&encoded).expect("the encoding decodes");
        assert_eq!(revision, Revision::R0);

        let testnet = encode_uivk(&uivk, &TEST_NETWORK).expect("the test UIVK has an encoding");
        assert!(testnet.starts_with(&hrp_prefix(constants::testnet::HRP_UNIFIED_IVK)));
    }
}
