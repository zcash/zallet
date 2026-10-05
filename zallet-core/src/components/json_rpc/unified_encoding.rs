//! ZIP 316 Revision 0 encodings of unified addresses and viewing keys for JSON-RPC
//! responses.
//!
//! TEMPORARY: `zcash_keys` encodes unified addresses and viewing keys only as ZIP 316
//! Revision 2 (`zu…`/`tu…`, `uvf…`, `uvi…`), which software that understands only
//! Revision 0 cannot parse. Until `zcash_keys` can encode Revision 0 itself, Zallet
//! re-encodes its output in the Revision 0 form that `zcashd` emitted (`u1…`, `uview1…`,
//! `uivk1…`). Anything Revision 0 cannot represent keeps its Revision 2 encoding.

use zcash_address::unified::{self, Container, Encoding, Revision};
use zcash_keys::address::UnifiedAddress;
use zcash_protocol::consensus::Parameters;

#[cfg(zallet_build = "wallet")]
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};

/// Encodes a unified address with every one of its receivers.
///
/// A transparent receiver is retained, as in `zcashd`'s Revision 0 addresses. An address
/// with no shielded receiver, or carrying metadata such as an expiry, has no Revision 0
/// form and is encoded as Revision 2.
pub(super) fn encode_unified_address(ua: &UnifiedAddress, params: &impl Parameters) -> String {
    to_revision_0::<unified::Address>(ua.encode_receiver_preserving(params))
}

/// Encodes a unified full viewing key.
///
/// A key carrying a P2SH viewing key item, which Revision 0 gives no meaning, or carrying
/// metadata, is encoded as Revision 2.
#[cfg(zallet_build = "wallet")]
pub(super) fn encode_ufvk(ufvk: &UnifiedFullViewingKey, params: &impl Parameters) -> String {
    let revision_2 = ufvk.encode(params);
    if ufvk.p2sh().is_some() {
        revision_2
    } else {
        to_revision_0::<unified::Ufvk>(revision_2)
    }
}

/// Encodes a unified incoming viewing key.
///
/// A key carrying a P2SH viewing key item, which Revision 0 gives no meaning, or carrying
/// metadata, is encoded as Revision 2.
#[cfg(zallet_build = "wallet")]
pub(super) fn encode_uivk(uivk: &UnifiedIncomingViewingKey, params: &impl Parameters) -> String {
    let revision_2 = uivk.encode(params);
    if uivk.p2sh().is_some() {
        revision_2
    } else {
        to_revision_0::<unified::Uivk>(revision_2)
    }
}

/// Re-encodes a Revision 2 unified container as Revision 0 with the same items, or returns
/// it unchanged if Revision 0 cannot represent them: it carries metadata, which Revision 0
/// predates, or has no shielded item.
fn to_revision_0<C>(revision_2: String) -> String
where
    C: Encoding + Container,
    C::Item: Clone,
{
    let Ok((network, _, container)) = C::decode(&revision_2) else {
        return revision_2;
    };
    if !container.metadata_items().is_empty() {
        return revision_2;
    }
    match C::try_from_items(Revision::R0, container.items_as_parsed().to_vec()) {
        Ok(revision_0) => revision_0.encode(&network),
        Err(_) => revision_2,
    }
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
        let encoded = encode_ufvk(&ufvk, &MAIN_NETWORK);
        assert!(encoded.starts_with(&hrp_prefix(constants::mainnet::HRP_UNIFIED_FVK)));

        let decoded = UnifiedFullViewingKey::decode(&MAIN_NETWORK, &encoded)
            .expect("the Revision 0 encoding decodes");
        assert_eq!(decoded.encode(&MAIN_NETWORK), ufvk.encode(&MAIN_NETWORK));

        let testnet = encode_ufvk(&ufvk, &TEST_NETWORK);
        assert!(testnet.starts_with(&hrp_prefix(constants::testnet::HRP_UNIFIED_FVK)));
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn uivk_is_revision_0_and_round_trips() {
        let uivk = test_ufvk().to_unified_incoming_viewing_key();
        let encoded = encode_uivk(&uivk, &MAIN_NETWORK);
        assert!(encoded.starts_with(&hrp_prefix(constants::mainnet::HRP_UNIFIED_IVK)));

        let (_, revision, _) = unified::Uivk::decode(&encoded).expect("the encoding decodes");
        assert_eq!(revision, Revision::R0);

        let testnet = encode_uivk(&uivk, &TEST_NETWORK);
        assert!(testnet.starts_with(&hrp_prefix(constants::testnet::HRP_UNIFIED_IVK)));
    }
}
