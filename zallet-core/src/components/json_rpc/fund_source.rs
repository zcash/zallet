//! The `fund_source` parameter of the account-based transaction methods.
//!
//! `fund_source` names where an account's funds may be drawn from. It is translated into a
//! [`SpendPolicy`], which is what the proposal builder actually consumes, so the account-based
//! methods select inputs through exactly the same path as `z_sendmany`.

use std::collections::HashSet;

use jsonrpsee::core::{JsonValue, RpcResult};
use nonempty::NonEmpty;
use transparent::address::TransparentAddress;
use zcash_client_backend::data_api::wallet::input_selection::{
    SpendPolicy, TransparentSpendPolicy,
};
use zcash_keys::address::Address;
use zcash_protocol::ShieldedPool;

use crate::network::Network;

use super::server::LegacyCode;

/// Where an account's funds may be drawn from when constructing a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FundSource {
    /// Spend only Orchard-family notes.
    Orchard,
    /// Spend only Sapling notes.
    Sapling,
    /// Spend any of the account's transparent funds.
    AnyTransparent,
    /// Spend only transparent funds received at the given transparent addresses.
    Transparent(HashSet<TransparentAddress>),
}

impl FundSource {
    /// Parses a `fund_source` JSON-RPC argument.
    ///
    /// Accepts either one of the strings `"orchard"`, `"sapling"`, `"any_transparent"`, or a
    /// non-empty array of transparent address strings.
    pub(super) fn parse(value: &JsonValue, params: &Network) -> RpcResult<Self> {
        match value {
            JsonValue::String(s) => match s.as_str() {
                "orchard" => Ok(Self::Orchard),
                "sapling" => Ok(Self::Sapling),
                "any_transparent" => Ok(Self::AnyTransparent),
                other => Err(LegacyCode::InvalidParameter.with_message(format!(
                    "Invalid fund_source: expected \"orchard\", \"sapling\", \"any_transparent\", \
                     or an array of transparent addresses, got \"{other}\"."
                ))),
            },
            JsonValue::Array(addrs) => {
                if addrs.is_empty() {
                    return Err(LegacyCode::InvalidParameter.with_static(
                        "Invalid fund_source: the array of transparent addresses is empty.",
                    ));
                }
                let mut set = HashSet::new();
                for addr in addrs {
                    let s = addr.as_str().ok_or_else(|| {
                        LegacyCode::InvalidParameter.with_static(
                            "Invalid fund_source: array entries must be transparent address \
                             strings.",
                        )
                    })?;
                    match Address::decode(params, s) {
                        Some(Address::Transparent(ta)) => {
                            set.insert(ta);
                        }
                        _ => {
                            return Err(LegacyCode::InvalidParameter.with_message(format!(
                                "Invalid fund_source: \"{s}\" is not a transparent address."
                            )));
                        }
                    }
                }
                Ok(Self::Transparent(set))
            }
            _ => Err(LegacyCode::InvalidParameter.with_static(
                "Invalid fund_source: expected a string or an array of transparent addresses.",
            )),
        }
    }

    /// The sources of funds the proposal builder may draw upon for this `fund_source`.
    ///
    /// Each variant names exactly one kind of input and forbids the rest, which is the whole
    /// point of the parameter: naming `sapling` must not quietly spend an Orchard note, and
    /// naming a transparent address must not quietly spend a shielded one. A source that cannot
    /// cover the payment fails as insufficient funds rather than reaching into another pool.
    ///
    /// `Orchard` permits the Ironwood pool as well. Ironwood notes are Orchard-shaped, and once
    /// NU6.3 activates an account's Orchard-receiver funds are held there rather than in the
    /// legacy Orchard pool; restricting the source to `ShieldedPool::Orchard` alone would report
    /// insufficient funds for an account whose Orchard funds are all in Ironwood.
    ///
    /// Coinbase UTXOs are never drawn upon: `TransparentSpendPolicy` defaults to
    /// `CoinbasePolicy::NonCoinbase`, because consensus requires coinbase to be spent to a
    /// single shielded output, which is `z_shieldcoinbase`'s job.
    pub(super) fn spend_policy(&self) -> SpendPolicy {
        match self {
            Self::Orchard => {
                SpendPolicy::shielded_pools([ShieldedPool::Orchard, ShieldedPool::Ironwood])
            }
            Self::Sapling => SpendPolicy::shielded_pools([ShieldedPool::Sapling]),
            Self::AnyTransparent => SpendPolicy::shielded_pools([])
                .with_transparent(TransparentSpendPolicy::any_account_addr()),
            Self::Transparent(addrs) => {
                let mut addrs = addrs.iter().copied();
                let first = addrs
                    .next()
                    .expect("`parse` rejects an empty address array");
                let addrs = NonEmpty::from((first, addrs.collect()));

                SpendPolicy::shielded_pools([])
                    .with_transparent(TransparentSpendPolicy::from_addresses(addrs))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use zcash_client_backend::data_api::wallet::input_selection::{
        CoinbasePolicy, TransparentSource,
    };
    use zcash_keys::{
        encoding::AddressCodec,
        keys::{UnifiedAddressRequest, UnifiedSpendingKey},
    };
    use zcash_protocol::consensus;
    use zip32::AccountId;

    use super::*;

    fn test_params() -> Network {
        Network::Consensus(consensus::Network::TestNetwork)
    }

    /// A transparent address of the account derived from `seed`, and its string encoding.
    ///
    /// Returns `None` for the seeds ZIP 32 rejects, so a property can skip them rather than
    /// assert on an address that cannot exist.
    fn taddr_from(seed: &[u8; 32], account: u32) -> Option<TransparentAddress> {
        let params = test_params();
        let account = AccountId::try_from(account).ok()?;
        let usk = UnifiedSpendingKey::from_seed(&params, seed, account).ok()?;
        let (ua, _) = usk
            .to_unified_full_viewing_key()
            .default_address(UnifiedAddressRequest::ALLOW_ALL)
            .ok()?;
        ua.transparent().copied()
    }

    #[test]
    fn parses_the_string_sources() {
        let params = test_params();
        assert_eq!(
            FundSource::parse(&JsonValue::from("orchard"), &params).unwrap(),
            FundSource::Orchard,
        );
        assert_eq!(
            FundSource::parse(&JsonValue::from("sapling"), &params).unwrap(),
            FundSource::Sapling,
        );
        assert_eq!(
            FundSource::parse(&JsonValue::from("any_transparent"), &params).unwrap(),
            FundSource::AnyTransparent,
        );
    }

    #[test]
    fn rejects_an_unknown_source() {
        let params = test_params();
        assert!(FundSource::parse(&JsonValue::from("ironwood"), &params).is_err());
        assert!(FundSource::parse(&JsonValue::from("transparent"), &params).is_err());
        assert!(FundSource::parse(&JsonValue::from(7), &params).is_err());
    }

    #[test]
    fn rejects_an_empty_address_array() {
        let params = test_params();
        let empty = JsonValue::Array(vec![]);
        assert!(FundSource::parse(&empty, &params).is_err());
    }

    #[test]
    fn rejects_a_non_transparent_address_in_the_array() {
        let params = test_params();
        let seed = [3u8; 32];
        let usk = UnifiedSpendingKey::from_seed(&params, &seed, AccountId::ZERO).unwrap();
        let (ua, _) = usk
            .to_unified_full_viewing_key()
            .default_address(UnifiedAddressRequest::ALLOW_ALL)
            .unwrap();

        // A unified address is not a transparent address, even though it has a transparent
        // receiver: the array names the addresses whose UTXOs may be spent, and a UA does not
        // identify one.
        let arr = JsonValue::Array(vec![JsonValue::from(ua.encode(&params))]);
        assert!(FundSource::parse(&arr, &params).is_err());
    }

    /// A shielded source must never permit transparent spending, and must permit only the pool
    /// it names: the parameter exists to bound where the funds come from.
    #[test]
    fn shielded_sources_permit_only_their_own_pool() {
        let orchard = FundSource::Orchard.spend_policy();
        assert!(orchard.transparent().is_none());
        assert!(orchard.permits_shielded(ShieldedPool::Orchard));
        // Orchard-receiver funds live in Ironwood once NU6.3 activates.
        assert!(orchard.permits_shielded(ShieldedPool::Ironwood));
        assert!(!orchard.permits_shielded(ShieldedPool::Sapling));

        let sapling = FundSource::Sapling.spend_policy();
        assert!(sapling.transparent().is_none());
        assert!(sapling.permits_shielded(ShieldedPool::Sapling));
        assert!(!sapling.permits_shielded(ShieldedPool::Orchard));
        assert!(!sapling.permits_shielded(ShieldedPool::Ironwood));
    }

    /// `any_transparent` spends the account's transparent funds and no shielded note. The
    /// permitted-pool set being empty says so exhaustively, including for any pool added later.
    #[test]
    fn any_transparent_permits_transparent_and_no_shielded_pool() {
        let policy = FundSource::AnyTransparent.spend_policy();

        assert!(policy.shielded().is_empty());

        let transparent = policy
            .transparent()
            .expect("transparent spending permitted");
        assert!(matches!(
            transparent.source(),
            TransparentSource::AnyAccountAddr,
        ));
        assert_eq!(transparent.coinbase(), CoinbasePolicy::NonCoinbase);
    }

    proptest! {
        // Each case derives a spending key, which is expensive, so take fewer samples than the
        // default 256. The properties hold for every address, not for rare corners of the seed
        // space, so a modest sample establishes them.
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Naming transparent addresses confines selection to exactly those addresses, and to
        /// no shielded pool.
        #[test]
        fn named_transparent_addresses_are_the_only_source(
            seed in any::<[u8; 32]>(),
            account in 0u32..(1 << 31),
        ) {
            let Some(taddr) = taddr_from(&seed, account) else { return Ok(()) };

            let source = FundSource::Transparent([taddr].into_iter().collect());
            let policy = source.spend_policy();

            prop_assert!(policy.shielded().is_empty());

            let transparent = policy
                .transparent()
                .expect("a transparent source permits transparent spending");

            match transparent.source() {
                TransparentSource::FromAddresses(addrs) => prop_assert_eq!(
                    addrs.iter().copied().collect::<Vec<_>>(),
                    vec![taddr],
                ),
                other => prop_assert!(false, "expected named addresses, got {other:?}"),
            }
            prop_assert_eq!(transparent.coinbase(), CoinbasePolicy::NonCoinbase);
        }

        /// A transparent address round-trips through the JSON parameter.
        #[test]
        fn parses_an_array_of_transparent_addresses(
            seed in any::<[u8; 32]>(),
            account in 0u32..(1 << 31),
        ) {
            let params = test_params();
            let Some(taddr) = taddr_from(&seed, account) else { return Ok(()) };

            let arr = JsonValue::Array(vec![JsonValue::from(taddr.encode(&params))]);
            let parsed = FundSource::parse(&arr, &params).expect("a valid transparent address");

            prop_assert_eq!(
                parsed,
                FundSource::Transparent([taddr].into_iter().collect()),
            );
        }
    }
}
