use std::{
    collections::{BTreeMap, HashSet},
    mem,
};

use documented::Documented;
use jsonrpsee::{
    core::RpcResult,
    tracing::{error, warn},
    types::{ErrorCode as RpcErrorCode, ErrorObjectOwned},
};
use nonempty::NonEmpty;
use schemars::JsonSchema;
use serde::Serialize;
use transparent::keys::TransparentKeyScope;
use zcash_address::unified;
use zcash_client_backend::data_api::{
    Account as _, AccountPurpose, AccountSource, WalletRead, Zip32Derivation,
};
use zcash_keys::address::Address;
use zcash_keys::encoding::AddressCodec;
use zcash_protocol::consensus::NetworkConstants;

use crate::components::{database::DbConnection, json_rpc::server::LegacyCode};

/// Response to a `listaddresses` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// A list of address sources.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(Vec<AddressSource>);

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct AddressSource {
    source: &'static str,

    /// This object contains transparent addresses for which we have no derivation
    /// information.
    #[serde(skip_serializing_if = "Option::is_none")]
    transparent: Option<TransparentAddresses>,

    /// Each element in this list represents a set of transparent addresses derived from a
    /// single BIP 44 account index.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    derived_transparent: Vec<DerivedTransparentAddresses>,

    /// Each element in this list represents a set of diversified addresses derived from a
    /// single IVK.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sapling: Vec<SaplingAddresses>,

    /// Each element in this list represents a set of diversified Unified Addresses
    /// derived from a single UFVK.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unified: Vec<UnifiedAddresses>,
}

impl AddressSource {
    fn empty(source: &'static str) -> Self {
        Self {
            source,
            transparent: None,
            derived_transparent: vec![],
            sapling: vec![],
            unified: vec![],
        }
    }

    fn has_data(&self) -> bool {
        self.transparent.is_some()
            || !self.derived_transparent.is_empty()
            || !self.sapling.is_empty()
            || !self.unified.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct TransparentAddresses {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,

    #[serde(rename = "changeAddresses")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    change_addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct DerivedTransparentAddresses {
    seedfp: String,

    /// The BIP 44 account index.
    account: u32,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,

    #[serde(rename = "changeAddresses")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    change_addresses: Vec<String>,

    #[serde(rename = "ephemeralAddresses")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ephemeral_addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct SaplingAddresses {
    #[serde(rename = "zip32KeyPath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    zip32_key_path: Option<String>,

    addresses: Vec<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct UnifiedAddresses {
    #[serde(skip_serializing_if = "Option::is_none")]
    seedfp: Option<String>,

    /// The ZIP 32 account index.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<u32>,

    addresses: Vec<UnifiedAddress>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct UnifiedAddress {
    /// The diversifier index that the UA was derived at.
    diversifier_index: u128,

    /// The receiver types that the UA contains (valid values are "p2pkh", "sapling", "orchard").
    receiver_types: Vec<String>,

    /// The unified address corresponding to the diversifier.
    address: String,
}

/// A transparent address of one account, with the key scope deciding which list it
/// belongs in.
///
/// A `None` scope means the address was imported rather than derived — a standalone
/// public key or redeem script — and so has no derivation information of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TransparentReceiver {
    address: String,
    scope: Option<TransparentKeyScope>,
}

/// The lists `listaddresses` splits an account's transparent addresses into.
///
/// The first three are derived, and are reported together with the ZIP 32 derivation
/// of the account they belong to. `imported` addresses have no derivation of their
/// own and are reported apart from it.
#[derive(Debug, Default, PartialEq, Eq)]
struct TransparentBuckets {
    external: Vec<String>,
    change: Vec<String>,
    ephemeral: Vec<String>,
    imported: Vec<String>,
}

/// Splits an account's transparent addresses into the lists `listaddresses` reports.
///
/// The wallet enumerates transparent addresses two ways and neither is complete on
/// its own. `list_addresses` reports only addresses that have been exposed, and a
/// standalone import never is, so it is missing from `listed` entirely.
/// `get_transparent_receivers` applies no such filter and reports every receiver the
/// account tracks, imports included.
///
/// `tracked` is therefore consulted only for what it alone can supply: an address with
/// no derivation of its own. `listed` is taken first, and an address in both is
/// reported once.
///
/// Every unrecognized scope is returned, and only from `listed`. Ordering the buckets
/// and phrasing the error are the caller's job; the tests below carry the reasoning
/// behind each of these choices.
fn bucket_transparent(
    listed: Vec<TransparentReceiver>,
    tracked: Vec<TransparentReceiver>,
) -> Result<TransparentBuckets, NonEmpty<(String, TransparentKeyScope)>> {
    let mut seen = HashSet::new();
    let mut buckets = TransparentBuckets::default();
    let mut unrecognized = vec![];
    let tracked = tracked
        .into_iter()
        .filter(|receiver| receiver.scope.is_none());
    for receiver in listed.into_iter().chain(tracked) {
        if !seen.insert(receiver.address.clone()) {
            continue;
        }
        match receiver.scope {
            Some(TransparentKeyScope::EXTERNAL) => buckets.external.push(receiver.address),
            None => buckets.imported.push(receiver.address),
            Some(TransparentKeyScope::INTERNAL) => buckets.change.push(receiver.address),
            Some(TransparentKeyScope::EPHEMERAL) => buckets.ephemeral.push(receiver.address),
            Some(other) => unrecognized.push((receiver.address, other)),
        }
    }
    match NonEmpty::from_vec(unrecognized) {
        Some(unrecognized) => Err(unrecognized),
        None => Ok(buckets),
    }
}

pub(crate) fn call(wallet: &DbConnection) -> Response {
    let mut imported_watchonly = AddressSource::empty("imported_watchonly");
    let mut mnemonic_seed = AddressSource::empty("mnemonic_seed");

    for account_id in wallet
        .get_account_ids()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
    {
        let account = wallet
            .get_account(account_id)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            // This would be a race condition between this and account deletion.
            .ok_or(RpcErrorCode::InternalError)?;

        let addresses = wallet
            .list_addresses(account.id())
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

        let mut listed_transparent = vec![];
        let mut sapling_addresses = vec![];
        let mut unified_addresses = vec![];

        for address_info in addresses {
            let addr = address_info.address();
            match addr {
                Address::Transparent(_) | Address::Tex(_) => {
                    listed_transparent.push(TransparentReceiver {
                        address: addr.encode(wallet.params()),
                        scope: address_info.source().transparent_key_scope().copied(),
                    });
                }
                Address::Sapling(_) => sapling_addresses.push(addr.encode(wallet.params())),
                Address::Unified(addr) => {
                    let address = addr.encode(wallet.params());
                    unified_addresses.push(UnifiedAddress {
                        diversifier_index: match address_info.source() {
                            zcash_client_backend::data_api::AddressSource::Derived {
                                diversifier_index,
                                ..
                            } => diversifier_index.into(),
                            #[cfg(feature = "transparent-key-import")]
                            zcash_client_backend::data_api::AddressSource::Standalone => {
                                error!(
                                    "Unified address {} lacks HD derivation information.",
                                    address
                                );
                                return Err(RpcErrorCode::InternalError.into());
                            }
                        },
                        receiver_types: addr
                            .receiver_types()
                            .into_iter()
                            .map(|r| match r {
                                unified::Typecode::P2pkh => "p2pkh".into(),
                                unified::Typecode::P2sh => "p2sh".into(),
                                unified::Typecode::Sapling => "sapling".into(),
                                unified::Typecode::Orchard => "orchard".into(),
                                unified::Typecode::Unknown(typecode) => {
                                    format!("unknown({typecode})")
                                }
                            })
                            .collect(),
                        address,
                    })
                }
            }
        }

        // Every transparent receiver the account tracks, which unlike `list_addresses`
        // includes standalone imported public keys and redeem scripts. The wallet
        // returns them in a `HashMap`, whose iteration order would vary between calls
        // for no reason a caller could see, so they are taken in address order.
        let tracked_transparent = wallet
            .get_transparent_receivers(account.id(), true, true)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(addr, metadata)| TransparentReceiver {
                address: addr.encode(wallet.params()),
                scope: metadata.scope(),
            })
            .collect();

        let mut buckets =
            bucket_transparent(listed_transparent, tracked_transparent).map_err(|e| {
                for (address, scope) in e {
                    error!("Unexpected {scope:?} for address {address}");
                }
                ErrorObjectOwned::from(RpcErrorCode::InternalError)
            })?;

        let add_addrs = |source: &mut AddressSource, derivation: Option<&Zip32Derivation>| {
            let seedfp = derivation
                .as_ref()
                .map(|d| d.seed_fingerprint().to_string());
            let account = derivation.as_ref().map(|d| d.account_index().into());

            // Addresses to report without any derivation information beside them.
            let mut underived_addresses = vec![];
            let mut underived_change_addresses = vec![];

            if !(buckets.external.is_empty()
                && buckets.change.is_empty()
                && buckets.ephemeral.is_empty())
            {
                if let Some((seedfp, account)) = seedfp.clone().zip(account) {
                    source
                        .derived_transparent
                        .push(DerivedTransparentAddresses {
                            seedfp,
                            account,
                            addresses: mem::take(&mut buckets.external),
                            change_addresses: mem::take(&mut buckets.change),
                            ephemeral_addresses: mem::take(&mut buckets.ephemeral),
                        });
                } else {
                    if !buckets.ephemeral.is_empty() {
                        warn!(
                            "Account {} has used transparent ephemeral addresses, but no derivation information",
                            account_id.expose_uuid(),
                        );
                    }

                    underived_addresses.append(&mut buckets.external);
                    underived_change_addresses.append(&mut buckets.change);
                }
            }

            // A standalone import is reported here even when its account is derived.
            // It is not reachable from the account's seed and ZIP 32 index, so listing
            // it beside the addresses that are would misdescribe what restoring from
            // that mnemonic recovers.
            underived_addresses.append(&mut buckets.imported);

            if !(underived_addresses.is_empty() && underived_change_addresses.is_empty()) {
                let transparent = source.transparent.get_or_insert(TransparentAddresses {
                    addresses: vec![],
                    change_addresses: vec![],
                });
                transparent.addresses.append(&mut underived_addresses);
                transparent
                    .change_addresses
                    .append(&mut underived_change_addresses);
            }

            if !sapling_addresses.is_empty() {
                source.sapling.push(SaplingAddresses {
                    zip32_key_path: account.map(|account_index| {
                        format!("m/32'/{}'/{}'", wallet.params().coin_type(), account_index)
                    }),
                    addresses: sapling_addresses,
                });
            }

            source.unified.push(UnifiedAddresses {
                seedfp,
                account,
                addresses: unified_addresses,
            });
        };

        match account.source() {
            AccountSource::Derived { derivation, .. } => {
                add_addrs(&mut mnemonic_seed, Some(derivation));
            }
            AccountSource::Imported { purpose, .. } => {
                let derivation = match purpose {
                    // Imported UFVKs marked for spending are still counted as watch-only
                    // because their corresponding spending key has never been observed by the
                    // wallet; the distinction only affects whether Zallet tracks additional
                    // metadata about the UFVK's notes. The `imported` category was used by
                    // `zcashd` where individual spending keys were imported into the wallet.
                    AccountPurpose::Spending { derivation } => derivation.as_ref(),
                    AccountPurpose::ViewOnly => None,
                };

                add_addrs(&mut imported_watchonly, derivation);
            }
        }
    }

    Ok(ResultType(
        [
            imported_watchonly.has_data().then_some(imported_watchonly),
            mnemonic_seed.has_data().then_some(mnemonic_seed),
        ]
        .into_iter()
        .flatten()
        .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derived(address: &str, scope: TransparentKeyScope) -> TransparentReceiver {
        TransparentReceiver {
            address: address.into(),
            scope: Some(scope),
        }
    }

    /// An imported address has no derivation, and so no key scope.
    fn imported(address: &str) -> TransparentReceiver {
        TransparentReceiver {
            address: address.into(),
            scope: None,
        }
    }

    /// The two lowest custom key scopes. A [`TransparentKeyScope`] is any index
    /// below 2^31, of which only the three standardized ones mean anything to
    /// `listaddresses`, so these stand in for whatever else the wallet might
    /// hand it.
    const FIRST_CUSTOM_SCOPE: u32 = 3;
    const SECOND_CUSTOM_SCOPE: u32 = 4;

    fn custom_scope(scope: u32) -> TransparentKeyScope {
        TransparentKeyScope::custom(scope).expect("custom scopes are below 2^31")
    }

    /// An address derived under a scope this function has no bucket for.
    fn custom(address: &str, scope: u32) -> TransparentReceiver {
        derived(address, custom_scope(scope))
    }

    #[test]
    fn splits_derived_addresses_by_scope() {
        let buckets = bucket_transparent(
            vec![
                derived("external", TransparentKeyScope::EXTERNAL),
                derived("change", TransparentKeyScope::INTERNAL),
                derived("ephemeral", TransparentKeyScope::EPHEMERAL),
            ],
            vec![],
        )
        .unwrap();

        assert_eq!(
            buckets,
            TransparentBuckets {
                external: vec!["external".into()],
                change: vec!["change".into()],
                ephemeral: vec!["ephemeral".into()],
                imported: vec![],
            },
        );
    }

    /// A standalone import — a public key or a redeem script — has no `AddressInfo`
    /// record, so it reaches us only through the tracked receivers. Dropping it is
    /// what makes a P2SH address created by `addmultisigaddress` (or imported by
    /// `z_importaddress`) invisible in `listaddresses`.
    ///
    /// It must land in `imported` rather than `external`: the caller reports the
    /// derived lists beneath the account's seed fingerprint and ZIP 32 index, and an
    /// import cannot be recovered from either.
    #[test]
    fn reports_an_address_known_only_as_a_tracked_receiver() {
        let buckets = bucket_transparent(vec![], vec![imported("imported")]).unwrap();

        assert_eq!(
            buckets,
            TransparentBuckets {
                external: vec![],
                change: vec![],
                ephemeral: vec![],
                imported: vec!["imported".into()],
            },
        );
    }

    /// An account can hold both, and the two must not be conflated: only the derived
    /// address is reachable from the account's seed.
    #[test]
    fn keeps_an_imported_address_apart_from_the_derived_ones() {
        let buckets = bucket_transparent(
            vec![derived("derived", TransparentKeyScope::EXTERNAL)],
            vec![imported("imported")],
        )
        .unwrap();

        assert_eq!(
            buckets,
            TransparentBuckets {
                external: vec!["derived".into()],
                change: vec![],
                ephemeral: vec![],
                imported: vec!["imported".into()],
            },
        );
    }

    /// The enumerations overlap once an import has been exposed — receiving funds is
    /// enough — after which it is in both, and must not be reported twice.
    #[test]
    fn reports_an_address_in_both_enumerations_once() {
        let buckets =
            bucket_transparent(vec![imported("shared")], vec![imported("shared")]).unwrap();

        assert_eq!(
            buckets,
            TransparentBuckets {
                external: vec![],
                change: vec![],
                ephemeral: vec![],
                imported: vec!["shared".into()],
            },
        );
    }

    /// `tracked` holds derived receivers that `listed` does not: the transparent
    /// receiver cached on each Unified Address, and the addresses generated ahead of
    /// use to fill the gap limit, which are reported only once exposed. Neither is
    /// what consulting `tracked` is for, and reporting them would put addresses the
    /// wallet has never handed out into `derived_transparent`.
    #[test]
    fn ignores_a_derived_address_known_only_as_a_tracked_receiver() {
        let buckets = bucket_transparent(
            vec![],
            vec![
                derived("external", TransparentKeyScope::EXTERNAL),
                derived("change", TransparentKeyScope::INTERNAL),
            ],
        )
        .unwrap();

        assert_eq!(buckets, TransparentBuckets::default());
    }

    /// An unrecognized scope fails the whole call, so which addresses are examined for
    /// one decides which wallets `listaddresses` will refuse to answer for. Consulting
    /// `tracked` must not widen that: an address dropped for having a derivation is
    /// dropped before its scope is anyone's business.
    #[test]
    fn ignores_an_unrecognized_scope_from_the_tracked_receivers() {
        let buckets =
            bucket_transparent(vec![], vec![custom("custom", FIRST_CUSTOM_SCOPE)]).unwrap();

        assert_eq!(buckets, TransparentBuckets::default());
    }

    /// A scope with no bucket is a wallet-internal inconsistency, and every address
    /// carrying one is evidence of it. Stopping at the first would report whichever
    /// address the enumeration happened to reach first and leave the rest of the
    /// evidence undiscovered until the operator looked again — hence the recognized
    /// address between the two offenders, which a short-circuit would never reach.
    #[test]
    fn reports_every_unrecognized_scope() {
        let unrecognized = bucket_transparent(
            vec![
                custom("first", FIRST_CUSTOM_SCOPE),
                derived("external", TransparentKeyScope::EXTERNAL),
                custom("second", SECOND_CUSTOM_SCOPE),
            ],
            vec![],
        )
        .unwrap_err();

        assert_eq!(
            unrecognized,
            NonEmpty::from((
                ("first".into(), custom_scope(FIRST_CUSTOM_SCOPE)),
                vec![("second".into(), custom_scope(SECOND_CUSTOM_SCOPE))],
            )),
        );
    }
}
