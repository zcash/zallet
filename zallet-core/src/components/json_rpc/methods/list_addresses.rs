use documented::Documented;
use jsonrpsee::{
    core::RpcResult,
    tracing::{error, warn},
    types::ErrorCode as RpcErrorCode,
};
use schemars::JsonSchema;
use serde::Serialize;
use transparent::keys::TransparentKeyScope;
use zcash_address::unified;
use zcash_client_backend::data_api::{
    Account as _, AccountPurpose, AccountSource, WalletRead, Zip32Derivation,
};
use zcash_keys::address::Address;
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

        let mut transparent_addresses = vec![];
        let mut transparent_change_addresses = vec![];
        let mut transparent_ephemeral_addresses = vec![];
        let mut sapling_addresses = vec![];
        let mut unified_addresses = vec![];

        for address_info in addresses {
            let addr = address_info.address();
            match addr {
                Address::Transparent(_) | Address::Tex(_) => {
                    match address_info.source().transparent_key_scope() {
                        Some(&TransparentKeyScope::EXTERNAL) | None => {
                            // 'None' scope keys are imported, which must be treated as external
                            transparent_addresses.push(addr.encode(wallet.params()));
                        }
                        Some(&TransparentKeyScope::INTERNAL) => {
                            transparent_change_addresses.push(addr.encode(wallet.params()));
                        }
                        Some(&TransparentKeyScope::EPHEMERAL) => {
                            transparent_ephemeral_addresses.push(addr.encode(wallet.params()));
                        }
                        _ => {
                            error!(
                                "Unexpected {:?} for address {}",
                                address_info.source().transparent_key_scope(),
                                addr.encode(wallet.params()),
                            );
                            return Err(RpcErrorCode::InternalError.into());
                        }
                    }
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

        let add_addrs = |source: &mut AddressSource, derivation: Option<&Zip32Derivation>| {
            let seedfp = derivation
                .as_ref()
                .map(|d| d.seed_fingerprint().to_string());
            let account = derivation.as_ref().map(|d| d.account_index().into());

            if !(transparent_addresses.is_empty()
                && transparent_change_addresses.is_empty()
                && transparent_ephemeral_addresses.is_empty())
            {
                if let Some((seedfp, account)) = seedfp.clone().zip(account) {
                    source
                        .derived_transparent
                        .push(DerivedTransparentAddresses {
                            seedfp,
                            account,
                            addresses: transparent_addresses,
                            change_addresses: transparent_change_addresses,
                            ephemeral_addresses: transparent_ephemeral_addresses,
                        });
                } else {
                    if !transparent_ephemeral_addresses.is_empty() {
                        warn!(
                            "Account {} has used transparent ephemeral addresses, but no derivation information",
                            account_id.expose_uuid(),
                        );
                    }

                    let transparent = source.transparent.get_or_insert(TransparentAddresses {
                        addresses: vec![],
                        change_addresses: vec![],
                    });
                    transparent.addresses.append(&mut transparent_addresses);
                    transparent
                        .change_addresses
                        .append(&mut transparent_change_addresses);
                }
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
