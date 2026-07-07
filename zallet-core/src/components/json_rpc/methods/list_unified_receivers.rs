use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use transparent::address::TransparentAddress;
use zcash_address::ZcashAddress;
use zcash_keys::{address::UnifiedAddress, encoding::AddressCodec};

use crate::components::{database::DbConnection, json_rpc::server::LegacyCode};

/// Response to a `z_listunifiedreceivers` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = ListUnifiedReceivers;

/// The receivers within a unified address.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ListUnifiedReceivers {
    /// The legacy P2PKH transparent address.
    ///
    /// Omitted if `p2sh` is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    p2pkh: Option<String>,

    /// The legacy P2SH transparent address.
    ///
    /// Omitted if `p2pkh` is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    p2sh: Option<String>,

    /// The legacy Sapling address.
    #[serde(skip_serializing_if = "Option::is_none")]
    sapling: Option<String>,

    /// A single-receiver Unified Address containing the Orchard receiver.
    #[serde(skip_serializing_if = "Option::is_none")]
    orchard: Option<String>,
}

pub(super) const PARAM_UNIFIED_ADDRESS_DESC: &str = "The unified address to inspect.";

pub(crate) fn call(wallet: &DbConnection, unified_address: &str) -> Response {
    ZcashAddress::try_from_encoded(unified_address)
        .map_err(|_| LegacyCode::InvalidAddressOrKey.with_message("Invalid address".to_string()))?;

    let address = match UnifiedAddress::decode(wallet.params(), unified_address) {
        Ok(addr) => addr,
        Err(_) => {
            return Err(LegacyCode::InvalidParameter
                .with_message("Address is not a unified address".to_string()));
        }
    };

    let transparent = address.transparent().map(|taddr| match taddr {
        TransparentAddress::PublicKeyHash(_) => (Some(taddr.encode(wallet.params())), None),
        TransparentAddress::ScriptHash(_) => (None, Some(taddr.encode(wallet.params()))),
    });

    let (p2pkh, p2sh) = transparent.unwrap_or((None, None));

    let sapling = address.sapling().map(|s| s.encode(wallet.params()));

    let orchard = address.orchard().and_then(|orch| {
        UnifiedAddress::from_receivers(Some(*orch), None, None).map(|ua| ua.encode(wallet.params()))
    });

    Ok(ListUnifiedReceivers {
        p2pkh,
        p2sh,
        sapling,
        orchard,
    })
}
