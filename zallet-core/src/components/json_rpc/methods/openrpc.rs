use crate::components::json_rpc::payments::AmountParameter;
use jsonrpsee::core::JsonValue;
use openrpsee::openrpc::{Generator, Info, OpenRpc};

// Imports to work around deficiencies in the build script.
#[cfg(zallet_build = "wallet")]
use super::{super::asyncop::OperationId, recover_accounts};

// See `generate_rpc_openrpc()` in `build.rs` for how this is generated.
include!(concat!(env!("OUT_DIR"), "/rpc_openrpc.rs"));

/// Response to an `rpc.discover` RPC request.
pub(crate) type Response = openrpsee::openrpc::Response;
pub(crate) type ResultType = openrpsee::openrpc::ResultType;

pub(crate) fn call() -> Response {
    let mut generator = Generator::new();

    let methods = METHODS
        .into_iter()
        .map(|(name, method)| method.generate(&mut generator, name))
        .collect();

    Ok(OpenRpc {
        openrpc: "1.3.2",
        info: Info {
            title: "Zallet",
            description: crate::build::PKG_DESCRIPTION,
            version: crate::build::PKG_VERSION,
        },
        methods,
        components: generator.into_components(),
    })
}
