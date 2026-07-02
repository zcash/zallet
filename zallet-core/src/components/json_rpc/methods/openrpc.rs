use std::borrow::Cow;

use crate::components::json_rpc::payments::AmountParameter;
use documented::Documented;
use jsonrpsee::core::{JsonValue, RpcResult};
use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings};
use serde::Serialize;

// Imports to work around deficiencies in the build script.
#[cfg(zallet_build = "wallet")]
use super::{super::asyncop::OperationId, recover_accounts};

// See `generate_rpc_help()` in `build.rs` for how this is generated.
include!(concat!(env!("OUT_DIR"), "/rpc_openrpc.rs"));

/// Response to an `rpc.discover` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = OpenRpc;

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

/// Static information about a Zallet JSON-RPC method.
pub(super) struct RpcMethod {
    pub(super) description: &'static str,
    params: fn(&mut Generator) -> Vec<ContentDescriptor>,
    result: fn(&mut Generator) -> ContentDescriptor,
    deprecated: bool,
}

impl RpcMethod {
    fn generate(&self, generator: &mut Generator, name: &'static str) -> Method {
        let description = self.description.trim();

        Method {
            name,
            summary: description
                .split_once('\n')
                .map(|(summary, _)| summary)
                .unwrap_or(description),
            description,
            params: (self.params)(generator),
            result: (self.result)(generator),
            deprecated: self.deprecated,
        }
    }
}

/// An OpenRPC document generator.
pub(super) struct Generator {
    inner: SchemaGenerator,
}

impl Generator {
    fn new() -> Self {
        Self {
            inner: SchemaSettings::draft07()
                .with(|s| {
                    s.definitions_path = "#/components/schemas/".into();
                })
                .into_generator(),
        }
    }

    /// Constructs the descriptor for a JSON-RPC method parameter.
    pub(super) fn param<T: JsonSchema>(
        &mut self,
        name: &'static str,
        description: &'static str,
        required: bool,
    ) -> ContentDescriptor {
        ContentDescriptor {
            name,
            summary: description
                .split_once('\n')
                .map(|(summary, _)| summary)
                .unwrap_or(description),
            description,
            required,
            schema: self.inner.subschema_for::<T>(),
            deprecated: false,
        }
    }

    /// Constructs the descriptor for a JSON-RPC method's result type.
    pub(super) fn result<T: Documented + JsonSchema>(
        &mut self,
        name: &'static str,
    ) -> ContentDescriptor {
        ContentDescriptor {
            name,
            summary: T::DOCS
                .split_once('\n')
                .map(|(summary, _)| summary)
                .unwrap_or(T::DOCS),
            description: T::DOCS,
            required: false,
            schema: self.inner.subschema_for::<T>(),
            deprecated: false,
        }
    }

    fn into_components(mut self) -> Components {
        Components {
            schemas: self.inner.take_definitions(false),
        }
    }
}

/// An OpenRPC document.
#[derive(Clone, Debug, Serialize, Documented)]
pub(crate) struct OpenRpc {
    openrpc: &'static str,
    info: Info,
    methods: Vec<Method>,
    components: Components,
}

impl JsonSchema for OpenRpc {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("OpenRPC Schema")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        Schema::new_ref(
            "https://raw.githubusercontent.com/open-rpc/meta-schema/master/schema.json".into(),
        )
    }
}

#[derive(Clone, Debug, Serialize)]
struct Info {
    title: &'static str,
    description: &'static str,
    version: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Method {
    name: &'static str,
    summary: &'static str,
    description: &'static str,
    params: Vec<ContentDescriptor>,
    result: ContentDescriptor,
    #[serde(skip_serializing_if = "is_false")]
    deprecated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ContentDescriptor {
    name: &'static str,
    summary: &'static str,
    description: &'static str,
    #[serde(skip_serializing_if = "is_false")]
    required: bool,
    schema: Schema,
    #[serde(skip_serializing_if = "is_false")]
    deprecated: bool,
}

#[derive(Clone, Debug, Serialize)]
struct Components {
    schemas: serde_json::Map<String, JsonValue>,
}

fn is_false(b: &bool) -> bool {
    !b
}
