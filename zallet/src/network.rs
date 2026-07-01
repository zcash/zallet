//! Zcash network parameters.

use serde::{Deserialize, Serialize};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    local_consensus,
};

/// Chain parameters for a Zcash consensus network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// A public global consensus network.
    Consensus(consensus::Network),
    /// A local network used for integration testing.
    RegTest(local_consensus::LocalNetwork),
}

impl Network {
    pub(crate) fn from_type(
        network_type: consensus::NetworkType,
        nuparams: &[RegTestNuParam],
    ) -> Self {
        match network_type {
            consensus::NetworkType::Main => Self::Consensus(consensus::Network::MainNetwork),
            consensus::NetworkType::Test => Self::Consensus(consensus::Network::TestNetwork),
            consensus::NetworkType::Regtest => {
                let find_nu = |nu: consensus::BranchId| {
                    nuparams
                        .iter()
                        .find(|p| p.consensus_branch_id == nu)
                        .map(|p| p.activation_height)
                };

                // If a NU is omitted, ensure that it activates at the same height as the
                // subsequent specified NU (if any).
                #[cfg(zcash_unstable = "nu7")]
                let nu7 = find_nu(consensus::BranchId::Nu7);
                let nu6_3 = find_nu(consensus::BranchId::Nu6_3);
                #[cfg(zcash_unstable = "nu7")]
                let nu6_3 = nu6_3.or(nu7);
                let nu6_2 = find_nu(consensus::BranchId::Nu6_2).or(nu6_3);
                let nu6_1 = find_nu(consensus::BranchId::Nu6_1).or(nu6_2);
                let nu6 = find_nu(consensus::BranchId::Nu6).or(nu6_1);
                let nu5 = find_nu(consensus::BranchId::Nu5).or(nu6);
                let canopy = find_nu(consensus::BranchId::Canopy).or(nu5);
                let heartwood = find_nu(consensus::BranchId::Heartwood).or(canopy);
                let blossom = find_nu(consensus::BranchId::Blossom).or(heartwood);
                let sapling = find_nu(consensus::BranchId::Sapling).or(blossom);
                let overwinter = find_nu(consensus::BranchId::Overwinter).or(sapling);

                Self::RegTest(local_consensus::LocalNetwork {
                    overwinter,
                    sapling,
                    blossom,
                    heartwood,
                    canopy,
                    nu5,
                    nu6,
                    nu6_1,
                    nu6_2,
                    nu6_3,
                    #[cfg(zcash_unstable = "nu7")]
                    nu7,
                })
            }
        }
    }

    #[cfg(feature = "zaino")]
    pub(crate) fn to_zaino(self) -> zaino_common::Network {
        match self {
            Network::Consensus(network) => match network {
                consensus::Network::MainNetwork => zaino_common::Network::Mainnet,
                consensus::Network::TestNetwork => zaino_common::Network::Testnet,
            },
            // TODO: This does not create a compatible regtest network because Zebra does
            // not have the necessary flexibility.
            Network::RegTest(local_network) => {
                zaino_common::Network::Regtest(zaino_common::network::ActivationHeights {
                    before_overwinter: Some(1),
                    overwinter: local_network.overwinter.map(|h| h.into()),
                    sapling: local_network.sapling.map(|h| h.into()),
                    blossom: local_network.blossom.map(|h| h.into()),
                    heartwood: local_network.heartwood.map(|h| h.into()),
                    canopy: local_network.canopy.map(|h| h.into()),
                    nu5: local_network.nu5.map(|h| h.into()),
                    nu6: local_network.nu6.map(|h| h.into()),
                    nu6_1: local_network.nu6_1.map(|h| h.into()),
                    nu6_2: local_network.nu6_2.map(|h| h.into()),
                    nu7: None,
                })
            }
        }
    }

    /// Converts this network into the corresponding `zebra-chain` network.
    ///
    /// Returns an error for regtest, which the read-state-service backend does not
    /// support.
    #[cfg(any(feature = "zaino", feature = "zebra-state"))]
    pub(crate) fn to_zebra(self) -> Result<zebra_chain::parameters::Network, &'static str> {
        use zebra_chain::parameters::Network as ZebraNetwork;
        match self {
            Network::Consensus(consensus::Network::MainNetwork) => Ok(ZebraNetwork::Mainnet),
            Network::Consensus(consensus::Network::TestNetwork) => {
                Ok(ZebraNetwork::new_default_testnet())
            }
            Network::RegTest(_) => {
                Err("the read-state-service indexer backend does not support regtest")
            }
        }
    }
}

impl consensus::Parameters for Network {
    fn network_type(&self) -> consensus::NetworkType {
        match self {
            Self::Consensus(params) => params.network_type(),
            Self::RegTest(params) => params.network_type(),
        }
    }

    fn activation_height(&self, nu: consensus::NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Self::Consensus(params) => params.activation_height(nu),
            Self::RegTest(params) => params.activation_height(nu),
        }
    }
}

/// A parameter for regtest mode.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct RegTestNuParam {
    consensus_branch_id: consensus::BranchId,
    activation_height: BlockHeight,
}

impl TryFrom<String> for RegTestNuParam {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (branch_id, height) = value.split_once(':').ok_or("Invalid `regtest_nuparam`")?;

        let consensus_branch_id = u32::from_str_radix(branch_id, 16)
            .ok()
            .and_then(|branch_id| consensus::BranchId::try_from(branch_id).ok())
            .ok_or("Invalid `regtest_nuparam`")?;

        let activation_height = height
            .parse()
            .map(BlockHeight::from_u32)
            .map_err(|_| "Invalid `regtest_nuparam`")?;

        Ok(Self {
            consensus_branch_id,
            activation_height,
        })
    }
}

impl From<RegTestNuParam> for String {
    fn from(nuparam: RegTestNuParam) -> Self {
        format!(
            "{:08x}:{}",
            u32::from(nuparam.consensus_branch_id),
            nuparam.activation_height
        )
    }
}

#[cfg(all(test, feature = "zebra-state"))]
mod tests {
    use super::*;
    use zcash_protocol::consensus::NetworkType;
    use zebra_chain::parameters::Network as ZebraNetwork;

    #[test]
    fn to_zebra_maps_main_and_test() {
        let main = Network::from_type(NetworkType::Main, &[]);
        assert!(matches!(main.to_zebra(), Ok(ZebraNetwork::Mainnet)));

        let test = Network::from_type(NetworkType::Test, &[]);
        assert!(matches!(test.to_zebra(), Ok(ZebraNetwork::Testnet(_))));
    }

    #[test]
    fn to_zebra_rejects_regtest() {
        let regtest = Network::from_type(NetworkType::Regtest, &[]);
        assert!(regtest.to_zebra().is_err());
    }
}

pub(crate) mod kind {
    use std::fmt;

    use rusqlite::{
        ToSql,
        types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, ValueRef},
    };
    use serde::{Deserializer, Serializer, de::Visitor};
    use zcash_protocol::consensus::NetworkType;

    fn str_to_type(s: &str) -> Option<NetworkType> {
        match s {
            "main" => Some(NetworkType::Main),
            "test" => Some(NetworkType::Test),
            "regtest" => Some(NetworkType::Regtest),
            _ => None,
        }
    }

    pub(crate) fn type_to_str(network_type: &NetworkType) -> &'static str {
        match network_type {
            NetworkType::Main => "main",
            NetworkType::Test => "test",
            NetworkType::Regtest => "regtest",
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<NetworkType, D::Error> {
        struct NetworkTypeVisitor;
        impl Visitor<'_> for NetworkTypeVisitor {
            type Value = NetworkType;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "one of 'main', 'test', or 'regtest'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                str_to_type(v).ok_or_else(|| {
                    serde::de::Error::invalid_type(serde::de::Unexpected::Str(v), &self)
                })
            }
        }

        deserializer.deserialize_str(NetworkTypeVisitor)
    }

    pub(crate) fn serialize<S: Serializer>(
        network_type: &NetworkType,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(type_to_str(network_type))
    }

    #[derive(serde::Serialize)]
    pub(crate) struct Serializable(#[serde(with = "crate::network::kind")] pub(crate) NetworkType);

    pub(crate) struct Sql(pub(crate) NetworkType);

    impl FromSql for Sql {
        fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
            str_to_type(value.as_str()?)
                .ok_or(FromSqlError::InvalidType)
                .map(Self)
        }
    }

    impl ToSql for Sql {
        fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
            Ok(ToSqlOutput::Borrowed(ValueRef::Text(
                type_to_str(&self.0).as_bytes(),
            )))
        }
    }
}
