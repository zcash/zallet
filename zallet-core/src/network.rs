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

/// The network upgrades this build of Zallet recognizes, in activation order. Sprout
/// (branch ID 0) and ZFuture are excluded: they are not configurable network upgrades and a
/// full node never reports them. This is the single source of truth for the set of upgrades;
/// both regtest configuration (here) and the consensus-compatibility check
/// ([`crate::components::chain`]) iterate it.
pub(crate) const NETWORK_UPGRADES: &[consensus::BranchId] = &[
    consensus::BranchId::Overwinter,
    consensus::BranchId::Sapling,
    consensus::BranchId::Blossom,
    consensus::BranchId::Heartwood,
    consensus::BranchId::Canopy,
    consensus::BranchId::Nu5,
    consensus::BranchId::Nu6,
    consensus::BranchId::Nu6_1,
    consensus::BranchId::Nu6_2,
    consensus::BranchId::Nu6_3,
    #[cfg(zcash_unstable = "nu7")]
    consensus::BranchId::Nu7,
];

impl Network {
    /// Constructs the network parameters for the given network type, using the
    /// provided network-upgrade parameters for regtest.
    pub fn from_type(network_type: consensus::NetworkType, nuparams: &[RegTestNuParam]) -> Self {
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

                // Resolve each upgrade's activation height. If a NU is omitted from
                // `nuparams`, it activates at the same height as the next specified NU, so
                // walk from the latest upgrade to the earliest, carrying that height back.
                let mut next = None;
                let heights: Vec<(consensus::BranchId, Option<BlockHeight>)> = NETWORK_UPGRADES
                    .iter()
                    .rev()
                    .map(|&nu| {
                        next = find_nu(nu).or(next);
                        (nu, next)
                    })
                    .collect();
                let height = |nu| {
                    heights
                        .iter()
                        .find(|(branch, _)| *branch == nu)
                        .and_then(|&(_, h)| h)
                };

                Self::RegTest(local_consensus::LocalNetwork {
                    overwinter: height(consensus::BranchId::Overwinter),
                    sapling: height(consensus::BranchId::Sapling),
                    blossom: height(consensus::BranchId::Blossom),
                    heartwood: height(consensus::BranchId::Heartwood),
                    canopy: height(consensus::BranchId::Canopy),
                    nu5: height(consensus::BranchId::Nu5),
                    nu6: height(consensus::BranchId::Nu6),
                    nu6_1: height(consensus::BranchId::Nu6_1),
                    nu6_2: height(consensus::BranchId::Nu6_2),
                    nu6_3: height(consensus::BranchId::Nu6_3),
                    #[cfg(zcash_unstable = "nu7")]
                    nu7: height(consensus::BranchId::Nu7),
                })
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

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::NetworkType;

    #[test]
    fn regtest_omitted_upgrades_default_to_next_specified() {
        // Specify only Nu6; earlier upgrades inherit its height, later ones stay unset.
        let params = [RegTestNuParam {
            consensus_branch_id: consensus::BranchId::Nu6,
            activation_height: BlockHeight::from_u32(200),
        }];
        let Network::RegTest(local) = Network::from_type(NetworkType::Regtest, &params) else {
            panic!("expected a regtest network");
        };
        let h200 = Some(BlockHeight::from_u32(200));
        assert_eq!(local.overwinter, h200);
        assert_eq!(local.sapling, h200);
        assert_eq!(local.nu5, h200);
        assert_eq!(local.nu6, h200);
        assert_eq!(local.nu6_1, None);
        assert_eq!(local.nu6_2, None);
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
