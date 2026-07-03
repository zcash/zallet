use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use transparent::address::TransparentAddress;
use zcash_address::{ToAddress, ZcashAddress};
use zcash_keys::encoding::AddressCodec;
use zcash_protocol::consensus::Parameters;

use crate::{components::json_rpc::server::LegacyCode, fl, network::Network};

pub(crate) type Response = RpcResult<ResultType>;

/// The TEX address encoding of the input transparent P2PKH address.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(String);

pub(super) const PARAM_TRANSPARENT_ADDRESS_DESC: &str = "The transparent P2PKH address to convert.";

/// Converts a transparent P2PKH Zcash address to a TEX address.
///
/// # Arguments
/// - `params`: Network parameters for address encoding/decoding.
/// - `transparent_address`: The transparent P2PKH address to convert.
pub(crate) fn call(params: &Network, transparent_address: &str) -> Response {
    let decoded = TransparentAddress::decode(params, transparent_address).map_err(|_| {
        LegacyCode::InvalidAddressOrKey.with_message(fl!("err-rpc-convert-tex-invalid-address"))
    })?;

    let pubkey_hash = match decoded {
        TransparentAddress::PublicKeyHash(hash) => hash,
        TransparentAddress::ScriptHash(_) => {
            return Err(
                LegacyCode::InvalidParameter.with_message(fl!("err-rpc-convert-tex-not-p2pkh"))
            );
        }
    };

    let tex_address = ZcashAddress::from_tex(params.network_type(), pubkey_hash);

    Ok(ResultType(tex_address.encode()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus;

    // From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/zcash_test_vectors/transparent/zip_0320.py
    const TEST_VECTORS: &[(&str, &str)] = &[
        (
            "t1V9mnyk5Z5cTNMCkLbaDwSskgJZucTLdgW",
            "tex10wur2u9clts5dcpu2vc6qg93uzyj7cca2xm732",
        ),
        (
            "t1LZdE42PAt1wREUv1YMYRFwJDPHPW8toLL",
            "tex1rkq7seu3cukjjtusde7q8xnjne93laluyvdxu7",
        ),
        (
            "t1M5AgJw56FNFRBNGtzAGX4AHfQh7ZCxd4w",
            "tex1yvvrncc9czsza45pgph67g39shmxywgyvsypwn",
        ),
        (
            "t1bh6KjXccz6Ed45vFc3GeqoxWbwPxe8w2n",
            "tex1cd648x9ckalkx0720n9a4yqgx9rcj7wfvjcq63",
        ),
        (
            "t1WvCtHojWHSHBdDtCFgorUN1TzUFV8sCth",
            "tex13ute2r3zkzygdtzgxt3zuf8jareuk6ep7qd8ty",
        ),
        (
            "t1U2MF7f81qrXkWouT3Xt4hLDAMjC9LniTK",
            "tex1dav2mtczhdywdvuc53p29v55tz0qg93qvfjp46",
        ),
        (
            "t1awMYfhispKsnJPHn7jgUxNnVW1DTpTJx9",
            "tex1hvhmk4q0palyx33kdq82aghwlcm45av3ezlrzn",
        ),
        (
            "t1Kgn7v5a2rKkxC24LoXNyHRn4q4Gs3KEEF",
            "tex1z0jpu36ysy3v45fut3l4h5cuwa3e48uea95pc6",
        ),
        (
            "t1c1ixUTuStCzo19qPg89U9XFYmWDLru9mt",
            "tex1cmakfkr40ewgtv3s5v6cwytf0tn9gz6y9j5z8e",
        ),
        (
            "t1WBxR5jNWgg4Cqeot3FvNkBb9ztYyjVELp",
            "tex1sudq382yvf5257kq854x7c9wwzqg7wt5h2c24u",
        ),
        (
            "t1VEuDXP1QocoNaxrq4gZArTqqKCZdrwjG7",
            "tex10jc8cvd4spq2clxp90a25yuvl0hm8pzheuufxw",
        ),
        (
            "t1PXVM8oR6qVrVjtcnU1iNmH2CfvZyBai8u",
            "tex18cpwpz6evh7wnssvum0xl9q8vaxsrwsz83vght",
        ),
        (
            "t1M3p1MgJCgjq4FMogS84kVvuszJbxPnpSM",
            "tex1yttgm6anj2x6gprrwrf9a54mar27npws73jwdy",
        ),
        (
            "t1aqnebXhA45WpgQHLiXTPU1Kk6rp8vVDDr",
            "tex1hg3rpdqlmjqhzsegyv05p2mnl66jv3dykth955",
        ),
        (
            "t1UG6FVxexmJRFXG4gvEmSF9HSTwHMFaSDT",
            "tex1w8clcm7kjdc0yds32d4nke88muwwhmmfunhkhd",
        ),
    ];

    #[test]
    fn convert_test_vectors() {
        let params = Network::Consensus(consensus::Network::MainNetwork);
        for (input, expected) in TEST_VECTORS {
            let result = call(&params, input);
            assert!(result.is_ok(), "Failed to convert {input}");
            let ResultType(tex) = result.unwrap();
            assert_eq!(&tex, *expected, "Mismatch for input {input}");
        }
    }

    #[test]
    fn reject_invalid_address() {
        let params = Network::Consensus(consensus::Network::MainNetwork);
        let result = call(&params, "invalid_address");
        let err = result.unwrap_err();
        assert_eq!(err.code(), LegacyCode::InvalidAddressOrKey as i32);
        assert_eq!(err.message(), fl!("err-rpc-convert-tex-invalid-address"));
    }

    #[test]
    fn reject_p2sh_address() {
        let params = Network::Consensus(consensus::Network::MainNetwork);
        // Mainnet P2SH address (starts with t3)
        let result = call(&params, "t3Vz22vK5z2LcKEdg16Yv4FFneEL1zg9ojd");
        let err = result.unwrap_err();
        assert_eq!(err.code(), LegacyCode::InvalidParameter as i32);
        assert_eq!(err.message(), fl!("err-rpc-convert-tex-not-p2pkh"));
    }
}
