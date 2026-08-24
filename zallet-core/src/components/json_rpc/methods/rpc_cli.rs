#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Conversion {
    String,
    NullableString,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Parameter {
    name: &'static str,
    required: bool,
    conversion: Conversion,
}

impl Parameter {
    pub(super) const fn new(name: &'static str, required: bool, conversion: Conversion) -> Self {
        Self {
            name,
            required,
            conversion,
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) fn conversion(&self) -> Conversion {
        self.conversion
    }
}

#[derive(Debug)]
pub(crate) struct Method {
    params: &'static [Parameter],
}

impl Method {
    pub(super) const fn new(params: &'static [Parameter]) -> Self {
        Self { params }
    }

    pub(crate) fn params(&self) -> &'static [Parameter] {
        self.params
    }

    pub(crate) fn minimum_params(&self) -> usize {
        self.params
            .iter()
            .rposition(|parameter| parameter.required)
            .map_or(0, |index| index + 1)
    }

    pub(crate) fn maximum_params(&self) -> usize {
        self.params.len()
    }
}

include!(concat!(env!("OUT_DIR"), "/rpc_cli_params.rs"));

pub(crate) fn get(name: &str) -> Option<&'static Method> {
    METHODS.get(name)
}

#[cfg(test)]
mod tests {
    use super::{Conversion, Parameter, get};

    #[test]
    fn generates_common_text_and_required_vec_metadata() {
        assert_eq!(
            get("z_getaccount").expect("generated method").params(),
            &[Parameter::new("account_uuid", true, Conversion::String)],
        );
        assert_eq!(
            get("pczt_combine").expect("generated method").params(),
            &[Parameter::new("pczts", true, Conversion::Json)],
        );
        assert!(get("not_a_zallet_method").is_none());
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn generates_wallet_optional_metadata() {
        assert_eq!(
            get("help").expect("generated method").params(),
            &[Parameter::new("command", false, Conversion::NullableString)],
        );
        assert_eq!(
            get("z_getoperationstatus")
                .expect("generated method")
                .params(),
            &[Parameter::new("operationid", false, Conversion::Json)],
        );
        assert_eq!(
            get("walletpassphrase").expect("generated method").params(),
            &[
                Parameter::new("passphrase", true, Conversion::String),
                Parameter::new("timeout", true, Conversion::Json),
            ],
        );
        assert_eq!(
            get("z_sendmany").expect("generated method").params()[4],
            Parameter::new("privacy_policy", false, Conversion::NullableString),
        );
    }

    #[cfg(zallet_build = "merchant_terminal")]
    #[test]
    fn omits_wallet_only_metadata() {
        assert!(get("help").is_none());
        assert!(get("walletpassphrase").is_none());
    }

    #[cfg(zallet_build = "wallet")]
    #[test]
    fn minimum_count_uses_the_last_required_position() {
        let method = get("z_sendfromaccount").expect("generated method");
        assert_eq!(
            method.params(),
            &[
                Parameter::new("account", true, Conversion::Json),
                Parameter::new("fund_source", true, Conversion::Json),
                Parameter::new("recipients", true, Conversion::Json),
                Parameter::new("minconf", false, Conversion::Json),
                Parameter::new("privacy_policy", true, Conversion::String),
            ],
        );
        assert_eq!(method.minimum_params(), 5);
        assert_eq!(method.maximum_params(), 5);
    }
}
