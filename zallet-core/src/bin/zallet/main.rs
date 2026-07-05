//! Main entry point for Zallet

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use i18n_embed::DesktopLanguageRequester;

#[cfg(feature = "zaino")]
use zallet_core::components::chain::ZainoBackend as Backend;
#[cfg(feature = "zebra-state")]
use zallet_core::components::chain::ZebraBackend as Backend;

/// Boot Zallet
fn main() {
    zallet_core::application::boot(&Backend, DesktopLanguageRequester::requested_languages());
}
