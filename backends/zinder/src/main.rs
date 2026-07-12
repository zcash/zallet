//! Main entry point for Zallet using the Zinder chain-data backend.

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use i18n_embed::DesktopLanguageRequester;

mod chain;

/// Boot Zallet with the Zinder backend.
fn main() {
    zallet_core::application::boot(
        &chain::ZinderBackend,
        DesktopLanguageRequester::requested_languages(),
    );
}
