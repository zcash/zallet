//! Main entry point for Zallet, using the `zebra-state` chain backend.
//!
//! This binary reads finalized chain state directly from a co-located zebrad's
//! state database and follows the non-finalized tip over zebrad's gRPC indexer
//! interface. It requires a zebrad built with the (non-default) `indexer`
//! feature.

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use i18n_embed::DesktopLanguageRequester;

mod chain;

/// Boot Zallet with the zebra-state backend.
fn main() {
    zallet_core::application::boot(
        &chain::ZebraBackend,
        DesktopLanguageRequester::requested_languages(),
    );
}
