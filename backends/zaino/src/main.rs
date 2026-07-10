//! Main entry point for Zallet, using the Zaino chain indexer as its backend.
//!
//! This binary embeds Zaino's chain index, which follows a co-located zebrad over
//! JSON-RPC; when `[indexer.read_state_service]` is configured it instead reads
//! finalized state directly from zebrad's state database.

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use i18n_embed::DesktopLanguageRequester;

mod chain;
mod read_state;

/// Boot Zallet with the Zaino backend.
fn main() {
    zallet_core::application::boot(
        &chain::ZainoBackend,
        DesktopLanguageRequester::requested_languages(),
    );
}
