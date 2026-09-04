//! Zallet's native Zinder backend executable.

#![deny(warnings, missing_docs, trivial_casts, unused_qualifications)]
#![forbid(unsafe_code)]

use i18n_embed::DesktopLanguageRequester;

fn main() {
    zallet_core::application::boot(
        &zallet_zinder::ZinderBackend,
        DesktopLanguageRequester::requested_languages(),
    );
}
