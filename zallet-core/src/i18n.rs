use std::sync::{LazyLock, OnceLock};

use i18n_embed::{
    fluent::{FluentLanguageLoader, fluent_language_loader},
    unic_langid::LanguageIdentifier,
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Localizations;

pub(crate) static LANGUAGE_LOADER: LazyLock<FluentLanguageLoader> =
    LazyLock::new(|| fluent_language_loader!());

/// The languages that the first [`load_languages`] call selected and loaded.
static LOADED_LANGUAGES: OnceLock<Vec<LanguageIdentifier>> = OnceLock::new();

/// Selects the most suitable available language in order of preference by
/// `requested_languages`, and loads it using the `zallet` [`static@LANGUAGE_LOADER`] from the
/// languages available in `zallet/i18n/`.
///
/// Only the first call loads languages. A later call loads nothing and ignores
/// `requested_languages`. A call made while the first call runs waits for it to finish.
///
/// Returns the available languages that the first call negotiated as being the most
/// suitable to be selected, and loaded with [`i18n_embed::select`].
pub(crate) fn load_languages(
    requested_languages: &[LanguageIdentifier],
) -> Vec<LanguageIdentifier> {
    LOADED_LANGUAGES
        .get_or_init(|| {
            // A load replaces the loader's bundles with new ones that use isolation
            // marks. Loading only once means no message can be formatted between a
            // later load and the line that disables the marks again.
            let supported_languages =
                i18n_embed::select(&*LANGUAGE_LOADER, &Localizations, requested_languages).expect(
                    "the embedded localizations are valid and include the fallback language",
                );
            // Unfortunately the common Windows terminals don't support Unicode Directionality
            // Isolation Marks, so we disable them for now.
            LANGUAGE_LOADER.set_use_isolating(false);
            supported_languages
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::load_languages;
    use crate::fl;

    /// How many threads load languages and format messages at once.
    const THREADS: usize = 8;

    /// How many load-then-format rounds each thread runs.
    const ROUNDS: usize = 500;

    #[test]
    fn concurrent_loads_never_expose_isolation_marks() {
        // A load that replaces the bundles re-enables isolation until it disables it
        // again. A message formatted in that window wraps its argument in U+2068/U+2069.
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for _ in 0..ROUNDS {
                        load_languages(&[]);
                        let message = fl!("err-privacy-policy-unknown", policy = "x");
                        assert_eq!(message, "Unknown privacy policy x");
                    }
                });
            }
        });
    }
}
