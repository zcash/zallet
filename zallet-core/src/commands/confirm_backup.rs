use std::io::{self, BufRead, Write};

use abscissa_core::Runnable;
use rand::{rand_core::UnwrapErr, rngs::SysRng, seq::index};
use secrecy::ExposeSecret;

use crate::{
    cli::ConfirmBackupCmd,
    commands::{AsyncRunnable, seed_selection::resolve_seed_fingerprint},
    components::{database::Database, keystore::KeyStore},
    error::{Error, ErrorKind},
    fl,
    prelude::*,
};

/// How many words of the phrase the operator is asked to read back.
///
/// This is a check that the operator has their backup to hand. It matches the `zcashd-wallet-tool`
/// prompt that operators migrating from `zcashd` will have seen.
const QUIZ_WORDS: usize = 3;

impl AsyncRunnable for ConfirmBackupCmd {
    async fn run(&self) -> Result<(), Error> {
        let config = APP.config();
        let _lock = config.lock_datadir()?;

        let db = Database::open(&config).await?;
        let keystore = KeyStore::new(&config, db)?;

        let seed_fp = resolve_seed_fingerprint(&keystore, self.seedfp.as_deref()).await?;

        if keystore.backup_confirmed(&seed_fp).await? {
            println!("{}", fl!("cmd-confirm-backup-already-confirmed"));
            return Ok(());
        }

        // The phrase is needed to check the operator's answers against, but it is never
        // shown: Zallet does not emit key material in the clear, and an operator who
        // cannot reach their own copy of the phrase does not have a backup to confirm.
        // Obtaining that copy requires the age identity, so confirming here attests to
        // more than having seen some words on a screen.
        keystore.unlock_on_terminal().await?;
        let mnemonic = keystore.decrypt_mnemonic(&seed_fp).await?;
        let words = mnemonic
            .expose_secret()
            .split_whitespace()
            .collect::<Vec<_>>();

        println!(
            "{}",
            fl!(
                "cmd-confirm-backup-how-to-obtain",
                seedfp = seed_fp.to_string(),
                identity = config.encryption_identity().display().to_string(),
            )
        );
        println!();

        quiz(&words)?;

        keystore.confirm_backup(&seed_fp).await?;

        println!();
        println!("{}", fl!("cmd-confirm-backup-confirmed"));
        println!();
        println!("{}", fl!("cmd-confirm-backup-not-complete-backup"));

        Ok(())
    }
}

/// Asks the operator to read back [`QUIZ_WORDS`] words of the phrase by position.
///
/// Returns an error as soon as one answer is wrong; the caller must not record the
/// backup as confirmed in that case.
fn quiz(words: &[&str]) -> Result<(), Error> {
    let stdin = io::stdin();

    for position in choose_quiz_positions(words.len(), &mut UnwrapErr(SysRng)) {
        print!(
            "{}",
            fl!(
                "cmd-confirm-backup-word-prompt",
                position = (position + 1).to_string(),
            )
        );
        io::stdout()
            .flush()
            .map_err(|e| ErrorKind::Generic.context(e))?;

        let mut answer = String::new();
        stdin
            .lock()
            .read_line(&mut answer)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        if !answer_matches(&answer, words[position]) {
            return Err(ErrorKind::Generic
                .context(fl!("err-confirm-backup-wrong-word"))
                .into());
        }
    }

    Ok(())
}

/// Chooses which word positions to ask about, as a sorted list of zero-based indices.
///
/// Asks about [`QUIZ_WORDS`] distinct positions, or every position if the phrase is
/// shorter than that. Sorted so the operator reads their backup forwards rather than
/// hunting back and forth across it.
fn choose_quiz_positions(word_count: usize, rng: &mut impl rand::Rng) -> Vec<usize> {
    let mut positions = index::sample(rng, word_count, QUIZ_WORDS.min(word_count)).into_vec();
    positions.sort_unstable();
    positions
}

/// Compares a typed answer against the expected word.
///
/// Leading and trailing whitespace is stripped (the answer arrives with its newline
/// attached) and case is ignored, since the BIP 39 English wordlist is entirely
/// lowercase and a capitalised answer is a typing artefact rather than a wrong word.
fn answer_matches(answer: &str, expected: &str) -> bool {
    answer.trim().eq_ignore_ascii_case(expected)
}

impl Runnable for ConfirmBackupCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The number of words in the phrases `zallet generate-mnemonic` produces.
    const GENERATED_PHRASE_WORDS: usize = 24;

    #[test]
    fn quiz_positions_are_distinct_sorted_and_in_range() {
        let mut rng = UnwrapErr(SysRng);

        for _ in 0..100 {
            let positions = choose_quiz_positions(GENERATED_PHRASE_WORDS, &mut rng);

            assert_eq!(positions.len(), QUIZ_WORDS);
            assert!(
                positions.windows(2).all(|w| w[0] < w[1]),
                "positions must be sorted and distinct, got {positions:?}",
            );
            assert!(
                positions.iter().all(|p| *p < GENERATED_PHRASE_WORDS),
                "positions must index the phrase, got {positions:?}",
            );
        }
    }

    #[test]
    fn quiz_covers_whole_phrase_when_shorter_than_quiz_length() {
        let short = QUIZ_WORDS - 1;
        let positions = choose_quiz_positions(short, &mut UnwrapErr(SysRng));

        assert_eq!(
            positions,
            (0..short).collect::<Vec<_>>(),
            "a phrase shorter than the quiz length must be asked about in full",
        );
    }

    #[test]
    fn answers_tolerate_whitespace_and_case_but_not_a_different_word() {
        assert!(answer_matches("abandon\n", "abandon"));
        assert!(answer_matches("  abandon  ", "abandon"));
        assert!(answer_matches("Abandon\r\n", "abandon"));
        assert!(!answer_matches("abandoned\n", "abandon"));
        assert!(!answer_matches("\n", "abandon"));
    }
}
