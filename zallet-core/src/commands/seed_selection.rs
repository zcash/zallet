//! Shared logic for naming which of a wallet's mnemonic seed phrases a command acts on.
//!
//! Zallet wallets may hold several mnemonic phrases, so commands that operate on one need
//! a way to say which. A wallet that holds exactly one phrase is the common case, and
//! having to name it there would be noise, so the fingerprint may be omitted then.

use zip32::fingerprint::SeedFingerprint;

use crate::{
    components::{
        json_rpc::utils::parse_seedfp,
        keystore::{KeyStore, SeedSelectionError},
    },
    error::{Error, ErrorKind},
    fl,
};

/// Resolves the seed fingerprint a command should act on.
///
/// If `seedfp` is given it is parsed and checked against the wallet; otherwise the
/// wallet must hold exactly one mnemonic phrase, which is used.
pub(super) async fn resolve_seed_fingerprint(
    keystore: &KeyStore,
    seedfp: Option<&str>,
) -> Result<SeedFingerprint, Error> {
    let seedfp = seedfp
        .map(|seedfp| {
            parse_seedfp(seedfp).map_err(|e| ErrorKind::Generic.context(format!("{e:?}")))
        })
        .transpose()?;

    keystore.select_seed(seedfp).await.map_err(|e| match e {
        SeedSelectionError::Database(e) => e,
        SeedSelectionError::NoSeeds => ErrorKind::Generic
            .context(fl!("err-seed-selection-no-mnemonics"))
            .into(),
        SeedSelectionError::Ambiguous => ErrorKind::Generic
            .context(fl!("err-seed-selection-seedfp-required"))
            .into(),
        SeedSelectionError::Unknown => ErrorKind::Generic
            .context(fl!("err-seed-selection-unknown-seedfp"))
            .into(),
    })
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::resolve_seed_fingerprint;
    use crate::components::keystore::{
        BackupStatus,
        testing::{keystore as test_keystore, phrase, run_async},
    };

    #[test]
    fn a_sole_mnemonic_needs_no_fingerprint() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;
            let seed_fp = keystore
                .encrypt_and_store_mnemonic(phrase([6; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();

            let resolved = resolve_seed_fingerprint(&keystore, None).await.unwrap();
            assert_eq!(resolved.to_bytes(), seed_fp.to_bytes());

            // Naming it explicitly must reach the same seed.
            let named = resolve_seed_fingerprint(&keystore, Some(&seed_fp.to_string()))
                .await
                .unwrap();
            assert_eq!(named.to_bytes(), seed_fp.to_bytes());
        });
    }

    #[test]
    fn a_wallet_with_no_mnemonics_is_an_error() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;

            resolve_seed_fingerprint(&keystore, None)
                .await
                .expect_err("there is no seed to resolve to");
        });
    }

    #[test]
    fn several_mnemonics_require_an_explicit_fingerprint() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;
            let first = keystore
                .encrypt_and_store_mnemonic(phrase([7; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();
            let second = keystore
                .encrypt_and_store_mnemonic(phrase([8; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();

            resolve_seed_fingerprint(&keystore, None).await.expect_err(
                "Zallet must not pick a root of spend authority on the operator's behalf",
            );

            // Each is still reachable by name, and they are distinct.
            assert_ne!(first.to_bytes(), second.to_bytes());
            for seed_fp in [first, second] {
                let resolved = resolve_seed_fingerprint(&keystore, Some(&seed_fp.to_string()))
                    .await
                    .unwrap();
                assert_eq!(resolved.to_bytes(), seed_fp.to_bytes());
            }
        });
    }

    #[test]
    fn a_fingerprint_the_wallet_does_not_hold_is_an_error() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;
            keystore
                .encrypt_and_store_mnemonic(phrase([9; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();

            // A well-formed fingerprint for a seed this wallet does not have.
            let absent = zip32::fingerprint::SeedFingerprint::from_bytes([0xab; 32]);
            resolve_seed_fingerprint(&keystore, Some(&absent.to_string()))
                .await
                .expect_err("an unknown seed fingerprint must be rejected");

            // And something that is not a fingerprint at all.
            resolve_seed_fingerprint(&keystore, Some("not-a-fingerprint"))
                .await
                .expect_err("an unparseable seed fingerprint must be rejected");
        });
    }
}
