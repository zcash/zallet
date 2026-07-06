//! A [`SecretSink`] adapter that persists ZeWIF secret material in the Zallet
//! keystore.
//!
//! [`zcash_client_sqlite::zewif::import_wallet`] delivers every entry of a
//! ZeWIF document's secret store to a [`SecretSink`] before it imports any
//! account, so that no account can be created whose spending material has not
//! already been persisted. [`KeyStoreSecretSink`] implements that sink on top
//! of the Zallet keystore: each entry is decoded from its canonical ZeWIF
//! string encoding, verified against the public material recorded alongside
//! it, age-encrypted, and stored.
//!
//! The sink is synchronous (as required by the `SecretSink` trait) while the
//! keystore is asynchronous; the adapter bridges the two with
//! [`tokio::task::block_in_place`], and therefore requires the multi-threaded
//! Tokio runtime that Zallet always runs on.
//!
//! Sprout spending keys and extracted unified spending keys have no backing
//! store in Zallet; they are counted (for reporting by the caller) and
//! otherwise ignored, which matches the behavior of the previous zcashd
//! migration code.

use std::fmt;

use bech32::{Bech32m, primitives::decode::CheckedHrpstring};
use bip0039::{English, Mnemonic};
use secrecy::{SecretString, SecretVec};
use tokio::runtime::Handle;
use zcash_client_sqlite::zewif::SecretSink;
use zcash_keys::encoding::{decode_extended_spending_key, encode_extended_full_viewing_key};
use zcash_protocol::consensus::NetworkConstants;
use zip32::fingerprint::SeedFingerprint;

use crate::error::Error;

use super::{Encryptor, KeyStore};

macro_rules! wfl {
    ($f:ident, $message_id:literal) => {
        write!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        write!($f, "{}", $crate::fl!($message_id, $($args), *))
    };
}

/// The Human-Readable Part of the canonical ZIP 32 seed fingerprint encoding.
const SEED_FINGERPRINT_HRP: &str = "zip32seedfp";

/// Decodes a seed fingerprint from its canonical `zip32seedfp` Bech32m
/// encoding, returning `None` if the encoding is not a valid fingerprint.
pub(crate) fn decode_seed_fingerprint(
    fingerprint: &zewif::SeedFingerprint,
) -> Option<SeedFingerprint> {
    let checked = CheckedHrpstring::new::<Bech32m>(fingerprint.encoding()).ok()?;
    (checked.hrp().as_str() == SEED_FINGERPRINT_HRP)
        .then(|| checked.byte_iter().collect::<Vec<_>>())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(SeedFingerprint::from_bytes)
}

/// A [`SecretSink`] that persists ZeWIF secret material in the Zallet
/// keystore.
pub(crate) struct KeyStoreSecretSink<'a, N> {
    keystore: &'a KeyStore,
    network: N,
    runtime: Handle,
    encryptor: Encryptor,
    sprout_keys_ignored: usize,
    unified_keys_ignored: usize,
}

impl<'a, N: NetworkConstants> KeyStoreSecretSink<'a, N> {
    /// Constructs a sink that persists secrets with `keystore`, decoding
    /// network-dependent key encodings for `network`.
    pub(crate) async fn new(keystore: &'a KeyStore, network: N) -> Result<Self, Error> {
        let encryptor = keystore.encryptor().await?;
        Ok(Self {
            keystore,
            network,
            runtime: Handle::current(),
            encryptor,
            sprout_keys_ignored: 0,
            unified_keys_ignored: 0,
        })
    }

    /// The number of Sprout spending keys that were delivered to the sink;
    /// Zallet has no store for Sprout key material, so these were not
    /// persisted.
    pub(crate) fn sprout_keys_ignored(&self) -> usize {
        self.sprout_keys_ignored
    }

    /// The number of extracted unified spending keys that were delivered to
    /// the sink; Zallet has no store for extracted unified key material, so
    /// these were not persisted.
    pub(crate) fn unified_keys_ignored(&self) -> usize {
        self.unified_keys_ignored
    }

    /// Runs a keystore future to completion from the synchronous sink context.
    fn block_on<F: Future>(&self, fut: F) -> F::Output {
        tokio::task::block_in_place(|| self.runtime.block_on(fut))
    }

    /// Verifies that a keystore-computed seed fingerprint matches the
    /// fingerprint recorded in the document (in its canonical `zip32seedfp`
    /// Bech32m encoding).
    fn check_fingerprint(
        recorded: &zewif::SeedFingerprint,
        computed: &SeedFingerprint,
    ) -> Result<(), SecretSinkError> {
        let decoded = decode_seed_fingerprint(recorded).ok_or_else(|| {
            SecretSinkError::SeedFingerprintEncoding(recorded.encoding().to_string())
        })?;
        if decoded.to_bytes() == computed.to_bytes() {
            Ok(())
        } else {
            Err(SecretSinkError::SeedFingerprintMismatch {
                recorded: recorded.encoding().to_string(),
            })
        }
    }
}

impl<N: NetworkConstants> SecretSink for KeyStoreSecretSink<'_, N> {
    type Error = SecretSinkError;

    fn store_seed(&mut self, entry: &zewif::SeedEntry) -> Result<(), Self::Error> {
        let computed = match entry.material() {
            zewif::SeedMaterial::Bip39Mnemonic(mnemonic) => {
                // zcashd only ever generated English mnemonics, and the Zallet
                // keystore stores mnemonic phrases without a language tag, so
                // restrict imports to the English wordlist.
                if mnemonic
                    .language()
                    .is_some_and(|l| *l != zewif::MnemonicLanguage::English)
                {
                    return Err(SecretSinkError::UnsupportedMnemonicLanguage);
                }
                let mnemonic = Mnemonic::<English>::from_phrase(mnemonic.mnemonic())
                    .map_err(SecretSinkError::InvalidMnemonic)?;
                self.block_on(self.keystore.encrypt_and_store_mnemonic(mnemonic))
                    .map_err(SecretSinkError::Keystore)?
            }
            zewif::SeedMaterial::LegacySeed(seed) => {
                let seed_bytes = SecretVec::new(seed.as_bytes().to_vec());
                self.block_on(self.keystore.encrypt_and_store_legacy_seed(&seed_bytes))
                    .map_err(SecretSinkError::Keystore)?
            }
        };
        Self::check_fingerprint(entry.fingerprint(), &computed)
    }

    fn store_transparent_key(
        &mut self,
        entry: &zewif::TransparentKeyEntry,
    ) -> Result<(), Self::Error> {
        let encoded = SecretString::new(entry.spending_key().encoding().to_string());
        let key = zcash_keys::keys::transparent::Key::decode_base58(&self.network, &encoded)
            .map_err(|_| SecretSinkError::TransparentKeyDecoding)?;

        // Verify the decoded key against the public key it is stored under.
        let pubkey = key.pubkey();
        let matches = if key.compressed() {
            pubkey.serialize()[..] == *entry.pubkey().as_slice()
        } else {
            pubkey.serialize_uncompressed()[..] == *entry.pubkey().as_slice()
        };
        if !matches {
            return Err(SecretSinkError::TransparentKeyMismatch);
        }

        let encrypted = self
            .encryptor
            .encrypt_standalone_transparent_key(&key)
            .map_err(SecretSinkError::Keystore)?;
        self.block_on(
            self.keystore
                .store_encrypted_standalone_transparent_keys(&[encrypted]),
        )
        .map_err(SecretSinkError::Keystore)
    }

    fn store_sapling_key(&mut self, entry: &zewif::SaplingKeyEntry) -> Result<(), Self::Error> {
        let extsk = decode_extended_spending_key(
            self.network.hrp_sapling_extended_spending_key(),
            entry.spending_key().encoding(),
        )
        .map_err(|e| SecretSinkError::SaplingKeyDecoding(e.to_string()))?;

        // Verify the decoded key against the viewing key it is stored under.
        #[allow(deprecated)]
        let extfvk = extsk.to_extended_full_viewing_key();
        let encoded_fvk = encode_extended_full_viewing_key(
            self.network.hrp_sapling_extended_full_viewing_key(),
            &extfvk,
        );
        if encoded_fvk != entry.fvk().encoding() {
            return Err(SecretSinkError::SaplingKeyMismatch);
        }

        self.block_on(
            self.keystore
                .encrypt_and_store_standalone_sapling_key(&extsk),
        )
        .map(|_dfvk| ())
        .map_err(SecretSinkError::Keystore)
    }

    fn store_sprout_key(&mut self, _entry: &zewif::SproutKeyEntry) -> Result<(), Self::Error> {
        self.sprout_keys_ignored += 1;
        Ok(())
    }

    fn store_unified_key(&mut self, _entry: &zewif::UnifiedKeyEntry) -> Result<(), Self::Error> {
        self.unified_keys_ignored += 1;
        Ok(())
    }
}

/// The reasons persisting an entry of a ZeWIF document's secret store in the
/// Zallet keystore can fail.
#[derive(Debug)]
pub(crate) enum SecretSinkError {
    /// A mnemonic seed phrase uses a wordlist other than English.
    UnsupportedMnemonicLanguage,
    /// A mnemonic seed phrase is not a valid BIP 39 mnemonic.
    InvalidMnemonic(bip0039::Error),
    /// A recorded seed fingerprint is not a valid `zip32seedfp` Bech32m
    /// string.
    SeedFingerprintEncoding(String),
    /// The fingerprint of a stored seed does not match the fingerprint it was
    /// recorded under in the document.
    SeedFingerprintMismatch { recorded: String },
    /// A transparent spending key is not a valid WIF encoding for the wallet's
    /// network.
    TransparentKeyDecoding,
    /// A transparent spending key does not correspond to the public key it was
    /// recorded under in the document.
    TransparentKeyMismatch,
    /// A Sapling extended spending key could not be decoded from its canonical
    /// encoding.
    SaplingKeyDecoding(String),
    /// A Sapling extended spending key does not correspond to the extended
    /// full viewing key it was recorded under in the document.
    SaplingKeyMismatch,
    /// The keystore failed to persist an entry.
    Keystore(Error),
}

impl fmt::Display for SecretSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMnemonicLanguage => {
                wfl!(f, "err-migrate-secret-non-english-mnemonic")
            }
            Self::InvalidMnemonic(e) => {
                wfl!(
                    f,
                    "err-migrate-wallet-invalid-mnemonic",
                    err = e.to_string()
                )
            }
            Self::SeedFingerprintEncoding(encoding) => wfl!(
                f,
                "err-migrate-secret-fingerprint-encoding",
                fingerprint = encoding.as_str()
            ),
            Self::SeedFingerprintMismatch { recorded } => wfl!(
                f,
                "err-migrate-secret-fingerprint-mismatch",
                fingerprint = recorded.as_str()
            ),
            Self::TransparentKeyDecoding => {
                wfl!(f, "err-migrate-secret-transparent-key-decoding")
            }
            Self::TransparentKeyMismatch => {
                wfl!(f, "err-migrate-secret-transparent-key-mismatch")
            }
            Self::SaplingKeyDecoding(e) => wfl!(
                f,
                "err-migrate-secret-sapling-key-decoding",
                err = e.as_str()
            ),
            Self::SaplingKeyMismatch => wfl!(f, "err-migrate-secret-sapling-key-mismatch"),
            Self::Keystore(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SecretSinkError {}
