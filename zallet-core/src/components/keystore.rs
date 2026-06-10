//! The Zallet keystore.
//!
//! # Design
//!
//! Zallet uses `zcash_client_sqlite` for its wallet, which handles viewing capabilities
//! itself, while leaving key material handling to the application which may have secure
//! storage capabilities (such as provided by mobile platforms). Given that Zallet is a
//! server wallet, we do not assume any secure storage capabilities are available, and
//! instead encrypt key material ourselves.
//!
//! Zallet stores key material (mnemonic seed phrases, standalone spending keys, etc) in
//! the same database as `zcash_client_sqlite`. This simplifies backups (as the wallet
//! operator only has a single database file for both transaction data and key material),
//! and helps to avoid inconsistent state.
//!
//! Zallet uses [`age`] to encrypt key material. age is built around the concept of
//! "encryption recipients" and "decryption identities", and provides several features:
//!
//! - Once the wallet has been initialized for an identity file, spending key material can
//!   be securely added to the wallet at any time without requiring the identity file.
//! - Key material can be encrypted to multiple recipients, which enables wallet operators
//!   to add redundancy to their backup strategies.
//!   - For example, an operator could configure Zallet with an online identity file used
//!     for regular wallet operations, and an offline identity file used to recover the
//!     key material from the wallet database if the online identity file is lost).
//! - Identity files can themselves be encrypted with a passphrase, allowing the wallet
//!   operator to limit the time for which the age identities are present in memory.
//! - age supports plugins for its encryption and decryption, which enable identities to
//!   be stored on hardware tokens like YubiKeys, or managed by a corporate KMS.
//!
//! ```text
//!  Disk
//! ┌───────────────────────┐       ┌──────────┐
//! │      ┌───────────┐    │       │Passphrase│
//! │      │  File or  │    │       └──────────┘
//! │      │zallet.toml│    │             │
//! │      └───────────┘    │             ▼
//! │            │          │       ┌──────────┐
//! │            ▼          │       │ Decrypt  │
//! │    ┌──────────────┐   │ ┌ ─ ─▶│identities│─ ─ ┐
//! │    │ age identity │   │       └──────────┘
//! │    │     file     │───┼─┘─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
//! │    └──────────────┘   │                       │   Memory
//! │                       │             ┌ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ┐
//! │  Database ┌───────────┼─────┐                 ▼
//! │ ┌ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ┐ │     │       │ ┌───────────────┐ │
//! │           ▼           │     └─────────│age identities │──┐
//! │ │ ┌───────────────┐ │ │             │ └───────────────┘ ││
//! │   │age recipients │───┼─────┐                            │
//! │ │ └───────────────┘ │ │     ▼       │    ┌─────────┐    ││  ┌───────────┐
//! │                       │ ┌───────┐        │   Key   │     │  │Transaction│
//! │ │                   │ │ │encrypt│◀┬─┼────│material │────┼┼─▶│  signing  │
//! │     ┌───────────┐     │ └───────┘        └─────────┘     │  └───────────┘
//! │ │   │    age    │   │ │     │     │ │         ▲         ││
//! │     │ciphertext │◀────┼─────┘        ─ ─ ─ ─ ─│─ ─ ─ ─ ─ │
//! │ │   └───────────┘   │ │           │           │          │
//! │  ─ ─ ─ ─ ─│─ ─ ─ ─ ─  │      ┌─────────┐      │          │
//! └───────────┼───────────┘      │Query KMS│      │          │
//!             │                  └─────────┘      │          │
//!             │                       │           │          │
//!             │                               ┌───────┐      │
//!             └───────────────────────┴──────▶│decrypt│◀─────┘
//!                                             └───────┘
//! ```
//!
//! TODO: Integrate or remote thes other notes:
//!
//! - Store recipients in the keystore as common bundles (a la Tink keysets).
//! - Whenever an identity file is directly visible, check it matches the recipients, to
//!   discover incorrect or outdated identity files ASAP.
//!
//! - Encrypt the seed phrase(s) with age, derive any needed keys on-the-fly after
//!   requesting decryption of the relevant seed phrase.
//!   - Could support any or all of the following encryption methods:
//!     - "native identity file" (only plaintext on disk is the age identity, and that
//!       could be on a different disk)
//!     - "passphrase" (like zcashd's experimental wallet encryption)
//!       - The closest analogue to zcashd's experimental wallet encryption would be a
//!         passphrase-encrypted native identity file: need passphrase once to decrypt the
//!         age identity into memory, and then can use the identity to decrypt and access
//!         seed phrases on-the-fly.
//!       - An advantage over the zcashd approach is that you don't need the wallet to be
//!         decrypted in order to import or generate new seed phrases / key material
//!         (zcashd used solely symmetric crypto; native age identities use asymmetric).
//!       - Current downside is that because of the above, encrypted key material would be
//!         quantum-vulnerable (but ML-KEM support is in progress for the age ecosystem).
//!     - "plugin" (enabling key material to be encrypted in a user-specified way e.g. to
//!       a YubiKey, or a corporate KMS)
//!       - Might also want a hybrid approach here to allow for on-first-use decryption
//!         requests rather than every-time decryption requests. Or maybe we want to
//!         support both.
//!   - Zallet would be configured with a corresponding age identity for encrypting /
//!     decrypting seed phrases.
//!   - If the age identity is native and unencrypted, that means Zallet can access seed
//!     phrases whenever it wants. This would be useful in e.g. a Docker deployment, where
//!     the identity could be decrypted during deployment and injected into the correct
//!     location (e.g. via a custom volume).
//!   - If the age identity is passphrase-encrypted, then we could potentially enable the
//!     Bitcoin Core-inherited JSON-RPC methods for decrypting the wallet as the
//!     passphrase UI. The decrypted age identity would be cached in memory until either
//!     an explicit eviction via JSON-RPC or node shutdown.
//!   - If the age identity uses a plugin, then as long as the plugin doesn't require user
//!     interaction the wallet could request decryption on-the-fly during spend actions,
//!     or explicitly via JSON-RPC (with no passphrase).
//!   - If the age identity uses a plugin, and user interaction is required, then we
//!     couldn't support this without Zallet gaining some kind of UI (TUI or GUI) for
//!     users to interact with. Maybe this could be via a dedicated (non-JSON) RPC
//!     protocol between a zallet foobar command and a running zallet start process?
//!     Probably out of scope for the initial impl.

use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bip0039::{English, Mnemonic};
use rusqlite::named_params;
use secrecy::{ExposeSecret, SecretString, SecretVec, Zeroize};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time,
};
use zip32::fingerprint::SeedFingerprint;

use crate::network::Network;
use crate::{
    config::ZalletConfig,
    error::{Error, ErrorKind},
};

use super::database::Database;

use crate::fl;

use sapling::zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey};

#[cfg(feature = "zcashd-import")]
use {transparent::address::TransparentAddress, zcash_keys::address::Address};

pub(super) mod db;

mod error;
pub(crate) use error::KeystoreError;

#[cfg(feature = "zcashd-import")]
pub(crate) mod zewif;

type RelockTask = (SystemTime, JoinHandle<()>);

#[derive(Clone)]
pub(crate) struct KeyStore {
    db: Database,

    /// A ciphertext ostensibly containing encrypted age identities, or `None` if the
    /// keystore is not using runtime-encrypted identities.
    encrypted_identities: Option<Vec<u8>>,

    /// The in-memory cache of age identities for decrypting key material.
    identities: Arc<RwLock<Vec<Box<dyn age::Identity + Send + Sync>>>>,

    /// Task that will re-lock the keystore if it has been temporarily unlocked.
    relock_task: Arc<Mutex<Option<RelockTask>>>,
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStore").finish_non_exhaustive()
    }
}

impl KeyStore {
    pub(crate) fn new(config: &ZalletConfig, db: Database) -> Result<Self, Error> {
        // TODO: Maybe support storing the identity in `zallet.toml` instead of as a
        //       separate file on disk?
        //       https://github.com/zcash/zallet/issues/253
        let path = config.encryption_identity();
        if !path.exists() {
            return Err(ErrorKind::Init
                .context(fl!(
                    "err-init-identity-not-found",
                    path = path.display().to_string(),
                ))
                .into());
        }

        let (encrypted_identities, identities) = {
            let mut identity_data = vec![];
            File::open(&path)
                .map_err(|e| ErrorKind::Init.context(e))?
                .read_to_end(&mut identity_data)
                .map_err(|e| ErrorKind::Init.context(e))?;

            // Try parsing as an encrypted age identity.
            match age::Decryptor::new_buffered(age::armor::ArmoredReader::new(
                identity_data.as_slice(),
            )) {
                Ok(decryptor) => {
                    // Only passphrase-encrypted age identities are supported.
                    if age::encrypted::EncryptedIdentity::new(decryptor, age::NoCallbacks, None)
                        .is_none()
                    {
                        return Err(ErrorKind::Init
                            .context(fl!(
                                "err-init-identity-not-passphrase-encrypted",
                                path = path.display().to_string(),
                            ))
                            .into());
                    }

                    (Some(identity_data), vec![])
                }
                _ => {
                    identity_data.zeroize();

                    // Try parsing as multiple single-line age identities.
                    let identity_file = age::IdentityFile::from_file(
                        path.to_str()
                            .ok_or_else(|| {
                                ErrorKind::Init.context(fl!(
                                    "err-init-path-not-utf8",
                                    path = path.display().to_string(),
                                ))
                            })?
                            .to_string(),
                    )
                    .map_err(|e| ErrorKind::Init.context(e))?
                    .with_callbacks(age::cli_common::UiCallbacks);
                    let identities = identity_file.into_identities().map_err(|e| {
                        ErrorKind::Init.context(fl!(
                            "err-init-identity-not-usable",
                            path = path.display().to_string(),
                            error = e.to_string(),
                        ))
                    })?;

                    (None, identities)
                }
            }
        };

        Ok(Self {
            db,
            encrypted_identities,
            identities: Arc::new(RwLock::new(identities)),
            relock_task: Arc::new(Mutex::new(None)),
        })
    }

    /// Returns `true` if the keystore's age identities are runtime-encrypted.
    ///
    /// When this returns `true`, [`Self::is_locked`] must return `false` in order to have
    /// access to spending key material.
    pub(crate) fn uses_encrypted_identities(&self) -> bool {
        self.encrypted_identities.is_some()
    }

    /// Returns `true` if the keystore's age identities are not available for decrypting
    /// key material.
    ///
    /// - If [`Self::uses_encrypted_identities`] returns `false`, this always returns
    ///   `true`.
    /// - If [`Self::uses_encrypted_identities`] returns `true`, this returns `true` when
    ///   [`Self::unlocked_until`] returns `None`.
    pub(crate) async fn is_locked(&self) -> bool {
        self.identities.read().await.is_empty()
    }

    /// Returns the [`SystemTime`] at which the keystore will re-lock, if it is currently
    /// unlocked.
    ///
    /// - To unlock the keystore or extend this time, use [`Self::unlock`].
    /// - To re-lock the keystore before this time, use [`Self::lock`].
    pub(crate) async fn unlocked_until(&self) -> Option<SystemTime> {
        let relock_task = self.relock_task.lock().await;
        relock_task
            .as_ref()
            .and_then(|(deadline, task)| (!task.is_finished()).then_some(*deadline))
    }

    /// Decrypts the keystore's [`age::IdentityFile`] using the given passphrase.
    pub(crate) async fn decrypt_identity_file<C: age::Callbacks>(
        &self,
        callbacks: C,
    ) -> Result<Option<age::IdentityFile<age::NoCallbacks>>, Error> {
        let encrypted_identities = match &self.encrypted_identities {
            Some(data) => data,
            // If the keystore isn't encrypted, we don't need to do anything.
            None => return Ok(None),
        };

        let decryptor = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(
            encrypted_identities.as_slice(),
        ))
        .expect("validated on start");

        let encrypted_identity = age::encrypted::EncryptedIdentity::new(decryptor, callbacks, None)
            .expect("validated on start");

        encrypted_identity
            .decrypt(None)
            .map(|identity_file| Some(identity_file.with_callbacks(age::NoCallbacks)))
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }

    /// Unlocks the keystore using the given passphrase.
    ///
    /// The keystore will be re-locked after `timeout` seconds. Calling this method again
    /// before the existing timeout expires will reset the timeout.
    pub(crate) async fn unlock(
        &self,
        passphrase: age::secrecy::SecretString,
        timeout: u64,
    ) -> bool {
        // Prepare a callback that only responds to passphrase requests.
        #[derive(Clone)]
        struct PassphraseCallbacks(age::secrecy::SecretString);
        impl age::Callbacks for PassphraseCallbacks {
            fn display_message(&self, _: &str) {}
            fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
                unreachable!()
            }
            fn request_public_string(&self, _: &str) -> Option<String> {
                unreachable!()
            }
            fn request_passphrase(&self, _: &str) -> Option<age::secrecy::SecretString> {
                Some(self.0.clone())
            }
        }

        let identity_file = match self
            .decrypt_identity_file(PassphraseCallbacks(passphrase))
            .await
        {
            Ok(Some(identity_file)) => identity_file,
            _ => return false,
        };

        let decrypted_identities = match identity_file.into_identities() {
            Ok(identities) => identities,
            Err(_) => return false,
        };

        // If there is an existing relock task, abort it so we don't race while writing
        // the decrypted identities.
        let mut relock_task = self.relock_task.lock().await;
        if let Some((_, existing_timeout)) = relock_task.take() {
            existing_timeout.abort();
            // Wait for the task to either finish or abort, to ensure there's zero
            // possibility of the `decrypted_identities` write below being cleared.
            let _ = existing_timeout.await;
        }

        *self.identities.write().await = decrypted_identities;

        // Start a task to relock the keystore after the given timeout.
        let duration = Duration::from_secs(timeout);
        let identities = self.identities.clone();
        *relock_task = Some((
            SystemTime::now() + duration,
            crate::spawn!("Keystore relock", async move {
                time::sleep(duration).await;
                identities.write().await.clear();
            }),
        ));

        true
    }

    /// Clears the in-memory cache of age identities, locking the keystore.
    pub(crate) async fn lock(&self) {
        // If the keystore isn't encrypted, we don't want to clear the cached identities.
        if !self.uses_encrypted_identities() {
            return;
        }

        // Any existing relock task is now unnecessary.
        let mut relock_task = self.relock_task.lock().await;
        if let Some((_, existing_timeout)) = relock_task.take() {
            existing_timeout.abort();
            // Wait for the task to either finish or abort, to ensure there's zero
            // possibility of a subsequent `unlock` having its identities cleared.
            let _ = existing_timeout.await;
        }

        self.identities.write().await.clear();
    }

    async fn with_db<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection, &Network) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.db.handle().await?.with_raw(f)
    }

    async fn with_db_mut<T>(
        &self,
        f: impl FnOnce(&mut rusqlite::Connection, &Network) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.db.handle().await?.with_raw_mut(f)
    }

    /// Sets the age recipients for this keystore.
    ///
    /// It is the caller's responsibility to ensure that the corresponding age identities
    /// are known.
    pub(crate) async fn initialize_recipients(
        &self,
        recipient_strings: Vec<String>,
    ) -> Result<(), Error> {
        // If the wallet has any existing recipients, fail (we would instead need to
        // re-encrypt the wallet).
        if !self.maybe_encryptor().await?.is_empty() {
            return Err(ErrorKind::Generic
                .context(fl!("err-keystore-already-initialized"))
                .into());
        }

        let now = ::time::OffsetDateTime::now_utc();

        self.with_db_mut(|conn, _| {
            let mut stmt = conn
                .prepare(
                    "INSERT INTO ext_zallet_keystore_age_recipients
                    VALUES (:recipient, :added)",
                )
                .map_err(|e| ErrorKind::Generic.context(e))?;

            for recipient in recipient_strings {
                stmt.execute(named_params! {
                    ":recipient": recipient,
                    ":added": now,
                })
                .map_err(|e| ErrorKind::Generic.context(e))?;
            }

            Ok(())
        })
        .await?;

        Ok(())
    }

    /// Constructs the encryptor for this wallet using the recipients from the database.
    ///
    /// Returns an error if there are no age recipients.
    pub(crate) async fn encryptor(&self) -> Result<Encryptor, Error> {
        let encryptor = self.maybe_encryptor().await?;
        if encryptor.is_empty() {
            Err(ErrorKind::Generic
                .context(KeystoreError::MissingRecipients)
                .into())
        } else {
            Ok(encryptor)
        }
    }

    /// Constructs the encryptor for this wallet using the recipients from the database.
    ///
    /// Unlike [`Self::encryptor`], this might return an empty encryptor.
    async fn maybe_encryptor(&self) -> Result<Encryptor, Error> {
        self.with_db(|conn, _| {
            let mut stmt = conn
                .prepare(
                    "SELECT recipient
                        FROM ext_zallet_keystore_age_recipients",
                )
                .map_err(|e| ErrorKind::Generic.context(e))?;

            let rows = stmt
                .query_map([], |row| row.get(0))
                .map_err(|e| ErrorKind::Generic.context(e))?;
            let recipient_strings = rows
                .collect::<Result<_, _>>()
                .map_err(|e| ErrorKind::Generic.context(e))?;

            Encryptor::from_recipient_strings(recipient_strings)
        })
        .await
    }

    /// Lists the fingerprint of every seed available in the keystore.
    pub(crate) async fn list_seed_fingerprints(&self) -> Result<HashSet<SeedFingerprint>, Error> {
        self.with_db(|conn, _| {
            let mut stmt = conn
                .prepare(
                    "SELECT hd_seed_fingerprint
                    FROM ext_zallet_keystore_mnemonics",
                )
                .map_err(|e| ErrorKind::Generic.context(e))?;

            let rows = stmt
                .query_map([], |row| row.get(0).map(SeedFingerprint::from_bytes))
                .map_err(|e| ErrorKind::Generic.context(e))?;

            Ok(rows
                .collect::<Result<_, _>>()
                .map_err(|e| ErrorKind::Generic.context(e))?)
        })
        .await
    }

    /// Lists the fingerprint of every legacy non-mnemonic seed available in the keystore.
    pub(crate) async fn list_legacy_seed_fingerprints(
        &self,
    ) -> Result<HashSet<SeedFingerprint>, Error> {
        self.with_db(|conn, _| {
            let mut stmt = conn
                .prepare(
                    "SELECT hd_seed_fingerprint
                    FROM ext_zallet_keystore_legacy_seeds",
                )
                .map_err(|e| ErrorKind::Generic.context(e))?;

            let rows = stmt
                .query_map([], |row| row.get(0).map(SeedFingerprint::from_bytes))
                .map_err(|e| ErrorKind::Generic.context(e))?;

            Ok(rows
                .collect::<Result<_, _>>()
                .map_err(|e| ErrorKind::Generic.context(e))?)
        })
        .await
    }

    pub(crate) async fn encrypt_and_store_mnemonic(
        &self,
        mnemonic: Mnemonic,
    ) -> Result<SeedFingerprint, Error> {
        let encryptor = self.encryptor().await?;

        let seed_bytes = SecretVec::new(mnemonic.to_seed("").to_vec());
        let seed_fp = SeedFingerprint::from_seed(seed_bytes.expose_secret()).expect("valid length");

        // Take ownership of the memory of the mnemonic to ensure it will be correctly zeroized on drop
        let mnemonic = SecretString::new(mnemonic.into_phrase());
        let encrypted_mnemonic =
            encryptor.encrypt_string(mnemonic.expose_secret(), age::armor::Format::Binary)?;

        self.with_db_mut(|conn, _| {
            conn.execute(
                "INSERT INTO ext_zallet_keystore_mnemonics
                VALUES (:hd_seed_fingerprint, :encrypted_mnemonic)
                ON CONFLICT (hd_seed_fingerprint) DO NOTHING ",
                named_params! {
                    ":hd_seed_fingerprint": seed_fp.to_bytes(),
                    ":encrypted_mnemonic": encrypted_mnemonic,
                },
            )
            .map_err(|e| ErrorKind::Generic.context(e))?;
            Ok(())
        })
        .await?;

        Ok(seed_fp)
    }

    #[cfg(feature = "zcashd-import")]
    pub(crate) async fn encrypt_and_store_legacy_seed(
        &self,
        legacy_seed: &SecretVec<u8>,
    ) -> Result<SeedFingerprint, Error> {
        let encryptor = self.encryptor().await?;

        let legacy_seed_fp = SeedFingerprint::from_seed(legacy_seed.expose_secret())
            .ok_or_else(|| ErrorKind::Generic.context(fl!("err-failed-seed-fingerprinting")))?;

        let encrypted_legacy_seed = encryptor
            .encrypt_legacy_seed_bytes(legacy_seed)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        self.with_db_mut(|conn, _| {
            conn.execute(
                "INSERT INTO ext_zallet_keystore_legacy_seeds
                VALUES (:hd_seed_fingerprint, :encrypted_legacy_seed)
                ON CONFLICT (hd_seed_fingerprint) DO NOTHING ",
                named_params! {
                    ":hd_seed_fingerprint": legacy_seed_fp.to_bytes(),
                    ":encrypted_legacy_seed": encrypted_legacy_seed,
                },
            )
            .map_err(|e| ErrorKind::Generic.context(e))?;
            Ok(())
        })
        .await?;

        Ok(legacy_seed_fp)
    }

    pub(crate) async fn encrypt_and_store_standalone_sapling_key(
        &self,
        sapling_key: &ExtendedSpendingKey,
    ) -> Result<DiversifiableFullViewingKey, Error> {
        let encryptor = self.encryptor().await?;

        let dfvk = sapling_key.to_diversifiable_full_viewing_key();
        let encrypted_sapling_extsk = encryptor
            .encrypt_standalone_sapling_key(sapling_key)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        self.with_db_mut(|conn, _| {
            conn.execute(
                "INSERT INTO ext_zallet_keystore_standalone_sapling_keys
                VALUES (:dfvk, :encrypted_sapling_extsk)
                ON CONFLICT (dfvk) DO NOTHING ",
                named_params! {
                    ":dfvk": &dfvk.to_bytes(),
                    ":encrypted_sapling_extsk": encrypted_sapling_extsk,
                },
            )
            .map_err(|e| ErrorKind::Generic.context(e))?;
            Ok(())
        })
        .await?;

        Ok(dfvk)
    }

    #[cfg(feature = "zcashd-import")]
    #[allow(dead_code)]
    pub(crate) async fn encrypt_and_store_standalone_transparent_key(
        &self,
        key: &zcash_keys::keys::transparent::Key,
    ) -> Result<(), Error> {
        self.store_encrypted_standalone_transparent_keys(&[self
            .encryptor()
            .await?
            .encrypt_standalone_transparent_key(key)?])
            .await
    }

    /// Stores a batch of encrypted standalone transparent keys produced by
    /// [`Encryptor::encrypt_standalone_transparent_key`].
    ///
    /// This creates a single database transaction for all inserts, significantly reducing
    /// overhead for large migrated wallets.
    #[cfg(feature = "zcashd-import")]
    pub(crate) async fn store_encrypted_standalone_transparent_keys(
        &self,
        keys: &[EncryptedStandaloneTransparentKey],
    ) -> Result<(), Error> {
        self.with_db_mut(|conn, _| {
            // Use an explicit transaction to avoid autocommit mode and reduce overhead.
            let tx = conn
                .transaction()
                .map_err(|e| ErrorKind::Generic.context(e))?;

            {
                let mut stmt = tx
                    .prepare(
                        "INSERT INTO ext_zallet_keystore_standalone_transparent_keys
                        VALUES (:pubkey, :encrypted_key_bytes)
                        ON CONFLICT (pubkey) DO NOTHING ",
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                for key in keys {
                    stmt.execute(named_params! {
                        ":pubkey": &key.pubkey.serialize(),
                        ":encrypted_key_bytes": key.encrypted_key_bytes,
                    })
                    .map_err(|e| ErrorKind::Generic.context(e))?;
                }
            }

            tx.commit().map_err(|e| ErrorKind::Generic.context(e))?;

            Ok(())
        })
        .await?;

        Ok(())
    }

    /// Decrypts the mnemonic phrase corresponding to the given seed fingerprint.
    async fn decrypt_mnemonic(&self, seed_fp: &SeedFingerprint) -> Result<SecretString, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        let encrypted_mnemonic = self
            .with_db(|conn, _| {
                Ok(conn
                    .query_row(
                        "SELECT encrypted_mnemonic
                        FROM ext_zallet_keystore_mnemonics
                        WHERE hd_seed_fingerprint = :hd_seed_fingerprint",
                        named_params! {":hd_seed_fingerprint": seed_fp.to_bytes()},
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?)
            })
            .await?;

        let mnemonic = decrypt_string(&identities, &encrypted_mnemonic)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        Ok(mnemonic)
    }

    /// Decrypts the seed with the given fingerprint.
    pub(crate) async fn decrypt_seed(
        &self,
        seed_fp: &SeedFingerprint,
    ) -> Result<SecretVec<u8>, Error> {
        let mnemonic = self.decrypt_mnemonic(seed_fp).await?;

        let mut seed_bytes = Mnemonic::<English>::from_phrase(mnemonic.expose_secret())
            .map_err(|e| ErrorKind::Generic.context(e))?
            .to_seed("");
        let seed = SecretVec::new(seed_bytes.to_vec());
        seed_bytes.zeroize();

        Ok(seed)
    }

    /// Decrypts the legacy non-mnemonic HD seed with the given fingerprint.
    ///
    /// Unlike [`Self::decrypt_seed`], this returns the raw seed bytes exactly as
    /// they were imported from `zcashd`, which are what the very-legacy
    /// transparent shielding OVK derivation operates on.
    pub(crate) async fn decrypt_legacy_seed(
        &self,
        seed_fp: &SeedFingerprint,
    ) -> Result<SecretVec<u8>, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        let encrypted_legacy_seed = self
            .with_db(|conn, _| {
                Ok(conn
                    .query_row(
                        "SELECT encrypted_legacy_seed
                        FROM ext_zallet_keystore_legacy_seeds
                        WHERE hd_seed_fingerprint = :hd_seed_fingerprint",
                        named_params! {":hd_seed_fingerprint": seed_fp.to_bytes()},
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?)
            })
            .await?;

        decrypt_secret_bytes(&identities, &encrypted_legacy_seed)
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }

    /// Exports the mnemonic phrase corresponding to the given seed fingerprint.
    pub(crate) async fn export_mnemonic(
        &self,
        seed_fp: &SeedFingerprint,
        armor: bool,
    ) -> Result<Vec<u8>, Error> {
        let encryptor = self.encryptor().await?;

        let mnemonic = self.decrypt_mnemonic(seed_fp).await?;

        let encrypted_mnemonic = encryptor.encrypt_string(
            mnemonic.expose_secret(),
            if armor {
                age::armor::Format::AsciiArmor
            } else {
                age::armor::Format::Binary
            },
        )?;

        Ok(encrypted_mnemonic)
    }

    /// Decrypts the standalone Sapling spending key corresponding to the given payment
    /// address, if one exists in the keystore.
    ///
    /// Unlike transparent keys (which can be looked up by address via a SQL join), Sapling
    /// keys require loading all standalone DFVKs and using `decrypt_diversifier` to find
    /// the one that matches the given payment address. This is because the DB schema only
    /// stores the DFVK, not the derived payment addresses.
    pub(crate) async fn decrypt_standalone_sapling_key(
        &self,
        address: &sapling::PaymentAddress,
    ) -> Result<Option<ExtendedSpendingKey>, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        // Query all standalone sapling keys and find the one matching the address.
        let rows = self
            .with_db(|conn, _| {
                let mut stmt = conn
                    .prepare(
                        "SELECT dfvk, encrypted_sapling_extsk
                         FROM ext_zallet_keystore_standalone_sapling_keys",
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(|e| ErrorKind::Generic.context(e))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                Ok(rows)
            })
            .await?;

        for (dfvk_bytes, encrypted_extsk) in rows {
            let dfvk_array: [u8; 128] = match dfvk_bytes.try_into() {
                Ok(arr) => arr,
                Err(_) => continue,
            };
            let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_array);
            if let Some(dfvk) = dfvk
                && dfvk.decrypt_diversifier(address).is_some()
            {
                let extsk = decrypt_standalone_sapling_extsk(&identities, &encrypted_extsk)?;
                return Ok(Some(extsk));
            }
        }

        Ok(None)
    }

    #[cfg(feature = "zcashd-import")]
    pub(crate) async fn decrypt_standalone_transparent_key(
        &self,
        address: &TransparentAddress,
    ) -> Result<secp256k1::SecretKey, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        let encrypted_key_bytes = self
            .with_db(|conn, network| {
                let addr_str = Address::Transparent(*address).encode(network);
                let encrypted_key_bytes = conn
                    .query_row(
                        "SELECT encrypted_transparent_privkey
                         FROM ext_zallet_keystore_standalone_transparent_keys ztk
                         JOIN addresses a ON ztk.pubkey = a.imported_transparent_receiver_pubkey
                         WHERE a.cached_transparent_receiver_address = :address",
                        named_params! {
                            ":address": addr_str,
                        },
                        |row| row.get::<_, Vec<u8>>("encrypted_transparent_privkey"),
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;
                Ok(encrypted_key_bytes)
            })
            .await?;

        let secret_key =
            decrypt_standalone_transparent_privkey(&identities, &encrypted_key_bytes[..])?;

        Ok(secret_key)
    }
}

pub(crate) struct Encryptor {
    recipient_strings: Vec<String>,
    recipients: Vec<Box<dyn age::Recipient + Send>>,
}

impl Encryptor {
    fn from_recipient_strings(recipient_strings: Vec<String>) -> Result<Self, Error> {
        let recipients = Self::parse_recipient_strings(recipient_strings.clone())?;
        Ok(Self {
            recipient_strings,
            recipients,
        })
    }

    fn parse_recipient_strings(
        recipient_strings: Vec<String>,
    ) -> Result<Vec<Box<dyn age::Recipient + Send>>, Error> {
        // TODO: Replace with a helper with configurable callbacks.
        let mut stdin_guard = age::cli_common::StdinGuard::new(false);
        let recipients = age::cli_common::read_recipients(
            recipient_strings,
            vec![],
            vec![],
            None,
            &mut stdin_guard,
        )
        .map_err(|e| ErrorKind::Generic.context(e))?;
        Ok(recipients)
    }

    fn is_empty(&self) -> bool {
        self.recipient_strings.is_empty()
    }

    fn encrypt_string(
        &self,
        plaintext: &str,
        format: age::armor::Format,
    ) -> Result<Vec<u8>, Error> {
        encrypt_string(&self.recipients, plaintext, format)
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }

    #[cfg(feature = "zcashd-import")]
    pub(crate) fn encrypt_standalone_transparent_key(
        &self,
        key: &zcash_keys::keys::transparent::Key,
    ) -> Result<EncryptedStandaloneTransparentKey, Error> {
        let encrypted_key_bytes = self
            .encrypt_standalone_transparent_privkey(key.secret())
            .map_err(|e| ErrorKind::Generic.context(e))?;

        Ok(EncryptedStandaloneTransparentKey {
            pubkey: key.pubkey(),
            encrypted_key_bytes,
        })
    }

    #[cfg(feature = "zcashd-import")]
    fn encrypt_legacy_seed_bytes(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<Vec<u8>, age::EncryptError> {
        encrypt_secret(&self.recipients, seed)
    }

    fn encrypt_standalone_sapling_key(
        &self,
        key: &ExtendedSpendingKey,
    ) -> Result<Vec<u8>, age::EncryptError> {
        let secret = SecretVec::new(key.to_bytes().to_vec());
        encrypt_secret(&self.recipients, &secret)
    }

    #[cfg(feature = "transparent-key-import")]
    fn encrypt_standalone_transparent_privkey(
        &self,
        key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, age::EncryptError> {
        let secret = SecretVec::new(key.secret_bytes().to_vec());
        encrypt_secret(&self.recipients, &secret)
    }
}

#[cfg(feature = "transparent-key-import")]
pub(crate) struct EncryptedStandaloneTransparentKey {
    pubkey: secp256k1::PublicKey,
    encrypted_key_bytes: Vec<u8>,
}

fn encrypt_string(
    recipients: &[Box<dyn age::Recipient + Send>],
    plaintext: &str,
    format: age::armor::Format,
) -> Result<Vec<u8>, age::EncryptError> {
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as _))?;

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut writer = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut ciphertext,
        format,
    )?)?;
    writer.write_all(plaintext.as_bytes())?;
    writer.finish()?.finish()?;

    Ok(ciphertext)
}

fn decrypt_string(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<SecretString, age::DecryptError> {
    let decryptor = age::Decryptor::new(ciphertext)?;

    // The plaintext is always shorter than the ciphertext. Over-allocating the initial
    // string ensures that no internal re-allocations occur that might leave plaintext
    // bytes strewn around the heap.
    let mut buf = String::with_capacity(ciphertext.len());
    let res = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as _))?
        .read_to_string(&mut buf);

    // We intentionally do not use `?` on the decryption expression because doing so in
    // the case of a partial failure could result in part of the secret data being read
    // into `buf`, which would not then be properly zeroized. Instead, we take ownership
    // of the buffer in construction of a `SecretString` to ensure that the memory is
    // zeroed out when we raise the error on the following line.
    let mnemonic = SecretString::new(buf);
    res?;

    Ok(mnemonic)
}

/// Decrypts age-encrypted ciphertext into raw secret bytes.
fn decrypt_secret_bytes(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<SecretVec<u8>, age::DecryptError> {
    let decryptor = age::Decryptor::new(ciphertext)?;

    // The plaintext is always shorter than the ciphertext. Over-allocating the initial
    // buffer ensures that no internal re-allocations occur that might leave plaintext
    // bytes strewn around the heap.
    let mut buf = Vec::with_capacity(ciphertext.len());
    let res = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as _))?
        .read_to_end(&mut buf);

    // We intentionally do not use `?` on the decryption expression because doing so in
    // the case of a partial failure could result in part of the secret data being read
    // into `buf`, which would not then be properly zeroized. Instead, we take ownership
    // of the buffer in construction of a `SecretVec` to ensure that the memory is
    // zeroed out when we raise the error on the following line.
    let secret = SecretVec::new(buf);
    res?;

    Ok(secret)
}

fn encrypt_secret(
    recipients: &[Box<dyn age::Recipient + Send>],
    secret: &SecretVec<u8>,
) -> Result<Vec<u8>, age::EncryptError> {
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as _))?;

    let mut ciphertext = Vec::with_capacity(secret.expose_secret().len());
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(secret.expose_secret())?;
    writer.finish()?;

    Ok(ciphertext)
}

fn decrypt_standalone_sapling_extsk(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<ExtendedSpendingKey, Error> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(|e| ErrorKind::Generic.context(e))?;

    // The plaintext is always shorter than the ciphertext. Over-allocating the initial
    // buffer ensures that no internal re-allocations occur that might leave plaintext
    // bytes strewn around the heap.
    let mut buf = Vec::with_capacity(ciphertext.len());
    let res = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as _))
        .map_err(|e| ErrorKind::Generic.context(e))?
        .read_to_end(&mut buf);

    // We intentionally do not use `?` on the decryption expression because doing so in
    // the case of a partial failure could result in part of the secret data being read
    // into `buf`, which would not then be properly zeroized. Instead, we take ownership
    // of the buffer in construction of a `SecretVec` to ensure that the memory is
    // zeroed out when we raise the error on the following line.
    let buf_secret = SecretVec::new(buf);
    res.map_err(|e| ErrorKind::Generic.context(e))?;
    let extsk = ExtendedSpendingKey::from_bytes(buf_secret.expose_secret())
        .map_err(|_| ErrorKind::Generic.context("Invalid Sapling extended spending key"))?;

    Ok(extsk)
}

#[cfg(feature = "transparent-key-import")]
fn decrypt_standalone_transparent_privkey(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<secp256k1::SecretKey, Error> {
    let secret =
        decrypt_secret_bytes(identities, ciphertext).map_err(|e| ErrorKind::Generic.context(e))?;
    let secret_key = secp256k1::SecretKey::from_slice(secret.expose_secret())
        .map_err(|e| ErrorKind::Generic.context(e))?;

    Ok(secret_key)
}
