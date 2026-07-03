//! Zallet Config

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::Duration;

use documented::{Documented, DocumentedFields};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_protocol::consensus::NetworkType;

use crate::commands::{lock_datadir, resolve_datadir_path};
use crate::network::{Network, RegTestNuParam};

#[cfg(zallet_build = "wallet")]
use {
    std::num::NonZeroU16, zcash_client_backend::fees::SplitPolicy, zcash_protocol::value::Zatoshis,
    zip32::fingerprint::SeedFingerprint,
};

/// Zallet Configuration
///
/// Most fields are `Option<T>` to enable distinguishing between a user relying on a
/// default value (which may change over time), and a user explicitly configuring an
/// option with the current default value (which should be preserved). The sole exceptions
/// to this are:
/// - `consensus.network`, which cannot change for the lifetime of the wallet.
/// - `features.as_of_version`, which must always be set to some Zallet version.
#[derive(Clone, Debug, Default, Deserialize, Serialize, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct ZalletConfig {
    /// Zallet's data directory.
    ///
    /// This cannot be set in a config file; it must be provided on the command line, and
    /// is set to `None` until `EntryPoint::process_config` is called.
    #[serde(skip)]
    pub(crate) datadir: Option<PathBuf>,

    /// Settings that affect transactions created by Zallet.
    pub builder: BuilderSection,

    /// Zallet's understanding of the consensus rules.
    pub consensus: ConsensusSection,

    /// Settings for how Zallet stores wallet data.
    pub database: DatabaseSection,

    /// Settings controlling how Zallet interacts with the outside world.
    pub external: ExternalSection,

    /// Settings for Zallet features.
    pub features: FeaturesSection,

    /// Settings for the Zaino chain indexer.
    pub indexer: IndexerSection,

    /// Settings for the key store.
    #[cfg(zallet_build = "wallet")]
    pub keystore: KeyStoreSection,

    /// Settings for how Zallet manages notes.
    #[cfg(zallet_build = "wallet")]
    pub note_management: NoteManagementSection,

    /// Settings for the JSON-RPC interface.
    pub rpc: RpcSection,

    /// Settings controlling how Zallet synchronizes the wallet with the chain.
    ///
    /// Defaulted so that configs written before this section existed continue to parse.
    #[serde(default)]
    pub sync: SyncSection,
}

impl ZalletConfig {
    /// Returns the data directory to use.
    ///
    /// Only `pub(crate)` so it can be used in recommended commands for error messages. If
    /// you need to access a file in the datadir, use one of the dedicated path getters.
    pub(crate) fn datadir(&self) -> &Path {
        self.datadir
            .as_deref()
            .expect("must be set by command before running any code using paths")
    }

    /// Ensures only a single Zallet process is using the data directory.
    ///
    /// This should be called inside any command that writes to the Zallet datadir.
    pub(crate) fn lock_datadir(&self) -> Result<fmutex::Guard<'static>, crate::error::Error> {
        lock_datadir(self.datadir())
    }

    /// Returns the path to the encryption identity.
    #[cfg(zallet_build = "wallet")]
    pub(crate) fn encryption_identity(&self) -> PathBuf {
        resolve_datadir_path(self.datadir(), self.keystore.encryption_identity())
    }

    /// Returns the path to the indexer's database.
    #[cfg(feature = "zaino")]
    pub(crate) fn indexer_db_path(&self) -> PathBuf {
        resolve_datadir_path(self.datadir(), self.indexer.db_path())
    }

    /// Returns the path to the wallet database.
    pub(crate) fn wallet_db_path(&self) -> PathBuf {
        resolve_datadir_path(self.datadir(), self.database.wallet_path())
    }
}

/// Settings that affect transactions created by Zallet.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct BuilderSection {
    /// Whether to spend unconfirmed transparent change when sending transactions.
    ///
    /// Does not affect unconfirmed shielded change, which cannot be spent.
    pub spend_zeroconf_change: Option<bool>,

    /// The number of confirmations required for a trusted transaction output (TXO) to
    /// become spendable.
    ///
    /// A trusted TXO is a TXO received from a party where the wallet trusts that it will
    /// remain mined in its original transaction, such as change outputs created by the
    /// wallet's internal TXO handling.
    ///
    /// This setting is a trade-off between latency and reliability: a smaller value makes
    /// trusted TXOs spendable more quickly, but the spending transaction has a higher
    /// risk of failure if a chain reorg occurs that unmines the receiving transaction.
    pub trusted_confirmations: Option<u32>,

    /// The number of blocks after which a transaction created by Zallet that has not been
    /// mined will become invalid.
    ///
    /// - Minimum: `TX_EXPIRING_SOON_THRESHOLD + 1`
    pub tx_expiry_delta: Option<u16>,

    /// The number of confirmations required for an untrusted transaction output (TXO) to
    /// become spendable.
    ///
    /// An untrusted TXO is a TXO received by the wallet that is not trusted (in the sense
    /// used by the `trusted_confirmations` setting).
    ///
    /// This setting is a trade-off between latency and security: a smaller value makes
    /// trusted TXOs spendable more quickly, but the spending transaction has a higher
    /// risk of failure if the sender of the receiving transaction is malicious and
    /// double-spends the funds.
    ///
    /// Values smaller than `trusted_confirmations` are ignored.
    pub untrusted_confirmations: Option<u32>,

    /// Configurable limits on transaction builder operation (to prevent e.g. memory
    /// exhaustion).
    pub limits: BuilderLimitsSection,
}

impl BuilderSection {
    /// Whether to spend unconfirmed transparent change when sending transactions.
    ///
    /// Default is `true`.
    ///
    /// Does not affect unconfirmed shielded change, which cannot be spent.
    pub fn spend_zeroconf_change(&self) -> bool {
        self.spend_zeroconf_change.unwrap_or(true)
    }

    /// The number of confirmations required for a trusted transaction output (TXO) to
    /// become spendable.
    ///
    /// A trusted TXO is a TXO received from a party where the wallet trusts that it will
    /// remain mined in its original transaction, such as change outputs created by the
    /// wallet's internal TXO handling.
    ///
    /// This setting is a trade-off between latency and reliability: a smaller value makes
    /// trusted TXOs spendable more quickly, but the spending transaction has a higher
    /// risk of failure if a chain reorg occurs that unmines the receiving transaction.
    ///
    /// Default is 3.
    pub fn trusted_confirmations(&self) -> u32 {
        self.trusted_confirmations.unwrap_or(3)
    }

    /// The number of blocks after which a transaction created by Zallet that has not been
    /// mined will become invalid.
    ///
    /// - Minimum: `TX_EXPIRING_SOON_THRESHOLD + 1`
    /// - Default: 40
    pub fn tx_expiry_delta(&self) -> u16 {
        self.tx_expiry_delta.unwrap_or(40)
    }

    /// The number of confirmations required for an untrusted transaction output (TXO) to
    /// become spendable.
    ///
    /// An untrusted TXO is a TXO received by the wallet that is not trusted (in the sense
    /// used by the `trusted_confirmations` setting).
    ///
    /// This setting is a trade-off between latency and security: a smaller value makes
    /// trusted TXOs spendable more quickly, but the spending transaction has a higher
    /// risk of failure if the sender of the receiving transaction is malicious and
    /// double-spends the funds.
    ///
    /// Values smaller than `trusted_confirmations` are ignored.
    ///
    /// Default is 10.
    pub fn untrusted_confirmations(&self) -> u32 {
        self.untrusted_confirmations.unwrap_or(10)
    }

    /// Returns the confirmations policy used for spending, based on number of trusted and
    /// untrusted confirmations specified by this configuration section.
    ///
    /// This will return an error if the number of confirmations required for spending untrusted
    /// TXOs is less than the number of confirmations required for spending trusted TXOs
    #[allow(clippy::result_unit_err)]
    pub fn confirmations_policy(&self) -> Result<ConfirmationsPolicy, ()> {
        let allow_zero_conf_shielding = self.untrusted_confirmations() == 0;
        ConfirmationsPolicy::new(
            NonZeroU32::new(self.trusted_confirmations()).unwrap_or(NonZeroU32::MIN),
            NonZeroU32::new(self.untrusted_confirmations()).unwrap_or(NonZeroU32::MIN),
            allow_zero_conf_shielding,
        )
        .map_err(|_| ())
    }
}

/// Configurable limits on transaction builder operation (to prevent e.g. memory
/// exhaustion).
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct BuilderLimitsSection {
    /// The maximum number of Orchard actions permitted in a constructed transaction.
    pub orchard_actions: Option<u16>,
}

impl BuilderLimitsSection {
    /// The maximum number of Orchard actions permitted in a constructed transaction.
    ///
    /// Default is 50.
    pub fn orchard_actions(&self) -> u16 {
        self.orchard_actions.unwrap_or(50)
    }
}

/// Zallet's understanding of the consensus rules.
///
/// The configuration in this section MUST match the configuration of the full node being
/// used as a data source in the `validator_address` field of the `[indexer]` section.
#[derive(Clone, Debug, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct ConsensusSection {
    /// Network type.
    #[serde(with = "crate::network::kind")]
    pub network: NetworkType,

    /// The parameters for regtest mode.
    ///
    /// Ignored if `network` is not `NetworkType::Regtest`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regtest_nuparams: Vec<RegTestNuParam>,
}

impl Default for ConsensusSection {
    fn default() -> Self {
        Self {
            network: NetworkType::Main,
            regtest_nuparams: vec![],
        }
    }
}

impl ConsensusSection {
    /// Returns the network parameters for this wallet.
    pub fn network(&self) -> Network {
        Network::from_type(self.network, &self.regtest_nuparams)
    }
}

/// Settings for how Zallet stores wallet data.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct DatabaseSection {
    /// Path to the wallet database file.
    ///
    /// This can be either an absolute path, or a path relative to the data directory.
    /// Note that on Windows, you must either use single quotes for this field's value, or
    /// replace all backslashes `\` with forward slashes `/`.
    pub wallet: Option<PathBuf>,
}

impl DatabaseSection {
    /// Path to the wallet database file.
    ///
    /// This can be either an absolute path, or a path relative to the data directory.
    ///
    /// Default is `wallet.db`.
    fn wallet_path(&self) -> &Path {
        self.wallet
            .as_deref()
            .unwrap_or_else(|| Path::new("wallet.db"))
    }
}

/// Settings controlling how Zallet interacts with the outside world.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct ExternalSection {
    /// Whether the wallet should broadcast transactions.
    pub broadcast: Option<bool>,

    /// Directory to be used when exporting data.
    ///
    /// This must be an absolute path; relative paths are not resolved within the datadir.
    /// Note that on Windows, you must either use single quotes for this field's value, or
    /// replace all backslashes `\` with forward slashes `/`.
    pub export_dir: Option<PathBuf>,

    /// Executes the specified command when a wallet transaction changes.
    ///
    /// A wallet transaction "change" can be anything that alters how the transaction
    /// affects the wallet's balance. Examples include (but are not limited to):
    /// - A new transaction is created by the wallet.
    /// - A wallet transaction is added to the mempool.
    /// - A block containing a wallet transaction is mined or unmined.
    /// - A wallet transaction is removed from the mempool due to conflicts.
    ///
    /// `%s` in the command is replaced by the hex encoding of the transaction ID.
    pub notify: Option<String>,
}

impl ExternalSection {
    /// Whether the wallet should broadcast transactions.
    ///
    /// Default is `true`.
    pub fn broadcast(&self) -> bool {
        self.broadcast.unwrap_or(true)
    }
}

/// Settings for Zallet features.
#[derive(Clone, Debug, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct FeaturesSection {
    /// The most recent Zallet version for which this configuration file has been updated.
    ///
    /// This is used by Zallet to detect any changes to experimental or deprecated
    /// features. If this version is not compatible with `zallet --version`, most Zallet
    /// commands will error and print out information about how to upgrade your wallet,
    /// along with any changes you need to make to your usage of Zallet.
    pub as_of_version: String,

    /// Enable "legacy `zcashd` pool of funds" semantics for the given seed.
    ///
    /// The seed fingerprint should correspond to the mnemonic phrase of a `zcashd` wallet
    /// imported into this Zallet wallet.
    ///
    /// # Background
    ///
    /// `zcashd` had two kinds of legacy balance semantics:
    /// - The transparent JSON-RPC methods inherited from Bitcoin Core treated all
    ///   spendable funds in the wallet as being part of a single pool of funds. RPCs like
    ///   `sendmany` didn't allow the caller to specify which transparent addresses to
    ///   spend funds from, and RPCs like `getbalance` similarly computed a balance across
    ///   all transparent addresses returned from `getaddress`.
    /// - The early shielded JSON-RPC methods added for Sprout treated every address as a
    ///   separate pool of funds, because for Sprout there was a 1:1 relationship between
    ///   addresses and spend authority. RPCs like `z_sendmany` only spent funds that were
    ///   sent to the specified addressed, and RPCs like `z_getbalance` similarly computed
    ///   a separate balance for each address (which became complex and unintuitive with
    ///   the introduction of Sapling diversified addresses).
    ///
    /// With the advent of Unified Addresses and HD-derived spending keys, `zcashd` gained
    /// its modern balance semantics: each full viewing key in the wallet is a separate
    /// pool of funds, and treated as a separate "account". These are the semantics used
    /// throughout Zallet, and that should be used by everyone going forward. They are
    /// also incompatible with various legacy JSON-RPC methods that were deprecated in
    /// `zcashd`, as well as some fields of general RPC methods; these methods and fields
    /// are unavailable in Zallet by default.
    ///
    /// However, given that `zcashd` wallets can be imported into Zallet, and in order to
    /// ease the transition between them, this setting turns on legacy balance semantics
    /// in Zallet:
    /// - JSON-RPC methods that only work with legacy semantics become available for use.
    /// - Fields in responses that are calculated using legacy semantics are included.
    ///
    /// Due to how the legacy transparent semantics in particular were defined by Bitcoin
    /// Core, this can only be done for a single `zcashd` wallet at a time. Given that
    /// every `zcashd` wallet in production in 2025 had a single mnemonic seed phrase in
    /// its wallet, we use its ZIP 32 seed fingerprint as the `zcashd` wallet identifier
    /// in this setting.
    #[cfg(zallet_build = "wallet")]
    #[serde(default, with = "seedfp")]
    #[documented_fields(trim = false)]
    pub legacy_pool_seed_fingerprint: Option<SeedFingerprint>,

    /// Deprecated features.
    pub deprecated: DeprecatedFeaturesSection,

    /// Experimental features.
    pub experimental: ExperimentalFeaturesSection,
}

#[cfg(zallet_build = "wallet")]
mod seedfp {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use zip32::fingerprint::SeedFingerprint;

    use crate::components::json_rpc::utils::parse_seedfp;

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<SeedFingerprint>, D::Error> {
        Option::<String>::deserialize(deserializer).and_then(|v| {
            v.map(|s| parse_seedfp(&s).map_err(|e| D::Error::custom(format!("{e:?}"))))
                .transpose()
        })
    }

    pub(super) fn serialize<S: Serializer>(
        seedfp: &Option<SeedFingerprint>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_some(&seedfp.as_ref().map(|seedfp| seedfp.to_string()))
    }
}

impl Default for FeaturesSection {
    fn default() -> Self {
        Self {
            as_of_version: crate::build::PKG_VERSION.into(),
            #[cfg(zallet_build = "wallet")]
            legacy_pool_seed_fingerprint: None,
            deprecated: Default::default(),
            experimental: Default::default(),
        }
    }
}

/// Deprecated Zallet features that you are temporarily re-enabling.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
pub struct DeprecatedFeaturesSection {
    /// Any other deprecated feature flags.
    ///
    /// This is present to enable Zallet to detect the case where a deprecated feature has
    /// been removed, and a user's configuration still enables it.
    #[serde(flatten)]
    pub other: BTreeMap<String, toml::Value>,
}

/// Experimental Zallet features that you are using before they are stable.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
pub struct ExperimentalFeaturesSection {
    /// Any other experimental feature flags.
    ///
    /// This is present to enable Zallet to detect the case where a experimental feature has
    /// been either stabilised or removed, and a user's configuration still enables it.
    #[serde(flatten)]
    pub other: BTreeMap<String, toml::Value>,
}

/// Settings for the Zaino chain indexer.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct IndexerSection {
    /// IP address and port of the JSON-RPC interface for the full node / validator being
    /// used as a data source.
    ///
    /// If unset, connects on localhost to the standard JSON-RPC port for mainnet or
    /// testnet (as appropriate).
    pub validator_address: Option<String>,

    /// Path to the validator cookie file.
    ///
    /// If set, cookie file authorization will be used.
    pub validator_cookie_path: Option<PathBuf>,

    /// Full node / validator Username.
    pub validator_user: Option<String>,

    /// Full node / validator Password.
    pub validator_password: Option<String>,

    /// Path to the folder where the indexer maintains its state.
    ///
    /// This can be either an absolute path, or a path relative to the data directory.
    /// Note that on Windows, you must either use single quotes for this field's value, or
    /// replace all backslashes `\` with forward slashes `/`.
    pub db_path: Option<PathBuf>,

    /// Settings for reading chain state directly from a local zebrad's state database
    /// (read-only) instead of fetching all chain data over JSON-RPC.
    ///
    /// When this section is present, Zallet opens the running zebrad's state database
    /// as a read-only RocksDB secondary instance and follows the non-finalized chain
    /// tip via zebrad's gRPC indexer interface. The JSON-RPC settings above are still
    /// required: they are used for mempool access, transaction submission, and any
    /// non-best-chain block reads.
    pub read_state_service: Option<ReadStateServiceSection>,
}

impl IndexerSection {
    /// Path to the folder where the indexer maintains its state.
    ///
    /// This can be either an absolute path, or a path relative to the data directory.
    ///
    /// Default is `zaino`.
    fn db_path(&self) -> &Path {
        self.db_path
            .as_deref()
            .unwrap_or_else(|| Path::new("zaino"))
    }
}

/// Settings for the read-state-service indexer backend.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct ReadStateServiceSection {
    /// Address (`host:port`) of zebrad's gRPC indexer interface.
    ///
    /// Used to follow zebrad's non-finalized chain tip. This must match the
    /// `indexer_listen_addr` set in zebrad's `[rpc]` config section. Note that the
    /// indexer interface is only available in a `zebrad` built with the `indexer`
    /// feature flag; it is not present in a default build.
    pub grpc_address: String,

    /// Path to the running zebrad's existing state cache directory.
    ///
    /// Zallet opens this read-only (as a RocksDB secondary instance); it never writes
    /// to or deletes it. It must be on the same machine as Zallet, and zebrad's on-disk
    /// state format must be compatible with Zallet's `zebra-state` version.
    ///
    /// This can be either an absolute path, or a path relative to the data directory.
    pub zebra_state_path: PathBuf,
}

/// Settings for the key store.
#[cfg(zallet_build = "wallet")]
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct KeyStoreSection {
    /// Path to the age identity file that encrypts key material.
    ///
    /// This can be either an absolute path, or a path relative to the data directory.
    /// Note that on Windows, you must either use single quotes for this field's value, or
    /// replace all backslashes `\` with forward slashes `/`.
    pub encryption_identity: Option<PathBuf>,

    /// By default, the wallet will not allow generation of new spending keys & addresses
    /// from the mnemonic seed until the backup of that seed has been confirmed with the
    /// `zcashd-wallet-tool` utility. A user may start zallet with `--walletrequirebackup=false`
    /// to allow generation of spending keys even if the backup has not yet been confirmed.
    pub require_backup: Option<bool>,
}

#[cfg(zallet_build = "wallet")]
impl KeyStoreSection {
    /// Path to the age identity file that encrypts key material.
    ///
    /// This can be either an absolute path, or a path relative to the data directory.
    ///
    /// Default is `encryption-identity.txt`.
    fn encryption_identity(&self) -> &Path {
        self.encryption_identity
            .as_deref()
            .unwrap_or_else(|| Path::new("encryption-identity.txt"))
    }

    /// Whether to require a confirmed wallet backup.
    ///
    /// By default, the wallet will not allow generation of new spending keys & addresses
    /// from the mnemonic seed until the backup of that seed has been confirmed with the
    /// `zcashd-wallet-tool` utility. A user may start zallet with `--walletrequirebackup=false`
    /// to allow generation of spending keys even if the backup has not yet been confirmed.
    pub fn require_backup(&self) -> bool {
        self.require_backup.unwrap_or(true)
    }
}

/// Note management configuration section.
//
// TODO: Decide whether this should be part of `[builder]`.
//       https://github.com/zcash/zallet/issues/251
#[cfg(zallet_build = "wallet")]
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct NoteManagementSection {
    /// The minimum value that Zallet should target for each shielded note in the wallet.
    pub min_note_value: Option<u32>,

    /// The target number of shielded notes with value at least `min_note_value` that
    /// Zallet should aim to maintain within each account in the wallet.
    ///
    /// If an account contains fewer such notes, Zallet will split larger notes (in change
    /// outputs of other transactions) to achieve the target.
    pub target_note_count: Option<NonZeroU16>,
}

#[cfg(zallet_build = "wallet")]
impl NoteManagementSection {
    /// The minimum value that Zallet should target for each shielded note in the wallet.
    ///
    /// Default is 100_0000.
    pub fn min_note_value(&self) -> Zatoshis {
        Zatoshis::const_from_u64(self.min_note_value.unwrap_or(100_0000).into())
    }

    /// The target number of shielded notes with value at least `min_note_value` that
    /// Zallet should aim to maintain within each account in the wallet.
    ///
    /// If an account contains fewer such notes, Zallet will split larger notes (in change
    /// outputs of other transactions) to achieve the target.
    ///
    /// Default is 4.
    pub fn target_note_count(&self) -> NonZeroU16 {
        self.target_note_count
            .unwrap_or_else(|| NonZeroU16::new(4).expect("valid"))
    }

    pub(crate) fn split_policy(&self) -> SplitPolicy {
        SplitPolicy::with_min_output_value(self.target_note_count().into(), self.min_note_value())
    }
}

/// Settings for the JSON-RPC interface.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct RpcSection {
    /// Addresses to listen for JSON-RPC connections.
    ///
    /// Note: The RPC server is disabled by default. To enable the RPC server, set a
    /// listen address in the config:
    /// ```toml
    /// [rpc]
    /// bind = ["127.0.0.1:28232"]
    /// ```
    ///
    /// # Security
    ///
    /// If you bind Zallet's RPC port to a public IP address, anyone on the internet can
    /// view your transactions and spend your funds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bind: Vec<SocketAddr>,

    /// Timeout (in seconds) during HTTP requests.
    pub timeout: Option<u64>,

    /// A list of users for which access to the JSON-RPC interface is authorized.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth: Vec<RpcAuthSection>,
}

impl RpcSection {
    /// Timeout during HTTP requests.
    ///
    /// Default is 30 seconds.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout.unwrap_or(30))
    }
}

/// A user that is authorized to access the JSON-RPC interface.
#[derive(Clone, Debug, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct RpcAuthSection {
    /// The username for accessing the JSON-RPC interface.
    ///
    /// Each username must be unique. If duplicates are present, only one of the passwords
    /// will work.
    pub user: String,

    /// The password for this user.
    ///
    /// This cannot be set when `pwhash` is set.
    #[serde(serialize_with = "serialize_rpc_password")]
    pub password: Option<SecretString>,

    /// A hash of the password for this user.
    ///
    /// This can be generated with `zallet rpc add-user`.
    pub pwhash: Option<String>,
}

fn serialize_rpc_password<S: serde::Serializer>(
    password: &Option<SecretString>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match password {
        Some(p) => p.expose_secret().serialize(serializer),
        None => None::<String>.serialize(serializer),
    }
}

/// Settings controlling how Zallet synchronizes the wallet with the chain.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Documented, DocumentedFields)]
#[serde(deny_unknown_fields)]
pub struct SyncSection {
    /// The maximum number of blocks that the history-recovery task downloads and scans in
    /// a single batch.
    ///
    /// Larger batches improve scanning throughput, but increase peak memory usage: every
    /// block in a batch is held in memory while it is downloaded and trial-decrypted.
    /// Mainnet blocks can currently be up to 2 MiB each, so a batch of N blocks can require
    /// on the order of N * 2 MiB of memory.
    pub recover_batch_size: Option<NonZeroU32>,
}

impl SyncSection {
    /// The maximum number of blocks that the history-recovery task downloads and scans in
    /// a single batch.
    ///
    /// Default is 1000.
    pub fn recover_batch_size(&self) -> u32 {
        self.recover_batch_size.map_or(1000, NonZeroU32::get)
    }
}

impl ZalletConfig {
    /// Generates an example config file, with all default values included as comments.
    pub fn generate_example() -> String {
        // This is the one bit of duplication we can't yet avoid. It could be replaced
        // with a proc macro, but for now we just need to remember to update this as we
        // make changes to the config structure.
        let conf = ZalletConfig::default();
        let field_defaults = [
            builder(
                "spend_zeroconf_change",
                conf.builder.spend_zeroconf_change(),
            ),
            builder(
                "trusted_confirmations",
                conf.builder.trusted_confirmations(),
            ),
            builder("tx_expiry_delta", conf.builder.tx_expiry_delta()),
            builder(
                "untrusted_confirmations",
                conf.builder.untrusted_confirmations(),
            ),
            builder_limits("orchard_actions", conf.builder.limits.orchard_actions()),
            consensus(
                "network",
                crate::network::kind::Serializable(conf.consensus.network),
            ),
            consensus("regtest_nuparams", &conf.consensus.regtest_nuparams),
            database("wallet", conf.database.wallet_path()),
            external("broadcast", conf.external.broadcast()),
            external("export_dir", &conf.external.export_dir),
            external("notify", &conf.external.notify),
            features("as_of_version", &conf.features.as_of_version),
            features("legacy_pool_seed_fingerprint", None::<String>),
            indexer("validator_address", &conf.indexer.validator_address),
            indexer("validator_cookie_path", &conf.indexer.validator_cookie_path),
            indexer("validator_user", &conf.indexer.validator_user),
            indexer("validator_password", &conf.indexer.validator_password),
            indexer("db_path", conf.indexer.db_path()),
            read_state_service("grpc_address", "127.0.0.1:8230"),
            read_state_service("zebra_state_path", "/home/<username>/.cache/zebra"),
            #[cfg(zallet_build = "wallet")]
            keystore("encryption_identity", conf.keystore.encryption_identity()),
            #[cfg(zallet_build = "wallet")]
            keystore("require_backup", conf.keystore.require_backup()),
            #[cfg(zallet_build = "wallet")]
            note_management(
                "min_note_value",
                conf.note_management.min_note_value().into_u64(),
            ),
            #[cfg(zallet_build = "wallet")]
            note_management(
                "target_note_count",
                conf.note_management.target_note_count(),
            ),
            rpc("bind", &conf.rpc.bind),
            rpc("timeout", conf.rpc.timeout().as_secs()),
            sync("recover_batch_size", conf.sync.recover_batch_size()),
        ]
        .into_iter()
        .collect::<HashMap<_, _>>();

        // The glue that makes the above easy to maintain:
        const BUILDER: &str = "builder";
        const BUILDER_LIMITS: &str = "builder.limits";
        const CONSENSUS: &str = "consensus";
        const DATABASE: &str = "database";
        const EXTERNAL: &str = "external";
        const FEATURES: &str = "features";
        const FEATURES_DEPRECATED: &str = "features.deprecated";
        const FEATURES_EXPERIMENTAL: &str = "features.experimental";
        const INDEXER: &str = "indexer";
        const READ_STATE_SERVICE: &str = "indexer.read_state_service";
        #[cfg(zallet_build = "wallet")]
        const KEYSTORE: &str = "keystore";
        #[cfg(zallet_build = "wallet")]
        const NOTE_MANAGEMENT: &str = "note_management";
        const RPC: &str = "rpc";
        const RPC_AUTH: &str = "rpc.auth";
        const SYNC: &str = "sync";
        fn builder<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(BUILDER, f, d)
        }
        fn builder_limits<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(BUILDER_LIMITS, f, d)
        }
        fn consensus<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(CONSENSUS, f, d)
        }
        fn database<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(DATABASE, f, d)
        }
        fn external<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(EXTERNAL, f, d)
        }
        fn features<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(FEATURES, f, d)
        }
        fn indexer<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(INDEXER, f, d)
        }
        fn read_state_service<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(READ_STATE_SERVICE, f, d)
        }
        #[cfg(zallet_build = "wallet")]
        fn keystore<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(KEYSTORE, f, d)
        }
        #[cfg(zallet_build = "wallet")]
        fn note_management<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(NOTE_MANAGEMENT, f, d)
        }
        fn rpc<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(RPC, f, d)
        }
        fn sync<T: Serialize>(
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            field(SYNC, f, d)
        }
        fn field<T: Serialize>(
            s: &'static str,
            f: &'static str,
            d: T,
        ) -> ((&'static str, &'static str), Option<toml::Value>) {
            (
                (s, f),
                match toml::Value::try_from(d) {
                    Ok(v) => Some(v),
                    Err(e) if e.to_string() == "unsupported None value" => None,
                    Err(_) => unreachable!(),
                },
            )
        }

        let sec_def = |section_name, field_name| {
            field_defaults
                .get(&(section_name, field_name))
                .expect("need to update field_defaults with changes to ZalletConfig")
                .as_ref()
        };

        let mut config = r"# Default configuration for Zallet.
#
# This file is generated as an example using Zallet's current defaults. It can
# be used as a skeleton for custom configs.
#
# Fields that are required to be set are uncommented, and set to an example
# value. Every other field is commented out, and set to the current default
# value that Zallet will use for it (or `UNSET` if the field has no default).
#
# Leaving a field commented out means that Zallet will always use the latest
# default value, even if it changes in future. Uncommenting a field but keeping
# it set to the current default value means that Zallet will treat it as a
# user-configured value going forward.

"
        .to_owned();

        fn write_section<'a, T: Documented + DocumentedFields>(
            config: &mut String,
            section_name: &'static str,
            sec_def: &impl Fn(&'static str, &'static str) -> Option<&'a toml::Value>,
        ) {
            write_section_inner::<T>(config, section_name, false, sec_def);
        }

        fn write_list_section<'a, T: Documented + DocumentedFields>(
            config: &mut String,
            section_name: &'static str,
            sec_def: &impl Fn(&'static str, &'static str) -> Option<&'a toml::Value>,
        ) {
            write_section_inner::<T>(config, section_name, true, sec_def);
        }

        fn write_optional_section<'a, T: Documented + DocumentedFields>(
            config: &mut String,
            section_name: &'static str,
            sec_def: &impl Fn(&'static str, &'static str) -> Option<&'a toml::Value>,
        ) {
            writeln!(config).unwrap();
            writeln!(config, "#").unwrap();
            for line in T::DOCS.lines() {
                if line.is_empty() {
                    writeln!(config, "#").unwrap();
                } else {
                    writeln!(config, "# {line}").unwrap();
                }
            }
            writeln!(config, "#").unwrap();
            writeln!(
                config,
                "# This section is optional. Uncomment the header and fields below to enable it."
            )
            .unwrap();
            writeln!(config, "#").unwrap();
            writeln!(config, "#[{section_name}]").unwrap();
            writeln!(config).unwrap();

            for field_name in T::FIELD_NAMES {
                write_field::<T>(config, field_name, false, sec_def(section_name, field_name));
            }
        }

        fn write_section_inner<'a, T: Documented + DocumentedFields>(
            config: &mut String,
            section_name: &'static str,
            is_list: bool,
            sec_def: &impl Fn(&'static str, &'static str) -> Option<&'a toml::Value>,
        ) {
            writeln!(config).unwrap();
            writeln!(config, "#").unwrap();
            for line in T::DOCS.lines() {
                if line.is_empty() {
                    writeln!(config, "#").unwrap();
                } else {
                    writeln!(config, "# {line}").unwrap();
                }
            }
            writeln!(config, "#").unwrap();
            if is_list {
                writeln!(
                    config,
                    "# Repeat this section to add more entries to the list."
                )
                .unwrap();
                writeln!(config, "#").unwrap();
                writeln!(config, "#[[{section_name}]]").unwrap();
            } else {
                writeln!(config, "[{section_name}]").unwrap();
            }
            writeln!(config).unwrap();

            for field_name in T::FIELD_NAMES {
                match (section_name, *field_name) {
                    // Render nested sections.
                    (BUILDER, "limits") => {
                        write_section::<BuilderLimitsSection>(config, BUILDER_LIMITS, sec_def)
                    }
                    (FEATURES, "deprecated") => write_section::<DeprecatedFeaturesSection>(
                        config,
                        FEATURES_DEPRECATED,
                        sec_def,
                    ),
                    (FEATURES, "experimental") => write_section::<ExperimentalFeaturesSection>(
                        config,
                        FEATURES_EXPERIMENTAL,
                        sec_def,
                    ),
                    (RPC, "auth") => {
                        write_list_section::<RpcAuthSection>(config, RPC_AUTH, sec_def)
                    }
                    (INDEXER, "read_state_service") => write_optional_section::<
                        ReadStateServiceSection,
                    >(
                        config, READ_STATE_SERVICE, sec_def
                    ),
                    // Ignore flattened fields (present to support parsing old configs).
                    (FEATURES_DEPRECATED, "other") | (FEATURES_EXPERIMENTAL, "other") => (),
                    // Render section field.
                    _ => write_field::<T>(
                        config,
                        field_name,
                        (section_name == CONSENSUS && *field_name == "network")
                            || (section_name == FEATURES && *field_name == "as_of_version"),
                        if is_list {
                            None
                        } else {
                            sec_def(section_name, field_name)
                        },
                    ),
                }
            }
        }

        fn write_field<T: DocumentedFields>(
            config: &mut String,
            field_name: &str,
            required: bool,
            field_default: Option<&toml::Value>,
        ) {
            let field_doc = T::get_field_docs(field_name).expect("present");
            for mut line in field_doc.lines() {
                // Trim selectively-untrimmed lines for docs that contained indentations
                // we want to preserve.
                line = line.strip_prefix(' ').unwrap_or(line);

                if line.is_empty() {
                    writeln!(config, "#").unwrap();
                } else {
                    writeln!(config, "# {line}").unwrap();
                }
            }

            write!(
                config,
                "{}{} = ",
                if required { "" } else { "#" },
                field_name
            )
            .unwrap();
            match field_default {
                Some(present) => {
                    Serialize::serialize(&present, toml::ser::ValueSerializer::new(config)).unwrap()
                }
                None => write!(config, "UNSET").unwrap(),
            }

            writeln!(config).unwrap();
            writeln!(config).unwrap();
        }

        for field_name in Self::FIELD_NAMES {
            match *field_name {
                BUILDER => write_section::<BuilderSection>(&mut config, field_name, &sec_def),
                CONSENSUS => write_section::<ConsensusSection>(&mut config, field_name, &sec_def),
                DATABASE => write_section::<DatabaseSection>(&mut config, field_name, &sec_def),
                EXTERNAL => write_section::<ExternalSection>(&mut config, field_name, &sec_def),
                FEATURES => write_section::<FeaturesSection>(&mut config, field_name, &sec_def),
                INDEXER => write_section::<IndexerSection>(&mut config, field_name, &sec_def),
                #[cfg(zallet_build = "wallet")]
                KEYSTORE => write_section::<KeyStoreSection>(&mut config, field_name, &sec_def),
                #[cfg(zallet_build = "wallet")]
                NOTE_MANAGEMENT => {
                    write_section::<NoteManagementSection>(&mut config, field_name, &sec_def)
                }
                RPC => write_section::<RpcSection>(&mut config, field_name, &sec_def),
                SYNC => write_section::<SyncSection>(&mut config, field_name, &sec_def),
                // Top-level fields correspond to CLI settings, and cannot be configured
                // via a file.
                _ => (),
            }
        }

        config
    }
}

#[cfg(test)]
mod tests {
    use super::ReadStateServiceSection;

    #[test]
    fn read_state_service_section_parses() {
        let toml = r#"
grpc_address = "127.0.0.1:8231"
zebra_state_path = "/home/user/.cache/zebra"
"#;
        let section: ReadStateServiceSection = toml::from_str(toml).unwrap();
        assert_eq!(section.grpc_address, "127.0.0.1:8231");
        assert_eq!(
            section.zebra_state_path,
            std::path::PathBuf::from("/home/user/.cache/zebra")
        );
    }

    #[test]
    fn read_state_service_section_requires_all_fields() {
        let toml = r#"grpc_address = "127.0.0.1:8231""#;
        assert!(toml::from_str::<ReadStateServiceSection>(toml).is_err());
    }

    #[test]
    fn sync_section_uses_default_batch_size_when_unset() {
        let section: super::SyncSection = toml::from_str("").unwrap();
        assert_eq!(section.recover_batch_size(), 1000);
    }

    #[test]
    fn sync_section_parses_override() {
        let section: super::SyncSection = toml::from_str("recover_batch_size = 10000").unwrap();
        assert_eq!(section.recover_batch_size(), 10000);
    }

    #[test]
    fn sync_section_rejects_zero_batch_size() {
        assert!(toml::from_str::<super::SyncSection>("recover_batch_size = 0").is_err());
    }
}
