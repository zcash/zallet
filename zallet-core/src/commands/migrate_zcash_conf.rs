//! `migrate-zcash-conf` subcommand

use std::collections::{HashMap, HashSet};
use std::iter;
use std::path::PathBuf;

use abscissa_core::Runnable;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
};

use crate::{
    cli::MigrateZcashConfCmd,
    commands::AsyncRunnable,
    config::{RpcAuthSection, ZalletConfig},
    error::{Error, ErrorKind},
    fl,
    network::RegTestNuParam,
};

impl AsyncRunnable for MigrateZcashConfCmd {
    async fn run(&self) -> Result<(), Error> {
        let conf = if self.conf.is_relative() {
            if let Some(datadir) = self.zcashd_datadir.as_ref() {
                datadir.join(&self.conf)
            } else {
                zcashd_default_data_dir()
                    .ok_or(ErrorKind::Generic)?
                    .join(&self.conf)
            }
        } else {
            self.conf.to_path_buf()
        };

        let f = BufReader::new(
            File::open(&conf)
                .await
                .map_err(|e| ErrorKind::Generic.context(e))?,
        );
        let mut lines = f.lines();

        let actions = build_actions();
        let mut config = ZalletConfig::default();
        let mut observed = HashSet::new();
        let mut related = HashMap::<String, String>::new();
        let mut warnings = vec![];

        while let Some(line) = lines
            .next_line()
            .await
            .map_err(|e| ErrorKind::Generic.context(e))?
        {
            // Parse the Boost.Program_options file format.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (option, rest) = match line.split_once('=') {
                Some(res) => res,
                None => {
                    return Err(ErrorKind::Generic
                        .context(fl!(
                            "err-migrate-invalid-line",
                            line = line,
                            conf = conf.display().to_string(),
                        ))
                        .into());
                }
            };
            let value = rest
                .split_once('#')
                .map_or_else(|| rest.trim_end(), |(value, _)| value.trim_end());

            match actions.get(option) {
                Some(Action::MapTo { f, target }) => {
                    if let Some(prev) = target.and_then(|target| related.get(target)) {
                        return Err(ErrorKind::Generic
                            .context(fl!(
                                "err-migrate-multiple-related-zcashd-options",
                                option = option,
                                prev = prev,
                                conf = conf.display().to_string(),
                            ))
                            .into());
                    } else if observed.contains(option) {
                        return Err(ErrorKind::Generic
                            .context(fl!(
                                "err-migrate-duplicate-zcashd-option",
                                option = option,
                                conf = conf.display().to_string(),
                            ))
                            .into());
                    } else {
                        observed.insert(option.to_owned());
                        if let Some(target) = target {
                            related.insert(target.to_string(), option.to_owned());
                        }
                        f(&mut config, value)?
                    }
                }
                Some(Action::MapMulti(f)) => f(&mut config, value)?,
                Some(Action::Ignore) => (),
                Some(Action::Warn(f)) => {
                    if let Some(warning) = f(value) {
                        warnings.push(warning);
                    }
                }
                None => {
                    return Err(ErrorKind::Generic
                        .context(fl!("err-migrate-unknown-zcashd-option", option = option))
                        .into());
                }
            }
        }

        // Inform the user of any warnings.
        if !warnings.is_empty() {
            println!("{}", fl!("migrate-warnings"));
            println!();
            for warning in warnings {
                println!("{warning}");
                println!();
            }

            // Warnings must be allowed by the user.
            if !self.allow_warnings {
                return Err(ErrorKind::Generic
                    .context(fl!("err-migrate-allow-warnings"))
                    .into());
            }
        }

        if !self.this_is_alpha_code_and_you_will_need_to_redo_the_migration_later {
            return Err(ErrorKind::Generic.context(fl!("migrate-alpha-code")).into());
        }

        // Serialize the config.
        let mut output = format!(
            r"# Zallet configuration file
# Migrated from {}

",
            conf.display(),
        );
        let config_toml =
            toml::Value::try_from(config).map_err(|e| ErrorKind::Generic.context(e))?;
        output +=
            &toml::to_string_pretty(&config_toml).map_err(|e| ErrorKind::Generic.context(e))?;

        // Write the Zallet config file.
        let output_path = match self.output.as_deref() {
            None => todo!("Fetch default Zallet config path"),
            Some("-") => None,
            Some(path) => Some(path),
        };
        if let Some(path) = output_path {
            let mut f = if self.force {
                File::create(path).await
            } else {
                File::create_new(path).await
            }
            .map_err(|e| ErrorKind::Generic.context(e))?;
            f.write_all(output.as_bytes())
                .await
                .map_err(|e| ErrorKind::Generic.context(e))?;
            println!("{}", fl!("migrate-config-written", conf = path));
        } else {
            println!("{output}")
        }

        Ok(())
    }
}

impl Runnable for MigrateZcashConfCmd {
    fn run(&self) {
        self.run_on_runtime();
    }
}

pub(crate) fn zcashd_default_data_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        use known_folders::{KnownFolder, get_known_folder_path};
        get_known_folder_path(KnownFolder::RoamingAppData).map(|base| base.join("Zcash"))
    }

    #[cfg(target_os = "macos")]
    {
        xdg::BaseDirectories::new()
            .ok()
            .map(|base_dirs| base_dirs.get_data_home().join("Zcash"))
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        home::home_dir().map(|base| base.join(".zcash"))
    }
}

type MapAction = Box<dyn Fn(&mut ZalletConfig, &str) -> Result<(), Error>>;
type WarnMessage = Box<dyn Fn(&str) -> Option<String>>;

/// The action to take when a specific `zcashd` option is encountered.
enum Action {
    /// Maps the option to its equivalent Zallet config option.
    MapTo {
        f: MapAction,
        /// The target Zallet config option, if this is one of a set of related `zcashd` options.
        target: Option<&'static str>,
    },
    /// Maps the multi-valued option to its equivalent Zallet config option.
    MapMulti(MapAction),
    /// Silently ignores the option.
    Ignore,
    /// Warns the user that the option is not supported in Zallet.
    ///
    /// The warning might be conditional on the configured value of the option.
    Warn(WarnMessage),
}

impl Action {
    fn map<T>(
        option: &'static str,
        f: impl for<'a> Fn(&'a mut ZalletConfig) -> &'a mut Option<T> + 'static,
        v: impl Fn(&str) -> Result<T, ()> + 'static,
    ) -> Option<(&'static str, Self)> {
        Some((
            option,
            Self::MapTo {
                f: Box::new(move |config, value| {
                    let value = match v(value) {
                        Ok(v) => Ok(v),
                        Err(()) => invalid_option_value(option, value),
                    }?;
                    *f(config) = Some(value);
                    Ok(())
                }),
                target: None,
            },
        ))
    }

    fn map_bool(
        option: &'static str,
        f: impl for<'a> Fn(&'a mut ZalletConfig) -> &'a mut Option<bool> + 'static,
    ) -> Option<(&'static str, Self)> {
        Self::map(option, f, |value| match value {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(()),
        })
    }

    /// Maps multiple related boolean flags onto the same config option.
    fn map_related<T>(
        option: &'static str,
        target: &'static str,
        f: impl for<'a> Fn(&'a mut ZalletConfig) -> &'a mut T + 'static,
        v: impl Fn(&str) -> Result<Option<T>, ()> + 'static,
    ) -> Option<(&'static str, Self)> {
        Some((
            option,
            Self::MapTo {
                f: Box::new(move |config, value| {
                    if let Some(value) = match v(value) {
                        Ok(v) => Ok(v),
                        Err(()) => invalid_option_value(option, value),
                    }? {
                        *f(config) = value;
                    }
                    Ok(())
                }),
                target: Some(target),
            },
        ))
    }

    fn map_multi<T>(
        option: &'static str,
        f: impl for<'a> Fn(&'a mut ZalletConfig) -> &'a mut Vec<T> + 'static,
        v: impl Fn(&str) -> Result<T, ()> + 'static,
    ) -> Option<(&'static str, Self)> {
        Some((
            option,
            Self::MapMulti(Box::new(move |config, value| {
                let value = match v(value) {
                    Ok(v) => Ok(v),
                    Err(()) => invalid_option_value(option, value),
                }?;
                f(config).push(value);
                Ok(())
            })),
        ))
    }

    fn ignore(option: &'static str) -> Option<(&'static str, Self)> {
        Some((option, Action::Ignore))
    }

    fn warn(f: impl Fn(&str) -> Option<String> + 'static) -> Self {
        Self::Warn(Box::new(f))
    }
}

fn invalid_option_value<T>(option: &str, value: &str) -> Result<T, Error> {
    Err(ErrorKind::Generic
        .context(fl!(
            "err-migrate-invalid-zcashd-option",
            option = option,
            value = value,
        ))
        .into())
}

fn build_actions() -> HashMap<&'static str, Action> {
    // Documented wallet options.
    let documented_wallet_options = iter::empty()
        .chain(Some((
            "disablewallet",
            Action::warn(|value| {
                (value != "0").then(|| fl!("migrate-warn-disablewallet", option = "disablewallet"))
            }),
        )))
        // Zallet does not support "bare" transparent keys, so there is no need to
        // maintain a keypool for performance.
        .chain(Action::ignore("keypool"))
        .chain(Some((
            "migration",
            Action::warn(|_| Some(fl!("migrate-warn-sprout-migration", option = "migration"))),
        )))
        .chain(Some((
            "migrationdestaddress",
            Action::warn(|_| {
                Some(fl!(
                    "migrate-warn-sprout-migration",
                    option = "migrationdestaddress",
                ))
            }),
        )))
        .chain(Action::map(
            "orchardactionlimit",
            |config| &mut config.builder.limits.orchard_actions,
            |value| value.parse().map_err(|_| ()),
        ))
        .chain(Some((
            "paytxfee",
            Action::warn(|_| Some(fl!("migrate-warn-paytxfee", option = "paytxfee"))),
        )))
        .chain(Some((
            "rescan",
            Action::warn(|_| {
                Some(fl!(
                    "migrate-warn-cli-only",
                    option = "rescan",
                    flag = "--rescan",
                ))
            }),
        )))
        .chain(Some((
            "salvagewallet",
            Action::warn(|_| {
                Some(fl!(
                    "migrate-warn-cli-only",
                    option = "salvagewallet",
                    flag = "--salvage-wallet",
                ))
            }),
        )))
        .chain(Action::map_bool("spendzeroconfchange", |config| {
            &mut config.builder.spend_zeroconf_change
        }))
        .chain(Action::map(
            "txexpirydelta",
            |config| &mut config.builder.tx_expiry_delta,
            |value| match value.parse() {
                // Minimum is `TX_EXPIRING_SOON_THRESHOLD + 1`.
                Ok(0..=3) => Err(()),
                Ok(n @ 4..) => Ok(n),
                Err(_) => Err(()),
            },
        ))
        // TODO: Decide if we want to distinguish between database migrations (which we
        // currently require) and wallet format upgrades.
        .chain(Action::ignore("upgradewallet"))
        // TODO: Decide whether we want to allow renaming the `WalletDb` backing file.
        .chain(Action::ignore("wallet"))
        .chain(Action::map_bool("walletbroadcast", |config| {
            &mut config.external.broadcast
        }))
        // TODO: Decide if we want to change how this is configured, or do anything to
        // improve security.
        .chain(Action::map(
            "walletnotify",
            |config| &mut config.external.notify,
            |value| Ok(value.into()),
        ))
        .chain(Action::map_bool("walletrequirebackup", |config| {
            &mut config.keystore.require_backup
        }))
        .chain(Some((
            "zapwallettxes",
            Action::warn(|_| {
                Some(fl!(
                    "migrate-warn-cli-only",
                    option = "zapwallettxes",
                    flag = "--zap-txes=MODE",
                ))
            }),
        )));

    // Documented wallet debugging/testing options.
    let documented_wallet_debug_options = iter::empty()
        // `dblogsize` doesn't have an SQLite analogue.
        .chain(Action::ignore("dblogsize"))
        // `flushwallet` does have SQLite analogues, but they have different semantics, so
        // we aren't migrating this across by default.
        .chain(Some((
            "flushwallet",
            Action::warn(|value| {
                (value != "1").then(|| {
                    fl!(
                        "migrate-warn-unsupported",
                        option = "flushwallet",
                        value = value,
                    )
                })
            }),
        )))
        // TODO: Figure out if SQLite has an analogue for BDB's `DB_PRIVATE`.
        .chain(Action::ignore("privdb"));

    // Undocumented options used only by wallet code.
    let undocumented_wallet_options = iter::empty()
        // TODO: Decide if we want to map this to the eventual "untrusted confirmations"
        // setting for the improved note selection logic.
        .chain(Action::ignore("anchorconfirmations"))
        // Unsupported in `zcashd` since 5.5.0.
        .chain(Action::ignore("mintxfee"))
        // TODO: Determine whether we need this for regtest testing of Zallet.
        .chain(Action::ignore("regtestwalletsetbestchaineveryblock"))
        // Unsupported in `zcashd` since 5.5.0.
        .chain(Action::ignore("sendfreetransactions"))
        // Unsupported in `zcashd` since 5.5.0.
        .chain(Action::ignore("txconfirmtarget"));

    // Node options used directly by wallet code.
    let node_options_direct_wallet = iter::empty()
        // Experimental feature we aren't migrating.
        .chain(Action::ignore("developerencryptwallet"))
        // Used to re-enable CPU mining after disabling it during proving.
        // Irrelevant for Zallet which doesn't include mining.
        .chain(Action::ignore("genproclimit"))
        // TODO: Figure out where this was used, and if we want to keep it.
        .chain(Action::ignore("maxtxfee"))
        // Used to check whether the configured miner address exists in the wallet.
        // Irrelevant for Zallet which doesn't include mining.
        .chain(Action::ignore("mineraddress"))
        // Experimental feature we aren't migrating.
        .chain(Action::ignore("paymentdisclosure"))
        .chain(Some((
            "preferredtxversion",
            Action::warn(|value| {
                Some(fl!(
                    "migrate-warn-unsupported",
                    option = "preferredtxversion",
                    value = value,
                ))
            }),
        )));

    // Node options used indirectly by the `zcashd` wallet (such as in common ambient
    // infrastructure that is being replicated in Zallet).
    let node_options_indirect_wallet = iter::empty()
        // This is likely the file we're migrating from; we don't want its name or path.
        .chain(Action::ignore("conf"))
        .chain(Some((
            "daemon",
            Action::warn(|value| {
                (value != "0").then(|| fl!("migrate-warn-daemon", option = "daemon"))
            }),
        )))
        // We don't want to store Zallet data in the same folder as `zcashd` data.
        .chain(Action::ignore("datadir"))
        // The logging systems of `zcashd` and Zallet differ sufficiently that we don't
        // try to map existing log targets across.
        .chain(Action::ignore("debug"))
        // We aren't going to migrate over the `zcashd` wallet's experimental features
        // compatibly. If we add a similar framework to Zallet it will be for from-scratch
        // features.
        .chain(Action::ignore("experimentalfeatures"))
        .chain(Action::map(
            "exportdir",
            |config| &mut config.external.export_dir,
            |value| Ok(value.into()),
        ))
        .chain(Action::map_multi(
            "nuparams",
            |config| &mut config.consensus.regtest_nuparams,
            |value| RegTestNuParam::try_from(value.to_string()).map_err(|_| ()),
        ))
        .chain(Action::map_related(
            "regtest",
            "network",
            |config| &mut config.consensus.network,
            |value| Ok((value == "1").then_some(zcash_protocol::consensus::NetworkType::Regtest)),
        ))
        // TODO: Support mapping multi-arg options.
        .chain(Action::ignore("rpcallowip"))
        // Unsupported in `zcashd` since 1.0.0-beta1.
        .chain(Action::ignore("rpcasyncthreads"))
        .chain(Action::map_multi(
            "rpcauth",
            |config| &mut config.rpc.auth,
            |value| {
                let (username, pwhash) = value.split_once(':').ok_or(())?;
                Ok(RpcAuthSection {
                    user: username.into(),
                    password: None,
                    pwhash: Some(pwhash.into()),
                })
            },
        ))
        // TODO: Need to check how this interacts with `rpcport`; we may instead need a
        // warning here and no migration.
        .chain(Action::map_multi(
            "rpcbind",
            |config| &mut config.rpc.bind,
            // TODO: Decide on a default Zallet JSON-RPC port.
            |value| format!("{}:{}", value, 8234).parse().map_err(|_| ()),
        ))
        // TODO
        .chain(Action::ignore("rpccookiefile"))
        .chain(Some((
            "rpcport",
            Action::warn(|_| {
                Some(fl!(
                    "migrate-warn-rpcport",
                    option = "rpcport",
                    port = "bind",
                    rpc = "[rpc]",
                ))
            }),
        )))
        .chain(Action::map(
            "rpcservertimeout",
            |config| &mut config.rpc.timeout,
            |value| value.parse().map_err(|_| ()),
        ))
        // Unsupported in `zcashd` since 1.0.8.
        .chain(Action::ignore("rpcssl"))
        // `jsonrpsee` is an async JSON-RPC implementation, so it doesn't have dedicated
        // threads; instead it shares the Tokio worker thread pool.
        .chain(Action::ignore("rpcthreads"))
        // TODO: Not quite the same thing as `ServerBuilder::set_message_buffer_capacity` I think?
        .chain(Action::ignore("rpcworkqueue"))
        .chain(Action::map_related(
            "testnet",
            "network",
            |config| &mut config.consensus.network,
            |value| Ok((value == "1").then_some(zcash_protocol::consensus::NetworkType::Test)),
        ));

    // Node options never used by the `zcashd` wallet. These can be safely ignored if
    // encountered in a `zcashd` config file.
    let node_options_unused_wallet = [
        "addnode",
        "alertnotify",
        "alerts",
        "allowdeprecated",
        "banscore",
        "bantime",
        "benchmark",
        "bind",
        "blockmaxsize",
        "blockminsize",
        "blocknotify",
        "blockprioritysize",
        "blocksonly",
        "blockunpaidactionlimit",
        "blockversion",
        "checkblockindex",
        "checkblocks",
        "checklevel",
        "checkmempool",
        "checkpoints",
        "clockoffset",
        "connect",
        "create",
        "datacarrier",
        "datacarriersize",
        "dbcache",
        "debuglogfile",
        "debugmetrics",
        "debugnet",
        "developersetpoolsizezero",
        "disablesafemode",
        "discover",
        "dns",
        "dnsseed",
        "dropmessagestest",
        "enforcenodebloom",
        "equihashsolver",
        "externalip",
        "forcednsseed",
        "fundingstream",
        "fuzzmessagestest",
        "gen",
        "help",
        "help-debug",
        "i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025",
        "ibdskiptxverification",
        "insightexplorer",
        "json",
        "lightwalletd",
        "limitancestorcount",
        "limitancestorsize",
        "limitdescendantcount",
        "limitdescendantsize",
        "listen",
        "listenonion",
        "loadblock",
        "logips",
        "logtimestamps",
        "maxconnections",
        "maxorphantx",
        "maxreceivebuffer",
        "maxsendbuffer",
        "maxsigcachesize",
        "maxtipage",
        "maxuploadtarget",
        "mempoolevictionmemoryminutes",
        "mempooltxcostlimit",
        "metricsallowip",
        "metricsbind",
        "metricsrefreshtime",
        "metricsui",
        "minetolocalwallet",
        "minrelaytxfee",
        "mocktime",
        "nodebug",
        "nurejectoldversions",
        "onion",
        "onlynet",
        "optimize-getheaders",
        "par",
        "paramsdir",
        "peerbloomfilters",
        "permitbaremultisig",
        "pid",
        "port",
        "printalert",
        "printpriority",
        "printtoconsole",
        "prometheusport",
        "proxy",
        "proxyrandomize",
        "prune",
        "regtestshieldcoinbase",
        "reindex",
        "reindex-chainstate",
        "rest",
        "rpcclienttimeout",
        "rpcconnect",
        "rpcpassword",
        "rpcuser",
        "rpcwait",
        "seednode",
        "sendalert",
        "server",
        "showmetrics",
        "shrinkdebugfile",
        "socks",
        "stdin",
        "stopafterblockimport",
        "sysperms",
        "testsafemode",
        "timeout",
        "tor",
        "torcontrol",
        "torpassword",
        "txexpirynotify",
        "txindex",
        "txunpaidactionlimit",
        "uacomment",
        "version",
        "whitebind",
        "whitelist",
        "whitelistforcerelay",
        "whitelistrelay",
    ];

    // Compose in parts to avoid type system recursion limits.
    iter::empty()
        .chain(documented_wallet_options)
        .chain(documented_wallet_debug_options)
        .chain(undocumented_wallet_options)
        .chain(node_options_direct_wallet)
        .chain(node_options_indirect_wallet)
        .chain(
            node_options_unused_wallet
                .into_iter()
                .filter_map(Action::ignore),
        )
        .collect()
}
