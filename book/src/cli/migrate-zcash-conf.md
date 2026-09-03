# The `migrate-zcash-conf` command

> Available on **crate feature** `zcashd-import` only.

`zallet migrate-zcash-conf` migrates a [`zcashd`] configuration file (`zcash.conf`) to an
equivalent Zallet [configuration file] (`zallet.toml`).

## Flags

The configuration file is located with two flags, neither of which is required:

- `--conf`: A path to a `zcashd` configuration file. Defaults to `zcash.conf`.
- `--zcashd-datadir`: A path to a `zcashd` datadir, against which a relative `--conf` is
  resolved. If omitted, the platform's default `zcashd` datadir is used (`~/.zcash` on
  Linux, the XDG data home's `Zcash` directory on macOS, `%APPDATA%\Zcash` on Windows).

The output is controlled by:

- `-o/--output PATH`: Where to write the Zallet config file. By default the config file
  path Zallet loads at startup is used (`zallet.toml` in the Zallet datadir). The value
  `-` writes the config to stdout instead.
- `-f/--force`: Overwrite an existing file at the `-o/--output` path. Without it, the
  command refuses to overwrite an existing file. `--force` has no effect on the default
  path: the live config file is never overwritten, so a re-run cannot discard manual
  edits to it. Pass `-o` explicitly to overwrite.
- `--allow-warnings`: Continue when one or more `zcashd` options produce a warning (see
  below). Without it, any warning aborts the command before anything is written.

> For the Zallet beta releases, the command also currently takes another required flag
> `--this-is-beta-code-and-you-will-need-to-redo-the-migration-later`.

## What the command does

1. Parses `zcash.conf` line by line. Blank lines and `#` comments are skipped; a
   non-comment line without `=` is an error.
2. Classifies every option according to the [table below](#how-zcashd-options-are-handled).
   An option that is not in the table at all is an error (`Unknown zcashd option`), so
   a config file with an option Zallet has never heard of must have that line removed or
   commented out before it can be migrated. An option that may appear only once but
   appears twice is also an error, as is having both `testnet=` and `regtest=` present
   (regardless of their values).
3. Prints every warning that was collected, then aborts unless `--allow-warnings` was
   passed. Nothing is written in that case.
4. Writes `zallet.toml`: a two-line header naming the source file, followed by every
   config section (sections with nothing to say are written empty), and reports the
   path it was written to.

The generated file contains only the options that were migrated, so it is a starting
point rather than a complete config: in particular the `[indexer]` section that tells
Zallet how to reach `zebrad` must still be filled in by hand (see
[Wallet setup](../guide/setup.md)).

## How `zcashd` options are handled

Every option `zcashd` accepts falls into one of three groups.

### Mapped to a `zallet.toml` option

| `zcash.conf` | `zallet.toml` | Notes |
| --- | --- | --- |
| `orchardactionlimit` | `builder.limits.orchard_actions` | |
| `spendzeroconfchange` | `builder.spend_zeroconf_change` | `0` / `1` become `false` / `true` |
| `txexpirydelta` | `builder.tx_expiry_delta` | Values below `4` are rejected as invalid |
| `walletbroadcast` | `external.broadcast` | `0` / `1` become `false` / `true` |
| `walletnotify` | `external.notify` | Migrated, but not yet implemented: `zallet start` warns and ignores it ([#773]) |
| `exportdir` | `external.export_dir` | Migrated, but not yet implemented: `zallet start` warns and ignores it ([#773]) |
| `walletrequirebackup` | `keystore.require_backup` | `0` / `1` become `false` / `true` |
| `rpcservertimeout` | `rpc.timeout` | |
| `rpcauth` | `[[rpc.auth]]` (`user` and `pwhash`) | May be repeated; each entry becomes one `[[rpc.auth]]` table |
| `rpcbind` | `rpc.bind` | May be repeated. Each address has Zallet's default port `8234` appended; `rpcport` is **not** applied (see below) |
| `nuparams` | `consensus.regtest_nuparams` | May be repeated |
| `testnet=1` | `consensus.network = "test"` | |
| `regtest=1` | `consensus.network = "regtest"` | |

[#773]: https://github.com/zcash/zallet/issues/773

### Produce a warning

These have no equivalent in Zallet, or one that differs enough that the value is not
carried across. Each prints a warning naming the option, and the command aborts unless
`--allow-warnings` is passed.

| `zcash.conf` | When | What the warning says |
| --- | --- | --- |
| `disablewallet` | value is not `0` | This node's wallet was not in use; check that you mean to migrate its config |
| `daemon` | value is not `0` | Use `systemd` or similar to run Zallet as a service |
| `paytxfee` | always | Zallet only supports [ZIP 317](https://zips.z.cash/zip-0317) fees |
| `migration`, `migrationdestaddress` | always | Zallet does not support Sprout, so the Sprout-to-Sapling migration is not migrated |
| `rescan`, `salvagewallet`, `zapwallettxes` | always | Not supported as config entries. The warning refers to `zallet start` flags (`--rescan`, `--salvage-wallet`, `--zap-txes=MODE`) that do not currently exist; see [`zallet repair`](repair/README.md) for the rescan and repair tooling Zallet does provide |
| `flushwallet` | value is not `1` | No equivalent; the value is dropped |
| `preferredtxversion` | always | No equivalent; the value is dropped |
| `rpcport` | always | `zcashd` served node and wallet RPC on one port; Zallet has its own. To change Zallet's port, set it in `rpc.bind` in `zallet.toml` |

### Ignored

Everything else that `zcashd` accepts is dropped **without** a warning. Two groups
deserve attention:

- **`rpcuser` and `rpcpassword` are dropped.** Only `rpcauth` entries are migrated.
  Zallet uses [cookie authentication](rpc.md#authentication) by default; to add a
  password credential, use [`zallet add-rpc-user`](add-rpc-user.md), which prints an
  `[[rpc.auth]]` entry to paste into `zallet.toml`.
- **Wallet options with no Zallet equivalent**: `anchorconfirmations`, `dblogsize`,
  `developerencryptwallet`, `genproclimit`, `keypool`, `maxtxfee`, `mineraddress`,
  `mintxfee`, `paymentdisclosure`, `privdb`, `regtestwalletsetbestchaineveryblock`,
  `sendfreetransactions`, `txconfirmtarget`, `upgradewallet`, `wallet`.
- **RPC and process options that Zallet configures differently or not at all**: `conf`,
  `datadir`, `debug`, `experimentalfeatures`, `rpcallowip`, `rpcasyncthreads`,
  `rpccookiefile`, `rpcssl`, `rpcthreads`, `rpcworkqueue`.

<details>
<summary>Node-only options that are ignored</summary>

These options only ever affected the `zcashd` node, so they have no meaning for a
wallet and are dropped silently:

`addnode`, `alertnotify`, `alerts`, `allowdeprecated`, `banscore`, `bantime`,
`benchmark`, `bind`, `blockmaxsize`, `blockminsize`, `blocknotify`,
`blockprioritysize`, `blocksonly`, `blockunpaidactionlimit`, `blockversion`,
`checkblockindex`, `checkblocks`, `checklevel`, `checkmempool`, `checkpoints`,
`clockoffset`, `connect`, `create`, `datacarrier`, `datacarriersize`, `dbcache`,
`debuglogfile`, `debugmetrics`, `debugnet`, `developersetpoolsizezero`,
`disablesafemode`, `discover`, `dns`, `dnsseed`, `dropmessagestest`,
`enforcenodebloom`, `equihashsolver`, `externalip`, `forcednsseed`, `fundingstream`,
`fuzzmessagestest`, `gen`, `help`, `help-debug`,
`i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025`,
`ibdskiptxverification`, `insightexplorer`, `json`, `lightwalletd`,
`limitancestorcount`, `limitancestorsize`, `limitdescendantcount`,
`limitdescendantsize`, `listen`, `listenonion`, `loadblock`, `logips`,
`logtimestamps`, `maxconnections`, `maxorphantx`, `maxreceivebuffer`,
`maxsendbuffer`, `maxsigcachesize`, `maxtipage`, `maxuploadtarget`,
`mempoolevictionmemoryminutes`, `mempooltxcostlimit`, `metricsallowip`,
`metricsbind`, `metricsrefreshtime`, `metricsui`, `minetolocalwallet`,
`minrelaytxfee`, `mocktime`, `nodebug`, `nurejectoldversions`, `onion`, `onlynet`,
`optimize-getheaders`, `par`, `paramsdir`, `peerbloomfilters`, `permitbaremultisig`,
`pid`, `port`, `printalert`, `printpriority`, `printtoconsole`, `prometheusport`,
`proxy`, `proxyrandomize`, `prune`, `regtestshieldcoinbase`, `reindex`,
`reindex-chainstate`, `rest`, `rpcclienttimeout`, `rpcconnect`, `rpcpassword`,
`rpcuser`, `rpcwait`, `seednode`, `sendalert`, `server`, `showmetrics`,
`shrinkdebugfile`, `socks`, `stdin`, `stopafterblockimport`, `sysperms`,
`testsafemode`, `timeout`, `tor`, `torcontrol`, `torpassword`, `txexpirynotify`,
`txindex`, `txunpaidactionlimit`, `uacomment`, `version`, `whitebind`, `whitelist`,
`whitelistforcerelay`, `whitelistrelay`.

</details>

## Example

Given this `zcash.conf` (one of the fixtures Zallet's own tests run the command
against):

```
{{#include ../../../backends/zebra/tests/cmd/migrate_zcash_conf_mainnet.in/zcash.conf}}
```

`zallet migrate-zcash-conf --zcashd-datadir . -o -` produces:

```toml
# Zallet configuration file
# Migrated from ./zcash.conf

[builder.limits]

[consensus]
network = "main"

[database]

[external]

[features]
as_of_version = "0.1.0-beta.3"

[features.deprecated]

[features.experimental]

[indexer]

[keystore]

[note_management]

[rpc]
bind = [
    "172.16.0.1:8234",
    "127.0.0.1:8234",
]

[[rpc.auth]]
pwhash = "50bb6ea2ab224071ecc3ef195a3a8$9090d8985b8d9969aa2062d134ebb2d568cd585a383ed76931ac34c7d4c8ebf5"
user = "foobar"

[sync]
```

Note what happened: the two `rpcbind` addresses gained port `8234`, the `rpcauth`
entry became an `[[rpc.auth]]` table, `rpcuser` / `rpcpassword` and every node-only
option vanished without comment, and the `[indexer]` section is empty.

[`zcashd`]: https://github.com/zcash/zcash
[configuration file]: example-config.md
