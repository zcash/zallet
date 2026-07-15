# JSON-RPC method status

This page lists every wallet JSON-RPC method that `zcashd` provided, and its
status in Zallet. Use it to inventory your RPC usage before migrating.

Statuses:

- **Implemented** — available in Zallet with `zcashd`-compatible semantics.
- **Implemented (altered)** — available, but with [altered semantics](json_rpc.md).
- **Not yet implemented** — intentionally absent so far; implementation is
  tracked in the linked issue. Whether each of these ships will be decided
  during the beta phase ([#287]).
- **Not planned** — not intended to be implemented; the Notes column says what
  to use instead. These reflect current team intent and may be revisited
  during the beta phase ([#287]).
- **Omitted** — intentionally not implemented; see the
  [omitted methods](json_rpc.md#omitted-rpc-methods) table for replacements.

[#287]: https://github.com/zcash/zallet/issues/287

| `zcashd` method | Status | Notes |
|---|---|---|
| `addmultisigaddress` | Not yet implemented | Blocked on P2SH support in `zcash_client_sqlite` ([#48](https://github.com/zcash/zallet/issues/48), [librustzcash#1370](https://github.com/zcash/librustzcash/issues/1370)) |
| `backupwallet` | Not planned | Not planned as an RPC; may become a CLI command ([#49](https://github.com/zcash/zallet/issues/49)); robust backup is tracked in [#195](https://github.com/zcash/zallet/issues/195) |
| `dumpprivkey` | Not planned | [#50](https://github.com/zcash/zallet/issues/50) |
| `dumpwallet` | Not planned | Already removed from `zcashd` itself ([zcash#5513](https://github.com/zcash/zcash/issues/5513)); a [ZeWIF](https://github.com/zcash/zewif) export is planned instead ([#71](https://github.com/zcash/zallet/issues/71)) |
| `encryptwallet` | Omitted | [Note](json_rpc.md#encryptwallet): key material is always encrypted |
| `getbalance` | Not planned | Use `z_getbalanceforaccount` ([#51](https://github.com/zcash/zallet/issues/51)) |
| `getnewaddress` | Omitted | Use `z_getnewaccount` + `z_getaddressforaccount` |
| `getrawchangeaddress` | Omitted | [Note](json_rpc.md#getrawchangeaddress): change is handled internally |
| `getreceivedbyaddress` | Not yet implemented | [#52](https://github.com/zcash/zallet/issues/52) |
| `gettransaction` | Not planned | Superseded by `z_viewtransaction`, which now includes its top-level fields ([altered semantics](json_rpc.md#z_viewtransaction)); `gettransaction` cannot represent partially-shielded transactions correctly |
| `getunconfirmedbalance` | Not yet implemented | [#54](https://github.com/zcash/zallet/issues/54) |
| `getwalletinfo` | Implemented (partial) | Balance fields will not be populated — use dedicated balance methods ([#55](https://github.com/zcash/zallet/issues/55)); most other fields are currently placeholders, and only `unlocked_until` is meaningful |
| `importaddress` | Not yet implemented | Planned to import into the legacy transparent account ([#56](https://github.com/zcash/zallet/issues/56)); if you have the public key or redeem script, `z_importaddress` covers this today |
| `importprivkey` | Not yet implemented | [#57](https://github.com/zcash/zallet/issues/57) |
| `importpubkey` | Omitted | Use `z_importaddress` |
| `importwallet` | Omitted | Use `z_importkey` per key, or [`zallet migrate-zcashd-wallet`](../cli/migrate-zcashd-wallet.md); a CLI import may be considered ([#81](https://github.com/zcash/zallet/issues/81)) |
| `keypoolrefill` | Omitted | [Note](json_rpc.md#keypoolrefill): no key pool exists |
| `listaddresses` | Implemented (altered) | [Changes](json_rpc.md#listaddresses) |
| `listaddressgroupings` | Not planned | [#59](https://github.com/zcash/zallet/issues/59) |
| `listlockunspent` | Not yet implemented | Planned with modified semantics ([#60](https://github.com/zcash/zallet/issues/60)) |
| `listreceivedbyaddress` | Not yet implemented | [#61](https://github.com/zcash/zallet/issues/61) |
| `listsinceblock` | Not yet implemented | [#62](https://github.com/zcash/zallet/issues/62) |
| `listtransactions` | Not yet implemented | Provided today in modified, account-scoped form as `z_listtransactions` ([#63](https://github.com/zcash/zallet/issues/63)) |
| `listunspent` | Not planned | Subsumed by `z_listunspent`, which now includes transparent outputs ([changes](json_rpc.md#z_listunspent), [#64](https://github.com/zcash/zallet/issues/64)) |
| `lockunspent` | Not yet implemented | Planned with modified semantics ([#65](https://github.com/zcash/zallet/issues/65)) |
| `sendmany` | Not planned | Use `z_sendmany`, or `z_sendfromaccount` once implemented ([#66](https://github.com/zcash/zallet/issues/66), [#217](https://github.com/zcash/zallet/issues/217)) |
| `sendtoaddress` | Not planned | Use `z_sendfromaccount` once implemented ([#217](https://github.com/zcash/zallet/issues/217)); `z_sendmany` covers most uses today ([#67](https://github.com/zcash/zallet/issues/67)) |
| `settxfee` | Omitted | [ZIP 317](https://zips.z.cash/zip-0317) fees are always used |
| `signmessage` | Not yet implemented | [#68](https://github.com/zcash/zallet/issues/68) |
| `walletconfirmbackup` | Not planned | Internal `zcashd` method not intended to be called directly (related: [#201](https://github.com/zcash/zallet/issues/201)) |
| `z_converttex` | Implemented | |
| `z_exportkey` | Implemented | |
| `z_exportviewingkey` | Not yet implemented | Planned as UFVK/UIVK export ([#70](https://github.com/zcash/zallet/issues/70)) |
| `z_exportwallet` | Not yet implemented | Planned as a [ZeWIF](https://github.com/zcash/zewif) export, likely a CLI operation rather than an RPC ([#71](https://github.com/zcash/zallet/issues/71)) |
| `z_getaddressforaccount` | Implemented (altered) | [Changes](json_rpc.md#z_getaddressforaccount) |
| `z_getbalance` | Omitted | Use `z_getbalanceforaccount` |
| `z_getbalanceforaccount` | Implemented | |
| `z_getbalanceforviewingkey` | Not planned | Imported viewing keys get accounts with UUIDs, so `z_getbalanceforaccount` covers them ([#74](https://github.com/zcash/zallet/issues/74)) |
| `z_getmigrationstatus` | Omitted | [Note](json_rpc.md#z_getmigrationstatus-and-z_setmigration): no Sprout support; may be revisited for a future pool migration ([#481](https://github.com/zcash/zallet/issues/481)) |
| `z_getnewaccount` | Implemented (altered) | [Changes](json_rpc.md#z_getnewaccount) |
| `z_getnewaddress` | Omitted | Use `z_getnewaccount` + `z_getaddressforaccount` |
| `z_getnotescount` | Implemented | |
| `z_getoperationresult` | Implemented | |
| `z_getoperationstatus` | Implemented | |
| `z_gettotalbalance` | Implemented (deprecated) | `include_watchonly = false` is not yet honored; use the account-scoped `z_getbalanceforaccount` / `z_getbalances` instead ([#324](https://github.com/zcash/zallet/issues/324)) |
| `z_importkey` | Implemented (altered) | Sapling extended spending keys only |
| `z_importviewingkey` | Not yet implemented | Planned for Sapling keys, UFVKs, and UIVKs ([#80](https://github.com/zcash/zallet/issues/80)) |
| `z_importwallet` | Omitted | Use `z_importkey` per key, or [`zallet migrate-zcashd-wallet`](../cli/migrate-zcashd-wallet.md); reconsideration tracked in [#81](https://github.com/zcash/zallet/issues/81) |
| `z_listaccounts` | Implemented (altered) | [Changes](json_rpc.md#z_listaccounts) |
| `z_listaddresses` | Omitted | Use `listaddresses` |
| `z_listoperationids` | Implemented | |
| `z_listreceivedbyaddress` | Not yet implemented | [#84](https://github.com/zcash/zallet/issues/84) |
| `z_listunifiedreceivers` | Implemented | |
| `z_listunspent` | Implemented (altered) | [Changes](json_rpc.md#z_listunspent) |
| `z_mergetoaddress` | Not yet implemented | [#87](https://github.com/zcash/zallet/issues/87) |
| `z_sendmany` | Implemented (altered) | [Changes](json_rpc.md#z_sendmany) |
| `z_setmigration` | Omitted | [Note](json_rpc.md#z_getmigrationstatus-and-z_setmigration): no Sprout support; may be revisited for a future pool migration ([#481](https://github.com/zcash/zallet/issues/481)) |
| `z_shieldcoinbase` | Implemented | |
| `z_viewtransaction` | Implemented (altered) | [Changes](json_rpc.md#z_viewtransaction) |
| `zcbenchmark` | Omitted | [Note](json_rpc.md#zcbenchmark) |
| `zcsamplejoinsplit` | Omitted | Sprout-specific benchmarking helper; no Sprout support |

## Methods Zallet adds

Zallet also provides methods that `zcashd`'s wallet did not have:

- `getwalletstatus` — wallet and sync status.
- `z_getaccount` — details for a single account.
- `z_getbalances` — balances for all accounts.
- `z_importaddress` — import a transparent P2PKH public key or P2SH redeem
  script into an account.
- `z_listtransactions` — account-scoped transaction listing.
- `z_recoveraccounts` — re-create accounts from existing seeds.
- `rpc.discover` — an [OpenRPC](https://open-rpc.org/) description of the full
  interface.

Zallet additionally implements these methods that lived outside `zcashd`'s
wallet category: `getrawtransaction` (with
[altered semantics](json_rpc.md#getrawtransaction)), `decoderawtransaction`,
`decodescript`, `validateaddress`, `verifymessage`, `help`, and `stop`, plus
the wallet encryption methods `walletlock` and `walletpassphrase`.
