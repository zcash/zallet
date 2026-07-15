# JSON-RPC method status

This page lists every wallet JSON-RPC method that `zcashd` provided, and its
status in Zallet. Use it to inventory your RPC usage before migrating.

Statuses:

- **Implemented** — available in Zallet with `zcashd`-compatible semantics.
- **Implemented (altered)** — available, but with [altered semantics](json_rpc.md).
- **Not yet implemented** — intentionally absent so far; implementation is
  tracked in the linked issue. Whether each of these ships will be decided
  during the beta phase ([#287]).
- **Not planned** — will not be implemented; the Notes column says what to use
  instead.
- **Omitted** — intentionally not implemented; see the
  [omitted methods](json_rpc.md#omitted-rpc-methods) table for replacements.

[#287]: https://github.com/zcash/zallet/issues/287

| `zcashd` method | Status | Notes |
|---|---|---|
| `addmultisigaddress` | Not yet implemented | [#48](https://github.com/zcash/zallet/issues/48) |
| `backupwallet` | Not yet implemented | [#49](https://github.com/zcash/zallet/issues/49); robust backup is tracked in [#195](https://github.com/zcash/zallet/issues/195) |
| `dumpprivkey` | Not yet implemented | [#50](https://github.com/zcash/zallet/issues/50) |
| `encryptwallet` | Omitted | [Note](json_rpc.md#encryptwallet): key material is always encrypted |
| `getbalance` | Not yet implemented | [#51](https://github.com/zcash/zallet/issues/51) |
| `getnewaddress` | Omitted | Use `z_getnewaccount` + `z_getaddressforaccount` |
| `getrawchangeaddress` | Omitted | [Note](json_rpc.md#getrawchangeaddress): change is handled internally |
| `getreceivedbyaddress` | Not yet implemented | [#52](https://github.com/zcash/zallet/issues/52) |
| `gettransaction` | Not planned | Superseded by `z_viewtransaction`, which now includes its top-level fields ([altered semantics](json_rpc.md#z_viewtransaction)) |
| `getunconfirmedbalance` | Not yet implemented | [#54](https://github.com/zcash/zallet/issues/54) |
| `getwalletinfo` | Implemented | |
| `importaddress` | Not yet implemented | [#56](https://github.com/zcash/zallet/issues/56); if you have the public key or redeem script, `z_importaddress` covers this today |
| `importprivkey` | Not yet implemented | [#57](https://github.com/zcash/zallet/issues/57) |
| `importpubkey` | Omitted | Use `z_importaddress` |
| `importwallet` | Omitted | Use `z_importkey` per key, or [`zallet migrate-zcashd-wallet`](../cli/migrate-zcashd-wallet.md) |
| `keypoolrefill` | Omitted | [Note](json_rpc.md#keypoolrefill): no key pool exists |
| `listaddresses` | Implemented (altered) | [Changes](json_rpc.md#listaddresses) |
| `listaddressgroupings` | Not yet implemented | [#59](https://github.com/zcash/zallet/issues/59) |
| `listlockunspent` | Not yet implemented | [#60](https://github.com/zcash/zallet/issues/60) |
| `listreceivedbyaddress` | Not yet implemented | [#61](https://github.com/zcash/zallet/issues/61) |
| `listsinceblock` | Not yet implemented | [#62](https://github.com/zcash/zallet/issues/62) |
| `listtransactions` | Not yet implemented | [#63](https://github.com/zcash/zallet/issues/63); Zallet provides the account-scoped `z_listtransactions` |
| `listunspent` | Not planned | Subsumed by `z_listunspent`, which now includes transparent outputs ([changes](json_rpc.md#z_listunspent), [#64](https://github.com/zcash/zallet/issues/64)) |
| `lockunspent` | Not yet implemented | [#65](https://github.com/zcash/zallet/issues/65) |
| `sendmany` | Not yet implemented | [#66](https://github.com/zcash/zallet/issues/66) |
| `sendtoaddress` | Not planned | Use `z_sendmany` (or `z_sendfromaccount` once implemented, [#217](https://github.com/zcash/zallet/issues/217)); see [#67](https://github.com/zcash/zallet/issues/67) |
| `settxfee` | Omitted | [ZIP 317](https://zips.z.cash/zip-0317) fees are always used |
| `signmessage` | Not yet implemented | [#68](https://github.com/zcash/zallet/issues/68) |
| `walletconfirmbackup` | Not yet implemented | No direct tracking issue; related to [#201](https://github.com/zcash/zallet/issues/201) |
| `z_converttex` | Implemented | |
| `z_exportkey` | Implemented | |
| `z_exportviewingkey` | Not yet implemented | [#70](https://github.com/zcash/zallet/issues/70) |
| `z_exportwallet` | Not yet implemented | [#71](https://github.com/zcash/zallet/issues/71) |
| `z_getaddressforaccount` | Implemented (altered) | [Changes](json_rpc.md#z_getaddressforaccount) |
| `z_getbalance` | Omitted | Use `z_getbalanceforaccount` |
| `z_getbalanceforaccount` | Implemented | |
| `z_getbalanceforviewingkey` | Not planned | Use `z_getbalanceforaccount` ([#74](https://github.com/zcash/zallet/issues/74)) |
| `z_getmigrationstatus` | Omitted | [Note](json_rpc.md#z_getmigrationstatus-and-z_setmigration): no Sprout support |
| `z_getnewaccount` | Implemented (altered) | [Changes](json_rpc.md#z_getnewaccount) |
| `z_getnewaddress` | Omitted | Use `z_getnewaccount` + `z_getaddressforaccount` |
| `z_getnotescount` | Implemented | |
| `z_getoperationresult` | Implemented | |
| `z_getoperationstatus` | Implemented | |
| `z_gettotalbalance` | Implemented | Prefer the account-scoped `z_getbalanceforaccount` / `z_getbalances` ([#324](https://github.com/zcash/zallet/issues/324)) |
| `z_importkey` | Implemented | |
| `z_importviewingkey` | Not yet implemented | [#80](https://github.com/zcash/zallet/issues/80) |
| `z_importwallet` | Omitted | Use `z_importkey` per key, or [`zallet migrate-zcashd-wallet`](../cli/migrate-zcashd-wallet.md); reconsideration tracked in [#81](https://github.com/zcash/zallet/issues/81) |
| `z_listaccounts` | Implemented (altered) | [Changes](json_rpc.md#z_listaccounts) |
| `z_listaddresses` | Omitted | Use `listaddresses` |
| `z_listoperationids` | Implemented | |
| `z_listreceivedbyaddress` | Not yet implemented | [#84](https://github.com/zcash/zallet/issues/84) |
| `z_listunifiedreceivers` | Implemented | |
| `z_listunspent` | Implemented (altered) | [Changes](json_rpc.md#z_listunspent) |
| `z_mergetoaddress` | Not yet implemented | [#87](https://github.com/zcash/zallet/issues/87) |
| `z_sendmany` | Implemented (altered) | [Changes](json_rpc.md#z_sendmany) |
| `z_setmigration` | Omitted | [Note](json_rpc.md#z_getmigrationstatus-and-z_setmigration): no Sprout support |
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
