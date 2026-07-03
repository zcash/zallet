# JSON-RPC altered semantics

Zallet implements a subset of the `zcashd` JSON-RPC wallet methods. While we
have endeavoured to preserve semantics where possible, for some methods it was
necessary to make changes in order for the methods to be usable with Zallet's
wallet architecture. This page documents the semantic differences between the
`zcashd` and Zallet wallet methods.

## Changed RPC methods

### `z_listaccounts`

Changes to parameters:
- New `include_addresses` optional parameter.

Changes to response:
- New `account_uuid` field.
- New `name` field.
- New `seedfp` field, if the account has a known derivation.
- New `zip32_account_index` field, if the account has a known derivation.
- The `account` field is now only present if the account has a known derivation.
- Changes to the struct within the `addresses` field:
  - All addresses known to the wallet within the account are now included.
  - The `diversifier_index` field is now only present if the address has known
    derivation information.
  - The `ua` field is now only present for Unified Addresses.
  - New `sapling` field if the address is a Sapling address.
  - New `transparent` field if the address is a transparent address.

### `z_getnewaccount`

Changes to parameters:
- New `account_name` required parameter.
- New `seedfp` optional parameter.
  - This is required if the wallet has more than one seed.

### `z_getaddressforaccount`

Changes to parameters:
- `account` parameter can be a UUID.

Changes to response:
- New `account_uuid` field.
- `account` field in response is not present if the `account` parameter is a UUID.
- The returned address is now time-based if no transparent receiver is present
  and no explicit index is requested.
- Returns an error if an empty list of receiver types is provided along with a
  previously-generated diversifier index, and the previously-generated address
  did not use the default set of receiver types.

### `listaddresses`

Changes to response:
- `imported_watchonly` includes addresses derived from imported Unified Viewing
  Keys.
- Transparent addresses for which we have BIP 44 derivation information are now
  listed in a new `derived_transparent` field (an array of objects) instead of
  the `transparent` field.

### `getrawtransaction`

Changes to parameters:
- `blockhash` must be `null` if set; single-block lookups are not currently
  supported.

Changes to response:
- `vjoinsplit`, `joinSplitPubKey`, and `joinSplitSig` fields are always omitted.

### `z_viewtransaction`

Changes to response:
- Some top-level fields from `gettransaction` have been added:
  - `status`
  - `confirmations`
  - `blockhash`, `blockindex`, `blocktime`
  - `version`
  - `expiryheight`, which is now always included (instead of only when a
    transaction has been mined).
  - `fee`, which is now included even if the transaction does not spend any
    value from any account in the wallet, but can also be omitted if the
    transparent inputs for a transaction cannot be found.
  - `generated`
- New `account_uuid` field on inputs and outputs (if relevant).
- New `accounts` top-level field, containing a map from UUIDs of involved
  accounts to the effect the transaction has on them.
- Information about all transparent inputs and outputs (which are always visible
  to the wallet) are now included. This causes the following semantic changes:
  - `pool` field on both inputs and outputs can be `"transparent"`.
  - New fields `tIn` and `tOutPrev` on inputs.
  - New field `tOut` on outputs.
  - `address` field on outputs: in `zcashd`, this was omitted only if the output
    was received on an account-internal address; it is now also omitted if it is
    a transparent output to a script that doesn't have an address encoding. Use
    `walletInternal` if you need to identify change outputs.
  - `outgoing` field on outputs: in `zcashd`, this was always set because every
    decryptable shielded output is either for the wallet (`outgoing = false`),
    or in a transaction funded by the wallet (`outgoing = true`). Now that
    transparent outputs are included, this field is omitted for outputs that are
    not for the wallet in transactions not funded by the wallet.
  - `memo` field on outputs is omitted if `pool = "transparent"`.
  - `memoStr` field on outputs is no longer only omitted if `memo` does not
    contain valid UTF-8.

### `z_listunspent`

Changes to response:
- For each output in the response array:
  - The `amount` field has been renamed to `value` for consistency with
    `z_viewtransaction`. The `amount` field may be reintroduced under a deprecation
    flag in the future if there is user demand.
  - A `valueZat` field has been added for consistency with `z_viewtransaction`
  - An `account_uuid` field identifying the account that received the output
    has been added.
  - The `account` field has been removed and there is no plan to reintroduce it;
    use the `account_uuid` field instead.
  - An `is_watch_only` field has been added.
  - The `spendable` field has been removed; use `is_watch_only` instead. The
    `spendable` field may be reintroduced under a deprecation flag in the
    future if there is user demand.
  - The `change` field has been removed, as determining whether an output
    qualifies as change involves a bunch of annoying subtleties and the
    meaning of this field has varied between Sapling and Orchard.
  - A `walletInternal` field has been added.
  - Transparent outputs are now included in the response array. The `pool`
    field for such outputs is set to the string `"transparent"`.
  - The `memo` field is now omitted for transparent outputs.

### `z_sendmany`

Changes to parameters:
- `fee` must be `null` if set; ZIP 317 fees are always used.
- If the `minconf` field is omitted, the default ZIP 315 confirmation policy
  (3 confirmations for trusted notes, 10 confirmations for untrusted notes)
  is used.

Changes to response:
- New `txids` array field in response.
- `txid` field is omitted if `txids` has length greater than 1.

## Omitted RPC methods

The following RPC methods from `zcashd` have intentionally not been implemented
in Zallet, either due to being long-deprecated in `zcashd`, or because other RPC
methods have been updated to replace them.

| Omitted RPC method     | Use this instead |
|------------------------|------------------|
| `createrawtransaction` | [To-be-implemented methods for working with PCZTs][pczts] |
| `fundrawtransaction`   | [To-be-implemented methods for working with PCZTs][pczts] |
| `getnewaddress`        | `z_getnewaccount`, `z_getaddressforaccount` |
| `getrawchangeaddress`  |
| `keypoolrefill`        |
| `importpubkey`         |
| `importwallet`         |
| `settxfee`             |
| `signrawtransaction`   | [To-be-implemented methods for working with PCZTs][pczts] |
| `z_importwallet`       |
| `z_getbalance`         | `z_getbalanceforaccount`, `z_getbalanceforviewingkey`, `getbalance` |
| `z_getmigrationstatus` |
| `z_getnewaddress`      | `z_getnewaccount`, `z_getaddressforaccount` |
| `z_listaddresses`      | `listaddresses` |
| `z_setmigration`       |

The `z_getmigrationstatus` and `z_setmigration` methods configured and reported
on the automatic Sprout-to-Sapling fund migration. Zallet does not support
Sprout, so there is nothing to migrate and no equivalent method is provided. If
you still hold Sprout funds, migrate them out of the Sprout pool before
transitioning your wallet to Zallet.

[pczts]: https://github.com/zcash/zallet/issues/99
