# The legacy transparent pool

Zallet's model is [one account per spending authority](accounts.md): each
account is a separate pool of funds, and transparent funds belong to the
account that received them. `zcashd`'s transparent RPC methods, inherited from
Bitcoin Core, instead treated **all** transparent funds in the wallet as a
single undifferentiated pool — `sendmany` spent from any address, `getbalance`
summed across all of them. Those semantics are incompatible with the
per-account model, so the methods and fields that depend on them are disabled
in Zallet by default.

For operators migrating a `zcashd` wallet that relied on this behaviour, Zallet
can re-enable it for **one** migrated wallet at a time.

## Enabling it

Set the seed fingerprint of the migrated `zcashd` wallet in your config:

```toml
[features]
legacy_pool_seed_fingerprint = "<seed fingerprint>"
```

The fingerprint identifies which migrated wallet's account acts as the legacy
pool (it is the account at the special ZIP 32 index `zcashd` used for its
legacy transparent funds). Available seed fingerprints appear in the output of
the `z_listaccounts` and `listaddresses` RPC methods.

Only one wallet can have legacy semantics enabled at a time: the Bitcoin-Core
single-pool model is inherently wallet-wide, so it cannot be scoped to more
than one migrated seed. Accounts imported from a viewing key cannot be the
legacy pool — `zcashd` derived the pool from the wallet's seed, so a legacy
account must have known ZIP 32 derivation.

## What it changes

With the fingerprint set:

- **`z_sendmany` accepts `"ANY_TADDR"`** as its `fromaddress`, selecting
  non-coinbase UTXOs from any transparent address in the pool — the
  Bitcoin-Core "spend from anywhere" behaviour. Because covering a payment from
  more than one of the pool's addresses links them on-chain, such a call
  requires a `privacy_policy` of `AllowLinkingAccountAddresses` (or `NoPrivacy`
  if it also has a transparent recipient or change). See
  [Notes, confirmations, and fees](notes.md).
- **`z_getbalances` includes legacy-pool balance fields** that are otherwise
  omitted.

## Should you use it?

Treat it as a migration bridge, not a destination. These semantics are
deprecated — they reveal more on-chain than the per-account model, and are not
how new wallets should operate. Prefer moving funds into a unified account and
using the account-scoped methods (`z_getbalanceforaccount`, and
`z_sendfromaccount` once available) going forward.
