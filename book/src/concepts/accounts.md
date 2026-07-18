# Accounts and keys

## Seeds

A Zallet wallet can hold multiple mnemonic seed phrases, created with
[`zallet generate-mnemonic`](../cli/generate-mnemonic.md) or imported with
[`zallet import-mnemonic`](../cli/import-mnemonic.md). Each phrase is an
independent root of spend authority, identified by its **seed fingerprint**
(`seedfp`), and must be [backed up](../guide/backup.md) independently.

## Accounts

Accounts are derived from a seed following [ZIP 32] hierarchical deterministic
derivation: an account is identified by its seed fingerprint plus a ZIP 32
account index, numbered from zero per seed. Each account is a separate group
of funds, and every account adds scanning cost, so create them deliberately —
they are not intended as address labels.

Within a Zallet instance, every account also has a **UUID**, which is how RPC
methods identify accounts (`account_uuid` fields, and account parameters).
UUIDs are local to the instance; the portable identity of an account is
`(seedfp, account index)`, which is what
[recovery](../guide/backup.md#from-a-mnemonic) uses.

This differs from `zcashd`, where the legacy wallet largely operated as a
single implicit account. Zallet still accepts plain account numbers in some
methods, but only for wallets with a single seed.

Wallets can also track things that are not derived from a seed: spending keys
imported with `z_importkey`, and watch-only transparent addresses imported
with `z_importaddress`. These become accounts with UUIDs too, but no mnemonic
covers them.

## Addresses

Addresses are obtained per account with the `z_getaddressforaccount` RPC
method, which derives [ZIP 316] **Unified Addresses**: a single encoding
bundling receivers for one or more pools (Orchard, Sapling, transparent). Many
addresses can be derived for the same account at different diversifier
indices; they all receive into the same account, and payments to their
shielded receivers are not linkable on-chain (transparent receivers, when
included, do not have this property).

[ZIP 32]: https://zips.z.cash/zip-0032
[ZIP 316]: https://zips.z.cash/zip-0316
