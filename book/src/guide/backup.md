# Backup and restore

> There is currently no single command or RPC method that produces a complete
> wallet backup ([#195] tracks adding one). Until it exists, backing up a
> Zallet wallet means keeping copies of the files and secrets described here.

[#195]: https://github.com/zcash/zallet/issues/195

## What needs backing up

A Zallet datadir contains two files that matter for recovery:

| Artifact | Default location | What it protects |
|---|---|---|
| Wallet database | `{datadir}/wallet.db` | Everything: accounts, transaction history, viewing keys, and *all* key material (including the key store) |
| age encryption identity | `{datadir}/encryption-identity.txt` (the `keystore.encryption_identity` config option) | The ability to decrypt any key material in `wallet.db` |

Additionally, each **mnemonic phrase** the wallet holds (created with
[`zallet generate-mnemonic`](../cli/generate-mnemonic.md) or imported with
[`zallet import-mnemonic`](../cli/import-mnemonic.md)) is an independent root
of spend authority that can be backed up on its own.

Two facts drive everything below:

- **`wallet.db` as a whole is not encrypted.** Spending key material inside it
  is encrypted to the age identity, but transaction history and viewing keys
  are stored in the clear — treat any copy of `wallet.db` as
  privacy-sensitive.
- **A mnemonic is not a complete backup.** It covers only the accounts derived
  from that seed. Spending keys imported with `z_importkey`, and watch-only
  material imported with `z_importaddress` or from a `zcashd` migration, exist
  only in `wallet.db`. If the wallet holds multiple mnemonics, each one must
  be backed up.

## Taking a backup

1. **Stop Zallet.** `wallet.db` is a SQLite database; copying it while the
   wallet is running can produce a torn copy.
2. **Copy `wallet.db` and the identity file** to secure storage. The identity
   file only changes if you regenerate it; `wallet.db` changes continuously,
   so back it up on a schedule.
3. **Record your recovery metadata** (see below).

If you lose the identity file — or forget its passphrase, if it is
passphrase-encrypted — the key material in every copy of `wallet.db` becomes
permanently undecryptable. Store the identity file separately from `wallet.db`
where practical, since together they grant full spending access.

### Backing up a mnemonic

[`zallet export-mnemonic`](../cli/export-mnemonic.md) exports the mnemonic for
a given account. The output is **not plain text**: it is encrypted to the
wallet's age identity, so decrypting it later requires the identity file (and
its passphrase, if set). If you want a plaintext copy — for example, to write
on paper — decrypt the export with the [age] or [rage] CLI using your identity
file.

[age]: https://age-encryption.org/
[rage]: https://github.com/str4d/rage

### Recovery metadata

Restoring accounts from a mnemonic requires more than the phrase itself.
Record, at backup time, for each account (all visible in the output of the
`z_listaccounts` and `listaddresses` RPC methods):

- the **seed fingerprint** (`seedfp`) identifying which mnemonic it derives
  from,
- the **ZIP 32 account index**,
- the account **name**, and
- the **birthday height** (recovery scans the chain from this height; an
  earlier guess works but slows recovery down).

## Restoring

### From a full backup (`wallet.db` + identity file)

1. Stop Zallet (if running).
2. Place the backed-up `wallet.db` and identity file at their configured
   locations in the datadir.
3. Start Zallet. The wallet resumes from the state captured in the backup and
   syncs forward; transactions received after the backup was taken are picked
   up by chain scanning.

This is the only restore path that recovers imported keys and watch-only
material.

### From a mnemonic

1. Set up a fresh wallet: create a config, then run
   [`zallet generate-encryption-identity`](../cli/generate-encryption-identity.md)
   and [`zallet init-wallet-encryption`](../cli/init-wallet-encryption.md)
   (see [Wallet setup](setup.md)).
2. Import the phrase with [`zallet import-mnemonic`](../cli/import-mnemonic.md).
   It prints the seed fingerprint; check it against your recovery metadata.
3. Start Zallet, then re-create each account with the `z_recoveraccounts` RPC
   method, passing the recorded `name`, `seedfp`, `zip32_account_index`, and
   `birthday_height` for each. The wallet then scans the chain from the
   birthday heights to recover funds and history.

Anything a mnemonic does not cover — imported spending keys, imported
addresses and viewing keys — is **not** recovered by this path, and must be
re-imported from its original source if you still have it.
