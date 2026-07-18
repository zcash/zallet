# The `migrate-zcashd-wallet` command

> Available on **crate feature** `zcashd-import` only.

`zallet migrate-zcashd-wallet` migrates a `zcashd` wallet file (`wallet.dat`) to a Zallet
wallet (`wallet.db`).

[`zallet init-wallet-encryption`] must be run before this command.

> **⚠️ Back up your wallets**
>
> **Keep your original `zcashd` `wallet.dat`.** This migration reports (see below) anything
> it cannot represent in a Zallet wallet rather than migrating it; that key material exists
> only in `wallet.dat`, so if you lose it those funds are unrecoverable. Do not delete or
> discard `wallet.dat` after migrating.
>
> **Back up the new Zallet wallet, too.** Its `wallet.db` can hold spending keys that a
> mnemonic backup does **not** cover — keys imported with `z_importkey`, and other
> standalone key material — so [`zallet export-mnemonic`] is **not** a complete backup, and
> there is currently no complete backup RPC or command. Keep a secure copy of **both** the
> `wallet.db` file *and* the age encryption identity file (the file named by the
> `keystore.encryption_identity` config option). Those spending keys are encrypted to that
> identity; if you lose it, or forget its passphrase, they cannot be decrypted and those
> funds are unrecoverable. Note that `wallet.db` itself is **not** encrypted — it also holds
> your transaction history and viewing keys in the clear — so keep the backup somewhere
> secure.

Parsing a `zcashd` wallet file requires the `db_dump` utility built for Berkeley DB
version 6.2 (the version `zcashd` uses). When Zallet is built with the `zcashd-import`
feature it compiles and uses a vendored copy of this utility automatically, so you
normally do not need to provide one yourself. If that vendored utility is unavailable,
Zallet falls back to a `db_dump` found on the system `$PATH`; you can also point Zallet
at a specific `zcashd` installation's `db_dump` with `--zcashd-install-dir` (see below).

The command requires at least one of the following two flag:

- `--path`: A path to a `zcashd` wallet file.
- `--zcashd-datadir`: A path to a `zcashd` datadir. If this is provided, then `--path` can
  be relative (or omitted, in which case the default filename `wallet.dat` will be used).

Additional CLI arguments:
- `--zcashd-install-dir`: A path to a local `zcashd` installation directory, for
  source-based builds of `zcashd`. When set, Zallet uses the `db_dump` from that
  installation's `zcutil/bin` directory instead of its vendored copy. This is rarely
  needed, and generally not recommended: the vendored `db_dump` is built for the
  Berkeley DB version (6.2) that `zcashd` wallets use, so prefer it unless you have a
  specific reason to use your `zcashd` installation's utility (for example, a wallet
  written by a non-standard Berkeley DB build). If neither this flag nor the vendored
  `db_dump` is available, Zallet falls back to a `db_dump` on the system `$PATH`.
- `--allow-multiple-wallet-imports`: An optional flag that must be set if a
  user wants to import keys and transactions from multiple `wallet.dat` files
  (not required for the first `wallet.dat` import.)
- `--allow-warnings`: If set, Zallet will ignore errors in parsing transactions
  extracted from the `wallet.dat` file. This can enable the import of key data
  from wallets that have been used on consensus forks of the Zcash chain.

> For the Zallet beta releases, the command also currently takes another required flag
> `--this-is-beta-code-and-you-will-need-to-redo-the-migration-later`.

When run, Zallet will parse the `zcashd` wallet file, export its contents to an
in-memory [ZeWIF] (Zcash Wallet Interchange Format) document, connect to the
backing full node (to obtain necessary chain information for setting up wallet
birthdays), and import the document: Zallet accounts are created corresponding
to the structure of the `zcashd` wallet, spending key material is stored in the
Zallet keystore, and the account birthdays carry the note commitment tree state
needed for recovery. Parsing is performed using the `db_dump` command-line
utility. By default Zallet uses the copy it vendors and builds, which is the
recommended choice; a `zcashd`-provided `db_dump` from the `zcutil/bin`
directory of a source installation (via `--zcashd-install-dir`), or one on the
system `$PATH`, are used otherwise.

Some `zcashd` wallet contents cannot be represented in a Zallet wallet, and are
reported (with counts) rather than migrated: Sprout spending keys (move any
Sprout funds using `zcashd` before migrating), address book entries, watch-only
entries recorded without their public keys or redeem scripts, and entries with
uncompressed public keys. Migration of regtest wallets is not currently
supported.

[ZeWIF]: https://github.com/zcash/zewif

[`zcashd`]: https://github.com/zcash/zcash
[`zallet init-wallet-encryption`]: init-wallet-encryption.md
[`zallet export-mnemonic`]: export-mnemonic.md
[is started]: start.md
