# Migrating from `zcashd`

`zcashd` was a single process that acted as both a Zcash full node and a wallet. Its
replacement is a stack of separate components: [`zebrad`] provides the full node, and
Zallet provides the wallet. Migrating therefore has two halves: replacing the node, and
migrating the wallet. This page covers the wallet half, and links out to the node parts
you need.

[`zebrad`]: https://zebra.zfnd.org/

> **⚠️ Keep your `zcashd` data.** Do not delete `wallet.dat` (or the `zcashd` datadir)
> after migrating. The migration reports anything it cannot represent in a Zallet wallet
> rather than migrating it, and that key material then exists only in `wallet.dat`.

## Migration steps

1. **Run a `zebrad` node, and let it sync to the chain tip.** Zallet reads chain data
   from `zebrad` via one of its two
   [chain backends](../guide/installation/README.md#choosing-a-chain-backend); the
   backend you choose determines how `zebrad` needs to be built and configured.

   Do not run the wallet migration (step 5) until `zebrad` has caught up: the migration
   sets each account's birthday from the blocks the node can already resolve, so an
   unsynced node silently produces a birthday later than your wallet's history, and
   the scan then never finds the earlier funds. See
   [How the wallet birthday is chosen](../cli/migrate-zcashd-wallet.md#how-the-wallet-birthday-is-chosen).

2. **Install Zallet.** See [Installation](../guide/installation/README.md).

3. **Create a Zallet config from your `zcash.conf`:**

   ```
   $ zallet migrate-zcash-conf --zcashd-datadir /path/to/zcashd/datadir -o /path/to/zallet/datadir/zallet.toml
   ```

   Wallet-relevant options are translated to their `zallet.toml` equivalents; options
   that only affect the node are ignored, and wallet options that cannot be migrated
   produce warnings. Note that `rpcuser` / `rpcpassword` are **not** migrated: Zallet's
   JSON-RPC interface uses [cookie authentication](../cli/rpc.md#authentication) by
   default, and you can add password credentials with
   [`zallet add-rpc-user`](../cli/add-rpc-user.md).

   > [Reference](../cli/migrate-zcash-conf.md)

4. **Initialize wallet encryption.** Zallet encrypts key material with an
   [age](https://age-encryption.org/) identity that you create before importing any
   keys; see [Wallet setup](../guide/setup.md#initialize-the-wallet-encryption).

5. **Migrate your `wallet.dat`:**

   ```
   $ zallet migrate-zcashd-wallet --zcashd-datadir /path/to/zcashd/datadir
   ```

   This imports the wallet's key material and creates corresponding Zallet accounts. If
   you have several `wallet.dat` files, run it once per file (subsequent runs need
   `--allow-multiple-wallet-imports`); each wallet becomes a distinct set of accounts.
   If the wallet's key material is encrypted, the command prompts for the `zcashd`
   wallet passphrase; see
   [Encrypted wallets](../cli/migrate-zcashd-wallet.md#encrypted-wallets).

   **Decide before the first run whether to pass `--allow-partial-import`.** Without it,
   the migration fails if any account or transparent spending key could not be imported,
   listing what was left behind. That failure happens *after* the importable accounts
   have been written, and a second run against the same wallet database is refused as a
   duplicate import, so recovering from it means starting over: delete `wallet.db`,
   re-run `zallet init-wallet-encryption` (the identity file can stay), and migrate
   again with the flag. Anything the flag lets the migration skip remains accessible
   only through the original `wallet.dat`.

   > [Reference](../cli/migrate-zcashd-wallet.md)

6. **Start Zallet and let it sync:**

   ```
   $ zallet start
   ```

   Your transaction history is already present: the migration imports every transaction
   from `wallet.dat` directly, including sends that were never mined and transactions
   that ended up on a non-main-chain block, which a chain scan alone could not recover.
   What the scan adds is the note commitment tree positions of your notes (and the
   mined heights of any transactions the migration could not place), and balances are
   not spendable until it has done so. Use `zallet rpc getwalletstatus` to observe sync
   progress, then verify your balances against `zcashd` before decommissioning it.

7. **Update your RPC clients.** Zallet implements a subset of the `zcashd` wallet
   JSON-RPC methods, some with [altered semantics](json_rpc.md), and some `zcashd`
   methods are [intentionally omitted](json_rpc.md#omitted-rpc-methods). Check
   every method you use against the [method status matrix](rpc_status.md). The
   [`zallet rpc`](../cli/rpc.md) command replaces `zcash-cli`.

## What is migrated

- Mnemonic seeds and the keys derived from them. Accounts are re-created following the
  structure of the `zcashd` wallet.
- Standalone (imported) Sapling spending keys and transparent keys.
- Transparent watch-only entries that include their public key or redeem script.
- Account birthdays, so that chain scanning starts from the right height.

## What is not migrated

The migration logs each of these with a count instead of importing it, except the last,
which is dropped silently:

- **Sprout spending keys and funds.** Zallet does not support the Sprout pool. Move any
  Sprout funds (e.g. to Sapling, using `zcashd`'s migration or a Sprout-capable tool)
  *before* retiring `zcashd`.
- **Address book entries.** Zallet has no store for them yet ([#774] tracks preserving
  them); the labels exist only in `wallet.dat`.
- **Watch-only entries recorded without their public key or redeem script**, and
  watch-only public keys that are uncompressed or malformed.
- **Watch-only redeem scripts the wallet cannot represent.** Only multisig scripts
  within the P2SH size limit are imported; any other watched script is dropped.
- **Standalone copies of unified spending keys.** The unified accounts themselves are
  re-derived from the mnemonic, so this loses nothing.
- **Transactions that carry no raw transaction data.** If such a transaction was mined,
  the post-migration scan recovers it.
- **Records of a kind the wallet parser does not recognise.** These are discarded with
  no warning at all, so a `wallet.dat` written by an unusual `zcashd` build may lose
  data without any sign of it in the log.

[#774]: https://github.com/zcash/zallet/issues/774

Not every skip is merely reported. A transparent *spending* key that cannot be imported
(one whose public key is uncompressed, or whose address appears under none of the
imported accounts) fails the migration unless `--allow-partial-import` is passed; see
step 5 above for why that decision has to be made before the first run.

## Back up the migrated wallet

After migration, a mnemonic backup alone is **not** sufficient: imported keys exist only
in the wallet database. Keep secure copies of the wallet database (`wallet.db`), the age
encryption identity file, *and* your mnemonic phrase(s) — and keep the original
`wallet.dat`. See the warning in the
[`migrate-zcashd-wallet` reference](../cli/migrate-zcashd-wallet.md) for details.
