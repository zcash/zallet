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

1. **Run a `zebrad` node.** Zallet reads chain data from `zebrad` via one of its two
   [chain backends](../guide/installation/README.md#choosing-a-chain-backend); the
   backend you choose determines how `zebrad` needs to be built and configured.

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

   > [Reference](../cli/migrate-zcashd-wallet.md)

6. **Start Zallet and let it sync:**

   ```
   $ zallet start
   ```

   Transaction history is recovered by scanning the chain, so the wallet needs to sync
   before balances are complete. Use `zallet rpc getwalletstatus` to observe sync
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

The migration reports these (with counts) instead of importing them:

- **Sprout spending keys and funds.** Zallet does not support the Sprout pool. Move any
  Sprout funds (e.g. to Sapling, using `zcashd`'s migration or a Sprout-capable tool)
  *before* retiring `zcashd`.
- Address book entries.
- Watch-only entries recorded without their public key or redeem script, and entries
  with uncompressed public keys.
- Regtest wallets (not currently supported).

## Back up the migrated wallet

After migration, a mnemonic backup alone is **not** sufficient: imported keys exist only
in the wallet database. Keep secure copies of the wallet database (`wallet.db`), the age
encryption identity file, *and* your mnemonic phrase(s) — and keep the original
`wallet.dat`. See the warning in the
[`migrate-zcashd-wallet` reference](../cli/migrate-zcashd-wallet.md) for details.
