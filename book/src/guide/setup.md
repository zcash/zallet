# Setting up a Zallet wallet

> WARNING: This process is currently unstable, very manual, and subject to change as we
> make Zallet easier to use.

## Create a config file

Zallet by default uses `$HOME/.zallet` as its data directory. You can override
this with the `-d/--datadir` flag.

Once you have picked a datadir for Zallet, create a `zallet.toml` file in it.
You currently need at least the following:

```toml
[builder.limits]

[consensus]
network = "main"

[database]

[external]

[features]
as_of_version = "0.0.0"

[features.deprecated]

[features.experimental]

[indexer]
validator_user = ".."
validator_password = ".."

# Required by the default backend; see "Reading chain state from a local zebrad".
[indexer.read_state_service]
grpc_address = "127.0.0.1:8230"
zebra_state_path = "/path/to/zebrad/state/cache"

[keystore]

[note_management]

[rpc]
bind = ["127.0.0.1:SOMEPORT"]
```

In particular, you currently need to configure the `[indexer]` section to point
at your full node's JSON-RPC endpoint. The relevant config options in that
section are:
- `validator_address` (if not running on localhost at the default port)
- `validator_cookie_auth = true` and `validator_cookie_path` (if using cookie
  auth)
- `validator_user` and `validator_password` (if using basic auth)

### Reading chain state from a local zebrad

Zallet supports two chain backends that determine how it reads chain state: the default
`zebra` backend and the `zaino` backend. The backend is selected at runtime by the
config file's top-level `backend` key, which the `zallet` launcher uses to dispatch to
the matching backend binary; see
[Choosing a chain backend](installation/README.md#choosing-a-chain-backend) for the
comparison and for how to run each one.

Zallet can read finalized chain state directly from a co-located `zebrad`'s state
database (opened read-only), rather than fetching every block over JSON-RPC. This is
enabled by the `[indexer.read_state_service]` section.

The default `zebra` backend **requires** this section; without one, `zallet
start` fails with:

```
the zebra-state backend requires an [indexer.read_state_service] config section
```

The `zaino` backend uses the section when it is present, and otherwise fetches all
chain data over JSON-RPC.

This relies on zebrad's indexer gRPC interface, which is **not** available
in a default `zebrad` build. You must compile `zebrad` with the `indexer` feature
flag and set an `indexer_listen_addr` in its `[rpc]` config section:

```toml
# zebrad config (e.g. ~/.config/zebra/zebrad.toml)
[rpc]
# Any free address/port; must match Zallet's grpc_address below.
indexer_listen_addr = '127.0.0.1:8230'
```

Then configure the matching `[indexer.read_state_service]` section in Zallet's
config:

```toml
[indexer.read_state_service]
# Must match zebrad's [rpc] indexer_listen_addr.
grpc_address = "127.0.0.1:8230"
# zebrad's existing state cache directory (the directory containing its on-disk
# state database). Relative paths are resolved against Zallet's datadir.
zebra_state_path = "/home/<username>/.cache/zebra"
```

Notes:
- The JSON-RPC `[indexer]` settings above are still required: they are used for the
  mempool, transaction submission, and non-best-chain block reads.
- `zebrad` must be running on the **same machine** (Zallet reads its state files
  directly), built with the `indexer` feature, and configured with an
  `indexer_listen_addr`.
- zebrad's on-disk state format must match Zallet's `zebra-state` version; a
  mismatch fails fast with a "no zebra-state v… database found" error rather than
  silently creating an empty database.
- Reading state this way does not support regtest; use the JSON-RPC `zaino` backend
  (without this section) for regtest.

If you have an existing `zcash.conf`, you can use it as a starting point:
```
$ zallet migrate-zcash-conf --datadir /path/to/zcashd/datadir -o /path/to/zallet/datadir/zallet.toml
```

> [Reference](../cli/migrate-zcash-conf.md)

## Initialize the wallet encryption

Zallet uses [age encryption](https://age-encryption.org/) to encrypt all key
material internally. Currently you can use two kinds of age identities, which you
can generate with `zallet generate-encryption-identity` (no external tooling
required):

- A plain identity file directly on disk:
  ```
  $ zallet -d /path/to/zallet/datadir generate-encryption-identity
  Public key: age1...
  ```

- A passphrase-encrypted identity file:
  ```
  $ zallet -d /path/to/zallet/datadir generate-encryption-identity -p
  Enter passphrase to encrypt the identity:
  Confirm passphrase:
  Public key: age1...
  ```
  In non-interactive contexts, the passphrase is read from the
  `ZALLET_IDENTITY_PASSPHRASE` environment variable instead of prompting.

> [Reference](../cli/generate-encryption-identity.md)

(age plugins will also be supported but currently are tricky to set up, and
require the external `age` or `rage` CLI to create the identity.)

Once you have created your identity file, initialize your Zallet wallet:
```
$ zallet -d /path/to/zallet/datadir init-wallet-encryption
```

> [Reference](../cli/init-wallet-encryption.md)

## Generate a mnemonic phrase

```
$ zallet -d /path/to/zallet/datadir generate-mnemonic
```

> [Reference](../cli/generate-mnemonic.md)

Each time you run this, a new [BIP 39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
mnemonic will be added to the wallet. Be careful to only run it multiple times
if you want multiple independent roots of spend authority!

## Start Zallet

```
$ zallet -d /path/to/zallet/datadir start
```

> [Reference](../cli/start.md)
