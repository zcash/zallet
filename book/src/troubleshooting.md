# Troubleshooting

Common error messages, their causes, and their fixes. Messages are quoted as
Zallet prints them so you can search this page for the text you see.

## "Cannot obtain a lock on data directory …"

> Cannot obtain a lock on data directory {datadir}. Zallet is probably already running.

Only one Zallet process can use a datadir at a time. Another Zallet command (or
a running `zallet start`) holds the lock. Stop the other process, or point this
one at a different `--datadir`.

This also applies to `zallet migrate-zcashd-wallet`, which holds the lock for
the whole migration because it writes into the same wallet database that
`zallet start` uses: stop Zallet before migrating, and do not start it until
the migration has finished.

## "The config file selects the '…' chain backend, but this binary provides the '…' backend"

You invoked a backend binary (e.g. `zallet-zaino`) directly against a config
whose `backend` key names a different backend. Run the `zallet` launcher (which
dispatches on the config), run the matching backend binary, or change the
config's `backend` key. See
[Choosing a chain backend](guide/installation/README.md#choosing-a-chain-backend).

## "failed to run the backend binary `zallet-…`"

The `zallet` launcher could not find or start the backend binary named by the
config's `backend` key. The launcher looks for backend binaries next to itself
and then on the `PATH`. Install the corresponding backend package, or make sure
the service's `PATH` includes it.

## "the zebra-state backend requires an [indexer.read_state_service] config section"

The default `zebra` backend reads chain state directly from a co-located
`zebrad` and cannot start without the `[indexer.read_state_service]` section.
Add it (see [Wallet setup](guide/setup.md#reading-chain-state-from-a-local-zebrad)),
or switch to the `zaino` backend if you cannot co-locate `zebrad`.

## "no zebra-state v… database found under '…'"

The `zebra` backend could not find a state database of the version it expects
at `indexer.read_state_service.zebra_state_path`. Either the path does not
point at `zebrad`'s state cache directory, or `zebrad`'s on-disk state format
does not match this Zallet release's `zebra-state` version — upgrade whichever
of the two is behind so the versions match.

## "The wallet has not been set up to store key material securely"

> The wallet has not been set up to store key material securely.
> Have you run 'zallet init-wallet-encryption'?

Commands that store keys (such as `zallet generate-mnemonic` or
`zallet import-mnemonic`) require wallet encryption to be initialized first.
Run [`zallet generate-encryption-identity`](cli/generate-encryption-identity.md)
followed by [`zallet init-wallet-encryption`](cli/init-wallet-encryption.md);
see [Wallet setup](guide/setup.md#initialize-the-wallet-encryption).

## "Wallet is locked"

The wallet's age identity is passphrase-encrypted and the key store is
currently locked, so operations that need spending keys fail. Unlock it with
the `walletpassphrase` RPC method (and re-lock with `walletlock`).

## "This transaction would … which is not enabled by default …"

The `z_sendmany` privacy policy errors, for example:

> This transaction would have transparent recipients, which is not enabled by
> default because it will publicly reveal transaction recipients and amounts.

These are intentional: by default Zallet refuses to build transactions that
reveal more information on-chain than fully-shielded ones. If you accept the
privacy trade-off the message describes, resubmit with the `privacy_policy`
parameter set to the policy named in the error (or a weaker one). This affects
your privacy — prefer the strongest policy that permits your transaction.

## Connection refused when calling `zallet rpc`

The JSON-RPC server is **disabled by default**: Zallet only listens if the
config sets `rpc.bind`. Add a listen address:

```toml
[rpc]
bind = ["127.0.0.1:28232"]
```

and restart. Also check that the wallet is actually running and that you are
pointing `zallet rpc` at the same datadir/config as the running instance.

## "The zcashd wallet being imported is for the '…' network, but this zallet instance is configured for '…'"

`zallet migrate-zcashd-wallet` refuses a `wallet.dat` from a different network
than the `consensus.network` in your `zallet.toml`. The default is mainnet, so
a testnet or regtest wallet fails this way until the config says
`network = "test"` or `network = "regtest"`. Generating the config from the
same `zcashd` datadir with `zallet migrate-zcash-conf` (step 3 of
[Migrating from `zcashd`](zcashd/README.md#migration-steps)) sets it correctly.

## "The wallet contains a mnemonic seed phrase using a wordlist other than English"

Zallet imports only English BIP 39 mnemonics. A `wallet.dat` whose mnemonic
was recorded with another wordlist cannot currently be migrated, and its funds
remain accessible only through `zcashd` and that `wallet.dat`. Keep the file
safe.

## "Consensus branch ID not known, cannot parse this transaction until it is mined"

Raised in the middle of `zallet migrate-zcashd-wallet` by releases before
0.1.0-beta.3 when the `zcashd` wallet held a transaction with neither a mined
height nor a non-zero expiry height: a coinbase transaction, or one whose
sender disabled expiry. Upgrade to 0.1.0-beta.3 or later and run the migration
again.

## "Invalid chain data was encountered in wallet migration … 'missing tree state for height …'"

The chain backend could not supply the note commitment tree state for the
block before the wallet's birthday. This happens when `zebrad` has not yet
synced that far: the migration sets the birthday from the earliest of the
wallet's transactions the node can resolve, then needs the tree state just
before it. Let `zebrad` reach the chain tip, then run the migration again. Do
not migrate against a partially synced node even when this error does not
appear: an unsynced node can also silently produce a birthday that is too
late (see [`migrate-zcashd-wallet`](cli/migrate-zcashd-wallet.md)).
