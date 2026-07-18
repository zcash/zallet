# Troubleshooting

Common error messages, their causes, and their fixes. Messages are quoted as
Zallet prints them so you can search this page for the text you see.

## "Cannot obtain a lock on data directory …"

> Cannot obtain a lock on data directory {datadir}. Zallet is probably already running.

Only one Zallet process can use a datadir at a time. Another Zallet command (or
a running `zallet start`) holds the lock. Stop the other process, or point this
one at a different `--datadir`.

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
