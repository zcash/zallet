# The `rpc` command

> Available on **crate feature** `rpc-cli` only.

`zallet rpc` lets you communicate with a Zallet wallet's JSON-RPC interface from a
command-line shell.

- `zallet rpc help` will print a list of all JSON-RPC methods supported by Zallet.
- `zallet rpc help <method>` will print out a description of `<method>`.
- `zallet rpc <method>` will call that JSON-RPC method. Parameters can be provided via
  additional CLI arguments (`zallet rpc <method> <param>`).

## Secret parameters

Command-line arguments are visible to other users through process listings, and your
shell records them in its history. Some JSON-RPC methods take secrets as parameters —
the spending key given to `z_importkey`, the passphrase given to `walletpassphrase` —
which should not be passed that way.

Write such a parameter as `@PATH` instead. Zallet reads the first line of `PATH` and
sends it as a JSON string, so no quoting is needed:

```
# Read the key from a pipe.
$ get-key-from-vault | zallet rpc z_importkey @- '"whenkeyisnew"'

# Read the key from a file descriptor, without it ever touching disk.
$ zallet rpc z_importkey @/dev/fd/3 3<<<"$KEY"

# Prompt for the key without echoing it.
$ zallet rpc z_importkey @-
Enter parameter value:
```

`@-` reads from standard input, prompting without echo when standard input is a
terminal. Prefer a pipe or file descriptor over a regular file on disk.

## Authentication

When Zallet starts its JSON-RPC server, it generates a random cookie credential and
writes it to `{datadir}/.cookie`. The `zallet rpc` command automatically reads this
cookie file to authenticate, so no manual password configuration is needed for local
access.

If `[[rpc.auth]]` users are configured in `zallet.toml`, `zallet rpc` will prefer
those credentials over the cookie file. Cookie-based auth and configured users coexist.

The username `__cookie__` is reserved for the cookie credential, so it cannot be used
for a `[[rpc.auth]]` user. Zallet refuses to start if a configured user claims it,
rather than letting a configured password grant access under the name that clients
treat as the cookie credential.

## Comparison to `zcash-cli`

The `zcashd` full node came bundled with a `zcash-cli` binary, which served an equivalent
purpose to `zallet rpc`. There are some differences between the two, which we summarise
below:

| `zcash-cli` functionality         | `zallet rpc` equivalent            |
|-----------------------------------|------------------------------------|
| `zcash-cli -conf=<file>`          | `zallet --config <file> rpc`       |
| `zcash-cli -datadir=<dir>`        | `zallet --datadir <dir> rpc`       |
| `zcash-cli -stdin`                | `@-` parameter (see above)         |
| `zcash-cli -rpcconnect=<ip>`      | `rpc.bind` setting in config file  |
| `zcash-cli -rpcport=<port>`       | `rpc.bind` setting in config file  |
| `zcash-cli -rpcwait`              | Not implemented                    |
| `zcash-cli -rpcuser=<user>`       | `[[rpc.auth]]` in config file      |
| `zcash-cli -rpcpassword=<pw>`     | `[[rpc.auth]]` in config file      |
| `zcash-cli -rpcclienttimeout=<n>` | `zallet rpc --timeout <n>`         |
| Hostname, domain, or IP address   | Only IP address                    |
| `zcash-cli <method> [<param> ..]` | `zallet rpc <method> [<param> ..]` |

For parameter parsing, `zallet rpc` is (as of the beta releases) both more and less
flexible than `zcash-cli`:

- It is more flexible because `zcash-cli` implements type-checking on method parameters,
  which means that it cannot be used with Zallet JSON-RPC methods where the parameters
  have [changed](../zcashd/json_rpc.md). `zallet rpc` currently lacks this, which means
  that:
    - `zallet rpc` will work against both `zcashd` and `zallet` processes, which can be
      useful during the migration phase.
    - As the alpha and beta phases of Zallet progress, we can easily make changes to RPC
      methods as necessary.

- It is less flexible because parameters need to be valid JSON:
  - Strings need to be quoted in order to parse as JSON strings.
  - Parameters that contain strings need to be externally quoted.

| `zcash-cli` parameter | `zallet rpc` parameter |
|-----------------------|------------------------|
| `null`                | `null`                 |
| `true`                | `true`                 |
| `42`                  | `42`                   |
| `string`              | `'"string"'`           |
| `[42]`                | `[42]`                 |
| `["string"]`          | `'["string"]'`         |
| `{"key": <value>}`    | `'{"key": <value>}'`   |
