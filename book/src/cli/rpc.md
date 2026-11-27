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

## Parameter parsing

`zallet rpc` uses parameter metadata generated from the RPC traits in the local Zallet
binary. For a method in that table, it validates the positional argument count locally
before reading any indirect parameters. Known string positions accept either a bare value
such as `string` or the backwards-compatible JSON-quoted shell argument `'"string"'`.
A nullable string treats bare `null` as JSON null and `'"null"'` as the string `null`.

Known non-string positions still require valid JSON. Arrays and objects therefore need
shell protection so their JSON syntax reaches Zallet unchanged. An `@PATH` parameter is
read only after count validation and always produces a JSON string, regardless of the
position's normal conversion.

Methods absent from the local generated table retain JSON-only parameter parsing and have
no local argument-count limit. This allows calls to remote-only methods, but it is not full
compatibility with a divergent `zcashd` server: a same-named method always follows the
local Zallet binary's parameter table.

| `zcash-cli` parameter | `zallet rpc` parameter |
|-----------------------|------------------------|
| `null`                | `null`                 |
| `true`                | `true`                 |
| `42`                  | `42`                   |
| `string`              | `string` or `'"string"'` |
| `[42]`                | `[42]`                 |
| `["string"]`          | `'["string"]'`         |
| `{"key": <value>}`    | `'{"key": <value>}'`   |
