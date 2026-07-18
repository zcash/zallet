# JSON-RPC methods

This reference documents every JSON-RPC method Zallet provides. It is
generated from the same source as the `zallet rpc help` output and the
machine-readable [OpenRPC](https://open-rpc.org/) document served by the
`rpc.discover` method, and a test pins it to that source, so it always matches
the release it ships with.

- To call these methods from a shell, see [the `rpc` command](../cli/rpc.md).
- For methods whose behaviour differs from their `zcashd` counterparts, see
  [JSON-RPC altered semantics](../zcashd/json_rpc.md).
- For the status of `zcashd` methods that Zallet does not provide, see the
  [method status matrix](../zcashd/rpc_status.md).

{{#include methods.md}}
