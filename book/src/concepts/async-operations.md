# Asynchronous operations

Building a shielded transaction involves note selection and zero-knowledge
proving, which takes real time — so the sending RPC methods do not block.
Methods such as `z_sendmany` and `z_shieldcoinbase` validate their arguments,
start the work in the background, and immediately return an **operation id**
(e.g. `opid-...`).

Clients then follow the same lifecycle `zcashd` used:

1. **Poll** with `z_getoperationstatus [["opid-..."]]` — returns the current
   state (executing, success, failed) without consuming it.
2. **Collect** with `z_getoperationresult [["opid-..."]]` — returns the
   outcome of finished operations *and removes them*: the result value on
   success (for sends, the transaction ids), or an error object on failure.
3. `z_listoperationids` lists the operations the wallet currently knows about.

Operations are held in memory, not in the wallet database — do not expect an
operation id to survive a wallet restart. If you lose track of a send, check
`z_listtransactions` / `z_viewtransaction` to see whether the transaction was
created and broadcast.
