# Notes, confirmations, and fees

## Notes

Shielded funds are held as **notes**: discrete, encrypted outputs in the
Orchard or Sapling pools, analogous to transparent UTXOs but visible only to
holders of the right viewing key. A wallet's shielded balance is the sum of
its unspent notes; spending selects specific notes, and any excess value
returns to the account as a new **change** note. Change handling is entirely
internal — Zallet derives change addresses itself and never exposes them
(there is no `getrawchangeaddress`).

## Confirmations and spendability

Zallet follows the [ZIP 315] wallet best-practices draft in distinguishing two
kinds of received outputs:

- **Trusted** outputs — those the wallet trusts to stay mined, such as change
  created by the wallet itself — become spendable after
  **3 confirmations** by default.
- **Untrusted** outputs — everything received from other parties — become
  spendable after **10 confirmations** by default, because a malicious sender
  could attempt a double-spend.

Both thresholds are configurable (`builder.trusted_confirmations` and
`builder.untrusted_confirmations`); lowering them trades reliability under
reorgs for latency. Methods such as `z_sendmany` apply this policy when
`minconf` is not given explicitly.

## Fees

Transaction fees follow [ZIP 317] (proportional to transaction size), always.
There is no fee parameter to tune: `z_sendmany` requires its `fee` argument to
be `null` if present, and `zcashd`'s `settxfee` has no equivalent.

[ZIP 315]: https://zips.z.cash/zip-0315
[ZIP 317]: https://zips.z.cash/zip-0317
