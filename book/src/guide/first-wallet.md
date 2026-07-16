# Sending your first transaction

This tutorial continues from [Wallet setup](setup.md): it assumes `zallet
start` is running and you have generated a mnemonic. You will create an
account, receive funds, and send them onward.

All commands below use [`zallet rpc`](../cli/rpc.md). Remember its quoting
rule: parameters must be valid JSON, so strings need shell-quoted double
quotes (`'"like this"'`).

## 1. Wait for sync

```
$ zallet rpc getwalletstatus
```

Compare `wallet_tip` with `node_tip` — they should match (and keep matching)
before you rely on balances.

## 2. Create an account

```
$ zallet rpc z_getnewaccount '"main"'
```

The string is the account's name. The response includes the account's UUID —
copy it, as it identifies the account in the other commands. (If your wallet
has more than one mnemonic, you must also pass the seed fingerprint as a
second parameter.)

## 3. Derive an address

```
$ zallet rpc z_getaddressforaccount '"<account-uuid>"'
```

This returns a Unified Address for the account. You can derive as many
addresses as you like — see
[Accounts and keys](../concepts/accounts.md) for how they relate.

## 4. Receive funds

Send ZEC to the address from another wallet (on testnet, a faucet works).
Once the funding transaction is mined, it appears in:

```
$ zallet rpc z_listunspent
```

Note that received funds are not *spendable* immediately: outputs received
from other parties are spendable after 10 confirmations by default. See
[Notes, confirmations, and fees](../concepts/notes.md).

## 5. Check the balance

```
$ zallet rpc z_getbalanceforaccount '"<account-uuid>"'
```

## 6. Send

```
$ zallet rpc z_sendmany '"<your-unified-address>"' \
    '[{"address": "<recipient-address>", "amount": 0.001}]'
```

The first parameter selects whose funds to spend (an address of your
account); the second is the list of payments. Fees are set automatically
([ZIP 317](https://zips.z.cash/zip-0317)); there is nothing to configure.

By default Zallet only builds fully-shielded transactions. If the recipient
address is transparent, the call fails with a privacy-policy error telling
you which `privacy_policy` value to pass to accept the trade-off — see
[Troubleshooting](../troubleshooting.md).

`z_sendmany` does not block: it returns an **operation id** (`opid-…`)
immediately while the wallet builds and proves the transaction in the
background.

## 7. Track the operation

```
$ zallet rpc z_getoperationstatus '["opid-…"]'
```

Poll until the status is no longer executing, then collect the result (this
also removes the finished operation):

```
$ zallet rpc z_getoperationresult '["opid-…"]'
```

On success the result contains the transaction id(s). See
[Asynchronous operations](../concepts/async-operations.md) for the lifecycle.

## 8. Inspect the transaction

```
$ zallet rpc z_viewtransaction '"<txid>"'
```

This shows the transaction as your wallet sees it, including decrypted
shielded outputs, the accounts involved, and the fee.
