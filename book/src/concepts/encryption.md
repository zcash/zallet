# Wallet encryption

Zallet encrypts key material with [age], asymmetric file encryption. During
[wallet setup](../guide/setup.md#initialize-the-wallet-encryption) — before
any keys exist — you create an **encryption identity** (a file, by default
`{datadir}/encryption-identity.txt`) and initialize the wallet with it.

From then on:

- **Everything secret is encrypted to that identity**: mnemonic phrases and
  imported spending keys are stored in the wallet database as age ciphertexts,
  and [`zallet export-mnemonic`](../cli/export-mnemonic.md) output is
  encrypted to it too. Decrypting any of it requires the identity file.
- **The wallet database as a whole is *not* encrypted.** Transaction history,
  addresses, and viewing keys are stored in the clear in `wallet.db` — anyone
  who reads the file learns your full transaction history, though they cannot
  spend without the identity.

The identity file can itself be protected with a passphrase (created with
`zallet generate-encryption-identity -p`). With a passphrase-encrypted
identity, the key store starts **locked**: operations that need spending keys
fail with "Wallet is locked" until it is unlocked with the `walletpassphrase`
RPC method (`walletlock` re-locks it). In non-interactive contexts the
passphrase can be supplied via the `ZALLET_IDENTITY_PASSPHRASE` environment
variable.

Consequences worth internalizing:

- Losing the identity file (or forgetting its passphrase) makes the key
  material in every copy of `wallet.db` permanently undecryptable — back it
  up, and see [Backup and restore](../guide/backup.md).
- There is no equivalent of `zcashd`'s `encryptwallet` RPC method: encryption
  is not something you turn on later, it is established at setup, before any
  key exists.

[age]: https://age-encryption.org/
