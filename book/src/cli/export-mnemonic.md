# The `export-mnemonic` command

`zallet export-mnemonic` enables a BIP 39 mnemonic to be exported from a Zallet wallet.

The command names the mnemonic to export in one of three ways:

- the UUID of an account derived from it, obtainable from a running Zallet wallet with
  `zallet rpc z_listaccounts`;
- `--seedfp`, its ZIP 32 seed fingerprint, as printed by
  [`zallet generate-mnemonic`](generate-mnemonic.md) and
  [`zallet import-mnemonic`](import-mnemonic.md); or
- neither, if the wallet holds exactly one mnemonic.

A freshly generated mnemonic has no accounts derived from it yet, so it can only be named
by the latter two.

Exporting decrypts the stored phrase in order to re-encrypt it for output, so it needs the
wallet's age encryption identity. If that identity file is passphrase-encrypted, you will
be prompted for the passphrase.

The mnemonic is encrypted to the same `age` identity that the wallet uses to internally
encrypt key material. Decrypting the exported file therefore requires that same identity
file (and its passphrase, if it is passphrase-encrypted): the encrypted mnemonic is not a
self-contained backup, so keep the identity file too. You can then use a tool like
[`rage`] to decrypt the resulting file.

> **⚠️ The mnemonic is not always a complete backup**
>
> `export-mnemonic` backs up **only** funds derived from this seed. A wallet can also hold
> spend authority that **no mnemonic covers**: keys imported with `z_importkey`, and any
> other standalone key material (for example, standalone keys brought in by
> [`zallet migrate-zcashd-wallet`]). That material lives only in the Zallet wallet database.
>
> To back it up, you must **also** keep a secure copy of **both** the `wallet.db` file
> *and* the age encryption identity file (the file named by the `keystore.encryption_identity`
> config option). The spending keys in `wallet.db` are encrypted to that identity; if you
> lose it, or forget its passphrase, they cannot be decrypted and those funds are
> unrecoverable. Note that `wallet.db` itself is **not** encrypted — it also holds your
> transaction history and viewing keys in the clear — so keep the backup somewhere secure.
> There is currently no complete backup RPC or command for this key material.

```
$ zallet export-mnemonic --armor 514ab5f4-62bd-4d8c-94b5-23fa8d8d38c2 >mnemonic.age
$ echo mnemonic.age
-----BEGIN AGE ENCRYPTED FILE-----
...
-----END AGE ENCRYPTED FILE-----
$ rage -d -i path/to/encrypted-identity.txt mnemonic.age
some seed phrase ...
```

[`rage`](https://github.com/str4d/rage)

[`zallet migrate-zcashd-wallet`]: migrate-zcashd-wallet.md
