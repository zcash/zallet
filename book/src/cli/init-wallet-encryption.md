# The `init-wallet-encryption` command

`zallet init-wallet-encryption` prepares a Zallet wallet for storing key material
securely.

The command currently takes no arguments (beyond the top-level flags on `zallet` itself).
When run, Zallet will use the [age encryption] identity stored in a wallet's datadir to
initialize the wallet's encryption keys. The encryption identity file name (or path) can
be set with the `keystore.encryption_identity` [config option].

> WARNING: `zallet` requires the encryption identity file to already exist.
> You can generate a plain or passphrase-encrypted identity with
> [`zallet generate-encryption-identity`].

## Identity kinds

Zallet supports several kinds of age identities, and how `zallet init-wallet-encryption`
interacts with the user depends on what kind is used:

### Plain (unencrypted) age identity file

In this case, `zallet init-wallet-encryption` will run successfully without any user
interaction.

The ability to spend funds in Zallet is directly tied to the capability to read the
age identity file on disk. If Zallet is running, funds can be spent at any time.

### Passphrase-encrypted identity file

In this case, `zallet init-wallet-encryption` will ask the user for the passphrase,
decrypt the identity, and then use it to initialize the wallet's encryption keys.

Starting Zallet requires the capability to read the identity file on disk, but spending
funds additionally requires the passphrase. Zallet can be temporarily unlocked using the
JSON-RPC method `walletpassphrase`, and locked with `walletlock`.

> WARNING: it is currently difficult to use [`zallet rpc`] for unlocking a Zallet wallet:
> `zallet rpc walletpassphrase PASSPHRASE` will leak your passphrase into your terminal's
> history.

### Plugin identity file

> age plugins will eventually be supported by `zallet init-wallet-encryption`, but
> currently are tricky to set up. [`zallet generate-encryption-identity`] does not
> generate plugin identities, so setting one up requires the external `age` or `rage` CLI
> (plus the relevant age plugin binary) to create the identity, followed by manual database
> editing.

Starting Zallet requires the capability to read the plugin identity file on disk. Then,
each time a JSON-RPC method is called that requires access to specific key material, the
plugin will be called to decrypt it, and Zallet will keep the key material in memory only
as long as required to perform the operation. This can be used to control spend authority
with an external device like a YubiKey (with [`age-plugin-yubikey`]) or a KMS.

[age encryption]: https://age-encryption.org/
[config option]: example-config.md
[`zallet generate-encryption-identity`]: generate-encryption-identity.md
[`zallet rpc`]: rpc.md
[`age-plugin-yubikey`]: https://github.com/str4d/age-plugin-yubikey
