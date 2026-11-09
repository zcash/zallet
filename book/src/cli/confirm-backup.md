# The `confirm-backup` command

`zallet confirm-backup` records that you have backed up a [BIP 39] mnemonic phrase that
Zallet generated.

A phrase produced by [`zallet generate-mnemonic`](generate-mnemonic.md) exists nowhere but
inside the wallet. Until you copy it somewhere durable, anything derived from it — every
account, and every address in those accounts — is lost along with the wallet database and
its encryption identity. Zallet therefore refuses to derive new accounts, or new
addresses within existing accounts, from such a phrase until this command has been run
against it. The `keystore.require_backup`
[configuration option](../config/README.md) turns that requirement off.

A phrase you supplied yourself with [`zallet import-mnemonic`](import-mnemonic.md) needs
no confirmation. You had it in your hands in order to type it in, so Zallet already treats
it as backed up. (For the same reason, importing a phrase Zallet generated also confirms
it — this command just saves you typing all twenty-four words.)

**Zallet never displays a recovery phrase**, not even here. You obtain your own copy by
exporting it and decrypting the export, which means confirming a backup attests to rather
more than having read some words off a screen: it shows you hold the export *and* a
working age identity *and* its passphrase. The identity is what every other secret in the
wallet is encrypted to, so being able to decrypt with it is the thing most worth
establishing.

> **Warning**
> The phrase is not a complete backup of your wallet. It covers only funds derived from
> that seed; a wallet can also hold spending keys imported with `z_importkey` and other
> standalone key material, which no phrase covers. See [Backup and
> restore](../guide/backup.md) for what a complete backup requires.

## Usage

```
$ zallet confirm-backup
zallet never displays a recovery phrase. To confirm this one's backup you need
your own decrypted copy of it:

    zallet export-mnemonic --armor --seedfp zip32seedfp1qhrfsdsq... >mnemonic.age
    age -d -i /home/you/.zallet/encryption-identity.txt mnemonic.age

Write the phrase down, including the numbering of the words, on something durable
that you will keep somewhere secure, and delete the decrypted copy afterwards. Then
read the words requested below back from what you wrote down.

Enter word #4: about
Enter word #11: absurd
Enter word #19: across

Backup confirmed.
```

If the wallet holds more than one mnemonic phrase, name the one to confirm with
`--seedfp`.

> **On regtest, confirmation is not required by default.** `keystore.require_backup`
> defaults to `false` there and `true` on every other network, matching `zcashd` (which
> set `fRequireWalletBackup = false` in its regtest chain parameters). A regtest wallet is
> disposable, and this command is interactive, so requiring it would leave automated tests
> with no way through. Set the option explicitly to get the same behaviour everywhere.

Three words chosen at random are requested. If any answer is wrong, nothing is recorded
and the command exits with an error; check your written copy and run it again. Running the
command against a phrase whose backup is already confirmed does nothing.

Reading the words back off the decrypted file rather than off your written copy defeats
the point of the exercise, so do not do that.

Because the phrase must be decrypted in order to check your answers, this command needs
the wallet's age encryption identity. If that identity file is passphrase-encrypted, you
will be prompted for the passphrase.

## Relationship to `zcashd`

This command replaces `zcashd`'s `zcashd-wallet-tool` utility, which `zcashd` required
before it would generate new spending keys or addresses under `-walletrequirebackup` (see
[Migrating from `zcashd`](../zcashd/README.md)). Reading part of the phrase back to the
wallet is the same check in substance, with three differences:

- `zcashd-wallet-tool` printed the phrase to the terminal, having obtained it by calling
  `z_exportwallet` — which writes *every* wallet secret to a file in plain text as a side
  effect. Zallet does neither, and confirms the operator's access to the age identity in
  the process.
- `zcashd` had exactly one mnemonic phrase per wallet. Zallet supports several, so
  confirmation is recorded per phrase, and `--seedfp` selects between them.
- `zcashd` gated six RPC methods; Zallet implements only two of them
  (`z_getnewaccount` and `z_getaddressforaccount`), and gates both, plus its own
  `z_recoveraccounts`. `getnewaddress`, `z_getnewaddress`, `getrawchangeaddress`, and
  `keypoolrefill` do not exist in Zallet.

[BIP 39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
