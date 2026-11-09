# The `generate-mnemonic` command

`zallet generate-mnemonic` generates a new [BIP 39] mnemonic and stores it in a Zallet
wallet.

The command takes no arguments (beyond the top-level flags on `zallet` itself). When run,
Zallet will generate a mnemonic, add it to the wallet, and print out its ZIP 32 seed
fingerprint (which you will use to identify it in other Zallet commands and RPCs).

```
$ zallet generate-mnemonic
Seed fingerprint: zip32seedfp1qhrfsdsqlj7xuvw3ncu76u98c2pxfyq2c24zdm5jr3pr6ms6dswss6dvur

This phrase exists nowhere but this wallet. Run 'zallet confirm-backup' to record
it somewhere durable; until you do, zallet will not derive accounts or addresses
from it.
```

The mnemonic itself is never printed. At this point it exists nowhere but inside the
wallet, so until you record it somewhere durable, Zallet will not derive accounts from it
or addresses within them. [`zallet confirm-backup`](confirm-backup.md) walks you through
obtaining a copy and registers that you have one.

Each time you run `zallet generate-mnemonic`, a new mnemonic will be added to the wallet.
Be careful to only run it multiple times if you want multiple independent roots of spend
authority!

[BIP 39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
