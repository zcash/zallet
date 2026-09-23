# The `migrate-zcash-conf` command

> Available on **crate feature** `zcashd-import` only.

`zallet migrate-zcash-conf` migrates a [`zcashd`] configuration file (`zcash.conf`) to an
equivalent Zallet [configuration file] (`zallet.toml`).

The configuration file is located with two flags, neither of which is required:

- `--conf`: A path to a `zcashd` configuration file. Defaults to `zcash.conf`.
- `--zcashd-datadir`: A path to a `zcashd` datadir, against which a relative `--conf` is
  resolved. If omitted, the platform's default `zcashd` datadir is used (`~/.zcash` on
  Linux, the XDG data home's `Zcash` directory on macOS, `%APPDATA%\Zcash` on Windows).

> For the Zallet beta releases, the command also currently takes another required flag
> `--this-is-beta-code-and-you-will-need-to-redo-the-migration-later`.

When run, Zallet will parse the `zcashd` config file, and migrate its various options to
equivalent Zallet config options. Non-wallet options will be ignored, and wallet options
that cannot be migrated will cause a warning to be printed to stdout.

[`zcashd`]: https://github.com/zcash/zcash
[configuration file]: example-config.md
