# Introduction

Zallet is a full-node Zcash wallet written in Rust. It is being built as a replacement for
the [`zcashd`] wallet.

[`zcashd`]: https://github.com/zcash/zcash

## Security Warnings

Zallet is currently under development and has not been fully reviewed.

## Current phase: Alpha release

Zallet is currently in alpha. What this means is:

- Breaking changes may occur at any time, requiring you to delete and recreate your Zallet
  wallet.
- Many JSON-RPC methods that will be ported from `zcashd` have not yet been implemented.
- We will be rapidly making changes as we release new alpha versions.

We encourage everyone to test out Zallet during the alpha period and provide feedback,
either by [opening issues on GitHub] or contacting us in the `#wallet-dev` channel of the
[Zcash R&D Discord].

[opening issues on GitHub]: https://github.com/zcash/zallet/issues/new
[Zcash R&D Discord]: https://discord.gg/xpzPR53xtU

## Future phase: Beta release

After alpha testing will come the beta phase. At this point, all of the JSON-RPC methods
that we intend to support will exist. Users will be expected to migrate to the provided
JSON-RPC methods; [semantic differences] will need to be taken into account.

[semantic differences]: zcashd/json_rpc.md
