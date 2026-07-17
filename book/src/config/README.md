# Configuration reference

Zallet reads its configuration from `zallet.toml` in the datadir (override the
file with `-c/--config`, and the datadir with `-d/--datadir`; see
[Wallet setup](../guide/setup.md)).

The reference below is the output of
[`zallet example-config`](../cli/example-config.md): every available option
with its documentation, generated directly from the source code and checked in
CI, so it always matches the release it ships with. Options are commented out
where they show a default value.

```toml
{{#include ../../../backends/zebra/tests/cmd/example_config.out/zallet.toml}}
```
