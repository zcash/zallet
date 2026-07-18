# Operating Zallet

This page covers running Zallet as a supervised service: logging, monitoring,
shutdown, upgrades, and securing the JSON-RPC interface. It assumes a
configured wallet (see [Wallet setup](../guide/setup.md)).

## Running as a service

Zallet is a foreground process started with [`zallet start`](../cli/start.md).
Two constraints matter for service management:

- Only one Zallet process can use a datadir at a time (the datadir is locked;
  a second process fails to start).
- The `zallet` launcher dispatches to the backend binary named by the config's
  `backend` key (`zallet-zebra` by default), so both the launcher and the
  backend binary must be on the service's `PATH` — or run the backend binary
  directly.

An example systemd unit:

```ini
[Unit]
Description=Zallet Zcash wallet
# Zallet needs its backing node; order after it if it runs on the same host.
After=network-online.target zebrad.service
Wants=network-online.target

[Service]
User=zallet
ExecStart=/usr/bin/zallet --datadir /var/lib/zallet start
Restart=on-failure
# Uncomment to increase log verbosity (see the Logging section):
# Environment="RUST_LOG=debug"
# systemd's default stop signal (SIGTERM) initiates Zallet shutdown.

[Install]
WantedBy=multi-user.target
```

Zallet logs to stderr, so under systemd its output lands in the journal
(`journalctl -u zallet`).

## Logging

Zallet uses [`tracing`](https://docs.rs/tracing) with an
[`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html):

- All log output goes to **stderr**.
- The default level is `info`.
- Set the `RUST_LOG` environment variable to change it, using standard
  `EnvFilter` directives — e.g. `RUST_LOG=debug`, or per-module filtering like
  `RUST_LOG=info,zallet=debug`.
- Events from dependencies using the `log` crate are captured too.

## Monitoring

There are no dedicated health endpoints yet (readiness/liveness endpoints are
tracked in [#366]). Monitor a running wallet by polling the `getwalletstatus`
JSON-RPC method, e.g. `zallet rpc getwalletstatus`. The response includes:

- `node_tip` — the backing full node's view of the chain tip. If this stops
  advancing, the problem is at the node, not the wallet.
- `wallet_tip` — the wallet's view of the chain tip. This should only diverge
  from `node_tip` for short periods; sustained divergence means the wallet is
  not keeping up.
- `fully_synced_height` — the height up to which the wallet is fully synced.
  During recovery of imported keys this lags the tip while historical ranges
  are scanned.

[#366]: https://github.com/zcash/zallet/issues/366

## Shutdown and upgrades

Zallet shuts down on Ctrl+C, `SIGINT`, or `SIGTERM` (in-flight work is
cancelled at the next await point; full graceful-shutdown support is tracked
in [#184]).

To upgrade:

1. Stop the service.
2. Replace the binaries. The launcher and backend binaries are built and
   shipped together — always replace them as a set, never mix versions.
3. Start the service again.

During the beta phase, check the release notes before upgrading: breaking
changes may require recreating the wallet.

[#184]: https://github.com/zcash/zallet/issues/184

## Securing the JSON-RPC interface

- The RPC server is **disabled by default**; it only listens if the config
  sets `rpc.bind`.
- **Never bind to a public IP address.** Anyone who can reach the RPC port can
  view your transactions and spend your funds. Bind to `127.0.0.1` (or another
  loopback/internal address) and use network-level controls if remote access
  is required.
- Authentication is required on every request: Zallet writes a random cookie
  credential to `{datadir}/.cookie` at startup (used automatically by
  [`zallet rpc`](../cli/rpc.md)), and password users can be provisioned with
  [`zallet add-rpc-user`](../cli/add-rpc-user.md). The cookie file grants full
  wallet access — keep the datadir's permissions restrictive.
