# Docker

The official image is [`zodlinc/zallet`](https://hub.docker.com/r/zodlinc/zallet)
on Docker Hub, published for `linux/amd64` and `linux/arm64` with the tags
`latest`, the release version (e.g. `0.1.0-beta.1`), and the git commit SHA.
The amd64 image is a reproducible [StageX](https://codeberg.org/stagex/stagex/)
build with SLSA provenance attestations; see
[Supply Chain Security](../../slsa/slsa.md).

The image contains the `zallet` launcher (the entrypoint) and the backend
binary (`zallet-zebra`) in `/usr/local/bin`, runs as the
non-root user `1000:1000`, and uses `/var/lib/zallet` as its working
directory. It is a minimal from-scratch image: there is no shell, and no
`$HOME`, so **always pass `--datadir` explicitly**.

## Setup

Keep the datadir on a volume, and generate a config into it:

```
$ docker volume create zallet-data
$ docker run --rm -v zallet-data:/var/lib/zallet zodlinc/zallet:latest \
    --datadir /var/lib/zallet example-config -o zallet.toml \
    --this-is-beta-code-and-you-will-need-to-recreate-the-example-later
```

Then follow [Wallet setup](../setup.md) for the config contents and wallet
initialization, running each `zallet` command through `docker run` as above
(interactive commands such as `import-mnemonic` need `-it`).

## Connecting to zebrad from a container

The launcher dispatches on the config's `backend` key as usual (see
[Choosing a chain backend](README.md#choosing-a-chain-backend)). The `zebra`
backend reads `zebrad`'s state database directly, so:

- the `zebrad` container's state directory must be mounted into the Zallet
  container (read-only) at the path named by
  `indexer.read_state_service.zebra_state_path`, which requires both
  containers to run on the same host;
- `zebrad` must be built with the `indexer` feature; and
- `indexer.validator_address` and `indexer.read_state_service.grpc_address`
  must point at the `zebrad` container, with both containers connected to the
  same network.

To run the backend binary directly, override the entrypoint:

```
$ docker run --rm -v zallet-data:/var/lib/zallet --entrypoint zallet-zebra \
    zodlinc/zallet:latest --datadir /var/lib/zallet start
```

## Running

```
$ docker network create zcash
$ docker run -d --name zallet \
    -v zallet-data:/var/lib/zallet \
    --network zcash \
    zodlinc/zallet:latest --datadir /var/lib/zallet start
```

Zallet logs to stderr, so `docker logs zallet` shows them. To use
`zallet rpc` against the running wallet, exec it in the same container so it
can read the RPC cookie from the datadir:

```
$ docker exec zallet zallet --datadir /var/lib/zallet rpc getwalletstatus
```

> Pin a version tag (e.g. `zodlinc/zallet:0.1.0-beta.1`) in production rather
> than `latest`, and read the release notes before moving the pin: during the
> beta phase, upgrades may require recreating the wallet.
