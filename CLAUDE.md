# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Zallet** is a full-node Zcash wallet written in Rust (alpha), designed to replace the `zcashd` wallet. It runs as a daemon with a JSON-RPC API and connects to a Zebra node and Zaino chain indexer for chain state.

- Rust 2024 edition, MSRV 1.85 (pinned via `rust-toolchain.toml`)
- Single-crate workspace: `zallet/` is the main crate; `book/` holds the mdBook user guide

## Commands

### Build & Run
```bash
cargo build --all-features
cargo build --release
cargo run -- --datadir /tmp/zallet-dev start   # requires a running Zebra node
```

### Test
```bash
cargo test --workspace --all-features          # full suite
cargo test --all-targets                       # includes doc tests
cargo test -p zallet <test_name>               # single test
```

Integration tests in `zallet/tests/` use `trycmd` (CLI fixture files in `zallet/tests/cmd/`) and `abscissa_core::testing::CmdRunner` (subprocess-based acceptance tests).

### Lint & Format
```bash
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
```

### Reproducible Docker Build
```bash
make build    # builds OCI image via StageX (requires Docker 25+, buildx)
make import   # loads image into local Docker
```

### Special Build Configurations
```bash
# Merchant terminal variant (different command set)
RUSTFLAGS='--cfg zallet_build="merchant_terminal"' cargo build

# NU7 network upgrade support (unstable)
RUSTFLAGS='--cfg zcash_unstable="nu7"' cargo build

# Tokio task inspector
RUSTFLAGS="--cfg=tokio_unstable" cargo build --features tokio-console
```

## Architecture

### Application Framework
Zallet uses **Abscissa** as its CLI/application framework with **Tokio** (multi-threaded). Entry point: `zallet/src/bin/zallet/main.rs` → `application::boot()`. Components are registered with Abscissa's component system and wired together at startup.

### Component System (`zallet/src/components/`)
Each major subsystem is an Abscissa component:

| Component | File | Role |
|-----------|------|------|
| `Database` | `database.rs` | `deadpool-sqlite` connection pool wrapping `zcash_client_sqlite`; migrations in `database/ext/` |
| `Sync` | `sync.rs` | Two async tasks: steady-state (last ~100 blocks) and history recovery (finalized) |
| `JsonRpc` | `json_rpc/` | `jsonrpsee` HTTP server; zcashd-compatible RPC methods in `json_rpc/methods/` |
| `KeyStore` | `keystore.rs` | `age`-encrypted key material stored in the wallet SQLite DB |
| `Chain` | (Zaino integration) | Finalized chain indexer state |
| `Tracing` | `tracing.rs` | Distributed tracing setup |

### Network Abstraction (`zallet/src/network.rs`)
`Network` enum wraps either `zcash_protocol::consensus::Network` (mainnet/testnet) or a local regtest with custom NU activation heights. All protocol-level code goes through this abstraction.

### JSON-RPC Layer (`zallet/src/components/json_rpc/`)
- `server.rs` — binds `jsonrpsee` server with optional HTTP Basic Auth
- `methods.rs` + `methods/` — 25+ RPC handlers (account, address, balance, transactions, utilities)
- `payments.rs` — transaction building
- `asyncop.rs` — long-running operations returned as async job IDs

### Database Schema
Managed entirely by `zcash_client_sqlite::WalletMigrator`. Zallet-specific extensions live in `components/database/ext/`. The wallet tracks its own version metadata in the DB to detect breaking format changes (as happened in alpha.4 with the Zaino DB format change).

### Configuration (`zallet/src/config.rs`)
Config file: `~/.zallet/zallet.toml` (override with `--datadir`). Key sections: `[consensus]`, `[indexer]` (Zaino), `[rpc]`, `[keystore]`, `[database]`, `[builder]`, `[features]`. Use `zallet example-config` to generate a template.

### Conditional Compilation
- `zallet_build = "wallet"` (default) vs `"merchant_terminal"` — controls which CLI subcommands are compiled in
- `zcash_unstable = "nu7"` — enables NU7 network upgrade code paths
- Feature flags: `zcashd-import` (migration from zcashd), `transparent-key-import`, `rpc-cli`, `tokio-console`

### Key External Dependencies
- **`zcash_client_sqlite`** / **`zcash_client_backend`** — wallet state and sync abstraction (ECC maintained)
- **`zaino-*`** — chain indexer for finalized state (replaces direct Zebra DB access)
- **`zebra-rpc`** — RPC client to communicate with a running Zebra node
- **`jsonrpsee`** — JSON-RPC 2.0 server
- **`abscissa_core`** — CLI application framework
- **`age`** / **`secrecy`** — key encryption and secret types

### Localization
Messages use `i18n-embed` with Fluent format. The `fl!()` macro does compile-time key lookup. Message files live in `zallet/i18n/`.
