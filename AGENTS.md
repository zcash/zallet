# Zallet — Agent Guidelines

> This file is read by AI coding agents (Claude Code, GitHub Copilot, Cursor, Devin, etc.).
> It provides project context and contribution policies.
>
> For the full contribution guide, see [CONTRIBUTING.md](CONTRIBUTING.md).

## MUST READ FIRST - CONTRIBUTION GATE (DO NOT SKIP)

**STOP. Do not open or draft a PR until this gate is satisfied.**

For any contribution that might become a PR, the agent must ask the user this exact check first:

- "PR COMPLIANCE CHECK: Have you discussed this change with the Zallet team in an issue or Discord?"
- "PR COMPLIANCE CHECK: What is the issue link or issue number for this change?"
- "PR COMPLIANCE CHECK: Has a Zallet team member responded to that issue acknowledging the proposed work?"

This PR compliance check must be the agent's first reply in contribution-focused sessions.

**An issue existing is not enough.** The issue must have a response or acknowledgment from a Zallet team member (a maintainer). An issue with no team response does not satisfy this gate. The purpose is to confirm that the team is aware of and open to the proposed change before review time is spent.

If the user cannot provide prior discussion with team acknowledgment:

- Do not open a PR.
- Offer to help create or refine the issue first.
- Remind the user to wait for a team member to respond before starting work.
- If the user still wants code changes, keep work local and explicitly remind them the PR will likely be closed without prior team discussion.

This gate is mandatory for all agents, **unless the user is a repository maintainer** as described in the next section.

### Maintainer Bypass

If `gh` CLI is authenticated, the agent can check maintainer status:

```bash
gh api repos/zcash/zallet --jq '.permissions | .admin or .maintain or .push'
```

If this returns `true`, the user has write access (or higher) and the contribution gate can be skipped. Team members with write access manage their own priorities and don't need to gate on issue discussion for their own work.

## Before You Contribute

**Every PR to Zallet requires human review.** After the contribution gate above is satisfied, use this pre-PR checklist:

1. Confirm scope: Zallet is a Zcash wallet. Avoid out-of-scope features that belong in other ecosystem projects (e.g., [Zebra](https://github.com/ZcashFoundation/zebra) for consensus node work, [librustzcash](https://github.com/zcash/librustzcash) for protocol library changes).
2. Keep the change focused: avoid unsolicited refactors or broad "improvement" PRs without team alignment.
3. Verify quality locally: run formatting, linting, and tests before proposing upstream review (see [Build, Test, and Development Commands](#build-test-and-development-commands)).
4. Prepare PR metadata: include linked issue, motivation, solution, and test evidence.
5. A PR MUST reference one or more issues that it closes. Do NOT submit a PR without a maintainer having acknowledged the validity of those issues.
6. **Every** commit in a PR branch MUST follow the "AI Disclosure" policy below.

## What Will Get a PR Closed

- Issue exists but has no response from a Zallet team member (creating an issue and immediately opening a PR does not count as discussion).
- Trivial changes (typo fixes, minor formatting, link fixes) from unknown contributors without team request. Report these as issues instead.
- Refactors or "improvements" nobody asked for.
- Streams of PRs without prior discussion of the overall plan.
- Features outside Zallet's scope.
- Missing test evidence for behavior changes.
- Inability to explain the logic or design tradeoffs of the changes when asked.
- Missing or removed `Co-Authored-By:` metadata for AI-assisted contributions (see [AI Disclosure](#ai-disclosure)).

## AI Disclosure

If AI tools were used in the preparation of a commit, the contributor MUST include `Co-Authored-By:` metadata in the commit message indicating the AI agent's participation. The contents of the `Co-Authored-By` field must clearly identify which AI system was used (if multiple systems were used, each should have a `Co-Authored-By` line). Failure to do so is grounds for closing the pull request. The contributor is the sole responsible author -- "the AI generated it" is not a justification during review.

Example:
```
Co-Authored-By: Claude <noreply@anthropic.com>
```

## Project Overview

Zallet is a Zcash full node wallet, designed to replace the legacy wallet that was included within zcashd.

- **Rust edition**: 2024
- **MSRV**: 1.88 (pinned in `rust-toolchain.toml`)
- **License**: MIT OR Apache-2.0
- **Repository**: https://github.com/zcash/zallet

## Project Structure

Zallet is split across **three independent Cargo workspaces**, each with its own
`Cargo.lock`. A thin launcher binary (`zallet`) selects a backend at runtime and
execs the matching per-backend binary (`zallet-zebra`, `zallet-zaino`).

```text
.
├── Cargo.toml               # Root workspace (excludes backends/ and crates/)
├── zallet/                  # `zallet` launcher binary: reads the config's
│                            #   `backend` key (default "zebra") and execs the
│                            #   matching `zallet-<backend>` binary on PATH
├── zallet-core/             # Shared wallet library: CLI, config, components,
│                            #   JSON-RPC methods, database, sync. Statically
│                            #   linked into every backend binary
├── tools/gen-copyright/     # Build tooling (root workspace member)
├── backends/
│   ├── zebra/               # Workspace for the `zallet-zebra` binary
│   │                        #   (Zebra read-state backend); deps on zallet-core
│   └── zaino/               # Workspace for the `zallet-zaino` binary
│                            #   (Zaino indexer backend); deps on zallet-core
├── utils/                   # Build + librustzcash lockstep scripts
├── book/                    # Documentation (mdBook)
└── .github/workflows/       # CI configuration
```

Because each backend binary statically links `zallet-core`, a change there
affects both backends. All three binaries open the **same** wallet database, so
the librustzcash stack (`zcash_client_backend`, `zcash_client_sqlite`, ...) MUST
resolve to one identical version across all three lockfiles. This is enforced in
CI by `utils/check-lockstep.sh`. These crates are consumed as released
crates.io versions, so when you bump one, apply the identical version
requirement to all three manifests (root `Cargo.toml` plus
`backends/{zebra,zaino}/Cargo.toml`), then run `utils/sync-lockfiles.sh` to
reconcile the three lockfiles together (never hand-edit a single lockfile).

Key external dependencies from the Zcash ecosystem:
- `zcash_client_backend`, `zcash_client_sqlite` -- wallet backend logic and storage
- `zcash_keys`, `zcash_primitives`, `zcash_proofs` -- protocol primitives
- `zebra-chain`, `zebra-state`, `zebra-rpc` -- chain data types and node RPC
- `zaino-*` -- indexer integration

## Code Conventions

- **Never use magic numbers.** Do not inline a bare numeric (or string) literal
  whose meaning is not obvious from context. Give it a `const` with a
  doc-commented rationale, and reuse the named constants the `librustzcash`
  crates already export rather than re-deriving their values:
  - `zcash_protocol::value::COIN` (zatoshis per ZEC),
  - `zcash_primitives::transaction::fees::zip317::MARGINAL_FEE` (the ZIP-317
    marginal fee),
  - the migration engine's constants from `zcash_pool_migration_backend`
    (for example `MIGRATION_MAX_DENOMINATION_ZEC`,
    `MIGRATION_MAX_PREPARED_NOTES_PER_RUN`, `RESIDUAL_MIGRATION_MIN_ZATOSHI`).

  This applies to production code and tests alike.

## Build, Test, and Development Commands

The three workspaces have separate lockfiles, so every check runs once **per
workspace**: the root, then each backend via `--manifest-path`. CI does exactly
this; run all legs before any PR. Formatting uses the pinned toolchain from
`rust-toolchain.toml` (plain `cargo fmt`, never `cargo +nightly fmt`).

```bash
# Format check (root, then each backend)
cargo fmt --all -- --check
cargo fmt --manifest-path backends/zebra/Cargo.toml -- --check
cargo fmt --manifest-path backends/zaino/Cargo.toml -- --check

# Lint (root, then each backend)
cargo clippy --all-targets -- -D warnings
cargo clippy --manifest-path backends/zebra/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path backends/zaino/Cargo.toml --all-targets -- -D warnings

# Test (root, then each backend)
cargo test
cargo test --manifest-path backends/zebra/Cargo.toml
cargo test --manifest-path backends/zaino/Cargo.toml

# Verify the three lockfiles resolve librustzcash identically (also run in CI)
utils/check-lockstep.sh
```

Build the launcher and the backend binaries:

```bash
cargo build --bin zallet
cargo build --manifest-path backends/zebra/Cargo.toml --bin zallet-zebra
cargo build --manifest-path backends/zaino/Cargo.toml --bin zallet-zaino
```

`zallet` dispatches to the backend named by the config `backend` key (default
`zebra`), so the launcher and the chosen `zallet-<backend>` binary must both be
on `PATH` at run time.

PRs MUST NOT introduce new warnings from `cargo +beta clippy --tests --all-features --all-targets`. Preexisting beta clippy warnings need not be resolved, but new ones introduced by a PR will block merging.

## Testing Scope: Unit Tests Only

**This repository does NOT host integration tests or scenario tests.** Those
live in [zcash/integration-tests](https://github.com/zcash/integration-tests),
which drives the whole Z3 stack (`zebrad` + `zainod` + `zallet`) over real RPC
against a regtest chain. Do not add a test here that stands up a chain, mines
blocks, sends a transaction end to end, or otherwise asserts on the behaviour of
the stack as a whole; it belongs there.

What belongs here is unit tests: fast, in-process, no chain, no network, no
fixture wallet seeded by mining. Test the pure logic a function owns, at the
boundary where a decision is actually made:

- Pure derivations and policy decisions (e.g. "a transparent `fromaddress`
  yields a spend policy that permits only that address's UTXOs, and no shielded
  pool").
- Parsing, validation, and error mapping of RPC parameters.
- Serialization and response shapes.
- Property tests (`proptest`) over the above where the input space is wide.
  Prefer a property over a fixture: derive the key material from an arbitrary
  seed rather than a hardcoded one, so the property is established for every
  input rather than for the one that happened to be written down.

Assert on the whole of a value rather than enumerating its parts, so a test does
not silently stop covering a variant added later. Prefer "the permitted-pool set
is empty" to a loop over today's three pools.

If a piece of logic can only be tested by building a chain, that is usually a
sign it should be extracted into a pure function that CAN be unit-tested, with
the remaining end-to-end behaviour covered in `integration-tests`. Prefer
extracting.

A change to this repository that needs new stack-level coverage should be paired
with a PR to `integration-tests`, referenced from the description, and wired via
a `ZIT-Revision: <branch>` line so this repository's CI exercises it (see the
Cross-Repository CI Integration docs).

## Auditing Dependency Version Bumps

This applies to any change to a pinned dependency version: the `Dockerfile` and `Dockerfile.stagex` apt pins and base-image digests, and by extension any other pinned external artifact.

A version bump is a supply-chain change. Bumping a pin means executing different third-party code in our build, so **a pin MUST NOT be bumped merely because the build went red.** "CI is broken, so I raised the number until it went green" is not a review; it is how a malicious or merely broken upstream gets in unexamined.

Note that the Dockerfile's apt pins rot on their own, with no change on our side: `deb.debian.org` serves only the *current* revision of each package, so a Debian point release or security update deletes the pinned revision and the build fails with `Version '...' was not found`. That is expected, and it is exactly the moment this audit is required.

**An agent bumping a pin MUST do all of the following**, and MUST NOT open the PR without them:

1. **Read the actual diff.** Not the version number, not the changelog summary: the code. For a Debian package, fetch both source packages and diff them, e.g.

   ```bash
   curl -sfL http://deb.debian.org/debian/pool/main/p/protobuf/protobuf_<old>.debian.tar.xz -o old.tar.xz
   curl -sfL http://deb.debian.org/debian/pool/main/p/protobuf/protobuf_<new>.debian.tar.xz -o new.tar.xz
   # then diff debian/patches/series and inspect every added patch
   ```

   Determine which source trees each patch touches, and state whether they are code we actually ship or execute.

2. **Link a discussion a human can follow.** The PR description MUST cite the upstream source: the Debian changelog URL (`https://metadata.ftp-master.debian.org/changelogs/main/<x>/<pkg>/<pkg>_<version>_changelog`), the CVE identifiers, the Debian bug numbers, and the upstream advisory or commit where applicable. A reviewer must be able to verify the claim without redoing the archaeology.

3. **State the impact on us explicitly.** Which of the changed components does this image actually use? A protobuf update that only patches its Java, Python, and PHP runtimes does not affect a build that uses `protoc` solely for Rust codegen and ships none of those runtimes; say so, and say how you established it.

4. **Confirm the new pin resolves**, against the digest-pinned base rather than your laptop:

   ```bash
   docker run --rm rust:<tag>@sha256:<digest> \
     bash -c 'apt-get update -qq && apt-cache policy <package>'
   ```

5. **Keep the bump minimal.** Bump only the pins that actually moved; re-read the candidate versions and leave the rest alone. Never relax a pin to an unpinned or range version to dodge the problem, and never silence `hadolint`.

If the diff is not benign, or you cannot establish what changed, STOP and say so in the PR rather than merging a version you have not audited.

## Database Write Atomicity

`rusqlite` autocommits every statement executed outside an explicit transaction. A
sequence of writes that must land together will therefore commit one at a time unless
it is wrapped, and a failure partway through (an I/O error, a full disk, a crash, or an
error returned by a later step) leaves a subset committed. This has produced real bugs
in Zallet, so it is checked on every change that touches the wallet database.

**Before writing or reviewing any code that writes to the wallet database, answer these
four questions in order.** Answer them in the PR description when the answer to the
first is "more than one".

1. **How many writes does this operation issue?** Count every `INSERT`, `UPDATE`, and
   `DELETE`, including those inside loops and inside the functions it calls. If the
   answer is one, stop here. Otherwise continue.
2. **Must they land together?** Is there any subset of these rows that, if committed
   alone, the rest of the wallet would treat as valid state? If so, they must share one
   transaction.
3. **What happens on retry?** Assume the operation failed after committing a subset and
   the user runs it again. Does the retry repair the state, or does it refuse, diverge,
   or duplicate? This is the question that decides whether a partial write is a
   transient annoyance or a permanent one, and it is the one most often skipped.
4. **Does any read path see only one side?** If one store is reachable through an API
   that never consults the other, a partial write surfaces to the user as valid data.

Two patterns turn a partial write into an unrecoverable one. Either of them present in
a multi-write operation is a hard requirement for a transaction, not a judgement call:

- **One-shot guards.** A check of the form "if this table is non-empty, refuse" turns a
  partial commit into a permanent refusal to ever finish the operation. The guard MUST
  also run inside the transaction, against the same connection. Reading it on a
  separate connection is both outside the rollback and a check-then-act race.
- **Asymmetric read paths.** When an export or read path consults one store while the
  scanning or spending path consults another, a half-committed write leaves the user
  holding material that looks present but does nothing.

### Which primitive to use

- Writes confined to Zallet's own `ext_zallet_*` tables: `conn.transaction()`, then
  `commit()` on the success path. See
  `KeyStore::store_encrypted_standalone_transparent_keys`.
- A wallet-database write that must be paired with an `ext_zallet_*` write:
  `WalletDb::transactionally_with_extension`, which runs both under one transaction and
  restricts the extension handle to `ext_`-prefixed tables. See `z_importkey` in
  `zallet-core/src/components/json_rpc/methods/import_key.rs`.
- Several `WalletRead` or `WalletWrite` operations that must be atomic with each other:
  `WalletDb::transactionally`.

A `rusqlite` transaction cannot be held across an `.await`. Hoist async and
non-database work (key encryption, chain queries, birthday lookups) to before the
transaction is opened, and keep only the statements inside it. Where that hoisting
moves a validity check outside the transaction, re-check inside it: the state it
checked may have changed by the time the transaction opens.

Inside a `transactionally` or `transactionally_with_extension` closure, every fallible
call MUST propagate with `?`. The `zcash_client_sqlite` implementations take no
savepoint per method, so a `WalletWrite` call that fails partway leaves its partial
writes in the enclosing transaction; the rollback happens only because the error
escapes the closure. Discarding an error there (`let _ = ...`, `.ok()`, or a `match`
arm that logs and continues) commits that partial state while the operation still
reports success.

Compensating logic ("undo the first write if the second fails") is not a substitute for
a transaction. It does not survive a crash, its undo path is rarely tested, and it is
sometimes not expressible at all: `delete_account` does not restore the wallet-wide
scan-queue and note-commitment-tree state that `add_account` rewinds.

### Test evidence

A change that adds or modifies a multi-statement write MUST come with a unit test that
returns an error from inside the transaction and asserts that none of the writes
persisted. Asserting that the success path commits is not sufficient; the bug being
guarded against is on the failure path.

## Commit & Pull Request Guidelines

### Commit History

- Commits should represent discrete semantic changes.
- Maintain a clean commit history. Squash fixups and review-response changes into the relevant earlier commits. The [git revise](https://github.com/mystor/git-revise) tool is recommended for this. An exception is that you should take account of requests by maintainers on a PR for prior commits not to be rebased or revised. Maintainers may indicate that existing commits should not be mutated by setting the `S-please-do-not-rebase` label on the pull request.
- There MUST NOT be "work in progress" commits in your history (see CONTRIBUTING.md for narrow exceptions).
- Each commit MUST pass `cargo clippy --all-targets -- -D warnings` and MUST NOT introduce new warnings from `cargo +beta clippy --tests --all-features --all-targets`.
- Each commit should be formatted with `cargo fmt`.

### Commit Messages

- Short title (preferably under ~120 characters).
- Body should include motivation for the change.
- Include `Co-Authored-By:` metadata for all contributors, including AI agents.

### CHANGELOG

- When a commit alters the public API, fixes a bug, or changes underlying semantics, it MUST also modify the affected `CHANGELOG.md` to document the change. These modifications to `CHANGELOG.md` MUST follow the existing conventions in that file which are originally based on those documented at [Keep a Changelog](https://keepachangelog.com/).
- Updated or added public API members MUST include complete `rustdoc` documentation comments.

### Merge Workflow

This project uses a merge-based workflow. PRs are merged with merge commits. Rebase-merge and squash-merge are generally not used.

When branching:
- For SemVer-breaking changes: branch from `main`.
- For SemVer-compatible changes: consider branching from the most recent tag of the previous major release to enable backporting.

### Pull Request Review

See the detailed PR review workflow in CONTRIBUTING.md, which describes the rebase-based review cycle, diff link conventions, and how to handle review comments via `git revise` and GitHub's suggestion feature.

## Coding Style

The Zallet authors hold this software to a high standard of quality. The following is a summary; see CONTRIBUTING.md for the full coding style guide.

### Type Safety

- Invalid states should be unrepresentable at the type level.
- Struct members should be private; expose safe constructors returning `Result` or `Option`.
- Avoid using bare native integer types and strings in public APIs to represent values of a more specific semantic type; use newtype wrappers in that case. Try to reuse existing wrappers where available.
- Use `enum`s liberally. Prefer custom enums with semantic variants over booleans.
- Make data types immutable unless mutation is required for performance.

### Side Effects & Capability-Oriented Programming

- Write referentially transparent functions where possible. If an overall operation cannot be referentially transparent but it involves significant referentially transparent subcomputations, consider factoring those into separate functions or methods.
- Avoid mutation; when necessary, use mutable variables in the narrowest possible scope.
- If a statement produces a side effect, use imperative style (e.g., `for` loops rather than `map`) to make the side effect evident.
- Prefer to use a pipelined functional style for iterating over collections when the operations to be performed do not involve side effects.
- Side-effect capabilities should be passed as explicit arguments (e.g., `clock: impl Clock`), defined independent of implementation concerns.

### Error Handling

- Use `Result` with custom error `enum`s.
- Implement `std::error::Error` for error types in public APIs.
- Panics and aborts should be avoided except in provably unreachable cases.
- If an error case is probably unreachable, prefer to use `.expect` with a short string documenting why the case is unreachable (following similar examples in the codebase), rather than `.unwrap()`.
- Publically accessible error enums should normally be marked non-exhaustive.
- Add `From` instances between error types if it simplifies error-handling code (and only in that case).

### Serialization

- All serialized data must be versioned at the top level.
- Derived serialization (e.g., `serde`) is NOT used except in specifically marked cases.
- Serialization-critical types may not be modified once exposed in a public release.
- These rules may be relaxed for purely ephemeral wire formats.
