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
- **MSRV**: 1.85 (pinned in `rust-toolchain.toml` to 1.85.1)
- **License**: MIT OR Apache-2.0
- **Repository**: https://github.com/zcash/zallet

## Project Structure

Zallet is a Rust workspace with a single application crate:

```text
.
├── zallet/                  # The wallet application crate
│   ├── src/
│   │   ├── bin/             # Binary entry points
│   │   ├── commands/        # CLI command implementations
│   │   ├── components/      # Application components
│   │   ├── application.rs   # Abscissa application setup
│   │   ├── cli.rs           # CLI definition
│   │   ├── config.rs        # Configuration types
│   │   ├── network.rs       # Network handling
│   │   └── ...
│   └── tests/               # Integration tests
├── utils/                   # Build and utility scripts
├── book/                    # Documentation (mdBook)
└── .github/workflows/       # CI configuration
```

Key external dependencies from the Zcash ecosystem:
- `zcash_client_backend`, `zcash_client_sqlite` -- wallet backend logic and storage
- `zcash_keys`, `zcash_primitives`, `zcash_proofs` -- protocol primitives
- `zebra-chain`, `zebra-state`, `zebra-rpc` -- chain data types and node RPC
- `zaino-*` -- indexer integration

## Build, Test, and Development Commands

All three of the following must pass before any PR:

```bash
# Format check
cargo fmt --all -- --check

# Lint check (using the pinned MSRV toolchain)
cargo clippy --all-targets -- -D warnings

# Run all tests
cargo test --workspace --all-features
```

Additional useful commands:

```bash
# Full build check
cargo build --workspace --all-features

# Check intra-doc links
cargo doc --all --document-private-items

# Run a single test by name
cargo test -- test_name
```

PRs MUST NOT introduce new warnings from `cargo +beta clippy --tests --all-features --all-targets`. Preexisting beta clippy warnings need not be resolved, but new ones introduced by a PR will block merging.

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
