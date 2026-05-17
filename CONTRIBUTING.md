# Contributing to materios-intent-settlement

Thanks for your interest in contributing. This repository powers a live Cardano-anchored chain (Materios preprod, spec_version 227+); changes to pallets and the keeper can affect real users, so we're deliberate about what lands.

## Before you start

- **For non-trivial changes** (new dispatchables, storage migrations, weight changes, keeper protocol changes), open an issue first describing the change and the motivation. We'll either acknowledge the direction or push back before you write the code.
- **For bug fixes and small improvements**, a PR with a failing test + fix is the fastest path.
- **For security vulnerabilities**, do NOT open a public issue. Email `security@fluxpointstudios.com` per [SECURITY.md](SECURITY.md).

## Development workflow

```bash
git clone https://github.com/Flux-Point-Studios/materios-intent-settlement
cd materios-intent-settlement
cargo test --workspace          # all pallet + keeper crate tests
cd keeper && pnpm install && pnpm test
cd ../sdk && pnpm install && pnpm test
cd ../e2e && pnpm install && pnpm test  # offline tests; preprod-gated tests run in CI
```

## PR expectations

- Branch off `main`. Branch names like `feat/<topic>`, `fix/<topic>`, `chore/<topic>`.
- Each PR ships a complete, reviewable change. No partial implementations.
- Tests required for any behavior change. We follow a TDD-leaning workflow: failing test first, minimum code to pass, refactor under green bar.
- `cargo test --workspace` must be green. `cargo check --workspace` must produce zero warnings.
- For pallet changes that touch dispatch surface or storage, include a runtime-upgrade design note in the PR description (storage migration if needed, spec_version bump rationale, weight impact).
- Every PR runs through an internal security review before merge. Findings are surfaced in PR comments; expect to iterate.

## Licensing

By submitting a PR you agree that your contributions are dual-licensed under Apache-2.0 (for pallet code) and MIT (for SDK / keeper / e2e), matching the repository's [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT).

## Code style

- **Rust pallets:** `cargo fmt`. Follow Substrate FRAME conventions. Prefer `bounded` types over `Vec`. Errors via `Error<T>` enum, not panics. No `unwrap()` / `expect()` in pallet bodies.
- **TypeScript (keeper, sdk, e2e):** strict mode. No `any` in public APIs. Prefer explicit error returns over thrown exceptions in protocol-critical paths.
- **Comments:** explain *why*, not *what*. No commented-out code, no `TODO` / `FIXME` in merged PRs (file an issue instead).

## What we'll probably reject

- Vendored crypto. Use `sp-core`, `parity-scale-codec`, established libraries.
- New abstractions with a single caller. Inline first; abstract on the third use.
- Breaking changes without an upgrade story (storage migration, spec_version bump, ceremony script).
- Backwards-compatibility shims for unreleased internal versions. The current `main` is the contract.
- Code that silently swallows errors (`catch {}`, `let _ = ...?`, `unwrap_or_default()` on chain reads).

Thanks for reading — looking forward to your contributions.
