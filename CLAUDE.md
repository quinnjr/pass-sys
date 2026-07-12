# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this crate is

`pass-sys` is a native Rust implementation of the password-store format used
by `pass` — it does **not** shell out to the `pass` script. All cryptography
goes through libgpgme via the `gpgme` crate. Stores must remain byte-level
interoperable with `pass` in both directions; the interop tests are the
contract. The crate is Unix-only (compile-time `compile_error!` gate).

## Commands

```sh
cargo test                                   # full suite (see test requirements below)
cargo test --test store rename_moves_entry   # single test by name
cargo test --test env                        # env-mutating tests only
cargo clippy --all-targets -- -D warnings    # lint gate (CI-enforced)
cargo fmt --check
cargo llvm-cov --fail-under-lines 99         # coverage gate (CI-enforced)
cargo +1.85 check --all-targets              # MSRV check (CI-enforced)
```

Tests require `gpg` and `pass` on PATH plus libgpgme headers (Arch: `gpgme
pass`; Debian: `libgpgme-dev pass`). Every test builds a throwaway
`GNUPGHOME` with batch-generated no-protection keys (`tests/common/mod.rs`)
— nothing touches the developer's real keyring or store. Tests that induce
permission errors self-skip under root.

## Architecture

Single-file library (`src/lib.rs`). The important structure:

- **Public ops** (`show`/`insert`/`copy`/`rename`/...) are thin wrappers that
  create one `gpgme::Context` and delegate to private `show_with`/
  `insert_with` taking `&mut Context` — so multi-step ops (`copy`, `rename`)
  share a single context. Keep new ops on this pattern.
- **`entry_path` is the security boundary.** It rejects names that escape
  the store textually (`..`, absolute, dotfile components) and via symlinks
  planted in the store tree (canonicalize + prefix check). Any new operation
  that touches the filesystem must resolve names through it.
- **`gpg_ids_for` walks from the entry's directory up to the store root**
  for the nearest non-empty `.gpg-id` (per-subfolder recipient sets). An
  unreadable `.gpg-id` is a hard `Io` error by design — falling back to the
  parent would encrypt to the wrong recipients.
- **Recipient keys are looked up one id at a time** (`get_key` per id), not
  batched with `find_keys`: a batched lookup can't attribute matches to
  patterns, so a missing recipient would silently encrypt to fewer keys than
  `.gpg-id` demands. Do not "optimize" this. Only gpg's EOF code maps to
  `KeyNotFound`; other failures surface as `Error::Gpg`.
- **Writes are atomic**: temp file (mode 0600) + rename, never truncate in
  place. `rename` within one `.gpg-id` domain is a plain `fs::rename`;
  across domains it re-encrypts and rolls back the destination if source
  removal fails.
- **Secret hygiene**: decrypted/generated intermediates are wrapped in
  `zeroize::Zeroizing`. Returned values are deliberately plain `String` —
  changing that is an API break.
- **`Error` is `#[non_exhaustive]` and leaks no `gpgme` types** (`Gpg` holds
  a boxed opaque source). Keep third-party types out of public signatures.

## Tests

- `tests/store.rs` — main integration suite. Use the `initialized(&f)`
  helper for standard setup; `store(&f)` when a test needs custom init.
  Re-encryption claims are asserted at the recipient level via
  `Fixture::recipient_keyids` (`gpg --list-packets`), not just round-trip
  decryption.
- `tests/env.rs` — the **only** place allowed to mutate process env
  (`set_var`/`remove_var`). It's a separate binary because test binaries run
  as separate sequential processes; within it, take `env_lock()`. Never add
  env mutation to `tests/store.rs` — concurrent `setenv`/`getenv` against
  libgpgme threads is UB.
- Coverage is gated at 99% lines in CI; new code paths need tests that
  exercise them (the suite currently sits at ~99.6% with only accounting
  artifacts uncovered).

## Conventions

- **Git-flow only**: day-to-day work on `develop` (or `feature/*` into
  `develop`); `main` receives merges exclusively through `release/*` /
  `hotfix/*` branches. Never merge or fast-forward `develop` into `main`
  directly.
- MSRV is 1.85 (`rust-version` in Cargo.toml); CI compiles at it. Avoid
  APIs stabilized later (e.g. bare `str::from_utf8` needs 1.87 — use
  `std::str::from_utf8`).
- Behavior must match `pass` semantics wherever a counterpart exists;
  deviations are documented in README's "Semantics" section and CHANGES.md.
  Known intentional gaps: no git integration, no extensions, UTF-8-only
  entry contents.
