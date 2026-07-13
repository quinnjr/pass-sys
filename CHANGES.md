# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-13

### Changed

- `init` now re-encrypts existing entries governed by the root `.gpg-id`
  when the id set changes, matching `pass init`. All new ids must resolve
  to keys before anything is modified; `.gpg-id` is written last so an
  interrupted re-encryption is repaired by re-running `init`. Non-UTF-8
  entries are re-encrypted correctly (the re-encryption path is raw
  bytes).
- `init` rejects an empty or whitespace-only id set with `Error::NoGpgIds`
  instead of proceeding (which would have fallen through to symmetric
  encryption during re-encryption).

## [0.1.1] - 2026-07-12

### Changed

- README installation instructions point at crates.io now that the crate is
  published (docs-only release; no code changes).

## [0.1.0] - 2026-07-12

### Added

- `PasswordStore` handle over the password-store format, implemented natively
  through libgpgme (no `pass` subprocess): `init`, `show`, `password`,
  `insert`, `generate`, `generate_alphanumeric`, `remove`, `copy`, `rename`,
  `list`, `exists`.
- Default store resolution from `$PASSWORD_STORE_DIR` falling back to
  `~/.password-store`; per-store GnuPG home override via `with_gpg_home`
  (readable back with the `gpg_home` getter).
- Recipient resolution from the nearest `.gpg-id` at or above an entry,
  matching `pass` per-subfolder key semantics; an unreadable `.gpg-id` is a
  hard error rather than a silent fallback to the parent's recipients.
- `copy`/`rename` re-encrypt to the destination's recipients; a rename
  within one `.gpg-id` domain is an atomic file move, renaming onto itself
  is a no-op, and a failed rename rolls the destination back.
- Atomic entry writes (temp file + rename, mode `0o600`); the store root is
  created `0o700`.
- Rejection of entry names that escape the store (`Error::SneakyPath`),
  mirroring `pass`'s sneaky-path check, including symlinks planted inside
  the store tree that resolve outside it.
- Password generation from `/dev/urandom` with `pass generate` character sets
  (`[:graph:]` / `[:alnum:]`); generated secrets and decrypted intermediates
  are zeroized in memory.
- Typed `#[non_exhaustive]` `Error` enum: `Io`, `Gpg` (opaque boxed source —
  the `gpgme` types are not part of the public API), `Utf8`, `NotFound`,
  `NotInitialized`, `KeyNotFound`, `SneakyPath`. A missing recipient key is
  `KeyNotFound`; operational gpg failures (agent down, ambiguous ids) are
  `Gpg`.
- Unix-only compile-time gate (the crate requires `/dev/urandom` and GnuPG's
  Unix engine).
- Integration test suite running against real GnuPG, including two-way
  interoperability tests with the `pass` binary and recipient-level
  re-encryption assertions via `gpg --list-packets`.
