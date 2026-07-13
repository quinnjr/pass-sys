# pass-sys

[![CI](https://github.com/quinnjr/pass-sys/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/quinnjr/pass-sys/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
![MSRV: 1.85](https://img.shields.io/badge/MSRV-1.85-informational)
![Platform: Unix](https://img.shields.io/badge/platform-unix-lightgrey)

Native Rust implementation of [`pass`](https://www.passwordstore.org/), the
standard unix password manager.

Rather than shelling out to the `pass` script, this crate implements the
password-store format directly — a directory tree of OpenPGP-encrypted `.gpg`
files with `.gpg-id` files naming the recipients — performing all cryptography
through libgpgme (GnuPG's C library) via the [`gpgme`](https://crates.io/crates/gpgme)
crate. Stores written by this crate are readable by `pass` and vice versa;
the test suite proves interoperability in both directions against the real
`pass` binary, down to asserting the recipient key ids on the wire format.

## Why

- **No subprocess, no parsing.** Calling the `pass` script means spawning a
  shell per operation and scraping tree-formatted, sometimes colorized
  output. This crate talks to GnuPG through its C API and to the store
  through the filesystem, returning typed values and typed errors.
- **Faithful to the format.** Per-subfolder `.gpg-id` recipient sets,
  re-encryption on cross-folder moves, `pass generate`'s exact character
  sets — the semantics you rely on in `pass` carry over (and the deliberate
  gaps are documented below).
- **Hardened where a password store should be.** Atomic writes, sneaky-path
  and symlink rejection, zeroized secret buffers, private file modes — see
  [Security posture](#security-posture).

## Installation

```sh
cargo add pass-sys
```

### Requirements

- Unix (the crate has a compile-time gate; it needs `/dev/urandom` and
  GnuPG's Unix engine)
- libgpgme (Arch: `gpgme`, Debian/Ubuntu: `libgpgme-dev`, Fedora: `gpgme-devel`)
- GnuPG with a usable key for your store
- Rust 1.85+

The `pass` binary itself is **not** required at runtime — only for running
the interoperability tests.

## Quick start

```rust
use pass_sys::PasswordStore;

fn main() -> pass_sys::Result<()> {
    // Your default store (~/.password-store or $PASSWORD_STORE_DIR):
    let store = PasswordStore::new();

    // Or an explicit location and GnuPG home:
    // let store = PasswordStore::with_store_dir("/path/to/store")
    //     .with_gpg_home("/path/to/gnupg");

    store.insert("web/example.com", "hunter2\nusername: joseph\n")?;

    let password = store.password("web/example.com")?; // first line: "hunter2"
    let contents = store.show("web/example.com")?;     // full decrypted contents

    let generated = store.generate("web/new-site", 24)?; // like `pass generate`

    for entry in store.list()? {
        println!("{entry}");
    }

    store.rename("web/example.com", "web/example.org")?;
    store.remove("web/example.org")?;
    Ok(())
}
```

Errors are a typed, `#[non_exhaustive]` enum, so callers can react to the
case they care about:

```rust
use pass_sys::{Error, PasswordStore};

fn lookup(store: &PasswordStore) -> pass_sys::Result<()> {
    match store.show("maybe/missing") {
        Ok(contents) => println!("{contents}"),
        Err(Error::NotFound(name)) => eprintln!("{name} isn't in the store"),
        Err(Error::NotInitialized(_)) => eprintln!("run `pass init <gpg-id>` first"),
        Err(other) => return Err(other),
    }
    Ok(())
}
```

## API

| Method | `pass` equivalent |
|---|---|
| `init(&["gpg-id"])` | `pass init` |
| `show(name)` | `pass show` |
| `password(name)` | `pass show` (first line only) |
| `insert(name, contents)` | `pass insert --multiline --force` |
| `generate(name, len)` | `pass generate --force` |
| `generate_alphanumeric(name, len)` | `pass generate --force --no-symbols` |
| `remove(name)` | `pass rm --force` |
| `copy(from, to)` | `pass cp --force` |
| `rename(from, to)` | `pass mv --force` |
| `list()` | `pass ls` (flat, recursive) |
| `exists(name)` | — |

### Semantics

Behavior follows `pass` where it matters:

- Recipients come from the nearest `.gpg-id` at or above an entry, so
  per-subfolder key sets work. An unreadable `.gpg-id` is a hard error,
  never a silent fallback to the parent's keys. Re-running `init` with a
  changed id set re-encrypts every entry the root `.gpg-id` governs
  (subfolders with their own `.gpg-id` are left alone), like `pass init`.
- Encryption requires **every** id listed in `.gpg-id` to resolve to a key;
  a missing recipient fails with `Error::KeyNotFound` rather than silently
  encrypting to fewer keys.
- `copy`/`rename` re-encrypt to the destination's recipients. A rename
  within the same `.gpg-id` domain is an atomic file move; renaming an
  entry onto itself is a no-op; a failed cross-domain rename rolls the
  destination back.
- Generated passwords are drawn from `/dev/urandom` by rejection sampling
  (uniform, no modulo bias) using the same character sets as
  `pass generate` (`[:graph:]`, or `[:alnum:]` with `generate_alphanumeric`).

**Not implemented** (deliberately, for now): git integration (`pass git`),
extensions, and non-UTF-8 entry contents (`show` returns `String`).

## Security posture

- **Atomic writes.** Entries are written to a temp file (mode `0o600`) and
  renamed into place — an interrupted overwrite can never truncate or
  corrupt the existing entry. The store root is created `0o700`.
- **Path containment.** Entry names that would escape the store (`../`,
  absolute paths, dotfile components) are rejected with
  `Error::SneakyPath`, and so are reads/writes through symlinks planted
  inside the store tree that resolve outside it.
- **Secret hygiene.** Decrypted and generated intermediates are wiped from
  memory on drop (via [`zeroize`](https://crates.io/crates/zeroize)).
  Values *returned* to you are ordinary `String`s — their lifetime is your
  responsibility.
- **Honest errors.** An unreadable `.gpg-id` or a failing gpg-agent
  surfaces as an error instead of being misread as "not found" — failure
  modes that could otherwise route secrets to the wrong recipients.

This crate does not attempt to defend against an attacker with write access
to your store or a compromised GnuPG installation — the same trust model as
`pass` itself.

## Testing

```sh
cargo test
```

Tests run against real GnuPG: each test builds a throwaway `GNUPGHOME` with
batch-generated keys and a temporary store, the interop tests drive the
actual `pass` binary, and re-encryption tests assert actual recipient key
ids via `gpg --list-packets`. No mocks. Requires `gpg` and `pass` on `PATH`.

CI enforces `rustfmt`, `clippy -D warnings`, the test suite, a 99% line
coverage floor, and an MSRV (1.85) build.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
