# pass-sys

Native Rust implementation of [`pass`](https://www.passwordstore.org/), the
standard unix password manager.

Rather than shelling out to the `pass` script, this crate implements the
password-store format directly — a directory tree of OpenPGP-encrypted `.gpg`
files with `.gpg-id` files naming the recipients — performing all cryptography
through libgpgme (GnuPG's C library) via the [`gpgme`](https://crates.io/crates/gpgme)
crate. Stores written by this crate are readable by `pass` and vice versa;
the test suite proves interoperability in both directions against the real
`pass` binary.

## Requirements

- libgpgme (Arch: `gpgme`, Debian/Ubuntu: `libgpgme-dev`, Fedora: `gpgme-devel`)
- GnuPG with a usable key for your store

The `pass` binary itself is **not** required at runtime — only for running the
interoperability tests.

## Usage

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

Semantics follow `pass` where it matters:

- Recipients come from the nearest `.gpg-id` at or above an entry, so
  per-subfolder key sets work. An unreadable `.gpg-id` is a hard error,
  never a silent fallback to the parent's keys.
- `copy`/`rename` re-encrypt to the destination's recipients. A rename
  within the same `.gpg-id` domain is an atomic file move; renaming an
  entry onto itself is a no-op.
- Entries are written atomically (temp file + rename, mode `0o600`), so an
  interrupted overwrite can't corrupt an existing entry. The store root is
  created with mode `0o700`.
- Entry names that would escape the store (`../`, absolute paths, dotfiles)
  are rejected with `Error::SneakyPath`, as are symlinks planted inside the
  store tree that point outside it.
- Generated passwords are drawn from `/dev/urandom` using the same character
  sets as `pass generate` (`[:graph:]`, or `[:alnum:]` with
  `generate_alphanumeric`).

Not implemented: git integration (`pass git`), extensions, and re-encryption
of existing entries on `init`.

## Testing

```sh
cargo test
```

Tests run against real GnuPG: each test builds a throwaway `GNUPGHOME` with a
batch-generated key and a temporary store, and the interop tests drive the
actual `pass` binary. No mocks. Requires `gpg` and `pass` on `PATH`.

## License

MIT OR Apache-2.0
