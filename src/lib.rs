//! Native Rust implementation of `pass`, the standard unix password manager.
//!
//! Rather than shelling out to the `pass` script, this crate implements the
//! password-store format directly — a directory tree of OpenPGP-encrypted
//! `.gpg` files with `.gpg-id` files naming the recipients — performing all
//! cryptography through libgpgme (GnuPG's C library) via the `gpgme` crate.
//!
//! Stores written by this crate are readable by `pass` and vice versa.
//!
//! This crate is **Unix-only**: it reads `/dev/urandom` for password
//! generation and targets GnuPG's Unix engine. Compilation fails on other
//! platforms.
//!
//! # Example
//!
//! ```no_run
//! use pass_sys::PasswordStore;
//!
//! # fn main() -> pass_sys::Result<()> {
//! // Your default store (~/.password-store or $PASSWORD_STORE_DIR):
//! let store = PasswordStore::new();
//!
//! store.insert("web/example.com", "hunter2\nusername: joseph\n")?;
//! let password = store.password("web/example.com")?; // "hunter2"
//! let everything = store.show("web/example.com")?;   // full contents
//!
//! for entry in store.list()? {
//!     println!("{entry}");
//! }
//! # Ok(())
//! # }
//! ```

#[cfg(not(unix))]
compile_error!("pass-sys only supports Unix: it requires /dev/urandom and GnuPG's Unix engine");

use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use zeroize::Zeroizing;

/// Errors returned by password store operations.
///
/// Error values are not comparable (`PartialEq` is intentionally not
/// implemented — the `Io`/`Gpg`/`Utf8` payloads don't support it); match on
/// variants with `matches!` instead.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A filesystem operation on the store failed.
    Io(std::io::Error),
    /// GPG encryption, decryption, or key lookup failed.
    Gpg(Box<dyn std::error::Error + Send + Sync>),
    /// A decrypted entry was not valid UTF-8.
    Utf8(std::str::Utf8Error),
    /// The named entry is not in the password store.
    NotFound(String),
    /// No `.gpg-id` was found for this location; the store (or subfolder)
    /// has not been initialized.
    NotInitialized(PathBuf),
    /// No key matched one of the GPG ids listed in `.gpg-id`.
    KeyNotFound(String),
    /// The entry name would resolve outside the password store.
    SneakyPath(String),
    /// `init` was called with no usable GPG ids.
    NoGpgIds,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "password store I/O error: {e}"),
            Error::Gpg(e) => write!(f, "gpg error: {e}"),
            Error::Utf8(e) => write!(f, "entry contents were not valid UTF-8: {e}"),
            Error::NotFound(name) => write!(f, "{name} is not in the password store"),
            Error::NotInitialized(dir) => {
                write!(
                    f,
                    "no .gpg-id found above {}: store not initialized",
                    dir.display()
                )
            }
            Error::KeyNotFound(id) => write!(f, "no GPG key found for id {id}"),
            Error::SneakyPath(name) => write!(f, "entry name {name} escapes the password store"),
            Error::NoGpgIds => write!(f, "no GPG ids given: a store needs at least one recipient"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Gpg(e) => Some(e.as_ref()),
            Error::Utf8(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Wrap a gpgme error without leaking the `gpgme` type into the public API.
fn gpg_err(e: gpgme::Error) -> Error {
    Error::Gpg(Box::new(e))
}

/// Parse a `.gpg-id` file's contents into its non-empty, trimmed id lines.
fn parse_gpg_ids(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

pub type Result<T> = std::result::Result<T, Error>;

/// A handle to a password store on disk.
#[derive(Debug, Clone)]
pub struct PasswordStore {
    store_dir: PathBuf,
    gpg_home: Option<PathBuf>,
}

impl PasswordStore {
    /// The default store: `$PASSWORD_STORE_DIR` if set, otherwise
    /// `~/.password-store`.
    pub fn new() -> Self {
        let fallback_home = PathBuf::from(".");
        let store_dir = std::env::var_os("PASSWORD_STORE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::home_dir()
                    .unwrap_or(fallback_home)
                    .join(".password-store")
            });
        Self::with_store_dir(store_dir)
    }

    /// A store rooted at `dir`.
    pub fn with_store_dir(dir: impl Into<PathBuf>) -> Self {
        PasswordStore {
            store_dir: dir.into(),
            gpg_home: None,
        }
    }

    /// Use a specific GnuPG home directory (keyrings, agent) instead of the
    /// engine default (`$GNUPGHOME` or `~/.gnupg`).
    pub fn with_gpg_home(mut self, dir: impl Into<PathBuf>) -> Self {
        self.gpg_home = Some(dir.into());
        self
    }

    /// The root directory of this store.
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// The configured GnuPG home directory, if one was set with
    /// [`with_gpg_home`](Self::with_gpg_home).
    pub fn gpg_home(&self) -> Option<&Path> {
        self.gpg_home.as_deref()
    }

    /// Initialize the store for the given GPG ids, creating the store
    /// directory (mode `0o700`) and writing `.gpg-id`.
    ///
    /// If the store already contains entries and the id set changes, every
    /// entry governed by the root `.gpg-id` (i.e. not inside a subfolder
    /// with its own non-empty `.gpg-id`) is re-encrypted to the new ids,
    /// like `pass init`. All new ids must resolve to keys before anything
    /// is modified. Entries are re-encrypted one at a time (each write
    /// atomic) and `.gpg-id` is written last, so an interrupted run is
    /// repaired by running `init` again with the same ids (provided a
    /// secret key for one of the new ids is available to decrypt the
    /// already-converted entries).
    pub fn init(&self, gpg_ids: &[&str]) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let new_ids: Vec<String> = gpg_ids.iter().map(|id| id.trim().to_owned()).collect();
        if new_ids.is_empty() || new_ids.iter().any(String::is_empty) {
            return Err(Error::NoGpgIds);
        }
        let old_ids = self.root_gpg_ids()?;
        fs::create_dir_all(&self.store_dir)?;
        fs::set_permissions(&self.store_dir, fs::Permissions::from_mode(0o700))?;

        if old_ids.as_deref() != Some(&new_ids[..]) {
            let entries = self.governed_entries()?;
            if !entries.is_empty() {
                let mut ctx = self.context()?;
                // Fail fast: resolve every new key before touching any entry.
                let keys = self.keys_for_ids(&mut ctx, &new_ids)?;
                for name in &entries {
                    let plaintext = self.decrypt_raw(&mut ctx, name)?;
                    let path = self.entry_path(name)?;
                    self.write_encrypted(&mut ctx, &keys, &plaintext, &path)?;
                }
            }
        }

        let mut contents = new_ids.join("\n");
        contents.push('\n');
        fs::write(self.store_dir.join(".gpg-id"), contents)?;
        Ok(())
    }

    /// The root `.gpg-id`'s ids, or `None` if absent or empty (matching
    /// `gpg_ids_for`'s treatment of empty files). Unreadable is a hard error.
    fn root_gpg_ids(&self) -> Result<Option<Vec<String>>> {
        match fs::read_to_string(self.store_dir.join(".gpg-id")) {
            Ok(contents) => {
                let ids = parse_gpg_ids(&contents);
                Ok((!ids.is_empty()).then_some(ids))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Entry names governed by the root `.gpg-id`: the whole tree minus
    /// subfolders that declare their own non-empty `.gpg-id` (separate
    /// domains, like `pass init` leaves alone). Returns empty when the
    /// store directory doesn't exist yet.
    fn governed_entries(&self) -> Result<Vec<String>> {
        fn walk(dir: &Path, prefix: &str, entries: &mut Vec<String>) -> Result<()> {
            for item in fs::read_dir(dir).map_err(Error::Io)? {
                let item = item.map_err(Error::Io)?;
                let file_name = item.file_name();
                let file_name = file_name.to_string_lossy();
                if file_name.starts_with('.') {
                    continue;
                }
                if item.file_type().map_err(Error::Io)?.is_dir() {
                    match fs::read_to_string(item.path().join(".gpg-id")) {
                        Ok(contents) if !parse_gpg_ids(&contents).is_empty() => continue,
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        // A present-but-unreadable .gpg-id must never be
                        // treated as absent (wrong-recipient hazard).
                        Err(e) => return Err(Error::Io(e)),
                    }
                    walk(&item.path(), &format!("{prefix}{file_name}/"), entries)?;
                } else if let Some(name) = file_name.strip_suffix(".gpg") {
                    entries.push(format!("{prefix}{name}"));
                }
            }
            Ok(())
        }
        let mut entries = Vec::new();
        if self.store_dir.is_dir() {
            walk(&self.store_dir, "", &mut entries)?;
        }
        entries.sort();
        Ok(entries)
    }

    /// Decrypt an entry and return its full contents.
    pub fn show(&self, name: &str) -> Result<String> {
        let mut ctx = self.context()?;
        self.show_with(&mut ctx, name)
    }

    /// Decrypt an entry and return only its first line, the password.
    pub fn password(&self, name: &str) -> Result<String> {
        let contents = Zeroizing::new(self.show(name)?);
        Ok(contents.lines().next().unwrap_or_default().to_owned())
    }

    /// Create or overwrite an entry, encrypting `contents` to the GPG ids
    /// governing its location (the nearest `.gpg-id` at or above it).
    ///
    /// The entry is written atomically (temp file + rename), so an
    /// interrupted overwrite cannot corrupt the existing entry.
    pub fn insert(&self, name: &str, contents: &str) -> Result<()> {
        let mut ctx = self.context()?;
        self.insert_with(&mut ctx, name, contents)
    }

    fn decrypt_raw(&self, ctx: &mut gpgme::Context, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.entry_path(name)?;
        let ciphertext = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound(name.to_owned()),
            _ => Error::Io(e),
        })?;
        let mut plaintext = Zeroizing::new(Vec::new());
        ctx.decrypt(&ciphertext, &mut *plaintext).map_err(gpg_err)?;
        Ok(plaintext)
    }

    fn show_with(&self, ctx: &mut gpgme::Context, name: &str) -> Result<String> {
        let plaintext = self.decrypt_raw(ctx, name)?;
        let text = std::str::from_utf8(&plaintext).map_err(Error::Utf8)?;
        Ok(text.to_owned())
    }

    fn keys_for_ids(&self, ctx: &mut gpgme::Context, ids: &[String]) -> Result<Vec<gpgme::Key>> {
        // Looked up per id, not batched via find_keys: a batched lookup
        // cannot attribute matches to patterns, so a missing recipient
        // would silently encrypt to fewer keys than .gpg-id demands.
        let mut keys = Vec::with_capacity(ids.len());
        for id in ids {
            let key = ctx.get_key(id.as_str()).map_err(|e| {
                // gpgme reports an absent key as EOF; anything else (agent
                // down, corrupt keyring) is a real gpg failure.
                if e.code() == gpgme::Error::EOF.code() {
                    Error::KeyNotFound(id.clone())
                } else {
                    gpg_err(e)
                }
            })?;
            keys.push(key);
        }
        Ok(keys)
    }

    fn write_encrypted(
        &self,
        ctx: &mut gpgme::Context,
        keys: &[gpgme::Key],
        plaintext: &[u8],
        path: &Path,
    ) -> Result<()> {
        let parent = path.parent().expect("entry path always has a parent");
        let mut ciphertext = Vec::new();
        ctx.encrypt(keys, plaintext, &mut ciphertext)
            .map_err(gpg_err)?;
        fs::create_dir_all(parent)?;
        // Atomic replace: write a temp file (created 0o600) in the same
        // directory, then rename over the target, so an interrupted write
        // can never truncate an existing entry.
        let tmp = tempfile::NamedTempFile::new_in(parent)?;
        fs::write(tmp.path(), &ciphertext)?;
        tmp.persist(path).map_err(|e| Error::Io(e.error))?;
        Ok(())
    }

    fn insert_with(&self, ctx: &mut gpgme::Context, name: &str, contents: &str) -> Result<()> {
        let path = self.entry_path(name)?;
        let parent = path.parent().expect("entry path always has a parent");
        let ids = self.gpg_ids_for(parent)?;
        let keys = self.keys_for_ids(ctx, &ids)?;
        self.write_encrypted(ctx, &keys, contents.as_bytes(), &path)
    }

    /// Delete an entry from the store.
    pub fn remove(&self, name: &str) -> Result<()> {
        let path = self.entry_path(name)?;
        fs::remove_file(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound(name.to_owned()),
            _ => Error::Io(e),
        })
    }

    /// Generate a random password of `length` printable ASCII characters
    /// (like `pass generate`), store it under `name`, and return it.
    ///
    /// Randomness is read from `/dev/urandom`.
    pub fn generate(&self, name: &str, length: usize) -> Result<String> {
        self.generate_from(name, length, |c| c.is_ascii_graphic())
    }

    /// Generate a random password of `length` alphanumeric characters
    /// (like `pass generate --no-symbols`), store it under `name`, and
    /// return it.
    ///
    /// Randomness is read from `/dev/urandom`.
    pub fn generate_alphanumeric(&self, name: &str, length: usize) -> Result<String> {
        self.generate_from(name, length, |c| c.is_ascii_alphanumeric())
    }

    fn generate_from(
        &self,
        name: &str,
        length: usize,
        charset: impl Fn(char) -> bool,
    ) -> Result<String> {
        use std::io::Read;
        let mut urandom = fs::File::open("/dev/urandom")?;
        let mut password = String::with_capacity(length);
        let mut buf = Zeroizing::new([0u8; 64]);
        while password.len() < length {
            urandom.read_exact(&mut buf[..])?;
            password.extend(
                buf.iter()
                    .map(|&b| b as char)
                    .filter(|&c| charset(c))
                    .take(length - password.len()),
            );
        }
        let contents = Zeroizing::new(format!("{password}\n"));
        self.insert(name, &contents)?;
        Ok(password)
    }

    /// All entry names in the store, sorted, recursing into subfolders.
    pub fn list(&self) -> Result<Vec<String>> {
        fn walk(dir: &Path, prefix: &str, entries: &mut Vec<String>) -> std::io::Result<()> {
            for item in fs::read_dir(dir)? {
                let item = item?;
                let file_name = item.file_name();
                let file_name = file_name.to_string_lossy();
                if file_name.starts_with('.') {
                    continue;
                }
                if item.file_type()?.is_dir() {
                    walk(&item.path(), &format!("{prefix}{file_name}/"), entries)?;
                } else if let Some(name) = file_name.strip_suffix(".gpg") {
                    entries.push(format!("{prefix}{name}"));
                }
            }
            Ok(())
        }
        let mut entries = Vec::new();
        walk(&self.store_dir, "", &mut entries)?;
        entries.sort();
        Ok(entries)
    }

    /// Copy an entry, re-encrypting to the GPG ids governing the
    /// destination (like `pass cp`). Copying an entry onto itself is a
    /// no-op.
    pub fn copy(&self, from: &str, to: &str) -> Result<()> {
        if self.entry_path(from)? == self.entry_path(to)? {
            return Ok(());
        }
        let mut ctx = self.context()?;
        let contents = Zeroizing::new(self.show_with(&mut ctx, from)?);
        self.insert_with(&mut ctx, to, &contents)
    }

    /// Move an entry (like `pass mv`). Renaming an entry onto itself is a
    /// no-op. When source and destination are governed by the same
    /// `.gpg-id`, the file is moved atomically without re-encryption;
    /// otherwise the entry is re-encrypted to the destination's ids.
    ///
    /// In the re-encrypting case, if deleting the source fails the copy at
    /// the destination is rolled back (unless the destination already
    /// existed and was overwritten, in which case both entries remain and
    /// the error is returned).
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        let from_path = self.entry_path(from)?;
        let to_path = self.entry_path(to)?;
        if from_path == to_path {
            return Ok(());
        }
        if !from_path.is_file() {
            return Err(Error::NotFound(from.to_owned()));
        }
        let from_parent = from_path.parent().expect("entry path always has a parent");
        let to_parent = to_path.parent().expect("entry path always has a parent");
        if self.gpg_ids_for(from_parent)? == self.gpg_ids_for(to_parent)? {
            fs::create_dir_all(to_parent)?;
            fs::rename(&from_path, &to_path)?;
            return Ok(());
        }
        let to_existed = to_path.is_file();
        self.copy(from, to)?;
        if let Err(e) = self.remove(from) {
            if !to_existed {
                let _ = fs::remove_file(&to_path);
            }
            return Err(e);
        }
        Ok(())
    }

    /// Whether an entry with this name exists in the store.
    ///
    /// Returns `false` both for invalid names (see
    /// [`Error::SneakyPath`]) and for entries that exist but cannot be
    /// inspected (e.g. an untraversable parent directory). Callers that
    /// need to distinguish those cases should use [`show`](Self::show),
    /// which returns a typed error.
    pub fn exists(&self, name: &str) -> bool {
        self.entry_path(name).is_ok_and(|p| p.is_file())
    }

    fn context(&self) -> Result<gpgme::Context> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp).map_err(gpg_err)?;
        if let Some(home) = &self.gpg_home {
            ctx.set_engine_home_dir(home.to_string_lossy().as_ref())
                .map_err(gpg_err)?;
        }
        Ok(ctx)
    }

    /// Resolve an entry name to its `.gpg` path, rejecting names that would
    /// escape the store either textually (`..`, absolute, dotfiles) or via
    /// a symlink planted inside the store tree.
    fn entry_path(&self, name: &str) -> Result<PathBuf> {
        let is_sneaky = |c: Component<'_>| match c {
            Component::Normal(part) => part.to_string_lossy().starts_with('.'),
            _ => true, // ParentDir, RootDir, CurDir, Prefix
        };
        if name.is_empty() || Path::new(name).components().any(is_sneaky) {
            return Err(Error::SneakyPath(name.to_owned()));
        }
        let path = self.store_dir.join(format!("{name}.gpg"));

        // Symlink guard: resolve the deepest existing ancestor of the entry
        // and require it to still be inside the (resolved) store root.
        if let Ok(store_real) = self.store_dir.canonicalize() {
            let mut ancestor = path.parent().expect("entry path always has a parent");
            while !ancestor.exists() && ancestor != self.store_dir {
                ancestor = ancestor
                    .parent()
                    .expect("store_dir is always an ancestor of the entry");
            }
            let real = ancestor.canonicalize()?;
            if !real.starts_with(&store_real) {
                return Err(Error::SneakyPath(name.to_owned()));
            }
            if path.is_symlink() && !path.canonicalize()?.starts_with(&store_real) {
                return Err(Error::SneakyPath(name.to_owned()));
            }
        }
        Ok(path)
    }

    /// The GPG ids governing `dir`: the nearest `.gpg-id` file at or above
    /// it, up to the store root.
    fn gpg_ids_for(&self, dir: &Path) -> Result<Vec<String>> {
        let mut current = dir;
        loop {
            let gpg_id = current.join(".gpg-id");
            match fs::read_to_string(&gpg_id) {
                Ok(contents) => {
                    let ids = parse_gpg_ids(&contents);
                    if !ids.is_empty() {
                        return Ok(ids);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                // A present-but-unreadable .gpg-id must never be treated as
                // absent: falling back to a parent would encrypt to the
                // wrong recipient set.
                Err(e) => return Err(Error::Io(e)),
            }
            if current == self.store_dir {
                return Err(Error::NotInitialized(dir.to_owned()));
            }
            current = current
                .parent()
                .expect("store_dir is always an ancestor of dir");
        }
    }
}

impl Default for PasswordStore {
    fn default() -> Self {
        Self::new()
    }
}
