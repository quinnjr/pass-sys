//! Tests that mutate process-global environment variables. They live in
//! their own test binary (cargo runs test binaries sequentially, so no other
//! test process is running) and serialize against each other with a mutex,
//! because concurrent `setenv`/`getenv` is undefined behavior at the libc
//! level — the other binaries drive libgpgme, which reads the environment.

mod common;

use std::sync::Mutex;

use common::{Fixture, TEST_KEY_ID};
use pass_sys::PasswordStore;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn default_store_resolution() {
    let _guard = env_lock();
    let original_dir = std::env::var_os("PASSWORD_STORE_DIR");
    let original_home = std::env::var_os("HOME");

    unsafe { std::env::set_var("PASSWORD_STORE_DIR", "/custom/store") };
    assert_eq!(
        PasswordStore::new().store_dir(),
        std::path::Path::new("/custom/store")
    );

    unsafe { std::env::remove_var("PASSWORD_STORE_DIR") };
    unsafe { std::env::set_var("HOME", "/home/someone") };
    assert_eq!(
        PasswordStore::default().store_dir(),
        std::path::Path::new("/home/someone/.password-store")
    );

    match original_home {
        Some(home) => unsafe { std::env::set_var("HOME", home) },
        None => unsafe { std::env::remove_var("HOME") },
    }
    match original_dir {
        Some(dir) => unsafe { std::env::set_var("PASSWORD_STORE_DIR", dir) },
        None => unsafe { std::env::remove_var("PASSWORD_STORE_DIR") },
    }
}

#[test]
fn show_corrupt_entry_returns_gpg_error() {
    let _guard = env_lock();
    let f = Fixture::new();
    let s_init = PasswordStore::with_store_dir(f.store_dir()).with_gpg_home(f.gnupghome());
    s_init.init(&[TEST_KEY_ID]).unwrap();
    std::fs::write(
        f.store_dir().join("corrupt.gpg"),
        b"this is not openpgp data",
    )
    .unwrap();

    // Deliberately no with_gpg_home override: exercises the engine-default
    // path in context(). GNUPGHOME is pointed at the fixture so the test
    // never touches the developer's real keyring or agent.
    let original = std::env::var_os("GNUPGHOME");
    unsafe { std::env::set_var("GNUPGHOME", f.gnupghome()) };
    let err = PasswordStore::with_store_dir(f.store_dir())
        .show("corrupt")
        .unwrap_err();
    match original {
        Some(home) => unsafe { std::env::set_var("GNUPGHOME", home) },
        None => unsafe { std::env::remove_var("GNUPGHOME") },
    }

    assert!(
        matches!(err, pass_sys::Error::Gpg(_)),
        "expected Gpg, got: {err:?}"
    );
    assert!(err.to_string().starts_with("gpg error"));
    assert!(std::error::Error::source(&err).is_some());
}
