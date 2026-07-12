mod common;

use common::{Fixture, RestorePerms, TEST_KEY_ID, TEST_KEY_ID_2, running_as_root};
use pass_sys::PasswordStore;

fn store(f: &Fixture) -> PasswordStore {
    PasswordStore::with_store_dir(f.store_dir()).with_gpg_home(f.gnupghome())
}

/// A store already initialized for the standard test key — the setup shared
/// by most tests. Tests with custom init keep using `store()`.
fn initialized(f: &Fixture) -> PasswordStore {
    let s = store(f);
    s.init(&[TEST_KEY_ID]).unwrap();
    s
}

#[test]
fn insert_then_show_roundtrips_contents() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("web/example.com", "hunter2\nusername: joseph\n")
        .expect("pass insert");
    let shown = s.show("web/example.com").expect("pass show");
    assert_eq!(shown, "hunter2\nusername: joseph\n");
}

#[test]
fn password_returns_first_line_only() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("web/example.com", "hunter2\nusername: joseph\n")
        .unwrap();
    assert_eq!(s.password("web/example.com").unwrap(), "hunter2");
}

#[test]
fn insert_overwrites_existing_entry() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("entry", "old\n").unwrap();
    s.insert("entry", "new\n")
        .expect("insert over existing entry");
    assert_eq!(s.show("entry").unwrap(), "new\n");
}

#[test]
fn show_missing_entry_returns_not_found() {
    let f = Fixture::new();
    let s = initialized(&f);
    let err = s.show("no/such/entry").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::NotFound(ref name) if name == "no/such/entry"),
        "expected NotFound, got: {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "no/such/entry is not in the password store"
    );
}

#[test]
fn exists_reflects_entry_presence() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("present", "secret\n").unwrap();
    assert!(s.exists("present"));
    assert!(!s.exists("absent"));
}

#[test]
fn remove_deletes_entry() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("doomed", "secret\n").unwrap();
    s.remove("doomed").expect("remove");
    assert!(!s.exists("doomed"));
}

#[test]
fn remove_missing_entry_returns_not_found() {
    let f = Fixture::new();
    let s = initialized(&f);
    let err = s.remove("ghost").unwrap_err();
    assert!(matches!(err, pass_sys::Error::NotFound(ref n) if n == "ghost"));
}

#[test]
fn generate_creates_entry_with_password_of_requested_length() {
    let f = Fixture::new();
    let s = initialized(&f);
    let password = s.generate("generated", 24).expect("generate");
    assert_eq!(password.chars().count(), 24);
    assert!(password.chars().all(|c| c.is_ascii_graphic()));
    assert_eq!(s.password("generated").unwrap(), password);
}

#[test]
fn generate_alphanumeric_uses_no_symbols() {
    let f = Fixture::new();
    let s = initialized(&f);
    let password = s.generate_alphanumeric("generated", 32).expect("generate");
    assert_eq!(password.chars().count(), 32);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn generate_length_zero_creates_empty_password() {
    let f = Fixture::new();
    let s = initialized(&f);
    let password = s.generate("empty", 0).expect("generate");
    assert_eq!(password, "");
    assert_eq!(s.password("empty").unwrap(), "");
}

#[test]
fn list_returns_sorted_entry_names_recursively() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("zeta", "1\n").unwrap();
    s.insert("web/example.com", "2\n").unwrap();
    s.insert("web/nested/deep", "3\n").unwrap();
    let entries = s.list().expect("list");
    assert_eq!(entries, vec!["web/example.com", "web/nested/deep", "zeta"]);
}

#[test]
fn list_on_empty_store_returns_empty() {
    let f = Fixture::new();
    let s = initialized(&f);
    assert_eq!(s.list().unwrap(), Vec::<String>::new());
}

#[test]
fn list_on_missing_store_dir_is_io_error() {
    let f = Fixture::new();
    let s = store(&f); // store dir never created
    let err = s.list().unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::Io(_)),
        "expected Io, got: {err:?}"
    );
}

#[test]
fn copy_duplicates_entry() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("original", "secret\n").unwrap();
    s.copy("original", "duplicate").expect("copy");
    assert_eq!(s.show("original").unwrap(), "secret\n");
    assert_eq!(s.show("duplicate").unwrap(), "secret\n");
}

#[test]
fn copy_to_same_name_is_noop() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("entry", "secret\n").unwrap();
    s.copy("entry", "entry").expect("copy onto itself");
    assert_eq!(s.show("entry").unwrap(), "secret\n");
}

#[test]
fn rename_moves_entry() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("old/name", "secret\n").unwrap();
    s.rename("old/name", "new/name").expect("rename");
    assert!(!s.exists("old/name"));
    assert_eq!(s.show("new/name").unwrap(), "secret\n");
}

#[test]
fn rename_to_same_name_preserves_entry() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("entry", "secret\n").unwrap();
    s.rename("entry", "entry").expect("rename onto itself");
    assert_eq!(s.show("entry").unwrap(), "secret\n");
}

#[test]
fn rename_missing_entry_returns_not_found() {
    let f = Fixture::new();
    let s = initialized(&f);
    let err = s.rename("ghost", "elsewhere").unwrap_err();
    assert!(matches!(err, pass_sys::Error::NotFound(ref n) if n == "ghost"));
}

#[test]
fn multi_recipient_store_encrypts_to_all_ids() {
    let f = Fixture::new();
    f.gen_second_key();
    let s = store(&f);
    s.init(&[TEST_KEY_ID, TEST_KEY_ID_2]).unwrap();
    s.insert("shared", "secret\n").unwrap();
    let recipients = f.recipient_keyids("shared");
    assert!(recipients.contains(&f.encryption_keyid(TEST_KEY_ID)));
    assert!(recipients.contains(&f.encryption_keyid(TEST_KEY_ID_2)));
}

#[test]
fn insert_with_one_missing_recipient_fails() {
    let f = Fixture::new();
    let s = store(&f);
    s.init(&[TEST_KEY_ID, "nobody@pass-sys.test.invalid"])
        .unwrap();
    let err = s.insert("entry", "secret\n").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::KeyNotFound(ref id) if id == "nobody@pass-sys.test.invalid"),
        "expected KeyNotFound, got: {err:?}"
    );
    assert!(!s.exists("entry"), "nothing must be written on failure");
}

#[test]
fn nested_gpg_id_override_governs_subfolder() {
    let f = Fixture::new();
    f.gen_second_key();
    let s = initialized(&f);
    std::fs::create_dir_all(f.store_dir().join("sub")).unwrap();
    std::fs::write(
        f.store_dir().join("sub/.gpg-id"),
        format!("{TEST_KEY_ID_2}\n"),
    )
    .unwrap();
    s.insert("sub/entry", "secret\n").unwrap();
    let recipients = f.recipient_keyids("sub/entry");
    assert_eq!(recipients, vec![f.encryption_keyid(TEST_KEY_ID_2)]);
}

#[test]
fn copy_reencrypts_to_destination_recipients() {
    let f = Fixture::new();
    f.gen_second_key();
    let s = initialized(&f);
    std::fs::create_dir_all(f.store_dir().join("sub")).unwrap();
    std::fs::write(
        f.store_dir().join("sub/.gpg-id"),
        format!("{TEST_KEY_ID_2}\n"),
    )
    .unwrap();
    s.insert("root-entry", "secret\n").unwrap();
    s.copy("root-entry", "sub/entry").expect("copy");
    assert_eq!(
        f.recipient_keyids("root-entry"),
        vec![f.encryption_keyid(TEST_KEY_ID)]
    );
    assert_eq!(
        f.recipient_keyids("sub/entry"),
        vec![f.encryption_keyid(TEST_KEY_ID_2)]
    );
    assert_eq!(s.show("sub/entry").unwrap(), "secret\n");
}

#[test]
fn rename_across_gpg_id_domains_reencrypts() {
    let f = Fixture::new();
    f.gen_second_key();
    let s = initialized(&f);
    std::fs::create_dir_all(f.store_dir().join("sub")).unwrap();
    std::fs::write(
        f.store_dir().join("sub/.gpg-id"),
        format!("{TEST_KEY_ID_2}\n"),
    )
    .unwrap();
    s.insert("root-entry", "secret\n").unwrap();
    s.rename("root-entry", "sub/entry").expect("rename");
    assert!(!s.exists("root-entry"));
    assert_eq!(
        f.recipient_keyids("sub/entry"),
        vec![f.encryption_keyid(TEST_KEY_ID_2)]
    );
    assert_eq!(s.show("sub/entry").unwrap(), "secret\n");
}

#[test]
fn rename_rolls_back_destination_when_source_removal_fails() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        eprintln!("skipping: permission bits are ignored under root");
        return;
    }
    let f = Fixture::new();
    f.gen_second_key();
    let s = initialized(&f);
    std::fs::create_dir_all(f.store_dir().join("sub")).unwrap();
    std::fs::write(
        f.store_dir().join("sub/.gpg-id"),
        format!("{TEST_KEY_ID_2}\n"),
    )
    .unwrap();
    s.insert("pinned", "secret\n").unwrap();
    // Read-only store root: copy can read the source and write into sub/,
    // but deleting the source must fail.
    let _restore = RestorePerms::new(f.store_dir(), 0o700);
    std::fs::set_permissions(f.store_dir(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let err = s.rename("pinned", "sub/entry").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::Io(_)),
        "expected Io, got: {err:?}"
    );
    assert!(s.exists("pinned"), "source must survive a failed rename");
    assert!(
        !s.exists("sub/entry"),
        "destination must be rolled back after a failed rename"
    );
}

#[test]
fn unicode_entry_names_roundtrip() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("café/naïve", "sécrète\n").unwrap();
    assert_eq!(s.show("café/naïve").unwrap(), "sécrète\n");
    assert_eq!(s.list().unwrap(), vec!["café/naïve"]);
}

#[test]
fn sneaky_entry_names_are_rejected() {
    let f = Fixture::new();
    let s = initialized(&f);
    for name in [
        "../outside",
        "a/../../outside",
        "/etc/passwd",
        ".gpg-id",
        "",
    ] {
        let err = s.show(name).unwrap_err();
        assert!(
            matches!(err, pass_sys::Error::SneakyPath(_)),
            "expected SneakyPath for {name:?}, got: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("entry name {name} escapes the password store")
        );
    }
}

#[test]
fn symlink_planted_in_store_is_rejected() {
    let f = Fixture::new();
    let s = initialized(&f);
    let outside = f.store_dir().parent().unwrap().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, f.store_dir().join("web")).unwrap();
    let err = s.insert("web/entry", "secret\n").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::SneakyPath(_)),
        "expected SneakyPath, got: {err:?}"
    );
    assert!(
        std::fs::read_dir(&outside).unwrap().next().is_none(),
        "nothing may be written outside the store"
    );
}

#[test]
fn ambiguous_gpg_id_returns_gpg_error() {
    let f = Fixture::new();
    f.gen_second_key();
    let s = store(&f);
    // "pass-sys" is a substring of both test key uids, so get_key fails
    // with an ambiguous-name error — an operational gpg failure, which
    // must not be misreported as KeyNotFound.
    s.init(&["pass-sys"]).unwrap();
    let err = s.insert("entry", "secret\n").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::Gpg(_)),
        "expected Gpg, got: {err:?}"
    );
}

#[test]
fn symlinked_entry_file_is_rejected() {
    let f = Fixture::new();
    let s = initialized(&f);
    let outside = f.store_dir().parent().unwrap().join("outside.gpg");
    std::fs::write(&outside, b"outside data").unwrap();
    std::os::unix::fs::symlink(&outside, f.store_dir().join("leak.gpg")).unwrap();
    let err = s.show("leak").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::SneakyPath(_)),
        "expected SneakyPath, got: {err:?}"
    );
}

#[test]
fn exists_is_false_when_store_dir_is_missing() {
    let f = Fixture::new();
    let s = store(&f); // store dir never created
    assert!(!s.exists("anything"));
}

#[test]
fn entries_written_by_this_crate_are_readable_by_pass() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("interop", "hunter2\nextra line\n").unwrap();
    let shown = f.pass_cli(&["show", "interop"]).expect("pass show");
    assert_eq!(shown, "hunter2\nextra line\n");
}

#[test]
fn entries_written_by_pass_are_readable_by_this_crate() {
    let f = Fixture::new();
    let s = initialized(&f);
    f.pass_cli_with_stdin(
        &["insert", "--multiline", "interop"],
        "hunter2\nextra line\n",
    )
    .expect("pass insert");
    assert_eq!(s.show("interop").unwrap(), "hunter2\nextra line\n");
}

#[test]
fn password_of_empty_entry_is_empty() {
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("empty", "").unwrap();
    assert_eq!(s.password("empty").unwrap(), "");
}

#[test]
fn insert_without_init_returns_not_initialized() {
    let f = Fixture::new();
    let s = store(&f);
    std::fs::create_dir_all(f.store_dir()).unwrap();
    let err = s.insert("entry", "secret\n").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::NotInitialized(_)),
        "expected NotInitialized, got: {err:?}"
    );
    assert!(err.to_string().contains("store not initialized"));
    assert!(std::error::Error::source(&err).is_none());
}

#[test]
fn insert_with_unknown_gpg_id_returns_key_not_found() {
    let f = Fixture::new();
    let s = store(&f);
    s.init(&["nobody@pass-sys.test.invalid"]).unwrap();
    let err = s.insert("entry", "secret\n").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::KeyNotFound(ref id) if id == "nobody@pass-sys.test.invalid"),
        "expected KeyNotFound, got: {err:?}"
    );
    assert!(err.to_string().contains("no GPG key found"));
}

#[test]
fn empty_gpg_id_in_subfolder_falls_back_to_parent() {
    let f = Fixture::new();
    let s = initialized(&f);
    std::fs::create_dir_all(f.store_dir().join("sub")).unwrap();
    std::fs::write(f.store_dir().join("sub/.gpg-id"), "\n").unwrap();
    s.insert("sub/entry", "secret\n")
        .expect("fall back to root .gpg-id");
    assert_eq!(s.show("sub/entry").unwrap(), "secret\n");
}

#[test]
fn unreadable_gpg_id_returns_io_error() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        eprintln!("skipping: permission bits are ignored under root");
        return;
    }
    let f = Fixture::new();
    let s = initialized(&f);
    let sub_gpg_id = f.store_dir().join("sub/.gpg-id");
    std::fs::create_dir_all(f.store_dir().join("sub")).unwrap();
    std::fs::write(&sub_gpg_id, format!("{TEST_KEY_ID}\n")).unwrap();
    let _restore = RestorePerms::new(&sub_gpg_id, 0o600);
    std::fs::set_permissions(&sub_gpg_id, std::fs::Permissions::from_mode(0o000)).unwrap();
    // An unreadable .gpg-id must be a hard error, not a silent fallback to
    // the parent's (different) recipient set.
    let err = s.insert("sub/entry", "secret\n").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::Io(_)),
        "expected Io, got: {err:?}"
    );
}

#[test]
fn show_non_utf8_entry_returns_utf8_error() {
    let f = Fixture::new();
    let s = initialized(&f);
    f.encrypt_raw("binary", &[0xff, 0xfe, 0x00, 0x80]);
    let err = s.show("binary").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::Utf8(_)),
        "expected Utf8, got: {err:?}"
    );
    assert!(err.to_string().contains("not valid UTF-8"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn show_unreadable_entry_returns_io_error() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        eprintln!("skipping: permission bits are ignored under root");
        return;
    }
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("locked", "secret\n").unwrap();
    let path = f.store_dir().join("locked.gpg");
    let _restore = RestorePerms::new(&path, 0o600);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    let err = s.show("locked").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::Io(_)),
        "expected Io, got: {err:?}"
    );
    assert!(err.to_string().contains("I/O error"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn remove_from_readonly_dir_returns_io_error() {
    use std::os::unix::fs::PermissionsExt;
    if running_as_root() {
        eprintln!("skipping: permission bits are ignored under root");
        return;
    }
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("pinned", "secret\n").unwrap();
    let _restore = RestorePerms::new(f.store_dir(), 0o700);
    std::fs::set_permissions(f.store_dir(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let err = s.remove("pinned").unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::Io(_)),
        "expected Io, got: {err:?}"
    );
}

#[test]
fn init_at_impossible_path_returns_io_error() {
    let s = PasswordStore::with_store_dir("/dev/null/store");
    let err = s.init(&[TEST_KEY_ID]).unwrap_err();
    assert!(
        matches!(err, pass_sys::Error::Io(_)),
        "expected Io, got: {err:?}"
    );
}

#[test]
fn init_creates_store_with_gpg_id() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    store(&f).init(&[TEST_KEY_ID]).expect("pass init");
    let gpg_id = std::fs::read_to_string(f.store_dir().join(".gpg-id")).unwrap();
    assert_eq!(gpg_id.trim(), TEST_KEY_ID);
    let mode = std::fs::metadata(f.store_dir())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "store dir must be private");
}

#[test]
fn gpg_home_getter_reflects_configuration() {
    let f = Fixture::new();
    assert_eq!(store(&f).gpg_home(), Some(f.gnupghome().as_path()));
    assert_eq!(
        PasswordStore::with_store_dir(f.store_dir()).gpg_home(),
        None
    );
}

#[test]
fn doc_example_flow_works_end_to_end() {
    // The crate-level doctest is no_run (it targets the user's real store);
    // this mirrors the same sequence against the fixture.
    let f = Fixture::new();
    let s = initialized(&f);
    s.insert("web/example.com", "hunter2\nusername: joseph\n")
        .unwrap();
    assert_eq!(s.password("web/example.com").unwrap(), "hunter2");
    assert_eq!(
        s.show("web/example.com").unwrap(),
        "hunter2\nusername: joseph\n"
    );
    assert_eq!(s.list().unwrap(), vec!["web/example.com"]);
}
