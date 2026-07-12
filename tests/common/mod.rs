//! Test fixture: a throwaway GNUPGHOME with no-protection keys, plus a
//! temporary password store directory, so tests exercise the real `pass`
//! binary end to end.
#![allow(dead_code)] // shared by several test binaries; not all use every helper

use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub const TEST_KEY_ID: &str = "pass-sys@test.invalid";
pub const TEST_KEY_ID_2: &str = "pass-sys-b@test.invalid";

const KEY_PARAMS: &str = "\
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Pass Sys Test
Name-Email: pass-sys@test.invalid
Expire-Date: 0
%commit
";

const KEY_PARAMS_2: &str = "\
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Pass Sys Test B
Name-Email: pass-sys-b@test.invalid
Expire-Date: 0
%commit
";

pub struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    pub fn new() -> Self {
        // Preflight with an actionable message instead of a cryptic
        // "No such file or directory" from a later expect.
        assert!(
            Command::new("gpg").arg("--version").output().is_ok(),
            "`gpg` not found on PATH — install GnuPG to run these tests"
        );
        let dir = tempfile::tempdir().expect("create tempdir");
        let gnupghome = dir.path().join("gnupg");
        fs::create_dir(&gnupghome).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&gnupghome, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fixture = Fixture { dir };
        fixture.gen_key("keyparams", KEY_PARAMS);
        fixture
    }

    /// Generate the second test key (`TEST_KEY_ID_2`). Only tests that need
    /// multiple recipients pay for the extra keygen.
    pub fn gen_second_key(&self) {
        self.gen_key("keyparams2", KEY_PARAMS_2);
    }

    fn gen_key(&self, params_file: &str, params: &str) {
        let params_path = self.dir.path().join(params_file);
        fs::write(&params_path, params).unwrap();
        let out = Command::new("gpg")
            .env("GNUPGHOME", self.gnupghome())
            .args(["--batch", "--quiet", "--gen-key"])
            .arg(&params_path)
            .output()
            .expect("run gpg --gen-key");
        assert!(
            out.status.success(),
            "gpg --gen-key failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    pub fn gnupghome(&self) -> PathBuf {
        self.dir.path().join("gnupg")
    }

    pub fn store_dir(&self) -> PathBuf {
        self.dir.path().join("store")
    }

    /// The keyid of the encryption subkey for `email` in this fixture's
    /// keyring.
    pub fn encryption_keyid(&self, email: &str) -> String {
        let out = Command::new("gpg")
            .env("GNUPGHOME", self.gnupghome())
            .args(["--list-keys", "--with-colons", email])
            .output()
            .expect("run gpg --list-keys");
        assert!(out.status.success(), "gpg --list-keys failed for {email}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        stdout
            .lines()
            .filter_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                (fields.first() == Some(&"sub") && fields.get(11).is_some_and(|c| c.contains('e')))
                    .then(|| fields[4].to_owned())
            })
            .next()
            .unwrap_or_else(|| panic!("no encryption subkey found for {email}"))
    }

    /// The recipient keyids a stored entry is encrypted to, per
    /// `gpg --list-packets`.
    pub fn recipient_keyids(&self, name: &str) -> Vec<String> {
        let path = self.store_dir().join(format!("{name}.gpg"));
        let out = Command::new("gpg")
            .env("GNUPGHOME", self.gnupghome())
            .args(["--list-packets"])
            .arg(&path)
            .output()
            .expect("run gpg --list-packets");
        let stdout = String::from_utf8_lossy(&out.stdout);
        stdout
            .lines()
            .filter(|line| line.contains("pubkey enc packet"))
            .filter_map(|line| line.split("keyid ").nth(1).map(|id| id.trim().to_owned()))
            .collect()
    }

    /// Encrypt arbitrary bytes straight into the store with the gpg CLI,
    /// bypassing the crate, so tests can plant non-UTF-8 entries.
    pub fn encrypt_raw(&self, name: &str, plaintext: &[u8]) {
        use std::io::Write;
        use std::process::Stdio;
        let out_path = self.store_dir().join(format!("{name}.gpg"));
        let mut child = Command::new("gpg")
            .env("GNUPGHOME", self.gnupghome())
            .args([
                "--batch",
                "--yes",
                "--recipient",
                TEST_KEY_ID,
                "--encrypt",
                "--output",
            ])
            .arg(&out_path)
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn gpg --encrypt");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(plaintext)
            .expect("write gpg stdin");
        assert!(child.wait().expect("wait for gpg").success());
    }

    /// Run the real `pass` binary against this fixture's store, for
    /// interoperability tests. Returns stdout.
    pub fn pass_cli(&self, args: &[&str]) -> Result<String, String> {
        self.pass_cli_with_stdin(args, "")
    }

    pub fn pass_cli_with_stdin(&self, args: &[&str], stdin: &str) -> Result<String, String> {
        use std::io::Write;
        use std::process::Stdio;
        let mut child = Command::new("pass")
            .env("PASSWORD_STORE_DIR", self.store_dir())
            .env("GNUPGHOME", self.gnupghome())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn `pass` — install pass to run the interop tests");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .expect("write pass stdin");
        let out = child.wait_with_output().expect("wait for pass");
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }
}

impl Drop for Fixture {
    // Runs on normal completion and unwinding panics. Under panic="abort"
    // or SIGKILL nothing runs and the agent/tempdir leak — accepted for a
    // test fixture; the suite uses the default unwind panic strategy.
    fn drop(&mut self) {
        // Reap the gpg-agent daemon spawned for the throwaway GNUPGHOME.
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", self.gnupghome())
            .args(["--kill", "gpg-agent"])
            .output();
    }
}

/// Skip permission-bit tests when running as root (root ignores DAC, so the
/// induced errors never happen). Call at the top of such tests.
pub fn running_as_root() -> bool {
    // SAFETY: geteuid has no failure modes or preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// RAII guard that restores a path's permissions on drop, even when the
/// test's assertions panic mid-flight.
pub struct RestorePerms {
    path: PathBuf,
    mode: u32,
}

impl RestorePerms {
    pub fn new(path: impl Into<PathBuf>, restore_mode: u32) -> Self {
        RestorePerms {
            path: path.into(),
            mode: restore_mode,
        }
    }
}

impl Drop for RestorePerms {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode));
    }
}
