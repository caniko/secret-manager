//! age decryption with identity fallback.
//!
//! [`decrypt_with_identities`] passes every candidate identity to one
//! `rage --decrypt` invocation. stderr / stdin stay on the terminal so
//! hardware-key PIN/touch prompts work; only stdout (the plaintext) is
//! captured. A single trailing newline is stripped because agenix payloads are
//! commonly newline-terminated, while downstream secret stores expect the bare
//! value.

use anyhow::{Result, anyhow, bail};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix_manager_core::ui;

/// Decrypt with all identities passed to one `rage --decrypt` invocation.
/// Returns the plaintext with one trailing newline stripped.
pub fn decrypt_with_identities(secret: &Path, identities: &[PathBuf]) -> Result<String> {
    if identities.is_empty() {
        bail!("no identities attempted");
    }

    ui::step(format!(
        "decrypting {} with {}",
        secret.display(),
        describe_identities(identities)
    ));
    let out = Command::new("rage")
        .args(rage_decrypt_args(secret, identities))
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| anyhow!("failed to spawn rage: {e}"))?;
    if !out.status.success() {
        bail!(
            "rage --decrypt with identities {} exited with {}. Check that the matching hardware key is present and touch it when prompted.",
            describe_identities(identities),
            out.status
        );
    }

    let mut value = String::from_utf8(out.stdout)
        .map_err(|_| anyhow!("decrypted payload is not valid UTF-8"))?;
    if value.ends_with('\n') {
        value.pop();
    }
    if value.is_empty() {
        bail!("decrypted payload is empty");
    }
    Ok(value)
}

fn rage_decrypt_args(secret: &Path, identities: &[PathBuf]) -> Vec<OsString> {
    let mut args = Vec::with_capacity(1 + identities.len() * 2 + 1);
    args.push(OsString::from("--decrypt"));
    for identity in identities {
        args.push(OsString::from("--identity"));
        args.push(identity.as_os_str().to_owned());
    }
    args.push(secret.as_os_str().to_owned());
    args
}

fn describe_identities(identities: &[PathBuf]) -> String {
    identities
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::process::Command;

    struct Fixture {
        _dir: tempfile::TempDir,
        pub_key: PathBuf,
        identity: PathBuf,
    }

    fn setup_fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();

        let key_path = dir.path().join("key.txt");
        let pub_path = dir.path().join("key.pub");

        let out = Command::new("rage-keygen")
            .arg("-o")
            .arg(&key_path)
            .output()
            .expect("rage-keygen must be installed");
        assert!(out.status.success(), "rage-keygen failed: {out:?}");

        let key_data = fs::read_to_string(&key_path).unwrap();
        let pub_line = key_data
            .lines()
            .find_map(|l| l.strip_prefix("# public key: "))
            .expect("public key line in rage-keygen output");
        fs::write(&pub_path, format!("{pub_line}\n")).unwrap();

        Fixture {
            _dir: dir,
            identity: key_path,
            pub_key: pub_path,
        }
    }

    fn encrypt(public_key: &Path, plaintext: &str, dir: &tempfile::TempDir) -> PathBuf {
        let encrypted = dir.path().join("secret.age");
        let recipient = fs::read_to_string(public_key).unwrap().trim().to_string();

        let mut child = Command::new("rage")
            .arg("--encrypt")
            .arg("-r")
            .arg(&recipient)
            .arg("-o")
            .arg(&encrypted)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("rage must be installed");
        {
            let stdin = child.stdin.as_mut().unwrap();
            stdin.write_all(plaintext.as_bytes()).unwrap();
        }
        child.wait().unwrap();
        assert!(encrypted.is_file(), "encrypted file should exist");
        encrypted
    }

    #[test]
    fn decrypts_with_software_identity() {
        let f = setup_fixture();
        let dir = tempfile::tempdir().unwrap();
        let encrypted = encrypt(&f.pub_key, "hello world\n", &dir);

        let result = decrypt_with_identities(&encrypted, &[f.identity]).unwrap();
        assert_eq!(result, "hello world");
    }

    #[test]
    fn builds_single_rage_command_with_multiple_identities() {
        let secret = PathBuf::from("secret.age");
        let first = PathBuf::from("age/master-a-identity.pub");
        let second = PathBuf::from("age/master_b_identity.pub");

        let args = rage_decrypt_args(&secret, &[first.clone(), second.clone()]);

        assert_eq!(
            args,
            vec![
                OsString::from("--decrypt"),
                OsString::from("--identity"),
                first.into_os_string(),
                OsString::from("--identity"),
                second.into_os_string(),
                secret.into_os_string(),
            ]
        );
    }

    #[test]
    fn decrypts_with_second_identity_in_single_rage_invocation() {
        let wrong = setup_fixture();
        let right = setup_fixture();
        let dir = tempfile::tempdir().unwrap();
        let encrypted = encrypt(&right.pub_key, "matched second\n", &dir);

        let result =
            decrypt_with_identities(&encrypted, &[wrong.identity, right.identity]).unwrap();

        assert_eq!(result, "matched second");
    }

    #[test]
    fn strips_trailing_newline() {
        let f = setup_fixture();
        let dir = tempfile::tempdir().unwrap();
        let encrypted = encrypt(&f.pub_key, "trailing newline\n", &dir);

        let result = decrypt_with_identities(&encrypted, &[f.identity]).unwrap();
        assert_eq!(result, "trailing newline");
        assert!(!result.ends_with('\n'));
    }

    #[test]
    fn preserves_content_without_trailing_newline() {
        let f = setup_fixture();
        let dir = tempfile::tempdir().unwrap();
        let encrypted = encrypt(&f.pub_key, "no newline", &dir);

        let result = decrypt_with_identities(&encrypted, &[f.identity]).unwrap();
        assert_eq!(result, "no newline");
    }

    #[test]
    fn errors_on_wrong_identity() {
        let f = setup_fixture();
        let dir = tempfile::tempdir().unwrap();
        let fake_secret = dir.path().join("fake.age");
        fs::write(&fake_secret, "garbage").unwrap();

        let result = decrypt_with_identities(&fake_secret, &[f.identity]);
        assert!(result.is_err());
    }
}
