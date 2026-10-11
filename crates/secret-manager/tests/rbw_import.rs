use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

const ID: &str = "12345678-1234-1234-1234-123456789abc";
const ITEM: &str = r#"{"id":"12345678-1234-1234-1234-123456789abc","data":{"username":"fixture-user","password":"fixture-password","totp":"GEZDGNBVGY3TQOJQ"},"fields":[],"history":[{"password":"old-secret"}]}"#;

fn executable(path: &Path, text: &str) {
    fs::write(path, format!("#!/bin/sh\n{text}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn rbw_import_fails_closed_before_vault_when_protection_is_unavailable() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let called = root.path().join("vault-opened");
    executable(
        &bin.join("rbw"),
        &format!("touch '{}'\nprintf '%s' '{ITEM}'", called.display()),
    );
    executable(
        &bin.join("encryptor"),
        "cat >/dev/null; printf 'age-encryption.org/v1\\n%080d' 0",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_secret-manager"))
        .args([
            "hm",
            "file",
            "--shared",
            "--name",
            "account",
            "--from-rbw",
            ID,
            "--no-stage",
            "--no-rekey",
        ])
        .current_dir(root.path())
        .stdin(Stdio::null())
        .env("SECRET_MANAGER_AGE_ENCRYPTOR", bin.join("encryptor"))
        .env("SECRET_MANAGER_SCOPE_ATTEMPT", "1")
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            format!("unix:path={}/absent-system-bus", root.path().display()),
        )
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .unwrap();
    assert!(
        !called.exists(),
        "missing credential protection admitted vault effects"
    );
    assert!(!output.status.success());
    assert!(
        !root
            .path()
            .join("age/secrets/users/shared/account.age")
            .exists()
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-password"));
}

#[test]
fn invalid_module_splice_cannot_open_vault_or_install_ciphertext() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let module_dir = root.path().join("home/user/can/repositories");
    fs::create_dir_all(&module_dir).unwrap();
    let default = module_dir.join("default.nix");
    let called = root.path().join("vault-opened");
    executable(
        &bin.join("rbw"),
        &format!("touch '{}'\nprintf '%s' '{ITEM}'", called.display()),
    );
    executable(
        &bin.join("encryptor"),
        "cat >/dev/null; printf 'age-encryption.org/v1\\n%080d' 0",
    );
    for content in ["{ ... }: {}\n", "{ imports = [\n"] {
        fs::write(&default, content).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_secret-manager"))
            .args([
                "hm",
                "file",
                "--user",
                "can",
                "--name",
                "account",
                "--file",
                ".config/account",
                "--from-rbw",
                ID,
                "--no-stage",
                "--no-rekey",
            ])
            .current_dir(root.path())
            .stdin(Stdio::null())
            .env("SECRET_MANAGER_AGE_ENCRYPTOR", bin.join("encryptor"))
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "malformed module wiring was accepted"
        );
        assert!(!called.exists(), "invalid module wiring opened the vault");
        assert!(
            !root
                .path()
                .join("age/secrets/users/can/account.age")
                .exists()
        );
        assert!(!module_dir.join("account.nix").exists());
        assert_eq!(fs::read_to_string(&default).unwrap(), content);
    }
}
