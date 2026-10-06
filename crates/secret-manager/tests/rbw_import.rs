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
fn cli_import_rotation_and_failure_preservation_use_only_encrypted_sources() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let identity = Command::new("rage-keygen").output().unwrap();
    assert!(identity.status.success());
    let identity_path = root.path().join("identity");
    fs::write(&identity_path, &identity.stdout).unwrap();
    let recipient = Command::new("rage-keygen")
        .arg("-y")
        .arg(&identity_path)
        .output()
        .unwrap();
    assert!(recipient.status.success());
    let encryptor = bin.join("encryptor");
    executable(
        &encryptor,
        &format!(
            "[ \"$1\" = encrypt ] || exit 2\nshift\nexec rage --encrypt -r '{}' \"$@\"",
            std::str::from_utf8(&recipient.stdout).unwrap().trim()
        ),
    );
    let rbw = bin.join("rbw");
    executable(
        &rbw,
        &format!("[ \"$*\" = 'get --raw -- {ID}' ] || exit 2\nprintf '%s' '{ITEM}'"),
    );
    let path = root.path().join("age/secrets/users/shared/account.age");
    let invoke = |extra: &[&str], no_rekey: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secret-manager"));
        if no_rekey {
            command.arg("hm").arg("file").arg("--no-rekey");
        } else {
            command.args(["hm", "file"]);
        }
        command
            .args([
                "--shared",
                "--name",
                "account",
                "--from-rbw",
                ID,
                "--rbw-map",
                "username=username",
                "--rbw-map",
                "password=password",
                "--rbw-map",
                "totpSecret=totp",
                "--no-stage",
            ])
            .args(extra)
            .current_dir(root.path())
            .stdin(Stdio::null())
            .env("SECRET_MANAGER_AGE_ENCRYPTOR", &encryptor)
            .env("AGENIX_REKEY_ADD_TO_GIT", "1")
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .output()
            .unwrap()
    };
    let run = |extra: &[&str]| invoke(extra, true);
    let output = run(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-password"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-password"));
    let previous = fs::read(&path).unwrap();
    let decrypted = Command::new("rage")
        .arg("--decrypt")
        .arg("-i")
        .arg(&identity_path)
        .arg(&path)
        .output()
        .unwrap();
    assert!(decrypted.status.success());
    let value: serde_json::Value = serde_json::from_slice(&decrypted.stdout).unwrap();
    assert_eq!(value["password"], "fixture-password");
    assert_eq!(value["totpSecret"], "GEZDGNBVGY3TQOJQ");
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert!(!run(&[]).status.success());
    assert_eq!(fs::read(&path).unwrap(), previous);
    executable(&rbw, "echo fixture-secret >&2; exit 1");
    let failed = run(&["--rbw-rotate"]);
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("fixture-secret"));
    assert_eq!(fs::read(&path).unwrap(), previous);
    executable(&rbw, &format!("printf '%s' '{ITEM}'"));
    executable(&encryptor, "cat; echo fixture-password >&2; exit 1");
    let failed = run(&["--rbw-rotate"]);
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("fixture-password"));
    assert_eq!(fs::read(&path).unwrap(), previous);
    executable(
        &encryptor,
        &format!(
            "shift\nexec rage --encrypt -r '{}' \"$@\"",
            std::str::from_utf8(&recipient.stdout).unwrap().trim()
        ),
    );
    assert!(run(&["--rbw-rotate"]).status.success());
    assert_ne!(fs::read(&path).unwrap(), previous);
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    assert!(
        Command::new("git")
            .arg("init")
            .current_dir(root.path())
            .output()
            .unwrap()
            .status
            .success()
    );
    fs::write(root.path().join("unrelated"), b"foreign staging").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "unrelated"])
            .current_dir(root.path())
            .output()
            .unwrap()
            .status
            .success()
    );
    executable(
        &bin.join("agenix"),
        "[ \"${AGENIX_REKEY_ADD_TO_GIT+x}\" != x ] || exit 20\nmkdir -p age/rekeyed\nprintf partial >age/rekeyed/pending.age\nexit 1",
    );
    let last = fs::read(&path).unwrap();
    let failed = invoke(&["--rbw-rotate"], false);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("distribution is incomplete"));
    assert_ne!(fs::read(&path).unwrap(), last);
    assert!(root.path().join("age/rekeyed/pending.age").exists());
    let staged = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(root.path())
        .output()
        .unwrap();
    assert_eq!(staged.stdout, b"unrelated\n");
}
