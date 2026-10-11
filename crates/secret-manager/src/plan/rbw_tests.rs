//! Private process fixtures exercise the protected import engine without a
//! production protection bypass or live vault/logind dependency.
use super::*;
use std::process::{Command, Stdio};

const ID: &str = "12345678-1234-1234-1234-123456789abc";
const ITEM: &str = r#"{"id":"12345678-1234-1234-1234-123456789abc","data":{"username":"fixture-user","password":"fixture-password","totp":"GEZDGNBVGY3TQOJQ"},"fields":[],"history":[{"password":"old-secret"}]}"#;

fn executable(path: &Path, text: &str) {
    fs::write(
        path,
        format!("#!/bin/sh\ntest -f \"$SECRET_MANAGER_TEST_PROTECTION_HELD\" || exit 91\n{text}\n"),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn rbw_fixture_process() {
    use std::os::unix::process::ExitStatusExt;
    let Some(root) = std::env::var_os("SECRET_MANAGER_TEST_IMPORT_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let source = crate::rbw::RbwSource {
        item_id: ID.into(),
        field: "password".into(),
        json_fields: std::collections::BTreeMap::from([
            ("username".into(), "username".into()),
            ("password".into(), "password".into()),
            ("totpSecret".into(), "totp".into()),
        ]),
        sync: false,
        timeout: std::time::Duration::from_secs(5),
    };
    let rotate = std::env::var_os("SECRET_MANAGER_TEST_ROTATE").is_some();
    let plan = AddPlan {
        slug: "account".into(),
        source: SourceKind::Rbw {
            source: source.clone(),
            rotate,
        },
        targets: vec![],
        source_only_paths: vec![PathBuf::from("age/secrets/users/shared/account.age")],
    };
    let args = CommonSourceArgs {
        no_stage: true,
        no_rekey: std::env::var_os("SECRET_MANAGER_TEST_REKEY").is_none(),
        ..CommonSourceArgs::default()
    };
    struct Guard(PathBuf);
    impl Drop for Guard {
        fn drop(&mut self) {
            fs::remove_file(&self.0).unwrap();
        }
    }
    let result = run_rbw_plan_with(
        &root,
        &args,
        &plan,
        &[],
        (&source, rotate),
        &crate::env::LocalEnv,
        (
            || {
                fs::write(root.join("scope-entered"), b"public command").unwrap();
                match std::env::var("SECRET_MANAGER_TEST_SCOPE").as_deref() {
                    Ok("fail") => bail!("fixture scope unavailable"),
                    Ok("child-success") => Ok(Some(std::process::ExitStatus::from_raw(0))),
                    Ok("child-failure") => Ok(Some(std::process::ExitStatus::from_raw(256))),
                    _ => Ok(None),
                }
            },
            || {
                if std::env::var_os("SECRET_MANAGER_TEST_ACQUIRE_FAIL").is_some() {
                    bail!("fixture protection unavailable");
                }
                assert!(root.join("scope-entered").exists());
                fs::write(root.join("guard-acquired"), b"public receipt").unwrap();
                let path = root.join("protection-held");
                fs::write(&path, b"held").unwrap();
                Ok(Guard(path))
            },
        ),
    );
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn invoke(root: &Path, rotate: bool, rekey: bool) -> Command {
    let bin = root.join("bin");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "plan::rbw_tests::rbw_fixture_process",
            "--nocapture",
        ])
        .current_dir(root)
        .stdin(Stdio::null())
        .env("SECRET_MANAGER_TEST_IMPORT_ROOT", root)
        .env(
            "SECRET_MANAGER_TEST_PROTECTION_HELD",
            root.join("protection-held"),
        )
        .env("SECRET_MANAGER_AGE_ENCRYPTOR", bin.join("encryptor"))
        .env("AGENIX_REKEY_ADD_TO_GIT", "1")
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        );
    if rotate {
        command.env("SECRET_MANAGER_TEST_ROTATE", "1");
    }
    if rekey {
        command.env("SECRET_MANAGER_TEST_REKEY", "1");
    }
    command
}

#[test]
fn import_scope_and_acquisition_failures_admit_no_vault_or_installation_effects() {
    for mode in [
        "scope-failure",
        "acquire-failure",
        "child-success",
        "child-failure",
    ] {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        executable(
            &bin.join("rbw"),
            &format!(
                "touch '{}'; printf '%s' '{ITEM}'",
                root.path().join("vault-opened").display()
            ),
        );
        executable(
            &bin.join("encryptor"),
            "cat >/dev/null; printf 'age-encryption.org/v1\\n%080d' 0",
        );
        let mut command = invoke(root.path(), false, false);
        match mode {
            "scope-failure" => {
                command.env("SECRET_MANAGER_TEST_SCOPE", "fail");
            }
            "acquire-failure" => {
                command.env("SECRET_MANAGER_TEST_ACQUIRE_FAIL", "1");
            }
            _ => {
                command.env("SECRET_MANAGER_TEST_SCOPE", mode);
            }
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.success(), mode == "child-success");
        assert!(root.path().join("scope-entered").exists());
        assert!(!root.path().join("guard-acquired").exists());
        assert!(!root.path().join("vault-opened").exists());
        assert!(
            !root
                .path()
                .join("age/secrets/users/shared/account.age")
                .exists()
        );
        assert!(!root.path().join("protection-held").exists());
    }
}

#[test]
fn protected_import_rotation_and_failure_preservation_use_only_encrypted_sources() {
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
    let encryption_script = format!(
        "[ \"$1\" = encrypt ] || exit 2\nshift\nexec rage --encrypt -r '{}' \"$@\"",
        std::str::from_utf8(&recipient.stdout).unwrap().trim()
    );
    let encryptor = bin.join("encryptor");
    executable(&encryptor, &encryption_script);
    let rbw = bin.join("rbw");
    executable(
        &rbw,
        &format!("[ \"$*\" = 'get --raw -- {ID}' ] || exit 2\nprintf '%s' '{ITEM}'"),
    );
    let path = root.path().join("age/secrets/users/shared/account.age");
    let run = |rotate| {
        let output = invoke(root.path(), rotate, false).output().unwrap();
        assert!(
            !root.path().join("protection-held").exists(),
            "guard outlived import"
        );
        output
    };
    let output = run(false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.path().join("guard-acquired").exists());
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
    assert!(!run(false).status.success());
    assert_eq!(fs::read(&path).unwrap(), previous);
    executable(&rbw, "echo fixture-secret >&2; exit 1");
    let failed = run(true);
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("fixture-secret"));
    assert_eq!(fs::read(&path).unwrap(), previous);
    executable(&rbw, &format!("printf '%s' '{ITEM}'"));
    executable(&encryptor, "cat; echo fixture-password >&2; exit 1");
    let failed = run(true);
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("fixture-password"));
    assert_eq!(fs::read(&path).unwrap(), previous);
    executable(&encryptor, &encryption_script);
    assert!(run(true).status.success());
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
    let failed = invoke(root.path(), true, true).output().unwrap();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("distribution is incomplete"));
    assert_ne!(fs::read(&path).unwrap(), last);
    assert!(root.path().join("age/rekeyed/pending.age").exists());
    assert!(!root.path().join("protection-held").exists());
    let staged = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(root.path())
        .output()
        .unwrap();
    assert_eq!(staged.stdout, b"unrelated\n");
}
