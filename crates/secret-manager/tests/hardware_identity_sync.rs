#![cfg(unix)]

use age::secrecy::ExposeSecret;
use age_core::format::{FILE_KEY_BYTES, FileKey, Stanza};
use base64::Engine;
use std::cell::RefCell;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

struct Capture(RefCell<Option<[u8; FILE_KEY_BYTES]>>);

impl age::Recipient for Capture {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, std::collections::HashSet<String>), age::EncryptError> {
        *self.0.borrow_mut() = Some(*file_key.expose_secret());
        let stanza = Stanza {
            tag: "test".into(),
            args: vec![],
            body: vec![],
        };
        Ok((vec![stanza], Default::default()))
    }
}

fn encrypt(path: &Path, plaintext: &str) -> String {
    let capture = Capture(RefCell::default());
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&capture as &dyn age::Recipient)).unwrap();
    let mut writer = encryptor
        .wrap_output(fs::File::create(path).unwrap())
        .unwrap();
    writer.write_all(plaintext.as_bytes()).unwrap();
    writer.finish().unwrap();
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(capture.0.take().unwrap())
}

fn executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn sync_unlocks_a_hardware_identity_once_for_every_secret() {
    let scope = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--quiet",
            "--property=MemorySwapMax=0",
            "true",
        ])
        .output();
    if !scope.is_ok_and(|output| output.status.success()) {
        eprintln!("SKIPPED: credential sync needs a systemd user session for its no-swap scope");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(root.join("age")).unwrap();
    fs::write(root.join("flake.nix"), "{}\n").unwrap();
    fs::write(
        root.join("age/master_test_identity.pub"),
        format!(
            "# public key: unused\n{}\n",
            age::plugin::Identity::default_for_plugin("test")
        ),
    )
    .unwrap();
    let alpha = encrypt(&root.join("age/alpha.age"), "alpha-value\n");
    let bravo = encrypt(&root.join("age/bravo.age"), "bravo-value");

    executable(
        &bin.join("age-plugin-test"),
        &format!(
            "#!/bin/sh\necho start >> \"$PLUGIN_LOG\"\n\
             while IFS= read -r line; do [ \"$line\" = '-> done' ] && break; done\nread -r _\n\
             printf -- '-> file-key 0\\n{alpha}\\n'; read -r _; read -r _\n\
             printf -- '-> file-key 1\\n{bravo}\\n'; read -r _; read -r _\n\
             printf -- '-> done\\n\\n'\n"
        ),
    );
    executable(
        &bin.join("rage"),
        "#!/bin/sh\necho rage >> \"$RAGE_LOG\"\nexit 1\n",
    );
    executable(
        &bin.join("gh"),
        "#!/bin/sh\nprintf '%s ' \"$@\" >> \"$GH_LOG\"\ncat >> \"$GH_LOG\"\necho >> \"$GH_LOG\"\n",
    );

    let config = root.join("targets.json");
    fs::write(
        &config,
        serde_json::json!({"hosts":[{"targets":{
            "alpha":{"secret":"age/alpha.age","name":"ALPHA","github":["caniko/demo"]},
            "bravo":{"secret":"age/bravo.age","name":"BRAVO","github":["caniko/demo"]}
        }}]})
        .to_string(),
    )
    .unwrap();
    let path = std::env::join_paths(
        std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_secret-manager"))
        .args(["sync", "--no-flake", "--config"])
        .arg(&config)
        .arg("--state")
        .arg(root.join("state.toml"))
        .env("SECRET_MANAGER_STORE", root)
        .env_remove("SECRET_MANAGER_SYNC_REPLAY")
        .env_remove("SECRET_MANAGER_AGE_IDENTITIES")
        .env("PATH", path)
        .env("PLUGIN_LOG", root.join("plugin.log"))
        .env("RAGE_LOG", root.join("rage.log"))
        .env("GH_LOG", root.join("gh.log"))
        .current_dir(root)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let gh = fs::read_to_string(root.join("gh.log")).unwrap();
    assert!(
        gh.contains("secret set ALPHA --repo github.com/caniko/demo alpha-value"),
        "{gh}"
    );
    assert!(
        gh.contains("secret set BRAVO --repo github.com/caniko/demo bravo-value"),
        "{gh}"
    );
    let starts = fs::read_to_string(root.join("plugin.log")).unwrap();
    assert_eq!(starts.lines().count(), 1, "plugin started more than once");
    assert!(
        !root.join("rage.log").exists(),
        "fell back to per-file rage"
    );
}
