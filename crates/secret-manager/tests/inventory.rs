//! `classify`, `inventory --output json`, `--check` and `--write` against a
//! store of placeholder sources. Nothing is decrypted: the files only need to
//! exist, and no byte of them may reach the output.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

const PLACEHOLDER: &str = "placeholder-ciphertext-7731";

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secret-manager"))
        .args(args)
        .env("SECRET_MANAGER_STORE", root)
        .current_dir(root)
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn classify_then_inventory_json_check_and_write() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("flake.nix"), "{}\n").unwrap();
    for rel in [
        "age/secrets/home/can/cloud/syndb_cloudflare_pages_token.age",
        "age/secrets/home/shared/ai/deepseek.age",
        "age/secrets/users/can/legacy.age",
    ] {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, PLACEHOLDER).unwrap();
    }

    let token = "age/secrets/home/can/cloud/syndb_cloudflare_pages_token.age";
    let classified = run(
        root,
        &[
            "classify",
            token,
            "--expires",
            "never",
            "--project",
            "syndb",
        ],
    );
    assert!(classified.status.success(), "{}", text(&classified));
    let refused = run(root, &["classify", token, "--expires", "2027-02-29"]);
    assert!(!refused.status.success(), "an impossible date was accepted");
    let sidecar = fs::read_to_string(root.join(token.replace(".age", ".meta.toml"))).unwrap();
    assert!(sidecar.contains("schema = 1"), "{sidecar}");
    assert!(
        !sidecar.contains("rotated_at"),
        "classify must not stamp a rotation: {sidecar}"
    );

    let printed = run(root, &["inventory", "--output", "json"]);
    assert!(printed.status.success(), "{}", text(&printed));
    let document: serde_json::Value = serde_json::from_slice(&printed.stdout).unwrap();
    assert_eq!(document["schemaVersion"], 1);
    let secrets = document["secrets"].as_array().unwrap();
    assert_eq!(secrets.len(), 2, "the legacy users/ source is not listed");
    let pages = &secrets[0];
    assert_eq!(pages["id"], "home/can/cloud/syndb_cloudflare_pages_token");
    assert_eq!(pages["custodian"], "can");
    assert_eq!(pages["project"], "syndb");
    assert_eq!(pages["kind"], "external");
    assert_eq!(pages["expiry"]["type"], "never");
    assert_eq!(pages["rotatedAt"], serde_json::Value::Null);
    assert!(
        !text(&printed).contains(PLACEHOLDER),
        "a value reached the output"
    );

    let checked = run(root, &["inventory", "--check"]);
    assert!(!checked.status.success(), "violations must fail the check");
    let report = text(&checked);
    assert!(report.contains("users/can/legacy.age"), "{report}");
    assert!(report.contains("shared/ai/deepseek.age"), "{report}");
    assert!(!report.contains("syndb_cloudflare_pages_token"), "{report}");

    let out = root.join("inventory.json");
    let written = run(
        root,
        &[
            "inventory",
            "--write",
            out.to_str().unwrap(),
            "--mode",
            "640",
        ],
    );
    assert!(written.status.success(), "{}", text(&written));
    assert!(
        written.stdout.is_empty(),
        "--write prints nothing to stdout"
    );
    assert_eq!(
        fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let on_disk: serde_json::Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(on_disk["secrets"], document["secrets"]);
}
