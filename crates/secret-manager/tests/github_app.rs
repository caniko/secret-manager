use std::{fs, process::Command};

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_secret-manager"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn github_app_lifecycle_is_exposed_without_printing_credentials() {
    for command in ["enroll", "import", "publish", "verify", "installation"] {
        let output = run(&["github", "app", command, "--help"]);
        assert!(output.status.success(), "missing command {command}");
    }
}

#[test]
fn invalid_repository_is_refused_before_creating_a_transaction() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("app.json");
    let transaction = root.path().join("transaction");
    fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "slug": "caniko-paperclip-review",
            "owner": "caniko",
            "repository": "another-owner/paperclip",
            "homepage": "https://github.com/caniko/paperclip",
            "source": "age/secrets/paperclip-review.age",
            "recipients": ["age1invalid"],
            "permissions": {"contents": "read", "pull_requests": "write"},
            "keySecretName": "COMMITPERCLIP_KEY",
            "appIdVariable": "COMMITPERCLIP_APP_ID",
            "appSlugVariable": "COMMITPERCLIP_APP_SLUG"
        }))
        .unwrap(),
    )
    .unwrap();
    let output = run(&[
        "github",
        "app",
        "enroll",
        "--config",
        config.to_str().unwrap(),
        "--transaction",
        transaction.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("repository owner"));
    assert!(!transaction.exists());
}
