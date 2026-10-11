use secret_manager::sync_state::{SyncState, desired_records, stale_records};
use secret_manager::sync_targets::SyncDocument;

#[test]
fn scoped_sync_replay_preserves_configuration_and_target_selection() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("flake.nix"), "{}\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_secret-manager"))
        .args([
            "sync",
            "--config",
            "already-consumed",
            "--target",
            "publisher",
            "--check",
        ])
        .env("SECRET_MANAGER_SYNC_REPLAY", "1")
        .env("SECRET_MANAGER_SCOPE_ATTEMPT", "1")
        .current_dir(root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(br#"{"hosts":[{"targets":{"publisher":{"secret":"publisher.age","name":"TOKEN","githubEnvironments":[{"repository":"caniko/demo","environment":"simit-crates-io"}]},"other":{"secret":"other.age","name":"OTHER","github":["caniko/demo"]}}}]}"#).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan = String::from_utf8(output.stdout).unwrap();
    assert!(plan.contains("simit-crates-io"));
    assert!(!plan.contains("other.age"));
}

#[test]
fn destination_free_secret_sync_needs_no_identities_or_protected_scope() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("flake.nix"), "{}\n").unwrap();
    let config = root.path().join("sync.json");
    std::fs::write(
        &config,
        br#"{"hosts":[{"targets":{"unused":{"secret":"missing.age","name":"TOKEN"}}}]}"#,
    )
    .unwrap();
    let state = root.path().join("state.toml");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_secret-manager"))
        .args(["sync", "--no-flake", "--config"])
        .arg(config)
        .arg("--state")
        .arg(&state)
        .arg("--identity")
        .arg(root.path().join("missing-identity"))
        // A credential scope attempt may never recurse. This fixture must not
        // need protection or touch its nonexistent source/identity in any cgroup.
        .env("SECRET_MANAGER_SCOPE_ATTEMPT", "1")
        .env_remove("SECRET_MANAGER_SYNC_REPLAY")
        .current_dir(root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(SyncState::load(&state).unwrap().unwrap().managed.is_empty());
    assert!(!root.path().join("missing.age").exists());
    assert!(!root.path().join("missing-identity").exists());
}

fn document(target: serde_json::Value) -> SyncDocument {
    SyncDocument::from_json(
        &serde_json::json!({"hosts":[{"targets":{"publisher":target}}]}).to_string(),
    )
    .unwrap()
}

#[test]
fn environment_destinations_preserve_distinct_state_and_stale_identities() {
    let doc = document(serde_json::json!({
        "secret":"age/publisher.age", "name":"CRATES_IO_API_TOKEN", "github":["caniko/demo"],
        "githubEnvironments":[
            {"repository":"caniko/demo", "environment":"simit-crates-io"},
            {"repository":"caniko/demo", "environment":"staging"},
            {"repository":"caniko/demo", "environment":"SIMIT-CRATES-IO"}
        ]
    }));
    let records = desired_records(&doc).unwrap();
    assert_eq!(
        records.len(),
        3,
        "repository and two environments need three identities, case aliases need one"
    );
    let environment = records
        .iter()
        .filter(|record| record.destination_label().contains("environment"))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(environment.len(), 2);
    let state = SyncState::new(records.clone());
    let reparsed: SyncState = toml::from_str(&toml::to_string(&state).unwrap()).unwrap();
    assert_eq!(reparsed, state);
    let stale = stale_records(&records, &environment);
    assert_eq!(stale.len(), 1);
    assert!(!stale[0].destination_label().contains("environment"));
    let stale = stale_records(&records, &environment[..1]);
    assert_eq!(stale.len(), 2);
}

#[test]
fn environment_only_sync_is_a_valid_destination_without_repository_fallback() {
    let doc = document(serde_json::json!({
        "source":"public/revision", "name":"SIMIT_PUBLISHER_REVISION",
        "githubEnvironments":[{"repository":"caniko/demo", "environment":"simit-crates-io"}]
    }));
    let records = desired_records(&doc).unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].destination_label().contains("environment"));
    assert!(serde_json::to_value(&records[0]).unwrap()["scope"] == "environment");
}

#[test]
fn malformed_environment_destinations_reject_before_effects() {
    for (repository, environment) in [
        ("caniko/demo", ""),
        ("caniko/demo", " "),
        ("caniko/demo", "prod\nnext"),
        ("caniko/demo/extra", "production"),
        ("--repo", "production"),
        ("caniko/../demo", "production"),
    ] {
        let doc = document(
            serde_json::json!({"secret":"age/publisher.age", "name":"TOKEN", "github":["caniko/demo"], "githubEnvironments":[{"repository":repository,"environment":environment}]}),
        );
        assert!(
            desired_records(&doc).is_err(),
            "state expansion bypassed validation"
        );
    }
    let doc = document(
        serde_json::json!({"secret":"age/publisher.age", "name":"TOKEN", "githubEnvironments":[{"repository":"caniko/demo","environment":"x".repeat(256)}]}),
    );
    assert!(desired_records(&doc).is_err());
}

#[cfg(unix)]
#[test]
fn native_sync_verifies_environment_upload_before_pruning_repository_copy() {
    use std::{fs, os::unix::fs::PermissionsExt, process::Command};
    for failure in [
        "",
        "missing-environment",
        "upload",
        "readback",
        "wrong-resource",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let bin = root.join("bin");
        fs::create_dir(&bin).unwrap();
        let gh = bin.join("gh");
        fs::write(
            &gh,
            r#"#!/bin/sh
set -eu
printf '<%s>' "$@" >> "$GH_LOG"
printf '\n' >> "$GH_LOG"
case "$1/$2" in
  api/repos/caniko/demo/environments/simit%2Fproduction)
    test "$GH_FAILURE" != missing-environment || exit 1
    printf '%s\n' '{"name":"simit/production"}' ;;
  variable/set)
    cat > "$GH_VALUE"
    test "$GH_FAILURE" != upload ;;
  api/repos/caniko/demo/environments/simit%2Fproduction/variables/REVISION)
    test "$GH_FAILURE" != readback || exit 1
    if test "$GH_FAILURE" = wrong-resource; then
      printf '%s\n' '{"name":"OTHER"}'
    else
      printf '%s\n' '{"name":"REVISION"}'
    fi ;;
  variable/delete) exit 0 ;;
  *) exit 95 ;;
esac
"#,
        )
        .unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(root.join("revision"), "verified-engine-identity").unwrap();
        let old = document(
            serde_json::json!({"source":"revision","name":"REVISION","github":["caniko/demo"]}),
        );
        let state = root.join("state.toml");
        SyncState::new(desired_records(&old).unwrap())
            .write_atomic(&state)
            .unwrap();
        let original = fs::read(&state).unwrap();
        let config = root.join("targets.json");
        fs::write(&config, serde_json::json!({"hosts":[{"targets":{"publisher":{
            "source":"revision","name":"REVISION","githubEnvironments":[{"repository":"caniko/demo","environment":"simit/production"}]
        }}}]}).to_string()).unwrap();
        let log = root.join("calls");
        let value = root.join("received");
        let path = std::env::join_paths(
            std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_secret-manager"))
            .args(["sync", "--config"])
            .arg(&config)
            .args(["--state"])
            .arg(&state)
            .arg("--prune")
            .env("SECRET_MANAGER_STORE", root)
            .env("PATH", path)
            .env("GH_LOG", &log)
            .env("GH_VALUE", &value)
            .env("GH_FAILURE", failure)
            .env("GH_HOST", "untrusted.example")
            .output()
            .unwrap();
        let calls = fs::read_to_string(&log).unwrap();
        assert!(!calls.contains("verified-engine-identity"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("verified-engine-identity"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("verified-engine-identity"));
        if failure.is_empty() {
            assert!(output.status.success(), "{output:?}");
            assert_eq!(
                fs::read_to_string(&value).unwrap(),
                "verified-engine-identity"
            );
            assert!(calls.contains(
                "<variable><set><REVISION><--repo><github.com/caniko/demo><--env=simit/production>"
            ));
            assert!(calls.contains("<variable><delete><REVISION><--repo><github.com/caniko/demo>"));
            assert!(
                calls
                    .lines()
                    .filter(|line| line.starts_with("<api>"))
                    .all(|line| line.contains("<--hostname><github.com>"))
            );
            let saved = SyncState::load(&state).unwrap().unwrap();
            assert_eq!(saved.managed.len(), 1);
            assert!(saved.managed[0].destination_label().contains("environment"));
        } else {
            assert!(!output.status.success());
            assert!(
                !calls.contains("<delete>"),
                "failure pruned existing credential: {calls}"
            );
            assert_eq!(fs::read(&state).unwrap(), original);
            if failure == "missing-environment" {
                assert!(!value.exists());
            }
        }
    }
}
