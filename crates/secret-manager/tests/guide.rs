//! `secret-manager guide`: catalogue loading, rendering, and the browser
//! launcher. The launcher spawns `xdg-open`, so the CLI runs with a PATH that
//! holds only a recording stub — an accidental spawn is visible in its log.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use secret_manager::guide::{load, render};
use secret_manager_schema::rotation::RotationCatalogue;

const STUB_XDG_OPEN: &str = r#"#!/bin/sh
# Recording stub: every URL the CLI opens lands in $STUB_DIR/log.
printf '%s\n' "$@" >>"$STUB_DIR/log"
"#;

fn fixture() -> &'static Path {
    Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rotation-catalogue.pkl"
    ))
}

/// A PATH directory holding only the recording `xdg-open` stub.
fn stub_dir(dir: &Path) -> std::path::PathBuf {
    let stub = dir.join("bin");
    fs::create_dir(&stub).unwrap();
    let opener = stub.join("xdg-open");
    fs::write(&opener, STUB_XDG_OPEN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&opener, fs::Permissions::from_mode(0o755)).unwrap();
    }
    stub
}

fn run(path: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_secret-manager"))
        .args(args)
        .env("PATH", path)
        .env("STUB_DIR", path)
        .output()
        .expect("run secret-manager guide")
}

#[test]
fn catalogue_renders_the_expected_text() {
    let catalogue = load(fixture()).expect("load fixture catalogue");
    let (key, guide) = catalogue.guides.get_key_value("github-token").unwrap();
    assert_eq!(
        render(key, guide),
        "github-token: GitHub personal access token\n  \
         1. Revoke the old token on the settings page.\n  \
         2. Create a fine-grained token with the repo scope.\n  \
         3. Store it with the command below.\n  \
         pages:\n    \
         https://github.com/settings/tokens\n    \
         https://docs.github.com/authentication\n  \
         command:\n    \
         secret-manager github token --out age/secrets/users/can/github.age\n  \
         cadence: every 90 days, warn 14 days before\n"
    );
    let (key, guide) = catalogue.guides.get_key_value("dockerhub-pat").unwrap();
    assert_eq!(
        render(key, guide),
        "dockerhub-pat: Docker Hub access token\n  \
         1. Create a read/write token.\n  \
         pages:\n    \
         https://hub.docker.com/settings/security\n  \
         command:\n    \
         secret-manager hm text --name dockerhub-pat\n"
    );
}

#[test]
fn validation_rejects_http_file_and_bad_keys() {
    let mut catalogue: RotationCatalogue =
        serde_json::from_str(r#"{"guides":{"github-token":{"title":"t"}}}"#).unwrap();
    for url in ["http://github.com/settings/tokens", "file:///etc/passwd"] {
        catalogue.guides.get_mut("github-token").unwrap().urls = vec![url.into()];
        let err = catalogue.validate().unwrap_err().to_string();
        assert!(err.contains("https://"), "{err}");
    }
    let guide = catalogue.guides.remove("github-token").unwrap();
    catalogue.guides.insert("GitHub Token".into(), guide);
    assert!(catalogue.validate().is_err());
}

#[test]
fn no_browser_opens_nothing_but_still_prints_the_pages() {
    let dir = tempfile::tempdir().unwrap();
    let stub = stub_dir(dir.path());

    let args = [
        "guide",
        "--catalogue",
        fixture().to_str().unwrap(),
        "github-token",
        "--no-browser",
    ];
    let out = run(&stub, &args);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("https://github.com/settings/tokens"),
        "{stdout}"
    );
    assert!(stdout.contains("cadence: every 90 days"), "{stdout}");
    // A spawned stub writes asynchronously; give it the same window the
    // browser test allows before asserting it never ran.
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(!stub.join("log").exists(), "no-browser must spawn nothing");
}

#[test]
fn browser_opens_every_url_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let stub = stub_dir(dir.path());

    let out = run(
        &stub,
        &[
            "guide",
            "--catalogue",
            fixture().to_str().unwrap(),
            "github-token",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    // Each URL is spawned separately, so the stub processes may record in
    // either order: compare the set, not the arrival order.
    let mut log = String::new();
    for _ in 0..50 {
        log = fs::read_to_string(stub.join("log")).unwrap_or_default();
        if log.lines().count() >= 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let mut opened: Vec<&str> = log.lines().collect();
    opened.sort_unstable();
    assert_eq!(
        opened,
        [
            "https://docs.github.com/authentication",
            "https://github.com/settings/tokens"
        ]
    );
}

#[test]
fn listing_and_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(
        dir.path(),
        &["guide", "--catalogue", fixture().to_str().unwrap()],
    );
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("dockerhub-pat: Docker Hub access token"),
        "{stdout}"
    );
    assert!(
        stdout.contains("github-token: GitHub personal access token"),
        "{stdout}"
    );

    let out = run(
        dir.path(),
        &[
            "guide",
            "--catalogue",
            fixture().to_str().unwrap(),
            "missing",
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no rotation guide \"missing\""), "{stderr}");
    assert!(stderr.contains("github-token"), "{stderr}");
}
