//! Kubernetes Secret destination: the decrypted value reaches `kubectl` on
//! stdin only, and never appears in argv, its environment, or our own output.
#![cfg(unix)]

use age::secrecy::ExposeSecret;
use age_core::format::{FILE_KEY_BYTES, FileKey, Stanza};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use secret_manager::sync_state::desired_records;
use secret_manager::sync_targets::SyncDocument;
use std::cell::RefCell;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const OPAQUE_VALUE: &str = "opaque-fixture-value-7731";
// Quote and backslash exercise JSON escaping inside the dockerconfigjson.
const DOCKER_VALUE: &str = r#"dock"er\fixture-pass-4402"#;

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
    STANDARD_NO_PAD.encode(capture.0.take().unwrap())
}

fn executable(path: &Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Credential sync needs a no-swap systemd user scope and a logind inhibitor.
fn protection_available() -> bool {
    [
        &[
            "systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "--property=MemorySwapMax=0",
            "true",
        ][..],
        &[
            "systemd-inhibit",
            "--what=sleep",
            "--mode=block",
            "--who=test",
            "--why=probe",
            "true",
        ],
    ]
    .iter()
    .all(|probe| {
        Command::new(probe[0])
            .args(&probe[1..])
            .output()
            .is_ok_and(|output| output.status.success())
    })
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    calls: PathBuf,
    path: std::ffi::OsString,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let bin = root.join("bin");
        let calls = root.join("calls");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&calls).unwrap();
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
        let opaque = encrypt(&root.join("age/a-opaque.age"), OPAQUE_VALUE);
        let docker = encrypt(&root.join("age/b-docker.age"), DOCKER_VALUE);
        // Secrets are unlocked in sorted record order: a-opaque, then b-docker.
        executable(
            &bin.join("age-plugin-test"),
            &format!(
                "#!/bin/sh\n\
                 while IFS= read -r line; do [ \"$line\" = '-> done' ] && break; done\nread -r _\n\
                 printf -- '-> file-key 0\\n{opaque}\\n'; read -r _; read -r _\n\
                 printf -- '-> file-key 1\\n{docker}\\n'; read -r _; read -r _\n\
                 printf -- '-> done\\n\\n'\n"
            ),
        );
        // Record argv, environment and stdin per invocation; optionally fail
        // while echoing stdin to stderr, as a hostile or verbose kubectl might.
        executable(
            &bin.join("kubectl"),
            "#!/bin/sh\n\
             id=$$\n\
             printf '%s\\n' \"$@\" > \"$KUBECTL_CALLS/argv.$id\"\n\
             env > \"$KUBECTL_CALLS/env.$id\"\n\
             cat > \"$KUBECTL_CALLS/stdin.$id\"\n\
             if [ -n \"${KUBECTL_FAIL:-}\" ]; then cat \"$KUBECTL_CALLS/stdin.$id\" >&2; exit 1; fi\n\
             echo 'secret/ignored serverside-applied'\n",
        );
        let path = std::env::join_paths(
            std::iter::once(bin).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        fs::write(
            root.join("targets.json"),
            serde_json::json!({"hosts":[{"targets":{
                "opaque":{"secret":"age/a-opaque.age","name":"API_TOKEN","kubernetes":[
                    {"context":"nrp","namespace":"syndb","secret":"a-opaque","format":"opaque"}
                ]},
                "docker":{"secret":"age/b-docker.age","name":"REGISTRY","kubernetes":[
                    {"context":"nrp","namespace":"syndb","secret":"b-docker",
                     "format":"dockerconfigjson","username":"robot","registry":"registry.example"}
                ]}
            }}]})
            .to_string(),
        )
        .unwrap();
        Self {
            _temp: temp,
            root,
            calls,
            path,
        }
    }

    fn sync(&self, extra: &[&str], fail: bool) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secret-manager"));
        command
            .args(["sync", "--no-flake", "--config"])
            .arg(self.root.join("targets.json"))
            .arg("--state")
            .arg(self.root.join("state.toml"))
            .args(extra)
            .env("SECRET_MANAGER_STORE", &self.root)
            .env_remove("SECRET_MANAGER_SYNC_REPLAY")
            .env_remove("SECRET_MANAGER_AGE_IDENTITIES")
            .env("PATH", &self.path)
            .env("KUBECTL_CALLS", &self.calls)
            .current_dir(&self.root);
        if fail {
            command.env("KUBECTL_FAIL", "1");
        }
        command.output().unwrap()
    }

    /// Recorded files named `<kind>.<pid>`, as (pid, content), sorted by content.
    fn recorded(&self, kind: &str) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(&self.calls)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&format!("{kind}."))
            })
            .map(|path| fs::read_to_string(path).unwrap())
            .collect();
        found.sort();
        found
    }
}

fn leaks(haystack: &str) -> Vec<&'static str> {
    let escaped = DOCKER_VALUE.replace('\\', "\\\\").replace('"', "\\\"");
    [
        (OPAQUE_VALUE.to_string(), "opaque plaintext"),
        (DOCKER_VALUE.to_string(), "docker plaintext"),
        (escaped, "docker plaintext (json)"),
        (STANDARD.encode(OPAQUE_VALUE), "opaque base64"),
        (STANDARD.encode(DOCKER_VALUE), "docker plaintext base64"),
        (
            STANDARD.encode(format!("robot:{DOCKER_VALUE}")),
            "docker auth base64",
        ),
    ]
    .into_iter()
    .filter(|(needle, _)| haystack.contains(needle))
    .map(|(_, label)| label)
    .collect()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn kubernetes_sync_keeps_values_on_stdin_only() {
    if !protection_available() {
        eprintln!(
            "SKIPPED: credential sync needs a no-swap systemd user scope and a logind inhibitor"
        );
        return;
    }
    let fixture = Fixture::new();
    let output = fixture.sync(&[], false);
    assert!(output.status.success(), "{}", text(&output));

    // Nothing the sync prints carries a value; only the status lines.
    let printed = text(&output);
    assert_eq!(leaks(&printed), Vec::<&str>::new(), "{printed}");
    assert!(
        printed.contains("kubernetes nrp/syndb/secret/a-opaque: applied"),
        "{printed}"
    );
    assert!(
        printed.contains("kubernetes nrp/syndb/secret/b-docker: applied"),
        "{printed}"
    );

    // Argv and environment of the child.
    let argv = fixture.recorded("argv");
    assert_eq!(argv.len(), 2);
    for args in &argv {
        assert_eq!(leaks(args), Vec::<&str>::new(), "{args}");
        let args: Vec<&str> = args.lines().collect();
        assert_eq!(
            args[..8],
            [
                "--context",
                "nrp",
                "--namespace",
                "syndb",
                "apply",
                "--server-side",
                "--force-conflicts",
                "--field-manager"
            ]
        );
        assert_eq!(args[8..], ["secret-manager", "-f", "-"]);
        assert!(
            !args
                .iter()
                .any(|arg| matches!(*arg, "-o" | "--output" | "-v" | "--v"))
        );
    }
    for env in fixture.recorded("env") {
        assert_eq!(leaks(&env), Vec::<&str>::new());
    }

    // Manifests on stdin.
    let manifests: Vec<serde_json::Value> = fixture
        .recorded("stdin")
        .iter()
        .map(|body| serde_json::from_str(body).unwrap())
        .collect();
    let by_name = |name: &str| {
        manifests
            .iter()
            .find(|manifest| manifest["metadata"]["name"] == name)
            .unwrap()
    };
    let opaque = by_name("a-opaque");
    assert_eq!(opaque["apiVersion"], "v1");
    assert_eq!(opaque["kind"], "Secret");
    assert_eq!(opaque["type"], "Opaque");
    assert_eq!(opaque["metadata"]["namespace"], "syndb");
    let data = opaque["data"]["API_TOKEN"].as_str().unwrap();
    assert_eq!(STANDARD.decode(data).unwrap(), OPAQUE_VALUE.as_bytes());

    let docker = by_name("b-docker");
    assert_eq!(docker["type"], "kubernetes.io/dockerconfigjson");
    let config: serde_json::Value = serde_json::from_slice(
        &STANDARD
            .decode(docker["data"][".dockerconfigjson"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let auth = &config["auths"]["registry.example"];
    assert_eq!(auth["username"], "robot");
    assert_eq!(auth["password"], DOCKER_VALUE);
    assert_eq!(
        STANDARD.decode(auth["auth"].as_str().unwrap()).unwrap(),
        format!("robot:{DOCKER_VALUE}").as_bytes()
    );

    // State holds destinations only.
    let state = fs::read_to_string(fixture.root.join("state.toml")).unwrap();
    assert_eq!(leaks(&state), Vec::<&str>::new());
    assert!(state.contains("kubernetes"), "{state}");

    // The persisted destinations reload and are not reported stale.
    let recheck = fixture.sync(&["--check"], false);
    assert!(recheck.status.success(), "{}", text(&recheck));
    assert!(text(&recheck).contains("no stale managed entries"));
}

#[test]
fn failing_kubectl_echoing_its_input_is_redacted() {
    if !protection_available() {
        eprintln!(
            "SKIPPED: credential sync needs a no-swap systemd user scope and a logind inhibitor"
        );
        return;
    }
    let fixture = Fixture::new();
    let output = fixture.sync(&[], true);
    assert!(!output.status.success());
    let printed = text(&output);
    assert_eq!(leaks(&printed), Vec::<&str>::new(), "{printed}");
    assert!(printed.contains("[redacted]"), "{printed}");
    assert!(
        printed.contains("kubectl apply for kubernetes nrp/syndb/secret/"),
        "{printed}"
    );
    // The fake really did echo the base64 value to stderr.
    assert!(
        fixture
            .recorded("stdin")
            .iter()
            .any(|body| body.contains(&STANDARD.encode(OPAQUE_VALUE)))
    );
}

#[test]
fn dry_run_names_destinations_and_keys_but_no_values() {
    let fixture = Fixture::new();
    let output = fixture.sync(&["--dry-run"], false);
    assert!(output.status.success(), "{}", text(&output));
    let printed = text(&output);
    assert_eq!(leaks(&printed), Vec::<&str>::new(), "{printed}");
    assert!(
        printed.contains("kubernetes/nrp secret syndb/a-opaque key API_TOKEN"),
        "{printed}"
    );
    assert!(
        printed.contains("kubernetes/nrp secret syndb/b-docker key .dockerconfigjson"),
        "{printed}"
    );
    assert!(
        fixture.recorded("argv").is_empty(),
        "dry-run invoked kubectl"
    );
}

#[test]
fn malformed_kubernetes_destinations_are_rejected_before_effects() {
    let secret = |kubernetes: serde_json::Value| {
        SyncDocument::from_json(
            &serde_json::json!({"hosts":[{"targets":{"t":{
                "secret":"age/t.age","name":"TOKEN","kubernetes":kubernetes
            }}}]})
            .to_string(),
        )
        .map_err(|error| error.to_string())
        .and_then(|doc| desired_records(&doc).map_err(|error| error.to_string()))
    };
    let good = serde_json::json!({"context":"c","namespace":"ns","secret":"s","format":"opaque"});
    assert!(secret(serde_json::json!([good])).is_ok());
    for (reason, bad) in [
        ("uppercase namespace", serde_json::json!({"namespace":"NS"})),
        ("underscore secret", serde_json::json!({"secret":"a_b"})),
        ("dash edge", serde_json::json!({"secret":"-a"})),
        ("empty label", serde_json::json!({"secret":"a..b"})),
        (
            "flag-like context",
            serde_json::json!({"context":"--token=x"}),
        ),
        ("bad key", serde_json::json!({"key":"a/b"})),
        ("opaque username", serde_json::json!({"username":"u"})),
        ("opaque registry", serde_json::json!({"registry":"r"})),
        (
            "docker without username",
            serde_json::json!({"format":"dockerconfigjson"}),
        ),
        (
            "docker key",
            serde_json::json!({"format":"dockerconfigjson","username":"u","key":"k"}),
        ),
        (
            "colon username",
            serde_json::json!({"format":"dockerconfigjson","username":"u:v"}),
        ),
        ("blank manager", serde_json::json!({"fieldManager":" "})),
        ("unknown format", serde_json::json!({"format":"tls"})),
        ("unknown field", serde_json::json!({"verbose":true})),
    ] {
        let mut destination = good.clone();
        destination
            .as_object_mut()
            .unwrap()
            .extend(bad.as_object().unwrap().clone());
        assert!(
            secret(serde_json::json!([destination])).is_err(),
            "{reason} accepted"
        );
    }
    assert!(
        secret(serde_json::json!([good, good])).is_err(),
        "duplicate Secret accepted"
    );

    let plaintext = SyncDocument::from_json(
        r#"{"hosts":[{"targets":{"t":{"source":"public.txt","name":"X","kubernetes":[{"context":"c","namespace":"ns","secret":"s","format":"opaque"}]}}}]}"#,
    )
    .unwrap();
    assert!(
        desired_records(&plaintext).is_err(),
        "plaintext source accepted"
    );
}

#[test]
fn nix_module_json_with_null_options_deserializes_with_defaults() {
    // Exactly what `builtins.toJSON` emits for the module's unset options.
    let doc = SyncDocument::from_json(
        r#"{"hosts":[{"targets":{"pull":{"secret":"age/pull.age","source":null,"name":"REGISTRY",
        "codeberg":[],"codefloe":[],"github":[],"githubEnvironments":[],"codebergOrgs":[],
        "codebergUser":false,"host":"codeberg.org","kubernetes":[{"context":"nautilus",
        "namespace":"syndb","secret":"registry-pull","format":"dockerconfigjson","key":null,
        "registry":null,"username":"robot","fieldManager":null}]}}}]}"#,
    )
    .unwrap();
    let records = desired_records(&doc).unwrap();
    assert_eq!(records.len(), 1);
    let label = records[0].destination_label();
    assert!(
        label.contains("syndb/registry-pull key .dockerconfigjson"),
        "{label}"
    );
}
