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
                 echo session >> \"$KUBECTL_CALLS/plugin-sessions\"\n\
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
fn multi_key_secret_is_one_apply_after_one_unlock() {
    if !protection_available() {
        eprintln!(
            "SKIPPED: credential sync needs a no-swap systemd user scope and a logind inhibitor"
        );
        return;
    }
    let fixture = Fixture::new();
    // Both sources fill keys of one Secret; the second is hashed.
    fs::write(
        fixture.root.join("targets.json"),
        serde_json::json!({"hosts":[{"targets":{
            "app":{"secret":"age/a-opaque.age","name":"APP","kubernetes":[
                {"context":"nrp","namespace":"syndb","secret":"auth","format":"opaque","key":"app"}
            ]},
            "hash":{"secret":"age/b-docker.age","name":"HASH","kubernetes":[
                {"context":"nrp","namespace":"syndb","secret":"auth","format":"opaque",
                 "key":"hash_sha256","render":"sha256-hex"}
            ]}
        }}]})
        .to_string(),
    )
    .unwrap();
    let output = fixture.sync(&["--target", "app"], false);
    assert!(output.status.success(), "{}", text(&output));
    let printed = text(&output);
    assert_eq!(leaks(&printed), Vec::<&str>::new(), "{printed}");
    assert!(printed.contains("also selecting `hash`"), "{printed}");
    // One hardware unlock for the run, one apply for the whole Secret.
    let sessions = fs::read_to_string(fixture.calls.join("plugin-sessions")).unwrap();
    assert_eq!(sessions.lines().count(), 1, "{sessions}");
    let manifests = fixture.recorded("stdin");
    assert_eq!(manifests.len(), 1);
    let manifest: serde_json::Value = serde_json::from_str(&manifests[0]).unwrap();
    let data = manifest["data"].as_object().unwrap();
    assert_eq!(data.keys().collect::<Vec<_>>(), ["app", "hash_sha256"]);
    let hash = STANDARD
        .decode(data["hash_sha256"].as_str().unwrap())
        .unwrap();
    let expected: String = ring_free_sha256_hex(DOCKER_VALUE.as_bytes());
    assert_eq!(String::from_utf8(hash).unwrap(), expected);
    let state = fs::read_to_string(fixture.root.join("state.toml")).unwrap();
    assert!(state.starts_with("version = 2"), "{state}");
    assert_eq!(state.matches("[[managed]]").count(), 1, "{state}");
    assert_eq!(state.matches("[[managed.members]]").count(), 2, "{state}");
}

/// SHA-256 hex via the system `sha256sum`, independent of the code under test.
fn ring_free_sha256_hex(value: &[u8]) -> String {
    let mut child = Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(value).unwrap();
    let output = child.wait_with_output().unwrap();
    String::from_utf8(output.stdout).unwrap()[..64].to_string()
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

/// etcd plus kube-apiserver on loopback, envtest-style: no kubelet, no
/// controllers. Killed on drop.
struct ApiServer {
    children: Vec<std::process::Child>,
    kubeconfig: PathBuf,
}

impl Drop for ApiServer {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl ApiServer {
    /// `None` unless `SECRET_MANAGER_TEST_KUBE_APISERVER` and
    /// `SECRET_MANAGER_TEST_ETCD` name the binaries.
    fn start(dir: &Path) -> Option<Self> {
        let apiserver = std::env::var_os("SECRET_MANAGER_TEST_KUBE_APISERVER")?;
        let etcd = std::env::var_os("SECRET_MANAGER_TEST_ETCD")?;
        let (client, peer, secure) = (free_port(), free_port(), free_port());
        let quiet = || std::process::Stdio::null();
        let mut server = ApiServer {
            children: Vec::new(),
            kubeconfig: dir.join("kubeconfig"),
        };
        server.children.push(
            Command::new(etcd)
                .arg(format!("--data-dir={}", dir.join("etcd").display()))
                .arg(format!("--listen-client-urls=http://127.0.0.1:{client}"))
                .arg(format!("--advertise-client-urls=http://127.0.0.1:{client}"))
                .arg(format!("--listen-peer-urls=http://127.0.0.1:{peer}"))
                .arg(format!(
                    "--initial-advertise-peer-urls=http://127.0.0.1:{peer}"
                ))
                .arg(format!("--initial-cluster=default=http://127.0.0.1:{peer}"))
                .stdout(quiet())
                .stderr(quiet())
                .spawn()
                .unwrap(),
        );
        // ECDSA service-account key pair: PKCS#8 signs, SubjectPublicKeyInfo verifies.
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        let key = dir.join("sa.pem");
        fs::write(
            &key,
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                STANDARD.encode(pkcs8.as_ref())
            ),
        )
        .unwrap();
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        // DER prefix of a P-256 SubjectPublicKeyInfo, followed by the 65-byte point.
        let mut spki = b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00".to_vec();
        spki.extend_from_slice(ring::signature::KeyPair::public_key(&pair).as_ref());
        let public = dir.join("sa.pub");
        fs::write(
            &public,
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                STANDARD.encode(&spki)
            ),
        )
        .unwrap();
        fs::write(
            dir.join("tokens.csv"),
            "envtest-token,admin,1,system:masters\n",
        )
        .unwrap();
        server.children.push(
            Command::new(apiserver)
                .arg(format!("--etcd-servers=http://127.0.0.1:{client}"))
                .arg(format!("--cert-dir={}", dir.join("certs").display()))
                .arg(format!("--secure-port={secure}"))
                .args(["--bind-address=127.0.0.1", "--advertise-address=127.0.0.1"])
                .arg("--service-cluster-ip-range=10.0.0.0/24")
                .arg(format!(
                    "--service-account-issuer=https://127.0.0.1:{secure}"
                ))
                .arg(format!("--service-account-key-file={}", public.display()))
                .arg(format!(
                    "--service-account-signing-key-file={}",
                    key.display()
                ))
                .arg(format!(
                    "--token-auth-file={}",
                    dir.join("tokens.csv").display()
                ))
                .arg("--authorization-mode=AlwaysAllow")
                // Loopback has no endpoint reconciliation: no kubernetes Service.
                .arg("--endpoint-reconciler-type=none")
                .stdout(quiet())
                .stderr(fs::File::create(dir.join("apiserver.log")).unwrap())
                .spawn()
                .unwrap(),
        );
        fs::write(
            &server.kubeconfig,
            format!(
                "apiVersion: v1\nkind: Config\ncurrent-context: envtest\n\
                 clusters: [{{name: envtest, cluster: {{server: 'https://127.0.0.1:{secure}', insecure-skip-tls-verify: true}}}}]\n\
                 users: [{{name: admin, user: {{token: envtest-token}}}}]\n\
                 contexts: [{{name: envtest, context: {{cluster: envtest, user: admin}}}}]\n"
            ),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        while !server
            .kubectl(&["get", "--raw", "/readyz"], None)
            .status
            .success()
        {
            let exited = server
                .children
                .iter_mut()
                .any(|child| !matches!(child.try_wait(), Ok(None)));
            assert!(
                !exited && std::time::Instant::now() < deadline,
                "kube-apiserver not ready: {}",
                fs::read_to_string(dir.join("apiserver.log")).unwrap_or_default()
            );
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        Some(server)
    }

    fn kubectl(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut command = Command::new("kubectl");
        command
            .args(["--context", "envtest"])
            .args(args)
            .env("KUBECONFIG", &self.kubeconfig)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.unwrap_or("").as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn secret(&self, name: &str) -> serde_json::Value {
        let output = self.kubectl(
            &[
                "-n",
                "syndb",
                "get",
                "secret",
                name,
                "-o",
                "json",
                "--show-managed-fields",
            ],
            None,
        );
        assert!(output.status.success(), "{}", text(&output));
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

fn data_owners(secret: &serde_json::Value) -> Vec<String> {
    secret["metadata"]["managedFields"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["fieldsV1"].get("f:data").is_some())
        .map(|entry| entry["manager"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn apiserver_adoption_hands_off_ownership_and_member_removal_deletes_the_key() {
    if !protection_available() {
        eprintln!(
            "SKIPPED: credential sync needs a no-swap systemd user scope and a logind inhibitor"
        );
        return;
    }
    let fixture = Fixture::new();
    let Some(api) = ApiServer::start(&fixture.root) else {
        eprintln!(
            "SKIPPED: set SECRET_MANAGER_TEST_KUBE_APISERVER and SECRET_MANAGER_TEST_ETCD to run \
             against a real apiserver"
        );
        return;
    };
    // The real kubectl, talking to the test apiserver.
    fs::remove_file(fixture.root.join("bin/kubectl")).unwrap();
    let sync = |extra: &[&str]| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secret-manager"));
        command
            .args(["sync", "--no-flake", "--config"])
            .arg(fixture.root.join("targets.json"))
            .arg("--state")
            .arg(fixture.root.join("state.toml"))
            .args(extra)
            .env("SECRET_MANAGER_STORE", &fixture.root)
            .env_remove("SECRET_MANAGER_SYNC_REPLAY")
            .env_remove("SECRET_MANAGER_AGE_IDENTITIES")
            .env("PATH", &fixture.path)
            .env("KUBECTL_CALLS", &fixture.calls)
            .env("KUBECONFIG", &api.kubeconfig)
            .current_dir(&fixture.root);
        command.output().unwrap()
    };
    let targets = |b_secret: &str| {
        fs::write(
            fixture.root.join("targets.json"),
            serde_json::json!({"hosts":[{"targets":{
                "a":{"secret":"age/a-opaque.age","name":"A","kubernetes":[
                    {"context":"envtest","namespace":"syndb","secret":"api","format":"opaque","key":"a"}]},
                "b":{"secret":"age/b-docker.age","name":"B","kubernetes":[
                    {"context":"envtest","namespace":"syndb","secret":b_secret,"format":"opaque","key":"b"}]}
            }}]})
            .to_string(),
        )
        .unwrap();
    };
    assert!(
        api.kubectl(&["create", "namespace", "syndb"], None)
            .status
            .success()
    );
    // Seed through a foreign manager, as the legacy writer did.
    let seeded = api.kubectl(
        &[
            "-n",
            "syndb",
            "create",
            "secret",
            "generic",
            "api",
            &format!("--from-literal=a={OPAQUE_VALUE}"),
            &format!("--from-literal=b={DOCKER_VALUE}"),
        ],
        None,
    );
    assert!(seeded.status.success(), "{}", text(&seeded));
    assert_eq!(data_owners(&api.secret("api")), ["kubectl-create"]);

    // A6: server-side apply honours a stale resourceVersion as a precondition.
    let stale = api.kubectl(
        &["apply", "--server-side", "--field-manager", "probe", "-f", "-"],
        Some(r#"{"apiVersion":"v1","kind":"Secret","metadata":{"name":"api","namespace":"syndb","resourceVersion":"1"},"data":{}}"#),
    );
    assert!(!stale.status.success(), "stale resourceVersion was applied");
    assert!(text(&stale).contains("modified"), "{}", text(&stale));

    targets("api");
    let verified = sync(&["--verify"]);
    assert!(verified.status.success(), "{}", text(&verified));
    let printed = text(&verified);
    assert!(printed.contains("secret/api key a: equal"), "{printed}");
    assert!(printed.contains("secret/api key b: equal"), "{printed}");
    assert!(
        printed.contains("foreign-manager kubectl-create"),
        "{printed}"
    );
    assert_eq!(leaks(&printed), Vec::<&str>::new(), "{printed}");

    let adopted = sync(&["--adopt"]);
    assert!(adopted.status.success(), "{}", text(&adopted));
    assert_eq!(leaks(&text(&adopted)), Vec::<&str>::new());
    assert_eq!(data_owners(&api.secret("api")), ["secret-manager"]);
    let confirmed = text(&sync(&["--verify"]));
    assert!(!confirmed.contains("foreign-manager"), "{confirmed}");

    // Moving member b to another Secret drops key b from `api`; the Secret stays.
    targets("other");
    let moved = sync(&[]);
    assert!(moved.status.success(), "{}", text(&moved));
    let live = api.secret("api");
    let keys: Vec<&String> = live["data"].as_object().unwrap().keys().collect();
    assert_eq!(keys, ["a"]);
    assert_eq!(
        STANDARD
            .decode(live["data"]["a"].as_str().unwrap())
            .unwrap(),
        OPAQUE_VALUE.as_bytes()
    );
    assert!(api.secret("other")["data"].get("b").is_some());
}
