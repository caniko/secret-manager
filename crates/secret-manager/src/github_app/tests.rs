use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
};

fn policy() -> Config {
    Config {
        version: 1,
        slug: "caniko-paperclip-review".into(),
        owner: "caniko".into(),
        repository: "caniko/paperclip".into(),
        homepage: "https://github.com/caniko/paperclip".into(),
        source: "age/secrets/review.age".into(),
        recipients: vec!["age1fixture".into()],
        permissions: BTreeMap::from([
            ("contents".into(), "read".into()),
            ("pull_requests".into(), "write".into()),
        ]),
        key_secret_name: "COMMITPERCLIP_KEY".into(),
        app_id_variable: "COMMITPERCLIP_APP_ID".into(),
        app_slug_variable: "COMMITPERCLIP_APP_SLUG".into(),
    }
}

fn app() -> App {
    App {
        id: 123,
        slug: policy().slug,
        owner: config::Owner {
            login: "caniko".into(),
        },
        permissions: policy().permissions,
    }
}

fn pem() -> Zeroizing<String> {
    let bytes = process::capture(
        Command::new("openssl").args(["genrsa", "-traditional", "2048"]),
        None,
    )
    .unwrap();
    Zeroizing::new(String::from_utf8(bytes.to_vec()).unwrap())
}

struct FixtureApi {
    app: App,
    installation: serde_json::Value,
    repositories: serde_json::Value,
    revoked: Cell<bool>,
    token_scope: RefCell<Option<serde_json::Value>>,
}

impl FixtureApi {
    fn new() -> Self {
        Self {
            app: app(),
            installation: serde_json::json!({"id": 456, "app_id": 123,
            "account": {"login": "caniko"}, "permissions": policy().permissions,
            "repository_selection": "selected", "suspended_at": null}),
            repositories: serde_json::json!({"total_count": 1, "repositories": [{"id": 789, "full_name": "caniko/paperclip"}]}),
            revoked: Cell::new(false),
            token_scope: RefCell::new(None),
        }
    }
}

impl Api for FixtureApi {
    fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&serde_json::Value>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(token.is_some(), "authenticated request required");
        let value = match (method, path) {
            (Method::GET, "/app") => serde_json::to_value(&self.app)?,
            (Method::GET, "/repos/caniko/paperclip/installation") => self.installation.clone(),
            (Method::POST, "/app/installations/456/access_tokens") => {
                *self.token_scope.borrow_mut() = body.cloned();
                serde_json::json!({"token": "fixture-ephemeral-token", "expires_at": "2026-10-02T20:00:00Z", "permissions": policy().permissions})
            }
            (Method::GET, "/installation/repositories") => self.repositories.clone(),
            (Method::DELETE, "/installation/token") => {
                self.revoked.set(true);
                serde_json::json!({})
            }
            _ => anyhow::bail!("unexpected request"),
        };
        Ok(Zeroizing::new(serde_json::to_vec(&value)?))
    }
}

#[test]
fn verified_receipt_binds_key_app_installation_and_single_repository() {
    let api = FixtureApi::new();
    let key = Key::parse(&pem()).unwrap();
    let receipt = api::verify(&api, &policy(), &app(), &key).unwrap();
    assert_eq!(receipt.repository_id, 789);
    assert_eq!(receipt.installation_id, 456);
    assert_eq!(receipt.public_key_sha256, key.fingerprint());
    assert_eq!(
        api.token_scope.borrow().as_ref().unwrap()["repositories"],
        serde_json::json!(["paperclip"])
    );
    assert!(api.revoked.get());
    let serialized = serde_json::to_string(&receipt).unwrap();
    assert!(!serialized.contains("fixture-ephemeral-token"));
    assert!(!serialized.contains("PRIVATE KEY"));
}

#[test]
fn wrong_app_identity_and_excess_permissions_refuse_before_minting() {
    let key = Key::parse(&pem()).unwrap();
    for change in ["id", "owner", "permissions"] {
        let mut api = FixtureApi::new();
        match change {
            "id" => api.app.id = 999,
            "owner" => api.app.owner.login = "paperclipai".into(),
            _ => {
                api.app
                    .permissions
                    .insert("contents".into(), "write".into());
            }
        }
        assert!(api::verify(&api, &policy(), &app(), &key).is_err());
        assert!(api.token_scope.borrow().is_none());
    }
}

#[test]
fn wrong_repository_or_broadened_scope_refuses_and_revokes_token() {
    let key = Key::parse(&pem()).unwrap();
    for repositories in [
        serde_json::json!({"total_count": 1, "repositories": [{"id": 1, "full_name": "caniko/other"}]}),
        serde_json::json!({"total_count": 2, "repositories": [{"id": 789, "full_name": "caniko/paperclip"}]}),
    ] {
        let mut api = FixtureApi::new();
        api.repositories = repositories;
        assert!(api::verify(&api, &policy(), &app(), &key).is_err());
        assert!(api.revoked.get());
    }
}

#[test]
fn suspended_or_all_repository_installation_is_refused() {
    let key = Key::parse(&pem()).unwrap();
    for field in ["suspended_at", "repository_selection"] {
        let mut api = FixtureApi::new();
        api.installation[field] = serde_json::json!(if field == "suspended_at" {
            "2026-10-02"
        } else {
            "all"
        });
        assert!(api::verify(&api, &policy(), &app(), &key).is_err());
        assert!(api.token_scope.borrow().is_none());
    }
}

#[test]
fn jwt_signature_and_github_fingerprint_match_real_openssl() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let pem = pem();
    let key = Key::parse(&pem).unwrap();
    let spki = process::capture(
        Command::new("openssl").args(["rsa", "-pubout", "-outform", "DER"]),
        Some(pem.as_bytes()),
    )
    .unwrap();
    assert_eq!(key.fingerprint(), sha256(&spki));
    let public = process::capture(
        Command::new("openssl").args(["rsa", "-RSAPublicKey_out", "-outform", "DER"]),
        Some(pem.as_bytes()),
    )
    .unwrap();
    let jwt = key.jwt(123, 1000).unwrap();
    let (message, signature) = jwt.rsplit_once('.').unwrap();
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        public.as_slice(),
    )
    .verify(
        message.as_bytes(),
        &URL_SAFE_NO_PAD.decode(signature).unwrap(),
    )
    .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(message.split_once('.').unwrap().1)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        payload,
        serde_json::json!({"iat": 970, "exp": 1120, "iss": "123"})
    );
}

#[test]
fn transaction_locks_policy_and_store_and_detects_checkpoint_tampering() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("transaction");
    let mut transaction = Transaction::open(&directory, root.path(), &policy()).unwrap();
    assert!(Transaction::open(&directory, root.path(), &policy()).is_err());
    transaction.checkpoint(b"encrypted fixture").unwrap();
    fs::write(directory.join("issued.age"), b"tampered").unwrap();
    assert!(transaction.checked_checkpoint().is_err());
    drop(transaction);
    let mut changed = policy();
    changed.repository = "caniko/other".into();
    assert!(Transaction::open(&directory, root.path(), &changed).is_err());
    assert!(Transaction::open(&directory, &root.path().join("other"), &policy()).is_err());
}

#[test]
fn symlinks_and_shared_transaction_directories_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("transaction");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Transaction::open(&directory, root.path(), &policy()).is_err());
    symlink(&directory, root.path().join("link")).unwrap();
    assert!(Transaction::open(&root.path().join("link"), root.path(), &policy()).is_err());
    fs::create_dir(root.path().join("age")).unwrap();
    symlink(root.path(), root.path().join("age/secrets")).unwrap();
    assert!(source_path(root.path(), &policy()).is_err());
}

#[test]
fn interrupted_publication_resumes_from_real_age_ciphertext_without_replacing_source() {
    let root = tempfile::tempdir().unwrap();
    let identity = process::capture(&mut Command::new("rage-keygen"), None).unwrap();
    let recipient =
        process::capture(Command::new("rage-keygen").arg("-y"), Some(&identity)).unwrap();
    let identity_path = root.path().join("identity");
    atomic_write(&identity_path, &identity).unwrap();
    let mut config = policy();
    config.recipients = vec![
        String::from_utf8(recipient.to_vec())
            .unwrap()
            .trim()
            .to_owned(),
    ];
    let common = CommonArgs {
        config: root.path().join("policy.json"),
        transaction: root.path().join("transaction"),
        store: Some(root.path().to_owned()),
        identities: vec![identity_path.clone()],
    };
    let store = crate::store::Store {
        root: root.path().to_owned(),
    };
    let mut transaction = Transaction::open(&common.transaction, &store.root, &config).unwrap();
    let issued = Issued {
        app: app(),
        pem: pem(),
    };
    let payload = Zeroizing::new(serde_json::to_vec(&issued).unwrap());
    transaction
        .checkpoint(&process::encrypt(&config, &payload).unwrap())
        .unwrap();
    settle(&config, &mut transaction, &issued).unwrap();
    let mut calls = 0;
    let partial = Publication {
        common: &common,
        config: &config,
        store: &store,
        transaction: &mut transaction,
        issued: &issued,
        replace_key: false,
    }
    .run(&FixtureApi::new(), |_, _, repo, _| {
        assert_eq!(repo, "caniko/paperclip");
        calls += 1;
        ensure!(calls != 2, "simulated variable publication failure");
        Ok(())
    });
    assert!(partial.is_err());
    assert_eq!(transaction.state.published_slots, ["COMMITPERCLIP_KEY"]);
    assert!(!transaction.directory.join("receipt.json").exists());
    let source = store.root.join(&config.source);
    let source_before = fs::read(&source).unwrap();
    assert!(!String::from_utf8_lossy(&source_before).contains("PRIVATE KEY"));
    drop(transaction);
    let mut transaction = Transaction::open(&common.transaction, &store.root, &config).unwrap();
    let recovered = common.issued(&store, &transaction).unwrap();
    let mut slots = Vec::new();
    Publication {
        common: &common,
        config: &config,
        store: &store,
        transaction: &mut transaction,
        issued: &recovered,
        replace_key: false,
    }
    .run(&FixtureApi::new(), |kind, name, _, value| {
        if kind == "secret" {
            assert_eq!(value, recovered.pem.as_bytes());
        }
        slots.push(name.to_owned());
        Ok(())
    })
    .unwrap();
    assert_eq!(
        slots,
        [
            "COMMITPERCLIP_KEY",
            "COMMITPERCLIP_APP_ID",
            "COMMITPERCLIP_APP_SLUG"
        ]
    );
    assert_eq!(fs::read(&source).unwrap(), source_before);
    assert_eq!(transaction.state.phase, "published");
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(transaction.directory.join("receipt.json")).unwrap())
            .unwrap();
    assert_eq!(receipt["actionsSlotQualified"], false);
    assert_eq!(receipt["verification"]["appId"], 123);

    // A second GitHub-issued key cannot silently replace the enrolled source.
    let replacement = Issued {
        app: app(),
        pem: pem(),
    };
    let mut rotation =
        Transaction::open(&root.path().join("rotation"), &store.root, &config).unwrap();
    rotation
        .checkpoint(
            &process::encrypt(
                &config,
                &Zeroizing::new(serde_json::to_vec(&replacement).unwrap()),
            )
            .unwrap(),
        )
        .unwrap();
    settle(&config, &mut rotation, &replacement).unwrap();
    let mut pushed = false;
    let refused = Publication {
        common: &common,
        config: &config,
        store: &store,
        transaction: &mut rotation,
        issued: &replacement,
        replace_key: false,
    }
    .run(&FixtureApi::new(), |_, _, _, _| {
        pushed = true;
        Ok(())
    });
    assert!(refused.is_err());
    assert!(!pushed);
    assert_eq!(fs::read(&source).unwrap(), source_before);
    Publication {
        common: &common,
        config: &config,
        store: &store,
        transaction: &mut rotation,
        issued: &replacement,
        replace_key: true,
    }
    .run(&FixtureApi::new(), |_, _, _, _| Ok(()))
    .unwrap();
    assert_eq!(
        fs::read(rotation.directory.join("previous.age")).unwrap(),
        source_before
    );
    let decrypted =
        Zeroizing::new(crate::age::decrypt_with_identities(&source, &[identity_path]).unwrap());
    assert_eq!(
        Key::parse(&decrypted).unwrap().fingerprint(),
        Key::parse(&replacement.pem).unwrap().fingerprint()
    );
}
