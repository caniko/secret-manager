//! GitHub-issued app credentials: guided enrollment, encrypted checkpoints,
//! repository-constrained verification and exact Actions-slot publication.
mod api;
mod config;
mod crypto;
mod enrollment;
mod process;
mod state;

use anyhow::{Context, Result, ensure};
use api::{Api, Github};
use clap::{Args, Subcommand};
use config::{App, Config};
use crypto::{Key, sha256};
use rand::RngCore;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use state::{Transaction, atomic_write, read_bounded, source_path};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub enum GithubCmd {
    /// Enroll, adopt and publish GitHub-issued App credentials.
    #[command(subcommand)]
    App(AppCmd),
}

#[derive(Subcommand)]
pub enum AppCmd {
    /// Serve a loopback manifest/callback flow; publish after installation consent.
    Enroll(EnrollArgs),
    /// Adopt an existing GitHub-issued PEM into an encrypted transaction.
    Import(ImportArgs),
    /// Verify the app and selected repository, then publish exact Actions slots.
    Publish(PublishArgs),
    /// Verify the encrypted source credential (destination use is proven by CI).
    Verify(CommonArgs),
    /// Add the declared repository to an existing, verified selected installation.
    Installation(InstallationArgs),
}

#[derive(Args)]
pub struct CommonArgs {
    /// Public GitHub App policy JSON.
    #[arg(long)]
    config: PathBuf,
    /// Private operator-owned transaction directory; reuse it for retries.
    #[arg(long)]
    transaction: PathBuf,
    /// Secret-store root; defaults to normal SECRET_MANAGER_STORE discovery.
    #[arg(long)]
    store: Option<PathBuf>,
    /// age decryption identities, using the existing store fallback contract.
    #[arg(long = "identity")]
    identities: Vec<PathBuf>,
}

#[derive(Args)]
pub struct EnrollArgs {
    #[command(flatten)]
    common: CommonArgs,
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(1..=3500))]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 0)]
    port: u16,
}

#[derive(Args)]
pub struct ImportArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Issued GitHub App ID. JWT authentication must confirm it.
    #[arg(long)]
    app_id: u64,
    /// Existing GitHub-issued private regular PEM file with mode 0600.
    #[arg(long)]
    pem_file: PathBuf,
}

#[derive(Args)]
pub struct PublishArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Rotate the encrypted source after verifying the new issued key.
    /// The previous encrypted source is retained inside this transaction.
    #[arg(long)]
    replace_key: bool,
}

#[derive(Args)]
pub struct InstallationArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Existing installation ID from GitHub. Without it, show consent URL.
    #[arg(long)]
    installation_id: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct Issued {
    #[serde(flatten)]
    app: App,
    #[serde(
        deserialize_with = "secret_string",
        serialize_with = "serialize_secret"
    )]
    pem: Zeroizing<String>,
}

fn serialize_secret<S: serde::Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    value.as_str().serialize(serializer)
}

fn secret_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn random_nonce() -> String {
    let mut bytes = [0; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

impl GithubCmd {
    pub fn run(self) -> Result<()> {
        let Self::App(command) = self;
        command.run()
    }
}

impl CommonArgs {
    fn load(&self) -> Result<(Config, crate::store::Store, Transaction)> {
        let config: Config = serde_json::from_slice(&read_bounded(&self.config)?)?;
        config.validate()?;
        let store = if let Some(root) = &self.store {
            crate::store::Store { root: root.clone() }
        } else {
            crate::store::Store::discover()?
        };
        let store = crate::store::Store {
            root: store.root.canonicalize()?,
        };
        ensure!(
            !store.root.starts_with("/nix/store"),
            "credential store must be outside the Nix store"
        );
        let transaction = Transaction::open(&self.transaction, &store.root, &config)?;
        Ok((config, store, transaction))
    }

    fn issued(&self, store: &crate::store::Store, transaction: &mut Transaction) -> Result<Issued> {
        let path = transaction.checked_checkpoint()?;
        let identities = store.resolve_identities(&self.identities)?;
        let plaintext = Zeroizing::new(crate::age::decrypt_with_identities(&path, &identities)?);
        let issued: Issued = serde_json::from_str(&plaintext)?;
        let expected = transaction
            .state
            .app
            .as_ref()
            .context("transaction has no issued app identity")?;
        ensure!(
            issued.app.id == expected.id
                && issued.app.slug == expected.slug
                && issued.app.owner.login == expected.owner.login,
            "encrypted checkpoint app identity mismatch"
        );
        ensure!(
            transaction.state.public_key_sha256.as_ref()
                == Some(&Key::parse(&issued.pem)?.fingerprint()),
            "encrypted checkpoint key fingerprint mismatch"
        );
        Ok(issued)
    }
}

impl AppCmd {
    fn run(self) -> Result<()> {
        match self {
            Self::Enroll(args) => enrollment::run(args),
            Self::Import(args) => {
                let (config, store, mut transaction) = args.common.load()?;
                ensure!(
                    matches!(
                        transaction.state.phase.as_str(),
                        "prepared" | "capture-started"
                    ),
                    "use a fresh transaction to import another key"
                );
                state::private_metadata(&args.pem_file, false)?;
                let bytes = read_bounded(&args.pem_file)?;
                let pem = Zeroizing::new(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|_| anyhow::anyhow!("PEM must be UTF-8"))?,
                );
                let key = Key::parse(&pem)?;
                let jwt = key.jwt(args.app_id, now()?)?;
                let github = Github::new()?;
                let app: App = serde_json::from_slice(&github.request(
                    Method::GET,
                    "/app",
                    Some(&jwt),
                    None,
                )?)?;
                ensure!(
                    app.id == args.app_id,
                    "key authenticated a different app ID"
                );
                app.validate(&config)?;
                let issued = Issued { app, pem };
                if transaction.directory.join("issued.age").exists() {
                    let previous = args.common.issued(&store, &mut transaction)?;
                    ensure!(
                        Key::parse(&previous.pem)?.fingerprint() == key.fingerprint(),
                        "retry PEM differs from encrypted checkpoint"
                    );
                } else {
                    if let Some(expected) = &transaction.state.public_key_sha256 {
                        ensure!(
                            *expected == key.fingerprint(),
                            "retry PEM differs from pending import"
                        );
                    }
                    transaction.state.app = Some(issued.app.clone());
                    transaction.state.public_key_sha256 = Some(key.fingerprint());
                    transaction.state.phase = "capture-started".into();
                    transaction.save()?;
                    let serialized = Zeroizing::new(serde_json::to_vec(&issued)?);
                    transaction.checkpoint(&process::encrypt(&config, &serialized)?)?;
                }
                settle(&config, &mut transaction, &issued)?;
                println!(
                    "Encrypted GitHub-issued key adopted. Installation and publication remain explicit."
                );
                Ok(())
            }
            Self::Publish(args) => {
                let (config, store, mut transaction) = args.common.load()?;
                let issued = args.common.issued(&store, &mut transaction)?;
                publish(
                    &args.common,
                    &config,
                    &store,
                    &mut transaction,
                    &issued,
                    args.replace_key,
                )
            }
            Self::Verify(args) => {
                let (config, store, transaction) = args.load()?;
                let app = transaction
                    .state
                    .app
                    .as_ref()
                    .context("enrollment is incomplete")?;
                let source = source_path(&store.root, &config)?;
                let identities = store.resolve_identities(&args.identities)?;
                let pem =
                    Zeroizing::new(crate::age::decrypt_with_identities(&source, &identities)?);
                let key = Key::parse(&pem)?;
                ensure!(
                    transaction.state.public_key_sha256.as_ref() == Some(&key.fingerprint()),
                    "source key differs from enrolled credential"
                );
                let receipt = api::verify(&Github::new()?, &config, app, &key)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "kind": "source-credential-verification", "verification": receipt,
                        "actionsSlotQualified": false,
                    }))?
                );
                Ok(())
            }
            Self::Installation(args) => {
                let (config, store, mut transaction) = args.common.load()?;
                let issued = args.common.issued(&store, &mut transaction)?;
                let key = Key::parse(&issued.pem)?;
                let github = Github::new()?;
                api::authenticated_app(&github, &config, &issued.app, &key)?;
                let Some(id) = args.installation_id else {
                    println!(
                        "Authorize selected-repository installation: {}",
                        installation_url(&issued.app)
                    );
                    anyhow::bail!(
                        "GitHub installation authorization is required before publication"
                    );
                };
                let jwt = key.jwt(issued.app.id, now()?)?;
                let installation: api::Installation = serde_json::from_slice(&github.request(
                    Method::GET,
                    &format!("/app/installations/{id}"),
                    Some(&jwt),
                    None,
                )?)?;
                installation.validate(&config, &issued.app)?;
                ensure!(installation.id == id, "installation ID mismatch");
                let repository: serde_json::Value = serde_json::from_slice(&process::gh(
                    &[
                        "api",
                        "--hostname",
                        "github.com",
                        &format!("repos/{}", config.repository),
                    ],
                    None,
                )?)?;
                ensure!(
                    repository["full_name"].as_str() == Some(&config.repository)
                        && repository["permissions"]["admin"].as_bool() == Some(true),
                    "operator must administer the declared repository"
                );
                let repo_id = repository["id"]
                    .as_u64()
                    .filter(|id| *id > 0)
                    .context("repository has no issued ID")?;
                process::gh(
                    &[
                        "api",
                        "--hostname",
                        "github.com",
                        "--method",
                        "PUT",
                        &format!("user/installations/{id}/repositories/{repo_id}"),
                    ],
                    None,
                )?;
                let receipt = api::verify(&github, &config, &issued.app, &key)?;
                println!("{}", serde_json::to_string_pretty(&receipt)?);
                Ok(())
            }
        }
    }
}

fn settle(config: &Config, transaction: &mut Transaction, issued: &Issued) -> Result<()> {
    issued.app.validate(config)?;
    let key = Key::parse(&issued.pem)?;
    if let Some(expected) = &transaction.state.app {
        ensure!(
            issued.app.id == expected.id
                && issued.app.slug == expected.slug
                && issued.app.owner.login == expected.owner.login,
            "encrypted checkpoint app identity mismatch"
        );
    }
    if let Some(expected) = &transaction.state.public_key_sha256 {
        ensure!(
            *expected == key.fingerprint(),
            "encrypted checkpoint key fingerprint mismatch"
        );
    }
    transaction.state.app = Some(issued.app.clone());
    transaction.state.public_key_sha256 = Some(key.fingerprint());
    transaction.state.phase = "enrolled".into();
    transaction.save()
}

fn installation_url(app: &App) -> String {
    format!("https://github.com/apps/{}/installations/new", app.slug)
}

fn publish(
    common: &CommonArgs,
    config: &Config,
    store: &crate::store::Store,
    transaction: &mut Transaction,
    issued: &Issued,
    replace_key: bool,
) -> Result<()> {
    Publication {
        common,
        config,
        store,
        transaction,
        issued,
        replace_key,
    }
    .run(&Github::new()?, |kind, name, repo, value| {
        process::gh(&[kind, "set", name, "--repo", repo], Some(value)).map(|_| ())
    })
}

struct Publication<'a> {
    common: &'a CommonArgs,
    config: &'a Config,
    store: &'a crate::store::Store,
    transaction: &'a mut Transaction,
    issued: &'a Issued,
    replace_key: bool,
}

impl Publication<'_> {
    fn run(
        self,
        api: &impl Api,
        mut push: impl FnMut(&str, &str, &str, &[u8]) -> Result<()>,
    ) -> Result<()> {
        let Self {
            common,
            config,
            store,
            transaction,
            issued,
            replace_key,
        } = self;
        issued.app.validate(config)?;
        let key = Key::parse(&issued.pem)?;
        ensure!(
            transaction.state.public_key_sha256.as_ref() == Some(&key.fingerprint()),
            "checkpoint key fingerprint mismatch"
        );
        let source = source_path(&store.root, config)?;
        use std::os::unix::fs::OpenOptionsExt;
        let lock_path = source.with_extension("publication-lock");
        let publication_lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)?;
        state::private_metadata(&lock_path, false)?;
        state::try_lock_exclusive(&publication_lock)
            .context("another transaction owns publication of this source")?;
        let verification = api::verify(api, config, &issued.app, &key)?;
        let id_path = source.with_extension("app-id");
        let slug_path = source.with_extension("app-slug");
        for (path, value) in [
            (&id_path, issued.app.id.to_string()),
            (&slug_path, issued.app.slug.clone()),
        ] {
            if path.exists() {
                ensure!(
                    read_bounded(path)?.as_slice() == value.as_bytes(),
                    "public identity output belongs to a different app"
                );
            }
        }
        let replace = if source.exists() {
            let identities = store.resolve_identities(&common.identities)?;
            let old = Zeroizing::new(crate::age::decrypt_with_identities(&source, &identities)?);
            if Key::parse(&old)?.fingerprint() == key.fingerprint() {
                false
            } else {
                ensure!(
                    replace_key,
                    "source holds a different key; use --replace-key after reviewing the rotation"
                );
                let backup = transaction.directory.join("previous.age");
                let previous = read_bounded(&source)?;
                if backup.exists() {
                    ensure!(
                        read_bounded(&backup)?.as_slice() == previous.as_slice(),
                        "rotation backup differs from current source; inspect before retrying"
                    );
                } else {
                    atomic_write(&backup, &previous)?;
                }
                true
            }
        } else {
            true
        };
        if replace {
            atomic_write(&source, &process::encrypt(config, issued.pem.as_bytes())?)?;
        }
        atomic_write(&id_path, issued.app.id.to_string().as_bytes())?;
        atomic_write(&slug_path, issued.app.slug.as_bytes())?;
        // Each successful slot is checkpointed. Retrying republishes the same
        // verified values, including after an ambiguous gh/network failure.
        let app_id = issued.app.id.to_string();
        for (kind, name, value) in [
            ("secret", &config.key_secret_name, issued.pem.as_bytes()),
            ("variable", &config.app_id_variable, app_id.as_bytes()),
            (
                "variable",
                &config.app_slug_variable,
                issued.app.slug.as_bytes(),
            ),
        ] {
            push(kind, name, &config.repository, value)?;
            if !transaction.state.published_slots.contains(name) {
                transaction.state.published_slots.push(name.clone());
            }
            transaction.save()?;
        }
        transaction.state.phase = "published".into();
        transaction.save()?;
        let receipt = serde_json::json!({
            "version": 1, "kind": "github-app-publication", "policySha256": transaction.state.policy_sha256,
            "checkpointSha256": transaction.state.checkpoint_sha256, "sourceCiphertextSha256": sha256(&read_bounded(&source)?),
            "verification": verification, "publishedSlots": transaction.state.published_slots,
            "actionsSlotQualified": false, "requiredNextGate": "trusted review workflow using the installed Actions secret",
        });
        atomic_write(
            &transaction.directory.join("receipt.json"),
            &serde_json::to_vec_pretty(&receipt)?,
        )?;
        println!("{}", serde_json::to_string_pretty(&receipt)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
