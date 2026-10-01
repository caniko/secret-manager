//! Publish existing public OpenPGP keys to authenticated forge accounts.

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use clap::{Args, Subcommand};
use nix_manager_core::forge::gpg::{self as forge, AccountGpgKeys, GpgKey};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const MAX_KEY_BYTES: usize = 1024 * 1024;

#[derive(Subcommand)]
pub enum GpgCmd {
    /// Publish one armored public key to the selected forge accounts.
    Publish(PublishArgs),
}

#[derive(Args)]
pub struct PublishArgs {
    /// Existing ASCII-armored public key, relative to the working directory.
    pub public_key: PathBuf,
    #[arg(long)]
    pub codefloe: bool,
    #[arg(long)]
    pub github: bool,
    #[arg(long)]
    pub codeberg: bool,
    /// Additional Forgejo host. Uses that host's existing fj authentication.
    #[arg(long = "forgejo", value_name = "HOST")]
    pub forgejo: Vec<String>,
    /// Inspect the key and destinations without authentication or network calls.
    #[arg(long, conflicts_with = "check")]
    pub dry_run: bool,
    /// Check registration using read-only API calls; fail if any key is missing.
    #[arg(long)]
    pub check: bool,
    /// Require this full fingerprint before contacting any forge.
    #[arg(long, value_name = "FINGERPRINT")]
    pub expected_fingerprint: Option<String>,
}

impl GpgCmd {
    pub fn run(self) -> Result<()> {
        match self {
            Self::Publish(args) => args.run(),
        }
    }
}

impl PublishArgs {
    pub fn run(self) -> Result<()> {
        let destinations = self.destinations()?;
        let mut bytes = Vec::new();
        File::open(&self.public_key)
            .with_context(|| format!("read {}", self.public_key.display()))?
            .take((MAX_KEY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_KEY_BYTES, "public key exceeds 1 MiB");
        let key =
            PublicKey::parse(String::from_utf8(bytes).context("public key must be ASCII armor")?)?;
        if let Some(expected) = self.expected_fingerprint {
            let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
            ensure!(
                key.fingerprint.eq_ignore_ascii_case(&expected),
                "public-key fingerprint {} does not match expected {expected}",
                key.fingerprint
            );
        }
        println!("GPG fingerprint: {}", key.fingerprint);
        if self.dry_run {
            for destination in destinations {
                println!("{}: would register public key", destination.label());
            }
            return Ok(());
        }
        let results = publish_with_backend(&key, &destinations, self.check, &mut ForgeBackend);
        let mut failures = 0;
        for (destination, result) in destinations.iter().zip(results) {
            match result {
                Ok(registration) => {
                    println!(
                        "{} ({}): {}",
                        destination.label(),
                        registration.login,
                        match registration.status {
                            RegistrationStatus::Added => "added",
                            RegistrationStatus::Present => "already registered",
                        }
                    );
                    println!(
                        "  can sign: {}; key ownership verified: {}",
                        registration.key.can_sign,
                        registration.key.verified.map_or("not reported", |v| if v {
                            "yes"
                        } else {
                            "no"
                        })
                    );
                    for email in &registration.key.emails {
                        println!(
                            "  email {}: {}",
                            email.email,
                            if email.verified {
                                "verified"
                            } else {
                                "unverified"
                            }
                        );
                    }
                }
                Err(error) => {
                    failures += 1;
                    eprintln!("{}: failed: {error:#}", destination.label());
                }
            }
        }
        ensure!(
            failures == 0,
            "GPG registration incomplete on {failures} platform(s); retry the same command after resolving the reported errors"
        );
        Ok(())
    }

    fn destinations(&self) -> Result<Vec<Destination>> {
        let mut destinations = BTreeSet::new();
        if self.codeberg {
            destinations.insert(Destination::Forgejo("codeberg.org".into()));
        }
        if self.codefloe {
            destinations.insert(Destination::Forgejo("codefloe.com".into()));
        }
        if self.github {
            destinations.insert(Destination::Github);
        }
        for host in &self.forgejo {
            let url = url::Url::parse(&format!("https://{host}"))?;
            ensure!(
                url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && !host.contains(['/', '\\'])
                    && !host.chars().any(char::is_whitespace),
                "expected a Forgejo host name, not a URL or path: {host}"
            );
            destinations.insert(Destination::Forgejo(host.to_ascii_lowercase()));
        }
        ensure!(
            !destinations.is_empty(),
            "select --codefloe, --github, --codeberg, or --forgejo HOST"
        );
        Ok(destinations.into_iter().collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Destination {
    Forgejo(String),
    Github,
}

impl Destination {
    fn label(&self) -> &str {
        match self {
            Self::Forgejo(host) => host,
            Self::Github => "github.com",
        }
    }
}

struct PublicKey {
    armor: String,
    fingerprint: String,
    key_id: String,
}

impl PublicKey {
    fn parse(armor: String) -> Result<Self> {
        ensure!(armor.len() <= MAX_KEY_BYTES, "public key exceeds 1 MiB");
        ensure!(
            armor
                .trim()
                .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----")
                && armor.trim().ends_with("-----END PGP PUBLIC KEY BLOCK-----")
                && armor.matches("-----BEGIN PGP").count() == 1
                && !armor.contains("PRIVATE KEY"),
            "expected exactly one ASCII-armored OpenPGP public-key block"
        );
        let KeyIdentity {
            fingerprint,
            key_id,
        } = inspect_key(armor.as_bytes())?;
        Ok(Self {
            armor,
            fingerprint,
            key_id,
        })
    }
}

struct KeyIdentity {
    fingerprint: String,
    key_id: String,
}

fn inspect_key(bytes: &[u8]) -> Result<KeyIdentity> {
    ensure!(bytes.len() <= MAX_KEY_BYTES, "public key exceeds 1 MiB");
    // show-keys does not import; a temporary GNUPGHOME also isolates trustdb,
    // options and any incidental GnuPG state from the operator's keyring.
    let home = tempfile::tempdir()?;
    let mut child = Command::new("gpg")
        .args(["--no-options", "--batch", "--homedir"])
        .arg(home.path())
        .args(["--with-colons", "--with-fingerprint", "--show-keys"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("run gpg to inspect public key")?;
    let mut stdin = child.stdin.take().context("gpg stdin was not captured")?;
    let bytes = bytes.to_vec();
    // Drain output while writing input, including adversarial multi-key input
    // that can otherwise fill both pipes before either process finishes.
    let writer = std::thread::spawn(move || stdin.write_all(&bytes));
    let output = child.wait_with_output();
    let written = writer
        .join()
        .map_err(|_| anyhow::anyhow!("gpg input writer panicked"))?;
    let output = output?;
    ensure!(
        output.status.success(),
        "GnuPG rejected the public key: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    written.context("write public key to gpg")?;
    fingerprint_from_listing(&String::from_utf8(output.stdout)?)
}

fn fingerprint_from_listing(listing: &str) -> Result<KeyIdentity> {
    let mut primary_count = 0;
    let mut primary_pending = false;
    let mut fingerprint = None;
    let mut key_id = None;
    for line in listing.lines() {
        let fields: Vec<_> = line.split(':').collect();
        match fields[0] {
            "sec" | "ssb" => bail!("private-key packets are not accepted"),
            "pub" => {
                primary_count += 1;
                primary_pending = true;
                let value = fields.get(4).context("GnuPG omitted the primary key ID")?;
                ensure!(
                    value.len() == 16 && value.bytes().all(|c| c.is_ascii_hexdigit()),
                    "invalid OpenPGP key ID"
                );
                key_id = Some(value.to_ascii_uppercase());
            }
            "sub" => {
                primary_pending = false;
            }
            "fpr" if primary_pending => {
                let value = fields
                    .get(9)
                    .context("GnuPG omitted the primary fingerprint")?;
                ensure!(
                    [40, 64].contains(&value.len()) && value.bytes().all(|c| c.is_ascii_hexdigit()),
                    "invalid OpenPGP fingerprint"
                );
                fingerprint = Some(value.to_ascii_uppercase());
                primary_pending = false;
            }
            _ => {}
        }
    }
    ensure!(
        primary_count == 1,
        "expected one public primary key, found {primary_count}"
    );
    Ok(KeyIdentity {
        fingerprint: fingerprint.context("GnuPG omitted the primary fingerprint")?,
        key_id: key_id.context("GnuPG omitted the primary key ID")?,
    })
}

trait Backend {
    fn list(&mut self, destination: &Destination) -> Result<AccountGpgKeys>;
    fn add(&mut self, destination: &Destination, login: &str, armor: &str) -> Result<GpgKey>;
}

struct ForgeBackend;
impl Backend for ForgeBackend {
    fn list(&mut self, destination: &Destination) -> Result<AccountGpgKeys> {
        match destination {
            Destination::Forgejo(host) => forge::list_forgejo_keys(host),
            Destination::Github => forge::list_github_keys(),
        }
    }
    fn add(&mut self, destination: &Destination, login: &str, armor: &str) -> Result<GpgKey> {
        match destination {
            Destination::Forgejo(host) => forge::add_forgejo_key(host, login, armor),
            Destination::Github => forge::add_github_key(login, armor),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RegistrationStatus {
    Added,
    Present,
}
struct Registration {
    login: String,
    status: RegistrationStatus,
    key: GpgKey,
}

fn remote_fingerprint(key: &GpgKey) -> Result<String> {
    ensure!(
        key.public_key.len() <= MAX_KEY_BYTES * 2,
        "remote public key exceeds size limit"
    );
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&key.public_key)
        .context("forge returned invalid base64 public-key packets")?;
    Ok(inspect_key(&bytes)?.fingerprint)
}

fn find_registered(public: &PublicKey, account: &AccountGpgKeys) -> Result<Option<GpgKey>> {
    for key in &account.keys {
        if key.key_id.eq_ignore_ascii_case(&public.key_id) {
            ensure!(
                remote_fingerprint(key)? == public.fingerprint,
                "remote key ID matches but its full fingerprint differs"
            );
            return Ok(Some(key.clone()));
        }
    }
    Ok(None)
}

fn publish_one(
    public: &PublicKey,
    destination: &Destination,
    check: bool,
    backend: &mut impl Backend,
) -> Result<Registration> {
    let account = backend.list(destination)?;
    if let Some(key) = find_registered(public, &account)? {
        return Ok(Registration {
            login: account.login,
            status: RegistrationStatus::Present,
            key,
        });
    }
    ensure!(
        !check,
        "key {} is missing from account {}",
        public.fingerprint,
        account.login
    );
    match backend.add(destination, &account.login, &public.armor) {
        Ok(key) => {
            ensure!(
                remote_fingerprint(&key)? == public.fingerprint,
                "forge returned a different public-key fingerprint after publication"
            );
            Ok(Registration {
                login: account.login,
                status: RegistrationStatus::Added,
                key,
            })
        }
        Err(error) => {
            // A timeout or concurrent duplicate can occur after a successful
            // POST. Reconcile once before declaring this destination failed.
            if let Ok(current) = backend.list(destination)
                && current.login == account.login
                && let Some(key) = find_registered(public, &current)?
            {
                return Ok(Registration {
                    login: current.login,
                    status: RegistrationStatus::Present,
                    key,
                });
            }
            Err(error)
        }
    }
}

fn publish_with_backend(
    public: &PublicKey,
    destinations: &[Destination],
    check: bool,
    backend: &mut impl Backend,
) -> Vec<Result<Registration>> {
    destinations
        .iter()
        .map(|destination| publish_one(public, destination, check, backend))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix_manager_core::forge::gpg::{AccountGpgKeys, GpgEmail, GpgKey};

    const PUBLIC: &str = include_str!("../tests/fixtures/gpg-public.asc");
    const FINGERPRINT: &str = "3EA1AA70463CD4A323FA0C5B059EAE883D51B31C";

    fn remote_key() -> GpgKey {
        GpgKey {
            id: 1,
            key_id: "059EAE883D51B31C".into(),
            public_key: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, PUBLIC),
            can_sign: true,
            verified: Some(false),
            emails: vec![GpgEmail {
                email: "gpg@example.invalid".into(),
                verified: true,
            }],
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        present: bool,
        fail_forgejo: bool,
        fail_after_add: bool,
        wrong_remote_key: bool,
        added: Vec<Destination>,
    }

    impl Backend for FakeBackend {
        fn list(&mut self, destination: &Destination) -> Result<AccountGpgKeys> {
            if self.fail_forgejo && matches!(destination, Destination::Forgejo(_)) {
                bail!("fixture authentication denied");
            }
            Ok(AccountGpgKeys {
                login: "fixture-user".into(),
                keys: if self.present {
                    vec![remote_key()]
                } else {
                    vec![]
                },
            })
        }
        fn add(&mut self, destination: &Destination, login: &str, armor: &str) -> Result<GpgKey> {
            assert_eq!(login, "fixture-user");
            assert_eq!(armor, PUBLIC);
            self.added.push(destination.clone());
            if self.fail_after_add {
                self.present = true;
                bail!("fixture response lost after upload");
            }
            if self.wrong_remote_key {
                let mut key = remote_key();
                key.public_key = "not-base64".into();
                return Ok(key);
            }
            Ok(remote_key())
        }
    }

    #[test]
    fn parses_the_full_public_fingerprint_without_importing_keys() {
        let public = PublicKey::parse(PUBLIC.into()).unwrap();
        assert_eq!(public.fingerprint, FINGERPRINT);
        assert_eq!(public.key_id, "059EAE883D51B31C");
    }

    #[test]
    fn rejects_private_and_malformed_public_input() {
        assert!(PublicKey::parse(PUBLIC.replace("PUBLIC KEY", "PRIVATE KEY")).is_err());
        assert!(
            PublicKey::parse(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\ngarbage\n-----END PGP PUBLIC KEY BLOCK-----"
                    .into()
            )
            .is_err()
        );
        assert!(PublicKey::parse(format!("{PUBLIC}{PUBLIC}")).is_err());
        assert!(fingerprint_from_listing("sec:-:255:22:059EAE883D51B31C:::::::scSC:\nfpr:::::::::3EA1AA70463CD4A323FA0C5B059EAE883D51B31C:\n").is_err());
    }

    #[test]
    fn repeated_publication_is_successful_without_uploading() {
        let public = PublicKey::parse(PUBLIC.into()).unwrap();
        let mut backend = FakeBackend {
            present: true,
            ..FakeBackend::default()
        };
        let results = publish_with_backend(&public, &[Destination::Github], false, &mut backend);
        assert_eq!(
            results[0].as_ref().unwrap().status,
            RegistrationStatus::Present
        );
        assert!(backend.added.is_empty());
    }

    #[test]
    fn partial_failure_still_publishes_to_other_platforms() {
        let public = PublicKey::parse(PUBLIC.into()).unwrap();
        let mut backend = FakeBackend {
            fail_forgejo: true,
            ..FakeBackend::default()
        };
        let results = publish_with_backend(
            &public,
            &[
                Destination::Forgejo("codefloe.com".into()),
                Destination::Github,
            ],
            false,
            &mut backend,
        );
        assert!(results[0].is_err());
        assert_eq!(
            results[1].as_ref().unwrap().status,
            RegistrationStatus::Added
        );
        assert_eq!(backend.added, [Destination::Github]);
    }

    #[test]
    fn check_reports_missing_keys_without_uploading() {
        let public = PublicKey::parse(PUBLIC.into()).unwrap();
        let mut backend = FakeBackend::default();
        let results = publish_with_backend(&public, &[Destination::Github], true, &mut backend);
        assert!(results[0].is_err());
        assert!(backend.added.is_empty());
    }

    #[test]
    fn reconciles_a_lost_post_response_without_uploading_again() {
        let public = PublicKey::parse(PUBLIC.into()).unwrap();
        let mut backend = FakeBackend {
            fail_after_add: true,
            ..FakeBackend::default()
        };
        let results = publish_with_backend(&public, &[Destination::Github], false, &mut backend);
        assert_eq!(
            results[0].as_ref().unwrap().status,
            RegistrationStatus::Present
        );
        assert_eq!(backend.added, [Destination::Github]);
    }

    #[test]
    fn invalid_post_response_is_not_reported_as_success() {
        let public = PublicKey::parse(PUBLIC.into()).unwrap();
        let mut backend = FakeBackend {
            wrong_remote_key: true,
            ..FakeBackend::default()
        };
        let results = publish_with_backend(&public, &[Destination::Github], false, &mut backend);
        assert!(results[0].is_err());
    }

    #[test]
    fn verifies_full_fingerprint_instead_of_only_the_key_id() {
        let mut public = PublicKey::parse(PUBLIC.into()).unwrap();
        public.fingerprint.replace_range(..1, "0");
        let mut backend = FakeBackend {
            present: true,
            ..FakeBackend::default()
        };
        let results = publish_with_backend(&public, &[Destination::Github], false, &mut backend);
        assert!(results[0].is_err());
        assert!(backend.added.is_empty());
    }

    #[test]
    fn api_public_packet_can_be_inspected_without_a_uid_or_signature() {
        let payload: String = PUBLIC
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with(['-', '=']))
            .collect();
        let packets = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .unwrap();
        // GnuPG's export uses a tag-6 old-format packet with a one-byte length.
        let primary = &packets[..2 + usize::from(packets[1])];
        let mut key = remote_key();
        key.public_key = base64::engine::general_purpose::STANDARD.encode(primary);
        assert_eq!(remote_fingerprint(&key).unwrap(), FINGERPRINT);
    }
}
