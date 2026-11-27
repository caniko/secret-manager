//! Release-signing onboarding engine: mint a repository's minisign keypair
//! into the age store and push it to the repository's GitHub Actions secrets,
//! without decrypting anything.
//!
//! One repository has two phases:
//! 1. The local phase mints, encrypts, installs, and stages the new pair; any
//!    failure restores every file it touched and unstages what it staged.
//! 2. The remote phase starts only after the local phase succeeded, records
//!    every upload in [`SyncState`] as it happens, and never rolls the store
//!    back (once installed, the store is the only copy of the new pair).

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::encryption::StreamEncryptor;
use crate::passphrase;
use crate::sync_state::{ManagedKind, ManagedRecord, Scope, SyncState};
use crate::sync_targets::Provider;

/// Entropy of the password that wraps the minisign key, matching the
/// `strong-passphrase-64` generator.
pub const PASSPHRASE_LEN: usize = 64;

/// Suffix a replaced file is renamed to for the length of the local phase, and
/// where a restore that fails leaves the previous bytes.
pub const BACKUP_SUFFIX: &str = ".release-signing-backup";

/// Default operator follow-up guidance for onboarding reports.
pub const PENDING_ACTION: &str = "Commit each printed public key as keys/minisign.pub in its repository. When every pending secret change is finished, queue `ops_request_standard kind=rekey` (or run `canix secret rekey` at a terminal) and approve it: the rekey needs one FIDO2 touch.";

/// One release-signing registry project.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseProject {
    pub repo: String,
    /// Whether `secret_sync` declares this project's destinations. An
    /// onboarding may run before the entry is enabled; the sync state then
    /// stays untouched so a later `sync --prune` owns the decision.
    #[serde(default)]
    pub enabled: bool,
    pub minisign_secret_name: String,
    pub minisign_password_name: String,
    pub minisign_secret_path: PathBuf,
    pub minisign_password_path: PathBuf,
    /// Mint the keypair locally. Projects that import one keep it
    /// (`generateKey = false`) and are refused here.
    #[serde(default)]
    pub generate_key: bool,
}

impl ReleaseProject {
    /// Where the generator writes the public key: next to the `.age` source.
    pub fn public_key_path(&self) -> PathBuf {
        self.minisign_secret_path.with_extension("pub")
    }

    /// Optional extra copy destination (`DIR/<repository>.pub`).
    pub fn public_key_out(&self, dir: &Path) -> PathBuf {
        let name = self.repo.rsplit('/').next().unwrap_or(&self.repo);
        dir.join(format!("{name}.pub"))
    }
}

/// What to do with one source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePlan {
    Create,
    Replace,
    Keep,
}

impl FilePlan {
    /// Whether this file will be written.
    pub fn writes(self) -> bool {
        self != Self::Keep
    }
}

/// Planned local actions for one [`ReleaseProject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedProject {
    pub project: ReleaseProject,
    pub password: FilePlan,
    pub secret_key: FilePlan,
    /// Whether the run was asked to replace an existing pair.
    pub rotate: bool,
}

impl PlannedProject {
    /// Whether either source file will be written.
    pub fn writes(&self) -> bool {
        self.password.writes() || self.secret_key.writes()
    }

    /// Short human/JSON label for the planned action (`keep`, `rotate`, `create`).
    pub fn action(&self) -> &'static str {
        if !self.writes() {
            "keep"
        } else if self.password == FilePlan::Replace || self.secret_key == FilePlan::Replace {
            "rotate"
        } else {
            "create"
        }
    }
}

/// What a run would do, plus the selections it cannot use.
#[derive(Debug)]
pub struct PlanOutcome {
    pub planned: Vec<PlannedProject>,
    /// Selected repositories the plan refused, as failed report entries: one
    /// bad selection is its own entry instead of aborting the others, and the
    /// run still fails overall.
    pub rejected: Vec<RepoReport>,
    /// Half pairs `--all` leaves alone. Named even when no work remains, so a
    /// run that only reports "nothing to onboard" still shows them.
    pub skipped: Vec<String>,
}

/// Select projects and decide per source what happens. `exists` reports
/// whether a store-relative path is present. A selection the plan cannot use
/// becomes a failed entry and the remaining selections still run.
pub fn plan(
    registry: &[ReleaseProject],
    repos: &[String],
    all: bool,
    rotate: bool,
    exists: impl Fn(&Path) -> bool,
) -> PlanOutcome {
    let mut rejected = Vec::new();
    let selected: Vec<&ReleaseProject> = if all {
        registry
            .iter()
            .filter(|project| {
                project.generate_key
                    && !exists(&project.minisign_password_path)
                    && !exists(&project.minisign_secret_path)
            })
            .collect()
    } else {
        let mut selected = Vec::with_capacity(repos.len());
        for repo in repos {
            let Some(project) = registry.iter().find(|project| &project.repo == repo) else {
                let known = registry
                    .iter()
                    .map(|project| project.repo.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                rejected.push(RepoReport::failed(
                    None,
                    repo,
                    "refused",
                    &anyhow!("{repo} is not in the release project registry (known: {known})"),
                ));
                continue;
            };
            if !project.generate_key {
                rejected.push(RepoReport::failed(
                    Some(project),
                    &project.repo,
                    "refused",
                    &anyhow!(
                        "{} imports its minisign pair (generateKey = false); not minted here. Add a generateKey project to the registry first",
                        project.repo
                    ),
                ));
                continue;
            }
            if !selected.contains(&project) {
                selected.push(project);
            }
        }
        selected
    };
    let mut planned = Vec::with_capacity(selected.len());
    for project in selected {
        match plan_project(project, rotate, &exists) {
            Ok(project) => planned.push(project),
            Err(error) => rejected.push(RepoReport::failed(
                Some(project),
                &project.repo,
                "refused",
                &error,
            )),
        }
    }
    PlanOutcome {
        planned,
        rejected,
        skipped: if all {
            half_pairs(registry, &exists)
        } else {
            Vec::new()
        },
    }
}

/// Decide one project's sources. Called again under the store lock: the plan
/// computed outside it may already be stale.
pub fn plan_project(
    project: &ReleaseProject,
    rotate: bool,
    exists: impl Fn(&Path) -> bool,
) -> Result<PlannedProject> {
    let has_password = exists(&project.minisign_password_path);
    let has_secret = exists(&project.minisign_secret_path);
    let (password, secret_key) = match (has_password, has_secret) {
        (false, false) => (FilePlan::Create, FilePlan::Create),
        (true, true) if rotate => (FilePlan::Replace, FilePlan::Replace),
        (true, true) => (FilePlan::Keep, FilePlan::Keep),
        (_, _) if rotate => (
            if has_password {
                FilePlan::Replace
            } else {
                FilePlan::Create
            },
            if has_secret {
                FilePlan::Replace
            } else {
                FilePlan::Create
            },
        ),
        _ => bail!(
            "{} is half onboarded ({}, {}); pass --rotate to replace both sources, or restore the missing one",
            project.repo,
            if has_password {
                format!("{} exists", project.minisign_password_path.display())
            } else {
                format!("{} is missing", project.minisign_password_path.display())
            },
            if has_secret {
                format!("{} exists", project.minisign_secret_path.display())
            } else {
                format!("{} is missing", project.minisign_secret_path.display())
            },
        ),
    };
    Ok(PlannedProject {
        project: project.clone(),
        password,
        secret_key,
        rotate,
    })
}

/// Half pairs `--all` cannot touch. Naming them keeps a run that only reports
/// missing pairs from hiding a project that needs `--repo X --rotate`.
pub fn half_pairs(registry: &[ReleaseProject], exists: impl Fn(&Path) -> bool) -> Vec<String> {
    registry
        .iter()
        .filter(|project| {
            project.generate_key
                && exists(&project.minisign_password_path) != exists(&project.minisign_secret_path)
        })
        .map(|project| {
            format!(
                "{} is half onboarded; `--repo {} --rotate` replaces the pair as a whole",
                project.repo, project.repo
            )
        })
        .collect()
}

/// A freshly minted pair. Values are wiped when they leave scope and never
/// leave memory except encrypted or uploaded.
pub struct MintedPair {
    pub password: Zeroizing<String>,
    pub secret_key: Zeroizing<String>,
    pub public_key: String,
}

/// Mint a strong 64-character password and a minisign keypair encrypted with
/// it via `minisign -G` in a 0700 temporary directory with stderr suppressed.
pub fn mint() -> Result<MintedPair> {
    let password = Zeroizing::new(passphrase::from_urandom(PASSPHRASE_LEN)?);
    let directory = tempfile::tempdir().context("create a private directory for minisign")?;
    let secret_key = directory.path().join("key");
    let public_key = directory.path().join("key.pub");
    let mut cmd = Command::new("minisign");
    cmd.args(["-G", "-p"])
        .arg(&public_key)
        .arg("-s")
        .arg(&secret_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        // Its diagnostics can quote what it read; they are never collected.
        .stderr(Stdio::null());
    // SAFETY: setrlimit is async-signal-safe and disables core dumps in the
    // child before exec so the minted key/password cannot be dumped to disk.
    unsafe {
        cmd.pre_exec(|| {
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let _ = libc::setrlimit(libc::RLIMIT_CORE, &zero);
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .context("run minisign -G; ensure minisign is on PATH")?;
    let write_result = (|| -> std::io::Result<()> {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("minisign stdin closed"))?;
        // minisign asks twice and never echoes it.
        writeln!(stdin, "{}", *password)?;
        writeln!(stdin, "{}", *password)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(err).context("write the minisign password");
    }
    let status = child.wait()?;
    ensure!(status.success(), "{}", minisign_error(status));
    Ok(MintedPair {
        password,
        secret_key: Zeroizing::new(
            std::fs::read_to_string(&secret_key)
                .with_context(|| format!("read the minted key {}", secret_key.display()))?,
        ),
        public_key: std::fs::read_to_string(&public_key)
            .with_context(|| format!("read the minted public key {}", public_key.display()))?,
    })
}

/// A fixed failure: an exit status and where to look, never the child's own
/// words, which can quote the password it was given.
fn minisign_error(status: std::process::ExitStatus) -> anyhow::Error {
    anyhow!(
        "minisign -G failed with {status}; its diagnostics are suppressed because they can quote the password"
    )
}

/// Aggregate onboarding report across all selected repositories.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardReport {
    pub dry_run: bool,
    /// Half pairs `--all` left alone, named so they are visible.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
    pub repos: Vec<RepoReport>,
    pub pending_operator_action: String,
}

impl OnboardReport {
    /// Every selected repository finished its local install and its delivery.
    pub fn is_ok(&self) -> bool {
        self.repos.iter().all(|repo| repo.status == RepoStatus::Ok)
    }

    /// One-line summary of failed and delivery-incomplete repositories.
    pub fn failure_summary(&self) -> String {
        let mut parts = Vec::new();
        let failed: Vec<&RepoReport> = self
            .repos
            .iter()
            .filter(|repo| repo.status == RepoStatus::Failed)
            .collect();
        if !failed.is_empty() {
            parts.push(format!(
                "release-signing onboarding failed for {}: {}",
                failed
                    .iter()
                    .map(|repo| repo.repo.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                failed
                    .iter()
                    .filter_map(|repo| repo.error.as_deref())
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        let incomplete: Vec<&RepoReport> = self
            .repos
            .iter()
            .filter(|repo| repo.status == RepoStatus::DeliveryIncomplete)
            .collect();
        if !incomplete.is_empty() {
            parts.push(format!(
                "release-signing delivery is incomplete for {}: the new pair is installed and staged. Commit the paths named in each entry (or unstage them with `git restore --staged`), then rerun `canix secret release-signing onboard --repo <repo> --rotate` for each (a fresh pair, both secrets delivered again, no key touch), then rekey",
                incomplete
                    .iter()
                    .map(|repo| repo.repo.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        parts.join(". ")
    }
}

/// One repository's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RepoStatus {
    Ok,
    /// The repository is not installed, or its local phase did not finish.
    Failed,
    /// The pair is installed but the forge copy is missing or unverified.
    DeliveryIncomplete,
}

/// Per-repository onboarding result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoReport {
    pub repo: String,
    pub status: RepoStatus,
    pub action: &'static str,
    /// Absent when the selection is not in the registry, so it has no paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<RepoPaths>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// The secrets the forge accepted. Empty when nothing was uploaded.
    pub delivered_secrets: Vec<String>,
    pub rekey_pending: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The local or remote failure, when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// What to do about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<String>,
}

impl RepoReport {
    /// Construct a failed report entry. `project` is absent when the selection
    /// is unknown to the registry.
    pub fn failed(
        project: Option<&ReleaseProject>,
        repo: &str,
        action: &'static str,
        error: &anyhow::Error,
    ) -> Self {
        Self {
            repo: repo.to_string(),
            status: RepoStatus::Failed,
            action,
            paths: project.map(RepoPaths::of),
            public_key: None,
            delivered_secrets: Vec::new(),
            rekey_pending: true,
            note: None,
            error: Some(format!("{error:#}")),
            recovery: Some(recovery(repo, action)),
        }
    }
}

fn recovery(repo: &str, action: &'static str) -> String {
    let rotate = if action == "rotate" { " --rotate" } else { "" };
    format!(
        "Fix the cause named above and rerun `canix secret release-signing onboard --repo {repo}{rotate}`"
    )
}

/// Store-relative paths of one repository's minisign files.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoPaths {
    pub password: String,
    pub secret_key: String,
    pub public_key: String,
}

impl RepoPaths {
    /// Extract display paths from a [`ReleaseProject`].
    pub fn of(project: &ReleaseProject) -> Self {
        Self {
            password: project.minisign_password_path.display().to_string(),
            secret_key: project.minisign_secret_path.display().to_string(),
            public_key: project.public_key_path().display().to_string(),
        }
    }

    /// The three paths comma-separated for prose.
    pub fn listed(&self) -> String {
        [&self.password, &self.secret_key, &self.public_key]
            .iter()
            .map(|path| path.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The three paths space-separated for shell commands.
    pub fn shell_words(&self) -> String {
        [&self.password, &self.secret_key, &self.public_key]
            .iter()
            .map(|path| path.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Build one repository's report. `installed_public_key` is the `.pub` this run
/// wrote, from memory: a later run's key must never be reported as this one's.
pub fn repository_report(
    root: &Path,
    project: &ReleaseProject,
    action: &'static str,
    installed_public_key: Option<&str>,
    delivered: Delivered,
    extra: Option<&str>,
) -> RepoReport {
    let public_key = installed_public_key.map(str::to_string).or_else(|| {
        std::fs::read_to_string(root.join(project.public_key_path()))
            .ok()
            .map(|key| key.trim_end().to_string())
    });
    let mut notes = Vec::new();
    if let Some(extra) = extra {
        notes.push(extra.to_string());
    }
    if !project.enabled {
        notes.push(
            "registry entry is disabled (enabled = false): `secret sync` declares no destination for it yet, so the sync state is untouched and the pushed secrets stay unmanaged until it is enabled"
                .to_string(),
        );
    }
    if action == "keep" && extra.is_none() {
        notes.push(
            "sources kept; deliver them with `canix secret sync --target ...` if the forge secrets are missing"
                .to_string(),
        );
    }
    let (status, error, recovery) = match delivered.failure {
        None => (RepoStatus::Ok, None, None),
        Some(failure) => (
            RepoStatus::DeliveryIncomplete,
            Some(format!("{failure:#}")),
            Some({
                let paths = RepoPaths::of(project);
                format!(
                    "The new pair is installed and staged. Commit {} (or unstage it with `git restore --staged {}`), then rerun `canix secret release-signing onboard --repo {} --rotate`: it mints a fresh pair and delivers both again (no key touch), then rekey",
                    paths.listed(),
                    paths.shell_words(),
                    project.repo
                )
            }),
        ),
    };
    if let Some(failure) = &error {
        notes.push(format!(
            "delivery incomplete: {failure}. The new pair exists only in the age store"
        ));
    }
    RepoReport {
        repo: project.repo.clone(),
        status,
        action,
        paths: Some(RepoPaths::of(project)),
        public_key,
        delivered_secrets: delivered.uploaded,
        rekey_pending: true,
        note: if notes.is_empty() {
            None
        } else {
            Some(notes.join("; "))
        },
        error,
        recovery,
    }
}

/// Build a failed [`RepoReport`] for a known project.
pub fn failed_report(
    project: &ReleaseProject,
    action: &'static str,
    error: &anyhow::Error,
) -> RepoReport {
    RepoReport::failed(Some(project), &project.repo, action, error)
}

/// Build the synthetic [`Delivered`] list for a dry run.
pub fn planned_delivery(planned: &PlannedProject) -> Delivered {
    if !planned.writes() {
        return Delivered::default();
    }
    Delivered {
        uploaded: vec![
            planned.project.minisign_password_name.clone(),
            planned.project.minisign_secret_name.clone(),
        ],
        ..Delivered::default()
    }
}

/// Run onboarding for every planned repository under the caller's store lock.
/// A failure in one repository becomes its own [`RepoReport`] entry so the run
/// continues and reports all selections.
pub fn onboard_all(
    root: &Path,
    planned: &[PlannedProject],
    encryptor: Option<&StreamEncryptor>,
    public_key_out: Option<&Path>,
    forge: &impl Forge,
) -> Vec<RepoReport> {
    planned
        .iter()
        .map(
            |planned| match onboard_one(root, planned, encryptor, public_key_out, forge) {
                Ok(report) => report,
                Err(error) => failed_report(&planned.project, planned.action(), &error),
            },
        )
        .collect()
}

/// Install one project's pair, then deliver it from memory.
pub fn onboard_one(
    root: &Path,
    planned: &PlannedProject,
    encryptor: Option<&StreamEncryptor>,
    public_key_out: Option<&Path>,
    forge: &impl Forge,
) -> Result<RepoReport> {
    // Recheck under the run's lock: the plan made outside it may be stale.
    let current = plan_project(&planned.project, planned.rotate, |path| {
        root.join(path).exists()
    })?;
    if !current.writes() {
        return Ok(repository_report(
            root,
            &planned.project,
            current.action(),
            None,
            Delivered::default(),
            Some(
                "another onboarding installed the pair before this run took the store lock; it is kept and this run delivered nothing",
            ),
        ));
    }
    let encryptor = encryptor.context("a write plan without its encryptor")?;
    let minted = install_project(root, &current, encryptor, public_key_out)?;
    let delivered = deliver(root, &planned.project, &minted, forge);
    Ok(repository_report(
        root,
        &planned.project,
        current.action(),
        Some(minted.public_key.trim_end()),
        delivered,
        None,
    ))
}

/// One local file this run installs.
pub struct LocalWrite<'a> {
    pub path: PathBuf,
    pub content: LocalContent<'a>,
}

/// Content written by a [`LocalWrite`].
pub enum LocalContent<'a> {
    /// Encrypted to the store's master recipients before it is written.
    AgeSource { plaintext: &'a [u8] },
    /// Written verbatim: a public key, which is not secret.
    Plain(&'a [u8]),
}

impl<'a> LocalWrite<'a> {
    /// Construct an encrypted `.age` write.
    pub fn age(path: &Path, plaintext: &'a [u8]) -> Self {
        Self {
            path: path.to_path_buf(),
            content: LocalContent::AgeSource { plaintext },
        }
    }

    /// Construct a plaintext file write (e.g. `.pub`).
    pub fn plain(path: &Path, bytes: &'a [u8]) -> Self {
        Self {
            path: path.to_path_buf(),
            content: LocalContent::Plain(bytes),
        }
    }
}

/// Execute a single [`LocalWrite`] using `encryptor` for encrypted sources.
pub fn write_local(encryptor: &StreamEncryptor, write: &LocalWrite<'_>) -> Result<()> {
    match write.content {
        LocalContent::AgeSource { plaintext } => write_source(encryptor, &write.path, plaintext),
        LocalContent::Plain(bytes) => {
            if let Some(parent) = write.path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            atomic_write(&write.path, bytes)
                .with_context(|| format!("write {}", write.path.display()))
        }
    }
}

/// Install every local file of one pair, then stage the store paths. Every
/// existing file is moved aside before anything is written; any failure moves
/// them back and unstages, so no half-written pair survives.
pub fn install_local(
    root: &Path,
    writes: &[LocalWrite<'_>],
    staged: &[&Path],
    write: impl Fn(&LocalWrite<'_>) -> Result<()>,
) -> Result<()> {
    refuse_staged(root, staged)?;
    let backups = SourceBackup::capture(writes.iter().map(|write| write.path.as_path()))?;
    // `git add` can stage some paths before it fails, so a failed add still
    // leaves this run's own staging to undo.
    let mut staged_by_us = false;
    let installed = (|| {
        writes.iter().try_for_each(write)?;
        staged_by_us = true;
        stage_sources(root, staged)
    })();
    match installed {
        Ok(()) => backups
            .iter()
            .try_for_each(SourceBackup::discard)
            .context("the new pair is installed and staged, but its backup could not be removed"),
        Err(error) => Err(restore_all(
            root,
            &backups,
            if staged_by_us { staged } else { &[] },
            error,
        )),
    }
}

/// Refuse to write a pair into an index that already stages one of its paths.
pub fn refuse_staged(root: &Path, paths: &[&Path]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(["diff", "--cached", "--name-only", "--"]);
    for path in paths {
        command.arg(path);
    }
    let output = command
        .output()
        .context("inspect the index with git diff --cached")?;
    ensure!(
        output.status.success(),
        "git diff --cached failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let staged = String::from_utf8_lossy(&output.stdout);
    let staged = staged.trim();
    ensure!(
        staged.is_empty(),
        "refusing to onboard: {staged} already has staged changes; commit or unstage them and rerun"
    );
    Ok(())
}

/// The local phase of one project: mint, encrypt, write `.pub`, and stage.
pub fn install_project(
    root: &Path,
    planned: &PlannedProject,
    encryptor: &StreamEncryptor,
    public_key_out: Option<&Path>,
) -> Result<MintedPair> {
    let project = &planned.project;
    let minted = mint()?;
    let password_path = root.join(&project.minisign_password_path);
    let secret_path = root.join(&project.minisign_secret_path);
    let public_path = root.join(project.public_key_path());
    // A kept source is not written at all, so its file is not moved aside.
    let mut writes = Vec::new();
    if planned.password.writes() {
        writes.push(LocalWrite::age(&password_path, minted.password.as_bytes()));
    }
    if planned.secret_key.writes() {
        writes.push(LocalWrite::age(&secret_path, minted.secret_key.as_bytes()));
    }
    writes.push(LocalWrite::plain(
        &public_path,
        minted.public_key.as_bytes(),
    ));
    if let Some(dir) = public_key_out {
        writes.push(LocalWrite::plain(
            &project.public_key_out(dir),
            minted.public_key.as_bytes(),
        ));
    }
    let public_rel = project.public_key_path();
    let staged = [
        project.minisign_password_path.as_path(),
        project.minisign_secret_path.as_path(),
        public_rel.as_path(),
    ];
    install_local(root, &writes, &staged, |write| {
        write_local(encryptor, write)
    })?;
    Ok(minted)
}

/// One file's previous contents, moved beside it for the length of one local
/// phase.
#[derive(Debug)]
pub struct SourceBackup {
    pub path: PathBuf,
    /// `<path>.release-signing-backup` when the file existed, `None` for a file
    /// this run created (whose rollback is a removal).
    pub backup: Option<PathBuf>,
}

impl SourceBackup {
    /// Move every existing file aside. An existing backup is refused before
    /// anything moves.
    pub fn capture<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Result<Vec<Self>> {
        let paths = paths.into_iter().collect::<Vec<_>>();
        let existing = paths
            .iter()
            .map(|path| with_suffix(path, BACKUP_SUFFIX))
            .filter(|backup| backup.symlink_metadata().is_ok())
            .collect::<Vec<_>>();
        ensure!(
            existing.is_empty(),
            "refusing to onboard: {} already exists; move it aside and rerun",
            existing
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        let mut backups: Vec<Self> = Vec::with_capacity(paths.len());
        for path in paths {
            let backup = with_suffix(path, BACKUP_SUFFIX);
            match std::fs::rename(path, &backup) {
                Ok(()) => backups.push(Self {
                    path: path.to_path_buf(),
                    backup: Some(backup),
                }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => backups.push(Self {
                    path: path.to_path_buf(),
                    backup: None,
                }),
                Err(error) => {
                    let mut failure =
                        anyhow!(error).context(format!("move {} aside", path.display()));
                    for restored in backups
                        .iter()
                        .rev()
                        .filter_map(|backup| backup.restore().err())
                    {
                        failure = failure.context(format!(
                            "restoring it after the failed move also failed: {restored:#}"
                        ));
                    }
                    return Err(failure);
                }
            }
        }
        Ok(backups)
    }

    /// Put the previous file back by renaming its backup over whatever this
    /// run wrote, or remove a file this run created.
    pub fn restore(&self) -> Result<()> {
        match &self.backup {
            Some(backup) => std::fs::rename(backup, &self.path)
                .with_context(|| format!("move {} back", backup.display())),
            None => match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error).with_context(|| format!("remove {}", self.path.display())),
            },
        }
    }

    /// Drop the backup: only for a local phase that fully succeeded.
    pub fn discard(&self) -> Result<()> {
        let Some(backup) = &self.backup else {
            return Ok(());
        };
        std::fs::remove_file(backup)
            .with_context(|| format!("remove the backup {}", backup.display()))
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Atomically write `bytes` to `path` via a synced temporary file in the same
/// directory.
///
/// Only encrypted `.age` sources and public `.pub` keys are accepted; plaintext
/// private key paths are refused.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(
        matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("age" | "pub")
        ),
        "refusing atomic_write to non-.age/.pub path {}",
        path.display()
    );
    let directory = path.parent().context("source has no parent directory")?;
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.write_all(bytes)?;
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

/// Restore every backed-up file and unstage what this run staged.
pub fn restore_all(
    root: &Path,
    backups: &[SourceBackup],
    staged: &[&Path],
    error: anyhow::Error,
) -> anyhow::Error {
    let mut failures = Vec::new();
    for backup in backups {
        if let Err(restore) = backup.restore() {
            failures.push(match &backup.backup {
                Some(path) => format!(
                    "{} ({restore:#}); its previous bytes are in {}",
                    backup.path.display(),
                    path.display()
                ),
                None => format!("{} ({restore:#})", backup.path.display()),
            });
        }
    }
    let unstaged = unstage(root, staged);
    match (failures.is_empty(), unstaged) {
        (true, Ok(())) => anyhow::anyhow!("{error:#}\n  the previous files are restored"),
        (true, Err(unstage)) => anyhow::anyhow!(
            "{error:#}\n  the previous files are restored, but unstaging them failed: {unstage:#}"
        ),
        (false, unstaged) => {
            let mut message = format!(
                "{error:#}\n  and restoring the previous files also failed: {}",
                failures.join("; ")
            );
            if let Err(unstage) = unstaged {
                message.push_str(&format!("; unstaging them also failed: {unstage:#}"));
            }
            anyhow::anyhow!(message)
        }
    }
}

fn write_source(encryptor: &StreamEncryptor, path: &Path, plaintext: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    encryptor
        .encrypt_new(path, plaintext)
        .with_context(|| format!("encrypt {}", path.display()))
}

/// `git add` only the sources this run wrote.
pub fn stage_sources(root: &Path, paths: &[&Path]) -> Result<()> {
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(["add", "--"]);
    for path in paths {
        command.arg(path);
    }
    let status = command
        .status()
        .context("stage the new sources with git add")?;
    if !status.success() {
        bail!("git add failed for the new release-signing sources");
    }
    Ok(())
}

/// Reverse [`stage_sources`]: paths go back to their HEAD entries, and files
/// that were never tracked leave the index.
pub fn unstage(root: &Path, paths: &[&Path]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut command = Command::new("git");
    command.arg("-C").arg(root).args(["reset", "--quiet", "--"]);
    for path in paths {
        command.arg(path);
    }
    let output = command
        .output()
        .context("unstage the new release-signing sources")?;
    ensure!(
        output.status.success(),
        "git reset failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// The remote half of a delivery, split from the upload loop so tests can
/// exercise partial delivery without contacting GitHub.
pub trait Forge {
    fn push(&self, project: &ReleaseProject, name: &str, value: &str) -> Result<()>;
    fn verify(&self, project: &ReleaseProject) -> Result<()>;
}

/// GitHub Actions delivery backend using the `gh` CLI via
/// [`crate::credential_process::capture_with_timeout`].
pub struct Github;

impl Forge for Github {
    fn push(&self, project: &ReleaseProject, name: &str, value: &str) -> Result<()> {
        push_github_from_memory(&project.repo, name, value.as_bytes())
    }

    fn verify(&self, project: &ReleaseProject) -> Result<()> {
        verify_github_secrets(project)
    }
}

fn push_github_from_memory(repo: &str, name: &str, value: &[u8]) -> Result<()> {
    let mut command = gh_command(secret_set_args(repo, name));
    crate::credential_process::capture_with_timeout(
        &mut command,
        Some(value),
        std::time::Duration::from_secs(90),
    )
    .with_context(|| format!("push {name} to {repo}"))?;
    Ok(())
}

fn github_repository(repo: &str) -> String {
    format!("github.com/{repo}")
}

fn secret_set_args(repo: &str, name: &str) -> Vec<String> {
    [
        "secret".to_string(),
        "set".to_string(),
        name.to_string(),
        "--repo".to_string(),
        github_repository(repo),
    ]
    .to_vec()
}

fn secret_list_args(repo: &str) -> Vec<String> {
    [
        "secret".to_string(),
        "list".to_string(),
        "--repo".to_string(),
        github_repository(repo),
        "--json".to_string(),
        "name".to_string(),
    ]
    .to_vec()
}

/// `gh` with every switch that could echo a credential removed, and GitHub
/// bound both ways: the qualified `--repo` and no `GH_HOST` in the child.
fn gh_command(args: Vec<String>) -> Command {
    let mut command = Command::new("gh");
    command.args(args);
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy();
        if matches!(
            key.as_ref(),
            "DEBUG" | "GH_DEBUG" | "AGEDEBUG" | "RUST_LOG" | "GH_HOST"
        ) || key.starts_with("GIT_TRACE")
        {
            command.env_remove(key.as_ref());
        }
    }
    command
}

/// What the remote phase achieved. The local pair is never rolled back here:
/// once it is installed it is the only copy of the new key.
#[derive(Default)]
pub struct Delivered {
    pub uploaded: Vec<String>,
    pub failure: Option<anyhow::Error>,
}

/// Push both secrets from memory, record each successful upload as it happens,
/// then verify the metadata.
pub fn deliver(
    root: &Path,
    project: &ReleaseProject,
    minted: &MintedPair,
    forge: &impl Forge,
) -> Delivered {
    let mut delivered = Delivered::default();
    for (name, value, secret_key) in [
        (
            &project.minisign_password_name,
            minted.password.as_str(),
            false,
        ),
        (
            &project.minisign_secret_name,
            minted.secret_key.as_str(),
            true,
        ),
    ] {
        if let Err(error) = forge.push(project, name, value) {
            delivered.failure = Some(error);
            return delivered;
        }
        delivered.uploaded.push(name.clone());
        if project.enabled
            && let Err(error) = record_managed(root, project, secret_key)
        {
            delivered.failure = Some(error.context(format!("record {name} as managed")));
            return delivered;
        }
    }
    if let Err(error) = forge.verify(project) {
        delivered.failure = Some(error);
    }
    delivered
}

fn sync_target(project: &ReleaseProject, secret_key: bool) -> String {
    let prefix = project.repo.replace('/', "-");
    if secret_key {
        format!("{prefix}-minisign")
    } else {
        format!("{prefix}-minisign-password")
    }
}

fn verify_github_secrets(project: &ReleaseProject) -> Result<()> {
    #[derive(Deserialize)]
    struct Name {
        name: String,
    }
    let repo = project.repo.as_str();
    let output = gh_command(secret_list_args(repo))
        .output()
        .with_context(|| format!("list the GitHub Actions secrets of {repo}"))?;
    ensure!(
        output.status.success(),
        "gh secret list failed for {repo} with {}",
        output.status
    );
    let names: Vec<Name> =
        serde_json::from_slice(&output.stdout).context("decode gh secret list JSON")?;
    for expected in [
        &project.minisign_password_name,
        &project.minisign_secret_name,
    ] {
        if !names.iter().any(|name| &name.name == expected) {
            bail!("GitHub reports no {expected} secret on {repo} after the upload");
        }
    }
    Ok(())
}

/// Append one destination to `.secret-manager/sync-state.toml` so a later
/// `secret sync --prune` keeps it.
pub fn record_managed(root: &Path, project: &ReleaseProject, secret_key: bool) -> Result<()> {
    let (owner, repo) = project
        .repo
        .split_once('/')
        .with_context(|| format!("{} is not OWNER/REPO", project.repo))?;
    let (name, target, source) = if secret_key {
        (
            &project.minisign_secret_name,
            sync_target(project, true),
            &project.minisign_secret_path,
        )
    } else {
        (
            &project.minisign_password_name,
            sync_target(project, false),
            &project.minisign_password_path,
        )
    };
    let state_path = root.join(".secret-manager").join("sync-state.toml");
    let mut state = SyncState::load(&state_path)?.unwrap_or_else(SyncState::empty);
    state.managed.push(ManagedRecord {
        provider: Provider::Github,
        host: "github.com".into(),
        scope: Scope::Repo,
        owner: Some(owner.to_ascii_lowercase()),
        repo: Some(repo.to_ascii_lowercase()),
        org: None,
        environment: None,
        kind: ManagedKind::Secret,
        name: name.to_string(),
        target,
        source: source.display().to_string(),
        kubernetes: None,
        members: Vec::new(),
    });
    SyncState::new(state.managed)
        .write_atomic(&state_path)
        .with_context(|| format!("record the new secrets in {}", state_path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::with_store_write_lock;
    use std::collections::BTreeSet;

    fn project(repo: &str, generate_key: bool) -> ReleaseProject {
        let prefix = repo.replace('/', "_");
        ReleaseProject {
            repo: repo.into(),
            enabled: true,
            minisign_secret_name: "MINISIGN_SECRET_KEY".into(),
            minisign_password_name: "MINISIGN_PASSWORD".into(),
            minisign_secret_path: PathBuf::from(format!(
                "age/secrets/root/modules/signing/{prefix}_minisign_secret_key.age"
            )),
            minisign_password_path: PathBuf::from(format!(
                "age/secrets/root/modules/signing/{prefix}_minisign_password.age"
            )),
            generate_key,
        }
    }

    fn git(root: &Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
    }

    fn commit_index(root: &Path, message: &str) {
        let tree = git(root, &["write-tree"]);
        let tree = String::from_utf8(tree.stdout).unwrap().trim().to_string();
        let head = git(root, &["rev-parse", "--verify", "--quiet", "HEAD"]);
        let parent = String::from_utf8(head.stdout).unwrap().trim().to_string();
        let mut args = vec!["commit-tree", tree.as_str(), "-m", message];
        if !parent.is_empty() {
            args.extend(["-p", parent.as_str()]);
        }
        let commit = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(&args)
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .output()
            .unwrap();
        assert!(
            commit.status.success(),
            "commit-tree: {}",
            String::from_utf8_lossy(&commit.stderr)
        );
        let commit = String::from_utf8(commit.stdout).unwrap().trim().to_string();
        assert!(
            git(root, &["update-ref", "HEAD", commit.as_str()])
                .status
                .success()
        );
    }

    fn git_fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        assert!(git(root.path(), &["init", "--quiet"]).status.success());
        std::fs::write(root.path().join("seed.age"), "seed").unwrap();
        assert!(
            git(root.path(), &["add", "--", "seed.age"])
                .status
                .success()
        );
        commit_index(root.path(), "fixture");
        root
    }

    fn committed(root: &Path) -> bool {
        git(root, &["status", "--porcelain"]).stdout.is_empty()
    }

    #[test]
    fn plan_selects_by_missing_sources_and_refuses_imported_keys() {
        let registry = vec![
            project("caniko/imported", false),
            project("caniko/empty", true),
            project("caniko/full", true),
        ];
        let full = project("caniko/full", true);
        let present: BTreeSet<PathBuf> = [full.minisign_password_path, full.minisign_secret_path]
            .into_iter()
            .collect();
        let exists = |path: &Path| present.contains(path);

        let planned = plan(&registry, &["caniko/empty".into()], false, false, exists).planned;
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].password, FilePlan::Create);
        assert_eq!(planned[0].secret_key, FilePlan::Create);
        assert_eq!(planned[0].action(), "create");

        let planned = plan(&registry, &["caniko/full".into()], false, false, exists).planned;
        assert_eq!(planned[0].action(), "keep");
        assert!(!planned[0].writes());
        let planned = plan(&registry, &["caniko/full".into()], false, true, exists).planned;
        assert_eq!(planned[0].action(), "rotate");
        assert_eq!(planned[0].password, FilePlan::Replace);
        assert_eq!(planned[0].secret_key, FilePlan::Replace);

        let planned = plan(&registry, &["caniko/empty".into()], false, true, exists).planned;
        assert_eq!(planned[0].action(), "create");

        let planned = plan(&registry, &[], true, false, exists).planned;
        assert_eq!(
            planned
                .iter()
                .map(|planned| planned.project.repo.as_str())
                .collect::<Vec<_>>(),
            ["caniko/empty"]
        );

        for repo in ["caniko/imported", "caniko/unknown"] {
            let outcome = plan(&registry, &[repo.into()], false, false, exists);
            assert!(outcome.planned.is_empty(), "{:?}", outcome.planned);
            assert_eq!(outcome.rejected.len(), 1);
            let rejected = &outcome.rejected[0];
            assert_eq!(rejected.repo, repo);
            assert_eq!(rejected.status, RepoStatus::Failed);
            let expected = if repo == "caniko/imported" {
                "generateKey = false"
            } else {
                "not in the release project registry"
            };
            let error = rejected.error.as_deref().unwrap();
            assert!(error.contains(expected), "{error}");
        }
        assert!(
            plan(&registry, &[], true, false, |_| true)
                .planned
                .is_empty()
        );
    }

    #[test]
    fn a_refused_selection_is_its_own_entry_and_the_run_fails_overall() {
        let registry = vec![project("caniko/half", true), project("caniko/empty", true)];
        let password = registry[0].minisign_password_path.clone();
        let outcome = plan(
            &registry,
            &["caniko/half".into(), "caniko/empty".into()],
            false,
            false,
            |path| path == password,
        );
        assert_eq!(
            outcome
                .planned
                .iter()
                .map(|planned| planned.project.repo.as_str())
                .collect::<Vec<_>>(),
            ["caniko/empty"]
        );
        assert_eq!(outcome.rejected.len(), 1);
        let rejected = &outcome.rejected[0];
        assert_eq!(rejected.repo, "caniko/half");
        assert_eq!(rejected.status, RepoStatus::Failed);
        assert!(
            rejected
                .error
                .as_deref()
                .unwrap()
                .contains("half onboarded")
        );
        assert!(rejected.paths.is_some());
        assert!(
            rejected
                .recovery
                .as_deref()
                .unwrap()
                .contains("--repo caniko/half")
        );
        let report = OnboardReport {
            dry_run: false,
            skipped: Vec::new(),
            repos: outcome.rejected,
            pending_operator_action: PENDING_ACTION.to_string(),
        };
        assert!(!report.is_ok());
        assert!(report.failure_summary().contains("caniko/half"));
        let unknown = plan(&registry, &["caniko/unknown".into()], false, false, |_| {
            false
        });
        assert_eq!(unknown.rejected.len(), 1);
        assert!(unknown.rejected[0].paths.is_none());
    }

    #[test]
    fn a_concurrent_pair_is_rechecked_and_kept_under_the_lock() {
        let registry = vec![project("caniko/race", true)];
        let planned = plan(&registry, &["caniko/race".into()], false, false, |_| false).planned;
        assert_eq!(planned[0].action(), "create");
        let rechecked = plan_project(&registry[0], planned[0].rotate, |_| true).unwrap();
        assert_eq!(rechecked.action(), "keep");
        assert!(!rechecked.writes());
    }

    #[test]
    fn rotate_replaces_a_half_pair_as_a_whole() {
        let registry = vec![project("caniko/half", true)];
        let password = registry[0].minisign_password_path.clone();
        let planned = plan(&registry, &["caniko/half".into()], false, true, |path| {
            path == password
        })
        .planned;
        assert_eq!(planned[0].password, FilePlan::Replace);
        assert_eq!(planned[0].secret_key, FilePlan::Create);
        assert_eq!(planned[0].action(), "rotate");

        let outcome = plan(&registry, &["caniko/half".into()], false, false, |path| {
            path == password
        });
        assert!(outcome.planned.is_empty());
        assert_eq!(outcome.rejected.len(), 1);
        assert!(
            outcome.rejected[0]
                .error
                .as_deref()
                .unwrap()
                .contains("--rotate")
        );

        let outcome = plan(&registry, &[], true, false, |path| path == password);
        assert!(outcome.planned.is_empty());
        assert_eq!(outcome.skipped.len(), 1);
        assert!(outcome.skipped[0].contains("caniko/half"));
        assert!(half_pairs(&registry, |_| false).is_empty());
    }

    #[test]
    fn all_reports_half_pairs_even_when_no_work_remains() {
        let registry = vec![
            project("caniko/done", true),
            project("caniko/half", true),
            project("caniko/imported", false),
        ];
        let half = registry[1].minisign_password_path.clone();
        let present: BTreeSet<PathBuf> = [
            registry[0].minisign_password_path.clone(),
            registry[0].minisign_secret_path.clone(),
            half,
        ]
        .into_iter()
        .collect();
        let exists = |path: &Path| present.contains(path);
        let outcome = plan(&registry, &[], true, false, exists);
        assert!(outcome.planned.is_empty());
        assert_eq!(outcome.skipped.len(), 1);
        assert!(outcome.skipped[0].contains("caniko/half"));

        let report = OnboardReport {
            dry_run: false,
            skipped: outcome.skipped,
            repos: Vec::new(),
            pending_operator_action: PENDING_ACTION.to_string(),
        };
        assert!(report.is_ok());
        assert_eq!(
            serde_json::to_value(&report).unwrap()["skipped"][0]
                .as_str()
                .unwrap(),
            report.skipped[0]
        );
    }

    #[test]
    fn public_keys_land_next_to_their_source_and_in_the_output_directory() {
        let project = project("caniko/fleetix", true);
        assert_eq!(
            project.public_key_path(),
            PathBuf::from(
                "age/secrets/root/modules/signing/caniko_fleetix_minisign_secret_key.pub"
            )
        );
        assert_eq!(
            project.public_key_out(Path::new("/keys")),
            PathBuf::from("/keys/fleetix.pub")
        );
    }

    #[test]
    fn onboarding_stages_sources_but_never_rekeys() {
        let source = include_str!("release_signing.rs");
        for forbidden in [
            ["stage", "and", "rekey"].join("_"),
            ["agenix", "rekey"].join(" "),
        ] {
            assert!(
                !source.contains(&forbidden),
                "onboarding must not {forbidden}"
            );
        }
        assert!(PENDING_ACTION.contains("kind=rekey"), "{PENDING_ACTION}");
        assert!(PENDING_ACTION.contains("FIDO2"), "{PENDING_ACTION}");

        let repository = tempfile::tempdir().unwrap();
        std::fs::write(repository.path().join("source.age"), "age").unwrap();
        std::fs::write(repository.path().join("source.pub"), "key").unwrap();
        assert!(
            git(repository.path(), &["init", "--quiet"])
                .status
                .success()
        );
        stage_sources(
            repository.path(),
            &[Path::new("source.age"), Path::new("source.pub")],
        )
        .unwrap();
        let staged = git(repository.path(), &["diff", "--cached", "--name-only"]);
        let mut staged: Vec<String> = String::from_utf8(staged.stdout)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        staged.sort_unstable();
        assert_eq!(staged, ["source.age", "source.pub"]);
    }

    #[test]
    fn the_run_takes_the_store_lock_once_around_every_repository() {
        let repository = git_fixture();
        let root = repository.path();
        std::fs::create_dir_all(root.join("age/minisign")).unwrap();
        with_store_write_lock(root, || {
            let nested = with_store_write_lock(root, || Ok(())).unwrap_err();
            assert!(
                format!("{nested:#}").contains("another rotation is running"),
                "{nested:#}"
            );
            let public = root.join("age/minisign/key.pub");
            let writes = [LocalWrite::plain(&public, b"new public")];
            let staged = [Path::new("age/minisign/key.pub")];
            install_local(root, &writes, &staged, |write| {
                std::fs::create_dir_all(write.path.parent().unwrap())?;
                std::fs::write(&write.path, b"new public")?;
                Ok(())
            })
            .unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("age/minisign/key.pub")).unwrap(),
            "new public"
        );
        assert!(
            git(root, &["diff", "--cached", "--name-only"])
                .stdout
                .starts_with(b"age/minisign/key.pub")
        );
    }

    #[test]
    fn the_report_names_the_public_key_this_run_installed() {
        let root = tempfile::tempdir().unwrap();
        let project = project("caniko/fresh", true);
        std::fs::create_dir_all(root.path().join("age/secrets/root/modules/signing")).unwrap();
        std::fs::write(root.path().join(project.public_key_path()), "a later key").unwrap();
        let report = repository_report(
            root.path(),
            &project,
            "create",
            Some("this run's key"),
            Delivered::default(),
            None,
        );
        assert_eq!(report.public_key.as_deref(), Some("this run's key"));
        assert_eq!(report.status, RepoStatus::Ok);
        let report = repository_report(
            root.path(),
            &project,
            "keep",
            None,
            Delivered::default(),
            None,
        );
        assert_eq!(report.public_key.as_deref(), Some("a later key"));
    }

    #[test]
    fn a_staged_source_is_refused_before_anything_is_written() {
        let repository = git_fixture();
        let root = repository.path();
        std::fs::create_dir_all(root.join("age/minisign")).unwrap();
        std::fs::write(root.join("age/minisign/password.age"), "old password").unwrap();
        assert!(
            git(root, &["add", "--", "age/minisign/password.age"])
                .status
                .success()
        );

        let writes = [
            LocalWrite::plain(&root.join("age/minisign/password.age"), b"new password"),
            LocalWrite::plain(&root.join("age/minisign/key.age"), b"new key"),
        ];
        let staged = [
            Path::new("age/minisign/password.age"),
            Path::new("age/minisign/key.age"),
        ];
        let error = install_local(root, &writes, &staged, |_| {
            unreachable!("a staged path must be refused before any write")
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("staged changes"), "{message}");
        assert!(message.contains("age/minisign/password.age"), "{message}");
        assert_eq!(
            std::fs::read_to_string(root.join("age/minisign/password.age")).unwrap(),
            "old password"
        );
        assert!(!root.join("age/minisign/key.age").exists());
    }

    #[test]
    fn every_restore_is_attempted_and_a_failed_one_keeps_its_backup() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("age/a")).unwrap();
        std::fs::create_dir_all(root.path().join("age/b")).unwrap();
        let failing = root.path().join("age/a/key.age");
        let good = root.path().join("age/b/key.age");
        std::fs::write(&failing, "old a").unwrap();
        std::fs::write(&good, "old b").unwrap();
        let backups = SourceBackup::capture([failing.as_path(), good.as_path()]).unwrap();
        assert!(!failing.exists());
        assert!(!good.exists());
        assert_eq!(
            std::fs::read_to_string(with_suffix(&failing, BACKUP_SUFFIX)).unwrap(),
            "old a"
        );

        std::fs::create_dir(&failing).unwrap();

        let error = restore_all(root.path(), &backups, &[], anyhow!("install failed"));
        let message = format!("{error:#}");
        assert!(message.contains("install failed"), "{message}");
        assert!(
            message.contains("restoring the previous files also failed"),
            "{message}"
        );
        assert_eq!(std::fs::read_to_string(&good).unwrap(), "old b");
        let kept = with_suffix(&failing, BACKUP_SUFFIX);
        assert!(message.contains(&kept.display().to_string()), "{message}");
        assert_eq!(std::fs::read_to_string(&kept).unwrap(), "old a");

        let error = SourceBackup::capture([failing.as_path()]).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("already exists"), "{message}");
        assert!(message.contains(&kept.display().to_string()), "{message}");
    }

    #[test]
    fn a_successful_local_phase_deletes_its_backups() {
        let repository = git_fixture();
        let root = repository.path();
        std::fs::write(root.join("old.age"), "old").unwrap();
        assert!(git(root, &["add", "--", "old.age"]).status.success());
        commit_index(root, "old source");
        let writes = [LocalWrite::plain(&root.join("old.age"), b"new")];
        install_local(root, &writes, &[Path::new("old.age")], |write| {
            std::fs::write(&write.path, b"new")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("old.age")).unwrap(),
            "new"
        );
        assert!(!with_suffix(&root.join("old.age"), BACKUP_SUFFIX).exists());
    }

    #[test]
    fn a_failed_local_phase_restores_the_pair_and_the_public_key() {
        let repository = git_fixture();
        let root = repository.path();
        std::fs::create_dir_all(root.join("age/minisign")).unwrap();
        std::fs::write(root.join("age/minisign/password.age"), "old password").unwrap();
        std::fs::write(root.join("age/minisign/key.age"), "old key").unwrap();
        std::fs::write(root.join("age/minisign/key.pub"), "old public").unwrap();
        assert!(git(root, &["add", "--", "age"]).status.success());
        commit_index(root, "old pair");
        let writes = [
            LocalWrite::age(&root.join("age/minisign/password.age"), b"new password"),
            LocalWrite::age(&root.join("age/minisign/key.age"), b"new key"),
            LocalWrite::plain(&root.join("age/minisign/key.pub"), b"new public"),
        ];
        let staged = [
            Path::new("age/minisign/password.age"),
            Path::new("age/minisign/key.age"),
            Path::new("age/minisign/key.pub"),
        ];
        let error = install_local(root, &writes, &staged, |write| {
            std::fs::write(&write.path, b"half written")?;
            if write.path.ends_with("key.age") {
                bail!("encryption failed");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("encryption failed"));
        assert!(format!("{error:#}").contains("restored"));
        assert_eq!(
            std::fs::read_to_string(root.join("age/minisign/password.age")).unwrap(),
            "old password"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("age/minisign/key.age")).unwrap(),
            "old key"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("age/minisign/key.pub")).unwrap(),
            "old public"
        );
        assert!(committed(root));
    }

    #[test]
    fn a_failed_create_leaves_no_files_behind() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("age")).unwrap();
        let writes = [
            LocalWrite::plain(&root.path().join("age/new.pub"), b"new public"),
            LocalWrite::plain(&root.path().join("age/new.age"), b"new key"),
        ];
        let error = install_local(root.path(), &writes, &[], |write| {
            assert!(std::fs::write(&write.path, b"partial").is_ok());
            bail!("disk full")
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("disk full"));
        assert!(!root.path().join("age/new.pub").exists());
        assert!(!root.path().join("age/new.age").exists());
    }

    struct FakeForge {
        fail_push: Option<&'static str>,
        fail_verify: bool,
    }

    impl Forge for FakeForge {
        fn push(&self, _project: &ReleaseProject, name: &str, _value: &str) -> Result<()> {
            match self.fail_push {
                Some(failed) if failed == name => bail!("gh secret set failed"),
                _ => Ok(()),
            }
        }

        fn verify(&self, _project: &ReleaseProject) -> Result<()> {
            ensure!(
                !self.fail_verify,
                "GitHub reports no secret after the upload"
            );
            Ok(())
        }
    }

    fn minted() -> MintedPair {
        MintedPair {
            password: Zeroizing::new("p".repeat(PASSPHRASE_LEN)),
            secret_key: Zeroizing::new("untrusted comment: fixture".to_string()),
            public_key: "untrusted comment: fixture public".to_string(),
        }
    }

    fn managed(root: &Path) -> Vec<ManagedRecord> {
        SyncState::load(&root.join(".secret-manager/sync-state.toml"))
            .unwrap()
            .map(|state| state.managed)
            .unwrap_or_default()
    }

    #[test]
    fn a_failed_upload_keeps_the_local_pair_and_reports_incomplete_delivery() {
        let root = tempfile::tempdir().unwrap();
        let project = project("caniko/remote", true);
        std::fs::create_dir_all(root.path().join(".secret-manager")).unwrap();
        std::fs::write(root.path().join("pair.age"), "installed").unwrap();

        let delivered = deliver(
            root.path(),
            &project,
            &minted(),
            &FakeForge {
                fail_push: Some("MINISIGN_PASSWORD"),
                fail_verify: false,
            },
        );
        assert!(delivered.uploaded.is_empty());
        assert!(delivered.failure.is_some());
        assert!(managed(root.path()).is_empty());

        let delivered = deliver(
            root.path(),
            &project,
            &minted(),
            &FakeForge {
                fail_push: Some("MINISIGN_SECRET_KEY"),
                fail_verify: false,
            },
        );
        assert_eq!(delivered.uploaded, ["MINISIGN_PASSWORD"]);
        assert!(delivered.failure.is_some());
        assert_eq!(
            managed(root.path())
                .iter()
                .map(|record| record.target.as_str())
                .collect::<Vec<_>>(),
            ["caniko-remote-minisign-password"]
        );

        let delivered = deliver(
            root.path(),
            &project,
            &minted(),
            &FakeForge {
                fail_push: None,
                fail_verify: true,
            },
        );
        assert_eq!(
            delivered.uploaded,
            ["MINISIGN_PASSWORD", "MINISIGN_SECRET_KEY"]
        );
        assert!(delivered.failure.is_some());

        assert_eq!(
            std::fs::read_to_string(root.path().join("pair.age")).unwrap(),
            "installed"
        );
        let report = repository_report(root.path(), &project, "create", None, delivered, None);
        assert_eq!(report.status, RepoStatus::DeliveryIncomplete);
        assert!(report.error.is_some());
        let recovery = report.recovery.clone().unwrap();
        assert!(recovery.contains("Commit"), "{recovery}");
        assert!(recovery.contains("git restore --staged"), "{recovery}");
        assert!(
            recovery.contains(&format!("--repo {} --rotate", project.repo)),
            "{recovery}"
        );
        assert!(report.note.unwrap().contains("delivery incomplete"));
    }

    #[test]
    fn a_failed_rotation_keeps_the_rotate_intent_in_its_recovery() {
        let project = project("caniko/half", true);
        let error = anyhow!("half onboarded; pass --rotate");
        let report = failed_report(&project, "rotate", &error);
        let recovery = report.recovery.as_deref().unwrap();
        assert!(recovery.contains(&format!("--repo {} --rotate", project.repo)));
        let report = failed_report(&project, "create", &error);
        let recovery = report.recovery.as_deref().unwrap();
        assert!(recovery.contains(&format!("--repo {}`", project.repo)));
        assert!(!recovery.contains("--rotate"));
    }

    #[test]
    fn github_commands_bind_the_repository_to_github_com() {
        assert_eq!(
            secret_set_args("caniko/fleetix", "MINISIGN_PASSWORD").join(" "),
            "secret set MINISIGN_PASSWORD --repo github.com/caniko/fleetix"
        );
        assert_eq!(
            secret_list_args("caniko/fleetix").join(" "),
            "secret list --repo github.com/caniko/fleetix --json name"
        );
    }

    #[test]
    fn a_failed_repository_is_reported_and_the_run_continues() {
        let root = tempfile::tempdir().unwrap();
        let done = project("caniko/done", true);
        let half = project("caniko/half", true);
        std::fs::create_dir_all(root.path().join("age/secrets/root/modules/signing")).unwrap();
        std::fs::write(root.path().join(&half.minisign_password_path), "existing").unwrap();
        std::fs::write(root.path().join(&done.minisign_password_path), "existing").unwrap();
        std::fs::write(root.path().join(&done.minisign_secret_path), "existing").unwrap();
        let planned = [
            PlannedProject {
                project: half,
                password: FilePlan::Create,
                secret_key: FilePlan::Create,
                rotate: false,
            },
            PlannedProject {
                project: done,
                password: FilePlan::Keep,
                secret_key: FilePlan::Keep,
                rotate: false,
            },
        ];
        let repos = onboard_all(
            root.path(),
            &planned,
            None,
            None,
            &FakeForge {
                fail_push: None,
                fail_verify: false,
            },
        );
        assert_eq!(repos.len(), 2);
        assert_eq!(repos[0].status, RepoStatus::Failed);
        assert!(
            repos[0]
                .error
                .as_deref()
                .unwrap()
                .contains("half onboarded")
        );
        assert!(
            repos[0]
                .recovery
                .as_deref()
                .unwrap()
                .contains("--repo caniko/half")
        );
        assert_eq!(repos[1].status, RepoStatus::Ok);

        let report = OnboardReport {
            dry_run: false,
            skipped: Vec::new(),
            repos,
            pending_operator_action: PENDING_ACTION.to_string(),
        };
        assert!(!report.is_ok());
        let summary = report.failure_summary();
        assert!(summary.contains("caniko/half"));
        assert!(!summary.contains("caniko/done"));
    }

    #[test]
    fn a_minisign_failure_reports_only_its_exit_status() {
        let status = Command::new("sh")
            .args(["-c", "echo 'the password is hunter2' >&2; exit 3"])
            .output()
            .unwrap()
            .status;
        let message = format!("{:#}", minisign_error(status));
        assert!(message.contains("exit status"), "{message}");
        assert!(message.contains('3'), "{message}");
        assert!(!message.contains("hunter2"), "{message}");
        assert!(!message.contains("password is"), "{message}");
    }

    #[test]
    fn a_complete_delivery_records_both_destinations_once() {
        let root = tempfile::tempdir().unwrap();
        let project = project("caniko/delivered", true);
        std::fs::create_dir_all(root.path().join(".secret-manager")).unwrap();
        let forge = FakeForge {
            fail_push: None,
            fail_verify: false,
        };
        let delivered = deliver(root.path(), &project, &minted(), &forge);
        assert!(delivered.failure.is_none());
        assert_eq!(delivered.uploaded.len(), 2);
        deliver(root.path(), &project, &minted(), &forge);
        assert_eq!(managed(root.path()).len(), 2);
    }

    #[test]
    fn minted_pair_signs_and_verifies_with_its_password() {
        if Command::new("minisign").arg("-v").output().is_err() {
            return;
        }
        let minted = mint().unwrap();
        assert_eq!(minted.password.len(), PASSPHRASE_LEN);
        assert!(minted.secret_key.starts_with("untrusted comment:"));
        assert!(minted.public_key.starts_with("untrusted comment:"));
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("key");
        let public = directory.path().join("key.pub");
        std::fs::write(&key, &*minted.secret_key).unwrap();
        std::fs::write(&public, &minted.public_key).unwrap();
        let message = directory.path().join("message");
        std::fs::write(&message, "release").unwrap();

        let mut child = Command::new("minisign")
            .args(["-S", "-s"])
            .arg(&key)
            .args(["-m"])
            .arg(&message)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{}", *minted.password).unwrap();
        assert!(child.wait().unwrap().success());
        assert!(
            Command::new("minisign")
                .args(["-V", "-p"])
                .arg(&public)
                .args(["-m"])
                .arg(&message)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}
