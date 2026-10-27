use anyhow::{Context, Result, anyhow, bail};
use clap::Args;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::store::{Store, resolve_against};
use crate::sync_state::{
    ManagedKind, ManagedRecord, Scope, SyncState, desired_records, retained_without_prune,
    stale_records,
};
use crate::sync_targets::{Provider, SyncDocument, SyncValue};
use nix_manager_core::{age, forge, ui};

/// Read collected sync targets and push each declared value to its
/// declared forge Actions destinations. When no explicit JSON input is passed,
/// the nearest flake is evaluated via `secret-manager.lib.collect`.
///
/// Encrypted agenix values are pushed as CI secrets. Plaintext source files are
/// pushed as Actions variables. Forgejo destinations use the `fj` auth store,
/// Codefloe uses Crow, and GitHub destinations use the `gh` CLI.
#[derive(Args)]
pub struct SyncArgs {
    /// Path to the collected sync-targets JSON document.
    /// If omitted, reads stdin when piped, otherwise auto-collects from a flake.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Flake root or flake reference to collect sync targets from.
    /// Defaults to the nearest flake root when no explicit JSON input is present.
    #[arg(long, value_name = "FLAKE")]
    pub flake: Option<String>,

    /// Disable flake auto-collection; require --config or piped JSON.
    #[arg(long)]
    pub no_flake: bool,

    /// age identity file(s) for decryption.
    /// Repeatable. Defaults to SECRET_MANAGER_AGE_IDENTITIES
    /// (colon-separated), then the store's master identities.
    #[arg(long = "identity", value_name = "PATH")]
    pub identities: Vec<PathBuf>,

    /// Print planned pushes without decrypting or contacting any forge.
    #[arg(long)]
    pub dry_run: bool,

    /// Check the sync plan without decrypting or contacting any forge.
    #[arg(long)]
    pub check: bool,

    /// Restrict sync to one declarative target id. Repeatable.
    #[arg(long = "target", value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Delete previously managed remote entries that are no longer declared.
    #[arg(long)]
    pub prune: bool,

    /// Print diagnostic progress details without exposing secret values.
    #[arg(long)]
    pub verbose: bool,

    /// Path to the sync state TOML file.
    /// Defaults to `<secret-store>/.secret-manager/sync-state.toml`.
    #[arg(long, value_name = "PATH")]
    pub state: Option<PathBuf>,
}

impl SyncArgs {
    pub fn run(self) -> Result<()> {
        validate_target_prune_args(&self.targets, self.prune)?;
        let doc = self.load_document()?;
        // The original stdin may already be consumed. Replay the complete
        // public document; the child reapplies the preserved --target
        // selection, CLI policy and state.
        let replay = serde_json::to_vec(&doc)?;
        self.run_document(
            doc,
            || crate::protection::enter_scope_with_input(Some(&replay)),
            crate::protection::CredentialProtection::acquire,
        )
    }

    /// Decide from the loaded document alone whether the run needs the
    /// credential scope, and re-exec before any store discovery, state load or
    /// stale check, so all planning output is produced exactly once, in the
    /// process that does the work.
    fn run_document<G>(
        self,
        doc: SyncDocument,
        enter_scope: impl FnOnce() -> Result<Option<std::process::ExitStatus>>,
        acquire: impl FnOnce() -> Result<G>,
    ) -> Result<()> {
        // Staleness is judged against every declared target; --target only
        // narrows which targets are pushed.
        let declared_state = desired_records(&doc)?;
        let doc = filter_document_targets(doc, &self.targets)?;
        let total = doc.total_targets();
        let desired_state = desired_records(&doc)?;
        let needs_decrypt = records_need_decrypt_session(&desired_state);
        with_sync_protection(
            needs_decrypt && !(self.dry_run || self.check),
            enter_scope,
            acquire,
            || {
                ui::step("discovering secret store");
                let store = Store::discover()?;
                if self.verbose {
                    ui::info(format!("store root: {}", store.root.display()));
                }
                let state_path = self
                    .state
                    .clone()
                    .unwrap_or_else(|| default_state_path(&store));
                ui::step("loading sync state");
                if self.verbose {
                    ui::info(format!("sync state path: {}", state_path.display()));
                }
                let previous_state = SyncState::load(&state_path)?.unwrap_or_else(SyncState::empty);
                ui::step("checking stale managed entries");
                let stale = stale_records(&previous_state.managed, &declared_state);
                if stale.is_empty() {
                    ui::step_success("no stale managed entries");
                } else {
                    ui::step(format!(
                        "found {} stale managed entr{}",
                        stale.len(),
                        plural_y(stale.len())
                    ));
                }

                if self.dry_run || self.check {
                    if self.check {
                        println!("Planned pushes (--check):");
                    } else {
                        println!("Planned pushes (--dry-run):");
                    }
                    for record in &desired_state {
                        println!();
                        println!("  target: {}", record.target);
                        println!("  kind:   {}", kind_label(record.kind));
                        println!("  source: {}", record.source);
                        println!("  name:   {}", record.name);
                        println!("  → {}", record.destination_label());
                    }
                    print_stale_records(&stale, self.prune);
                    println!();
                    println!("total targets: {total}");
                    return Ok(());
                }

                let decrypt_session = if needs_decrypt {
                    let identities = store.resolve_identities(&self.identities)?;
                    let session = age::DecryptSession::from_identities(&identities)?;
                    let secrets: Vec<PathBuf> = desired_state
                        .iter()
                        .filter(|record| record.kind == ManagedKind::Secret)
                        .filter_map(|record| validated_secret_path(&store, &record.source).ok())
                        .collect();
                    session.prefetch(&secrets)?;
                    Some(session)
                } else {
                    None
                };
                let mut value_cache = SyncValueCache::default();
                push_and_commit(
                    &desired_state,
                    &previous_state.managed,
                    self.prune,
                    &state_path,
                    |record| {
                        ui::step(format!(
                            "sync: `{}` {} from {}",
                            record.target,
                            kind_label(record.kind),
                            record.source
                        ));
                        if self.verbose {
                            ui::info(format!("destination: {}", record.destination_label()));
                        }
                        let value = value_cache.get(
                            &store,
                            &record_value(record),
                            decrypt_session.as_ref(),
                        )?;
                        push_managed_record(record, &value)
                    },
                    || {
                        if self.prune {
                            ui::step(format!(
                                "pruning {} stale managed entr{}",
                                stale.len(),
                                plural_y(stale.len())
                            ));
                            for record in &stale {
                                delete_managed_record(record)?;
                            }
                        } else {
                            ui::step("reporting stale managed entries");
                            report_stale_records(&stale);
                        }
                        Ok(())
                    },
                )?;

                ui::success(format!("synced {total} target(s)"));
                Ok(())
            },
        )
    }

    fn load_document(&self) -> Result<SyncDocument> {
        if std::env::var_os("SECRET_MANAGER_SYNC_REPLAY").is_some_and(|value| value == "1")
            && std::env::var_os("SECRET_MANAGER_SCOPE_ATTEMPT").is_some_and(|value| value == "1")
        {
            // Embedding frontends own their argv. Preserve it unchanged and
            // replay public configuration instead of rereading a consumed stdin
            // or mutable file/flake. Kernel protection is still checked below.
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            return Ok(SyncDocument::from_json(&input)?);
        }
        let doc = match &self.config {
            Some(path) => {
                ui::step(format!("reading sync targets from {}", path.display()));
                SyncDocument::from_path(path).map_err(anyhow::Error::from)
            }
            None => {
                let stdin = std::io::stdin();
                if !stdin.is_terminal() {
                    let mut buf = String::new();
                    stdin
                        .lock()
                        .read_to_string(&mut buf)
                        .map_err(|e| anyhow!("reading stdin: {e}"))?;
                    if !buf.trim().is_empty() {
                        ui::step("reading sync targets from stdin");
                        if self.verbose {
                            ui::info(format!("sync JSON bytes: {}", buf.len()));
                        }
                        return summarize_document(
                            SyncDocument::from_json(&buf).map_err(anyhow::Error::from)?,
                        );
                    }
                }

                if self.no_flake {
                    bail!(NO_INPUT);
                }

                let flake = self.resolve_flake()?;
                ui::step(format!(
                    "auto-collecting sync targets from {}",
                    flake.label()
                ));
                let json = collect_flake_sync_targets(&flake, self.verbose)?;
                if self.verbose {
                    ui::info(format!("sync JSON bytes: {}", json.len()));
                }
                SyncDocument::from_json(&json).map_err(anyhow::Error::from)
            }
        }?;

        summarize_document(doc)
    }

    fn resolve_flake(&self) -> Result<FlakeRef> {
        if let Some(flake) = &self.flake {
            return Ok(FlakeRef::Explicit(flake.clone()));
        }
        Store::discover()
            .map(|store| FlakeRef::Path(store.root))
            .map_err(|e| anyhow!("{NO_INPUT}: {e}"))
    }
}

/// Push each record, then run `finish` (prune/report). The sync state is
/// written even when a later record or `finish` fails, so records already
/// pushed in this run are not forgotten; the original error is then returned.
fn push_and_commit(
    desired: &[ManagedRecord],
    previous: &[ManagedRecord],
    prune: bool,
    state_path: &Path,
    mut push: impl FnMut(&ManagedRecord) -> Result<()>,
    finish: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut pushed = Vec::new();
    let outcome = (|| {
        for record in desired {
            push(record)?;
            pushed.push(record.clone());
        }
        finish()
    })();
    if outcome.is_err() && pushed.is_empty() {
        return outcome;
    }
    // A partial run never prunes the previous state down to what it pushed.
    let next = if prune && outcome.is_ok() {
        desired.to_vec()
    } else {
        retained_without_prune(previous, &pushed)
    };
    ui::step("writing sync state");
    match (outcome, SyncState::new(next).write_atomic(state_path)) {
        (Err(error), Err(write)) => Err(error.context(format!("sync state not saved: {write:#}"))),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), written) => written,
    }
}

fn validate_target_prune_args(targets: &[String], prune: bool) -> Result<()> {
    if prune && !targets.is_empty() {
        bail!("--prune cannot be combined with --target; prune requires the complete config");
    }
    Ok(())
}

const NO_INPUT: &str =
    "no input — pipe JSON, pass --config, or run from a flake with secret-manager.lib.collect";

#[derive(Debug, Clone, PartialEq, Eq)]
enum FlakeRef {
    Path(PathBuf),
    Explicit(String),
}

impl FlakeRef {
    fn label(&self) -> String {
        match self {
            FlakeRef::Path(path) => path.display().to_string(),
            FlakeRef::Explicit(flake) => flake.clone(),
        }
    }

    fn nix_expr(&self) -> String {
        let flake_ref = match self {
            FlakeRef::Path(path) => format!("(toString {})", nix_path_literal(path)),
            FlakeRef::Explicit(flake) => nix_string(flake),
        };
        format!(
            "let flake = builtins.getFlake {flake_ref}; in flake.inputs.secret-manager.lib.collect {{ inherit (flake) nixosConfigurations; }}"
        )
    }

    fn secret_sync_targets_attr(&self) -> String {
        match self {
            FlakeRef::Path(path) => format!("{}#secretSyncTargets", path.display()),
            FlakeRef::Explicit(flake) if flake.contains('#') => {
                format!("{flake}.secretSyncTargets")
            }
            FlakeRef::Explicit(flake) => format!("{flake}#secretSyncTargets"),
        }
    }
}

fn collect_flake_sync_targets(flake: &FlakeRef, verbose: bool) -> Result<String> {
    ui::step(format!("evaluating sync targets from {}", flake.label()));
    match collect_fast_flake_sync_targets(flake, verbose)? {
        FastCollect::Found(json) => return Ok(json),
        FastCollect::Missing => {
            if verbose {
                ui::info(format!(
                    "{} has no #secretSyncTargets; falling back to legacy NixOS collection",
                    flake.label()
                ));
            }
        }
    }

    collect_legacy_flake_sync_targets(flake, verbose)
}

enum FastCollect {
    Found(String),
    Missing,
}

fn collect_fast_flake_sync_targets(flake: &FlakeRef, verbose: bool) -> Result<FastCollect> {
    let args = fast_nix_eval_args(flake);
    if verbose {
        ui::info(format!(
            "nix argv: {:?}",
            std::iter::once("nix")
                .chain(args.iter().map(String::as_str))
                .collect::<Vec<_>>()
        ));
    }
    let pb = ui::spinner(format!("nix eval {}", flake.secret_sync_targets_attr()));
    let output = match Command::new("nix").args(&args).output() {
        Ok(output) => output,
        Err(err) => {
            ui::fail_spinner(pb, "failed to spawn nix");
            return Err(anyhow!("failed to spawn nix: {err}"));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_missing_secret_sync_targets(&stderr) {
            ui::finish_spinner(
                pb,
                format!("no #secretSyncTargets fast path on {}", flake.label()),
            );
            return Ok(FastCollect::Missing);
        }
        ui::fail_spinner(pb, "nix eval failed");
        bail!(
            "nix eval failed while reading #secretSyncTargets from {}\n{}",
            flake.label(),
            stderr.trim()
        );
    }

    ui::finish_spinner(
        pb,
        format!(
            "collected sync targets from {}#secretSyncTargets",
            flake.label()
        ),
    );
    Ok(FastCollect::Found(
        String::from_utf8(output.stdout).context("nix eval returned non-UTF-8 JSON")?,
    ))
}

fn collect_legacy_flake_sync_targets(flake: &FlakeRef, verbose: bool) -> Result<String> {
    let args = legacy_nix_eval_args(flake);
    if verbose {
        ui::info(format!(
            "nix argv: {:?}",
            std::iter::once("nix")
                .chain(args.iter().map(String::as_str))
                .collect::<Vec<_>>()
        ));
    }
    let pb = ui::spinner(format!("nix eval {}", flake.label()));
    let output = match Command::new("nix").args(&args).output() {
        Ok(output) => output,
        Err(err) => {
            ui::fail_spinner(pb, "failed to spawn nix");
            return Err(anyhow!("failed to spawn nix: {err}"));
        }
    };

    if !output.status.success() {
        ui::fail_spinner(pb, "nix eval failed");
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("attribute 'secret-manager' missing")
            || stderr.contains("attribute 'collect' missing")
            || stderr.contains("attribute 'lib' missing")
        {
            bail!(
                "flake {} does not expose #secretSyncTargets or inputs.secret-manager.lib.collect; \
                 add secretSyncTargets, add the secret-manager input, or pass --config <path>\n{}",
                flake.label(),
                stderr.trim()
            );
        }
        bail!(
            "nix eval failed while collecting sync targets from {}\n{}",
            flake.label(),
            stderr.trim()
        );
    }

    ui::finish_spinner(pb, format!("collected sync targets from {}", flake.label()));
    String::from_utf8(output.stdout).context("nix eval returned non-UTF-8 JSON")
}

fn fast_nix_eval_args(flake: &FlakeRef) -> Vec<String> {
    vec![
        "eval".to_string(),
        "--json".to_string(),
        flake.secret_sync_targets_attr(),
        "--accept-flake-config".to_string(),
        "--no-update-lock-file".to_string(),
    ]
}

fn legacy_nix_eval_args(flake: &FlakeRef) -> Vec<String> {
    vec![
        "eval".to_string(),
        "--json".to_string(),
        "--impure".to_string(),
        "--expr".to_string(),
        flake.nix_expr(),
        "--accept-flake-config".to_string(),
        "--no-update-lock-file".to_string(),
    ]
}

fn is_missing_secret_sync_targets(stderr: &str) -> bool {
    stderr.contains("secretSyncTargets")
        && (stderr.contains("does not provide attribute")
            || stderr.contains("attribute 'secretSyncTargets' missing")
            || stderr.contains("attribute `secretSyncTargets` missing")
            || stderr.contains("undefined variable 'secretSyncTargets'"))
}

fn nix_string(value: &str) -> String {
    serde_json::to_string(value).expect("JSON string encoding is infallible")
}

fn nix_path_literal(path: &std::path::Path) -> String {
    path.to_string_lossy().replace(' ', "\\ ")
}

fn default_state_path(store: &Store) -> PathBuf {
    store.root.join(".secret-manager").join("sync-state.toml")
}

fn summarize_document(doc: SyncDocument) -> Result<SyncDocument> {
    let summary = document_summary(&doc);
    ui::step_success(format!(
        "loaded {} enabled host{} with {} sync target{}",
        summary.hosts,
        plural_s(summary.hosts),
        summary.targets,
        plural_s(summary.targets)
    ));
    Ok(doc)
}

fn filter_document_targets(mut doc: SyncDocument, targets: &[String]) -> Result<SyncDocument> {
    if targets.is_empty() {
        return Ok(doc);
    }
    let requested = targets.iter().cloned().collect::<BTreeSet<_>>();
    let mut found = BTreeSet::new();
    for host in &mut doc.hosts {
        host.targets.retain(|name, _| {
            let keep = requested.contains(name);
            if keep {
                found.insert(name.clone());
            }
            keep
        });
    }
    let missing = requested.difference(&found).cloned().collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("unknown sync target(s): {}", missing.join(", "));
    }
    Ok(doc)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncDocumentSummary {
    hosts: usize,
    targets: usize,
}

fn document_summary(doc: &SyncDocument) -> SyncDocumentSummary {
    SyncDocumentSummary {
        hosts: doc.hosts.len(),
        targets: doc.total_targets(),
    }
}

fn plural_s(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

fn plural_y(count: usize) -> &'static str {
    if count == 1 { "y" } else { "ies" }
}

fn print_stale_records(stale: &[ManagedRecord], prune: bool) {
    for line in stale_record_lines(stale, prune) {
        println!("{line}");
    }
}

fn stale_record_lines(stale: &[ManagedRecord], prune: bool) -> Vec<String> {
    if stale.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![
        String::new(),
        if prune {
            "Planned prunes (--prune):".to_string()
        } else {
            "Stale managed entries (pass --prune to delete):".to_string()
        },
    ];

    for record in stale {
        lines.push(String::new());
        lines.push(format!("  target: {}", record.target));
        lines.push(format!("  kind:   {}", kind_label(record.kind)));
        lines.push(format!("  source: {}", record.source));
        lines.push(format!("  name:   {}", record.name));
        lines.push(format!("  → {}", record.destination_label()));
    }

    lines
}

fn report_stale_records(stale: &[ManagedRecord]) {
    if stale.is_empty() {
        return;
    }
    ui::warn(format!(
        "{} stale managed sync entr{} remain; rerun with --prune to delete them",
        stale.len(),
        if stale.len() == 1 { "y" } else { "ies" }
    ));
    for record in stale {
        ui::warn(format!(
            "  stale {} `{}` at {}",
            kind_label(record.kind),
            record.name,
            record.destination_label()
        ));
    }
}

fn records_need_decrypt_session(records: &[ManagedRecord]) -> bool {
    records
        .iter()
        .any(|record| record.kind == ManagedKind::Secret)
}

fn record_value(record: &ManagedRecord) -> SyncValue {
    match record.kind {
        ManagedKind::Secret => SyncValue::Secret(record.source.clone()),
        ManagedKind::Variable => SyncValue::Source(record.source.clone()),
    }
}

fn push_managed_record(record: &ManagedRecord, value: &str) -> Result<()> {
    ui::step(format!(
        "  {} as {}",
        record.destination_label(),
        record.name
    ));
    match record.provider {
        Provider::Forgejo => push_forgejo_record(record, value),
        Provider::Github => push_github_record(record, value),
        Provider::Crow => push_crow_record(record, value),
    }
}

fn push_forgejo_record(record: &ManagedRecord, value: &str) -> Result<()> {
    match record.scope {
        Scope::Environment => bail!("Forgejo environment sync is not supported"),
        Scope::Repo => {
            let repo = record_repo(record)?;
            match record.kind {
                ManagedKind::Secret => {
                    forge::push_codeberg_secret(&record.host, &repo, &record.name, value)
                }
                ManagedKind::Variable => {
                    forge::push_codeberg_variable(&record.host, &repo, &record.name, value)
                }
            }
        }
        Scope::Org => {
            let org = required_field(record.org.as_deref(), record, "org")?;
            match record.kind {
                ManagedKind::Secret => {
                    forge::push_codeberg_organization_secret(&record.host, org, &record.name, value)
                }
                ManagedKind::Variable => forge::push_codeberg_organization_variable(
                    &record.host,
                    org,
                    &record.name,
                    value,
                ),
            }
        }
        Scope::User if record.kind == ManagedKind::Secret => {
            let auth = forge::codeberg_auth(&record.host)?;
            ui::step(user_scope_push_label(
                &record.host,
                auth.username(),
                &record.name,
            ));
            forge::push_codeberg_user_secret(&record.host, &record.name, value)
        }
        Scope::User => {
            let auth = forge::codeberg_auth(&record.host)?;
            ui::step(user_scope_push_label(
                &record.host,
                auth.username(),
                &record.name,
            ));
            forge::push_codeberg_user_variable(&record.host, &record.name, value)
        }
    }
}

fn push_github_record(record: &ManagedRecord, value: &str) -> Result<()> {
    let args = github_record_args(record, "set")?;
    if record.scope == Scope::Environment {
        // Never implicitly create an unprotected environment during secret
        // synchronization. Enrollment and branch policy precede this data sync.
        check_github_resource(
            &github_environment_endpoint(record, None)?,
            required_field(record.environment.as_deref(), record, "environment")?,
        )?;
        run_gh_with_input(&args.iter().map(String::as_str).collect::<Vec<_>>(), value)?;
        check_github_resource(
            &github_environment_endpoint(record, Some(record.kind))?,
            &record.name,
        )?;
        return Ok(());
    }
    run_gh_with_input(&args.iter().map(String::as_str).collect::<Vec<_>>(), value)
}

fn github_record_args(record: &ManagedRecord, action: &str) -> Result<Vec<String>> {
    if record.provider != Provider::Github || record.host != "github.com" {
        bail!("GitHub sync record has a foreign provider or host");
    }
    let repo = record_repo(record)?;
    let kind = match record.kind {
        ManagedKind::Secret => "secret",
        ManagedKind::Variable => "variable",
    };
    let mut args = vec![
        kind.into(),
        action.into(),
        record.name.clone(),
        "--repo".into(),
        format!("github.com/{repo}"),
    ];
    match record.scope {
        Scope::Repo if record.environment.is_none() => {}
        Scope::Environment => {
            let environment = required_field(record.environment.as_deref(), record, "environment")?;
            crate::sync_targets::GithubEnvironment {
                repository: repo,
                environment: environment.into(),
            }
            .validate()?;
            crate::sync_targets::validate_github_environment_value_name(&record.name)?;
            args.push(format!("--env={environment}"));
        }
        _ => bail!("GitHub sync supports repository or environment scope only"),
    }
    Ok(args)
}

fn github_environment_endpoint(
    record: &ManagedRecord,
    kind: Option<ManagedKind>,
) -> Result<String> {
    // REST path segments need encoding even when gh's --env argument safely
    // accepts spaces, slashes, quotes or other punctuation.
    let mut url = url::Url::parse("https://api.github.com/")?;
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow!("invalid GitHub API URL"))?;
    segments.extend([
        "repos",
        required_field(record.owner.as_deref(), record, "owner")?,
        required_field(record.repo.as_deref(), record, "repo")?,
        "environments",
        required_field(record.environment.as_deref(), record, "environment")?,
    ]);
    if let Some(kind) = kind {
        segments
            .push(match kind {
                ManagedKind::Secret => "secrets",
                ManagedKind::Variable => "variables",
            })
            .push(&record.name);
    }
    drop(segments);
    Ok(url.path().trim_start_matches('/').to_owned())
}

fn check_github_resource(endpoint: &str, expected_name: &str) -> Result<()> {
    let output = crate::credential_process::capture(
        Command::new("gh").args(["api", endpoint, "--hostname", "github.com"]),
        None,
    )
    .context("GitHub environment resource verification failed")?;
    let resource: serde_json::Value = serde_json::from_slice(&output)
        .context("GitHub environment resource has no valid JSON metadata")?;
    if resource
        .get("name")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|name| name.to_lowercase() != expected_name.to_lowercase())
    {
        bail!("GitHub environment resource name does not match the selected destination");
    }
    Ok(())
}

fn push_crow_record(record: &ManagedRecord, value: &str) -> Result<()> {
    if record.scope != Scope::Repo || record.kind != ManagedKind::Secret {
        bail!("Crow supports repository secret sync targets only");
    }
    let repo = record_repo(record)?;
    let add = run_crow_secret("add", &repo, &record.name, Some(value))?;
    if add.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&add.stderr);
    if !stderr.to_ascii_lowercase().contains("already exists") {
        bail!("crow secret add failed: {}", stderr.trim());
    }
    let update = run_crow_secret("update", &repo, &record.name, Some(value))?;
    if update.status.success() {
        Ok(())
    } else {
        bail!(
            "crow secret update failed: {}",
            String::from_utf8_lossy(&update.stderr).trim()
        )
    }
}

fn run_crow_secret(
    action: &str,
    repo: &str,
    name: &str,
    value: Option<&str>,
) -> Result<std::process::Output> {
    let mut command = Command::new("crow");
    command.args(crow_secret_args(action, repo, name, value.is_some()));
    if let Some(value) = value {
        command.stdin(Stdio::piped());
        let mut child = command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("failed to spawn crow: {e}"))?;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("crow stdin was not captured"))?
            .write_all(value.as_bytes())?;
        drop(child.stdin.take());
        return child.wait_with_output().map_err(Into::into);
    }
    command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| anyhow!("failed to spawn crow: {e}"))
}

fn crow_secret_args(action: &str, repo: &str, name: &str, with_value: bool) -> Vec<String> {
    let mut args = vec![
        "--server".to_string(),
        "https://ci.codefloe.com".to_string(),
        "repo".to_string(),
        "secret".to_string(),
        action.to_string(),
        "--repo".to_string(),
        repo.to_string(),
        "--name".to_string(),
        name.to_string(),
    ];
    if with_value {
        args.extend([
            "--value".to_string(),
            "@/dev/stdin".to_string(),
            // ponytail: Codefloe sync currently serves tag-triggered release secrets;
            // add per-target Crow events when another workflow needs them.
            "--event".to_string(),
            "tag".to_string(),
        ]);
    }
    args
}

#[derive(Default)]
struct SyncValueCache {
    values: HashMap<SyncValueCacheKey, zeroize::Zeroizing<String>>,
}

impl SyncValueCache {
    fn get(
        &mut self,
        store: &Store,
        value: &SyncValue,
        decrypt_session: Option<&age::DecryptSession>,
    ) -> Result<zeroize::Zeroizing<String>> {
        match value {
            SyncValue::Secret(secret) => {
                let path = validated_secret_path(store, secret)?;
                let key = SyncValueCacheKey::new(SyncValueCacheKind::Secret, path.clone());
                self.get_or_load(key, || {
                    let session = decrypt_session.ok_or_else(|| {
                        anyhow!(
                            "encrypted sync target {} requires an age decrypt session",
                            path.display()
                        )
                    })?;
                    decrypt_sync_secret(&path, session)
                })
            }
            SyncValue::Source(source) => {
                let path = validated_source_path(store, source)?;
                let key = SyncValueCacheKey::new(SyncValueCacheKind::Source, path.clone());
                self.get_or_load(key, || read_plaintext_source_path(&path))
            }
        }
    }

    fn get_or_load(
        &mut self,
        key: SyncValueCacheKey,
        load: impl FnOnce() -> Result<String>,
    ) -> Result<zeroize::Zeroizing<String>> {
        if let Some(value) = self.values.get(&key) {
            return Ok(value.clone());
        }

        let value = zeroize::Zeroizing::new(load()?);
        self.values.insert(key, value.clone());
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SyncValueCacheKey {
    kind: SyncValueCacheKind,
    path: PathBuf,
}

impl SyncValueCacheKey {
    fn new(kind: SyncValueCacheKind, path: PathBuf) -> Self {
        Self { kind, path }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SyncValueCacheKind {
    Secret,
    Source,
}

fn validated_secret_path(store: &Store, secret: &str) -> Result<PathBuf> {
    let secret_path = resolve_against(&store.root, &PathBuf::from(secret));
    if !secret_path.is_file() {
        bail!("{} does not exist", secret_path.display());
    }
    if secret_path.extension().and_then(|s| s.to_str()) != Some("age") {
        bail!(
            "{} does not end in `.age` — refusing",
            secret_path.display()
        );
    }
    canonical_source_path(&secret_path)
}

fn validated_source_path(store: &Store, source: &str) -> Result<PathBuf> {
    let source_path = resolve_against(&store.root, &PathBuf::from(source));
    if !source_path.is_file() {
        bail!("{} does not exist", source_path.display());
    }
    canonical_source_path(&source_path)
}

fn canonical_source_path(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("canonicalizing {}", path.display()))
}

fn decrypt_sync_secret(path: &Path, session: &age::DecryptSession) -> Result<String> {
    let value = age::decrypt_with_session(path, session)?;
    if value.is_empty() {
        bail!("decrypted payload is empty");
    }
    Ok(value)
}

fn read_plaintext_source_path(source_path: &Path) -> Result<String> {
    let value = fs::read_to_string(source_path)
        .map_err(|e| anyhow::anyhow!("reading plaintext source {}: {e}", source_path.display()))?;
    if value.is_empty() {
        bail!("plaintext source {} is empty", source_path.display());
    }
    Ok(value)
}

fn user_scope_push_label(host: &str, username: &str, name: &str) -> String {
    format!(
        "  {}/{} user → {username} as {name}",
        forge_label(host),
        host
    )
}

fn forge_label(host: &str) -> &'static str {
    match host {
        "codeberg.org" => "codeberg",
        "codefloe.com" => "codefloe",
        _ => "forgejo",
    }
}

fn record_repo(record: &ManagedRecord) -> Result<String> {
    Ok(format!(
        "{}/{}",
        required_field(record.owner.as_deref(), record, "owner")?,
        required_field(record.repo.as_deref(), record, "repo")?
    ))
}

fn run_gh_with_input(args: &[&str], value: &str) -> Result<()> {
    run_gh_command_with_input(Command::new("gh").args(args), value)
}

pub(crate) fn run_gh_command_with_input(command: &mut Command, value: &str) -> Result<()> {
    // Bound/redact diagnostics, scrub debug flags, retain active inhibitor
    // descriptors, and terminate/reap the helper group on pipe/timeout failure.
    let _ = crate::credential_process::capture(command, Some(value.as_bytes()))?;
    Ok(())
}

fn with_sync_protection<G>(
    needs_decrypt: bool,
    enter_scope: impl FnOnce() -> Result<Option<std::process::ExitStatus>>,
    acquire: impl FnOnce() -> Result<G>,
    apply: impl FnOnce() -> Result<()>,
) -> Result<()> {
    // Acquire before identity resolution/decryption and retain across upload,
    // verification, pruning and state commit. Planning and public variables
    // do not enter this credential-handler boundary.
    if needs_decrypt {
        crate::protection::with_protection(enter_scope, acquire, apply)
    } else {
        apply()
    }
}

fn codeberg_client(host: &str, auth: &forge::CodebergAuth) -> Result<forgejo_api::sync::Forgejo> {
    let base_url = url::Url::parse(&format!("https://{host}"))
        .map_err(|e| anyhow::anyhow!("invalid host `{host}`: {e}"))?;

    forgejo_api::sync::Forgejo::new(auth.forgejo_auth(), base_url)
        .map_err(|e| anyhow::anyhow!("failed to create forgejo client for {host}: {e}"))
}

fn delete_managed_record(record: &ManagedRecord) -> Result<()> {
    ui::step(format!(
        "  pruning {} {} `{}`",
        record.destination_label(),
        kind_label(record.kind),
        record.name
    ));
    match record.provider {
        Provider::Forgejo => delete_forgejo_record(record),
        Provider::Github => delete_github_record(record),
        Provider::Crow => delete_crow_record(record),
    }
}

fn delete_crow_record(record: &ManagedRecord) -> Result<()> {
    if record.scope != Scope::Repo || record.kind != ManagedKind::Secret {
        bail!("Crow supports repository secret sync targets only");
    }
    let output = run_crow_secret("rm", &record_repo(record)?, &record.name, None)?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.to_ascii_lowercase().contains("not found") {
            Ok(())
        } else {
            bail!("crow secret rm failed: {}", stderr.trim())
        }
    }
}

fn delete_forgejo_record(record: &ManagedRecord) -> Result<()> {
    let action = delete_action_for(record)?;
    let auth = forge::codeberg_auth(&record.host)?;
    let api = codeberg_client(&record.host, &auth)?;

    let result = match action {
        DeleteAction::RepoSecret { owner, repo } => {
            api.delete_repo_secret(owner, repo, &record.name).send()
        }
        DeleteAction::RepoVariable { owner, repo } => {
            api.delete_repo_variable(owner, repo, &record.name).send()
        }
        DeleteAction::OrgSecret { org } => api.delete_org_secret(org, &record.name).send(),
        DeleteAction::OrgVariable { org } => api.delete_org_variable(org, &record.name).send(),
        DeleteAction::UserSecret => api.delete_user_secret(&record.name).send(),
        DeleteAction::UserVariable => api.delete_user_variable(&record.name).send(),
    };

    match result {
        Ok(()) => Ok(()),
        Err(err) if is_not_found(&err) => Ok(()),
        Err(err) => Err(anyhow::anyhow!(
            "failed to prune {} `{}` from {}: {err}",
            kind_label(record.kind),
            record.name,
            record.destination_label()
        )),
    }
}

fn delete_github_record(record: &ManagedRecord) -> Result<()> {
    let args = github_record_args(record, "delete")?;
    let output = Command::new("gh")
        .args(&args)
        .output()
        .map_err(|e| anyhow!("failed to spawn gh: {e}"))?;
    if output.status.success() || github_not_found(&output.stderr) {
        return Ok(());
    }
    bail!(
        "gh {} exited with status {}: {}",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn github_not_found(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr).contains("HTTP 404")
}

#[derive(Debug, PartialEq, Eq)]
enum DeleteAction<'a> {
    RepoSecret { owner: &'a str, repo: &'a str },
    RepoVariable { owner: &'a str, repo: &'a str },
    OrgSecret { org: &'a str },
    OrgVariable { org: &'a str },
    UserSecret,
    UserVariable,
}

fn delete_action_for(record: &ManagedRecord) -> Result<DeleteAction<'_>> {
    match (record.scope, record.kind) {
        (Scope::Environment, _) => bail!("Forgejo environment sync is not supported"),
        (Scope::Repo, ManagedKind::Secret) => Ok(DeleteAction::RepoSecret {
            owner: required_field(record.owner.as_deref(), record, "owner")?,
            repo: required_field(record.repo.as_deref(), record, "repo")?,
        }),
        (Scope::Repo, ManagedKind::Variable) => Ok(DeleteAction::RepoVariable {
            owner: required_field(record.owner.as_deref(), record, "owner")?,
            repo: required_field(record.repo.as_deref(), record, "repo")?,
        }),
        (Scope::Org, ManagedKind::Secret) => Ok(DeleteAction::OrgSecret {
            org: required_field(record.org.as_deref(), record, "org")?,
        }),
        (Scope::Org, ManagedKind::Variable) => Ok(DeleteAction::OrgVariable {
            org: required_field(record.org.as_deref(), record, "org")?,
        }),
        (Scope::User, ManagedKind::Secret) => Ok(DeleteAction::UserSecret),
        (Scope::User, ManagedKind::Variable) => Ok(DeleteAction::UserVariable),
    }
}

fn required_field<'a>(
    value: Option<&'a str>,
    record: &ManagedRecord,
    field: &str,
) -> Result<&'a str> {
    value.ok_or_else(|| {
        anyhow::anyhow!(
            "sync state record for `{}` is missing required {field} field",
            record.name
        )
    })
}

fn kind_label(kind: ManagedKind) -> &'static str {
    match kind {
        ManagedKind::Secret => "secret",
        ManagedKind::Variable => "variable",
    }
}

fn is_not_found(err: &forgejo_api::ForgejoError) -> bool {
    matches!(
        err,
        forgejo_api::ForgejoError::ApiError(api)
            if matches!(api.error_kind(), forgejo_api::ApiErrorKind::NotFound { .. })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_upload_helpers_scrub_debug_and_suppress_credential_diagnostics() {
        let mut command = Command::new("sh");
        command.args(["-c", "test -z \"${GH_DEBUG+x}${AGEDEBUG+x}${RUST_LOG+x}\" || { printf 'fake-secret-diagnostic' >&2; exit 17; }; cat >/dev/null"])
            .env("GH_DEBUG", "api").env("AGEDEBUG", "1").env("RUST_LOG", "trace");
        assert!(run_gh_command_with_input(&mut command, "fake-secret-diagnostic").is_ok());
    }

    #[test]
    fn encrypted_sync_fails_before_effects_and_holds_protection_until_completion() {
        use std::{cell::Cell, rc::Rc};
        let doc = SyncDocument::from_json(r#"{"hosts":[{"targets":{"publisher":{"secret":"token.age","name":"TOKEN","githubEnvironments":[{"repository":"caniko/demo","environment":"production"}]}}}]}"#).unwrap();
        let effects = Cell::new(0);
        let result = with_sync_protection(
            records_need_decrypt_session(&desired_records(&doc).unwrap()),
            || Ok(None),
            || -> Result<()> { bail!("protection unavailable") },
            || {
                effects.set(effects.get() + 1);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(
            effects.get(),
            0,
            "failed protection admitted decryption or upload"
        );

        struct Guard(Rc<Cell<bool>>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let held = Rc::new(Cell::new(false));
        for fail in [false, true] {
            let result = with_sync_protection(
                records_need_decrypt_session(&desired_records(&doc).unwrap()),
                || Ok(None),
                || {
                    held.set(true);
                    Ok(Guard(held.clone()))
                },
                || {
                    assert!(
                        held.get(),
                        "protection was released before upload/readback/state commit"
                    );
                    if fail {
                        bail!("upload failed");
                    }
                    Ok(())
                },
            );
            assert_eq!(result.is_err(), fail);
            assert!(
                !held.get(),
                "completed credential handler retained its inhibitor"
            );
        }
        let public = SyncDocument::from_json(r#"{"hosts":[{"targets":{"revision":{"source":"revision","name":"REVISION","githubEnvironments":[{"repository":"caniko/demo","environment":"production"}]}}}]}"#).unwrap();
        assert!(
            with_sync_protection(
                records_need_decrypt_session(&desired_records(&public).unwrap()),
                || -> Result<Option<std::process::ExitStatus>> {
                    panic!("public variable entered a credential scope")
                },
                || -> Result<()> { panic!("public variable acquired a credential inhibitor") },
                || Ok(())
            )
            .is_ok()
        );
    }

    #[test]
    fn encrypted_sync_enters_scope_before_admitting_plaintext_effects() {
        use std::{cell::Cell, os::unix::process::ExitStatusExt};
        let doc = SyncDocument::from_json(r#"{"hosts":[{"targets":{"token":{"secret":"token.age","name":"TOKEN","github":["caniko/demo"]}}}]}"#).unwrap();
        let scoped = Cell::new(false);
        let applied = Cell::new(false);
        with_sync_protection(
            records_need_decrypt_session(&desired_records(&doc).unwrap()),
            || {
                scoped.set(true);
                Ok(None)
            },
            || -> Result<()> {
                assert!(
                    scoped.get(),
                    "decryption protection was acquired outside the credential scope"
                );
                Ok(())
            },
            || {
                applied.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(applied.get());
        for code in [0, 1] {
            let result = with_sync_protection(
                records_need_decrypt_session(&desired_records(&doc).unwrap()),
                || Ok(Some(std::process::ExitStatus::from_raw(code << 8))),
                || -> Result<()> { panic!("parent decrypted after child scope execution") },
                || {
                    panic!("parent duplicated scoped upload");
                },
            );
            assert_eq!(result.is_ok(), code == 0);
        }
        assert!(
            with_sync_protection(
                records_need_decrypt_session(&desired_records(&doc).unwrap()),
                || bail!("scope unavailable"),
                || -> Result<()> { panic!("scope failure admitted decryption") },
                || Ok(())
            )
            .is_err()
        );
    }

    #[test]
    fn parent_reexecs_before_planning_and_child_plans_once() {
        use std::{cell::Cell, os::unix::process::ExitStatusExt};
        let dir = tempfile::tempdir().unwrap();
        // Unreadable state: any planning step in the parent would fail.
        let state = dir.path().join("state.toml");
        fs::write(&state, "not [valid toml").unwrap();
        let doc = || {
            SyncDocument::from_json(r#"{"hosts":[{"targets":{"token":{"secret":"token.age","name":"TOKEN","github":["caniko/demo"]}}}]}"#).unwrap()
        };
        let args = || SyncArgs {
            config: None,
            flake: None,
            no_flake: true,
            identities: vec![],
            dry_run: false,
            check: false,
            targets: vec![],
            prune: false,
            verbose: false,
            state: Some(state.clone()),
        };
        let scoped = Cell::new(0);
        args()
            .run_document(
                doc(),
                || {
                    scoped.set(scoped.get() + 1);
                    Ok(Some(std::process::ExitStatus::from_raw(0)))
                },
                || -> Result<()> { panic!("parent acquired protection after re-exec") },
            )
            .unwrap();
        assert_eq!(scoped.get(), 1);
        // Planning-only runs never enter the scope; they do reach the state.
        let mut check = args();
        check.check = true;
        let result = check.run_document(
            doc(),
            || -> Result<Option<std::process::ExitStatus>> { panic!("--check entered a scope") },
            || -> Result<()> { panic!("--check acquired protection") },
        );
        assert!(result.is_err(), "planning should have loaded the state");
    }

    #[test]
    fn partial_failure_still_persists_pushed_records() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.toml");
        let doc = SyncDocument::from_json(
            r#"{"hosts":[{"targets":{
            "a":{"source":"a","name":"A","github":["caniko/one"]},
            "b":{"source":"b","name":"B","github":["caniko/two"]}}}]}"#,
        )
        .unwrap();
        let desired = desired_records(&doc).unwrap();
        assert_eq!(desired.len(), 2);
        let result = push_and_commit(
            &desired,
            &[],
            false,
            &state,
            |record| {
                if record.target == "b" {
                    bail!("token expired");
                }
                Ok(())
            },
            || panic!("finish ran after a failed push"),
        );
        assert_eq!(result.unwrap_err().to_string(), "token expired");
        let saved = SyncState::load(&state).unwrap().unwrap();
        assert_eq!(saved.managed, vec![desired[0].clone()]);

        // Nothing pushed: the state file is not created.
        let untouched = dir.path().join("none.toml");
        assert!(
            push_and_commit(&desired, &[], false, &untouched, |_| bail!("x"), || Ok(())).is_err()
        );
        assert!(!untouched.exists());
    }

    #[test]
    fn scoped_sync_replays_filtered_destinations() {
        let doc = SyncDocument::from_json(FIXTURE).unwrap();
        let mut doc = filter_document_targets(doc, &["my-app-token".into()]).unwrap();
        doc.hosts[0]
            .targets
            .get_mut("my-app-token")
            .unwrap()
            .github_environments
            .push(crate::sync_targets::GithubEnvironment {
                repository: "caniko/demo".into(),
                environment: "production".into(),
            });
        let records = desired_records(&doc).unwrap();
        let input = serde_json::to_string(&doc).unwrap();
        assert_eq!(
            desired_records(&SyncDocument::from_json(&input).unwrap()).unwrap(),
            records
        );
        assert!(
            !input.contains("deploy-key"),
            "scoped child regained a filtered target"
        );
    }

    /// Contract fixture matching the shape nix/collect.nix produces.
    const FIXTURE: &str = r#"{
  "hosts": [
    {
      "targets": {
        "my-app-token": {
          "secret": "age/secrets/my-app-token.age",
          "name": "MY_APP_TOKEN",
          "codeberg": ["caniko/my-repo"],
          "codefloe": ["caniko/codefloe-repo"],
          "github": ["caniko/github-repo"],
          "codebergOrgs": ["caniko"],
          "codebergUser": true,
          "host": "codeberg.org"
        },
        "deploy-key": {
          "source": "age/secrets/deploy-key.pub",
          "name": "DEPLOY_KEY",
          "codeberg": ["caniko/my-repo", "caniko/other-repo"],
          "codebergOrgs": ["infra"],
          "codebergUser": false,
          "host": "git.example.com"
        }
      }
    }
  ]
}"#;

    #[test]
    fn dry_run_lists_all_targets_and_repos() {
        let doc: SyncDocument = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(doc.total_targets(), 2);

        // Verify target expansion and per-target host handling
        let mut targets: Vec<(&str, &str, &str, &str, &str, &str)> = doc
            .iter_targets()
            .flat_map(|(_, _name, target)| {
                let host: &str = &target.host;
                let source: &str = target.value.path();
                let kind: &str = target.value.kind();
                let secret_name: &str = &target.name;
                let repos = target
                    .repo_destinations()
                    .map(move |(_, host, repo)| (kind, host, source, secret_name, "repo", repo));
                let orgs = target
                    .codeberg_orgs
                    .iter()
                    .map(move |org| (kind, host, source, secret_name, "org", org.as_str()));
                let user = target.codeberg_user.then_some((
                    kind,
                    host,
                    source,
                    secret_name,
                    "user",
                    "authenticated",
                ));
                repos.chain(orgs).chain(user)
            })
            .collect();
        targets.sort_by_key(|t| (t.3, t.4, t.5));

        assert_eq!(
            targets,
            vec![
                (
                    "variable",
                    "git.example.com",
                    "age/secrets/deploy-key.pub",
                    "DEPLOY_KEY",
                    "org",
                    "infra"
                ),
                (
                    "variable",
                    "git.example.com",
                    "age/secrets/deploy-key.pub",
                    "DEPLOY_KEY",
                    "repo",
                    "caniko/my-repo"
                ),
                (
                    "variable",
                    "git.example.com",
                    "age/secrets/deploy-key.pub",
                    "DEPLOY_KEY",
                    "repo",
                    "caniko/other-repo"
                ),
                (
                    "secret",
                    "codeberg.org",
                    "age/secrets/my-app-token.age",
                    "MY_APP_TOKEN",
                    "org",
                    "caniko"
                ),
                (
                    "secret",
                    "ci.codefloe.com",
                    "age/secrets/my-app-token.age",
                    "MY_APP_TOKEN",
                    "repo",
                    "caniko/codefloe-repo"
                ),
                (
                    "secret",
                    "github.com",
                    "age/secrets/my-app-token.age",
                    "MY_APP_TOKEN",
                    "repo",
                    "caniko/github-repo"
                ),
                (
                    "secret",
                    "codeberg.org",
                    "age/secrets/my-app-token.age",
                    "MY_APP_TOKEN",
                    "repo",
                    "caniko/my-repo"
                ),
                (
                    "secret",
                    "codeberg.org",
                    "age/secrets/my-app-token.age",
                    "MY_APP_TOKEN",
                    "user",
                    "authenticated"
                ),
            ],
            "dry-run planning should expand every forge repository target"
        );
    }

    #[test]
    fn dry_run_with_zero_targets_is_ok() {
        let json = r#"{"hosts": []}"#;
        let doc: SyncDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.total_targets(), 0);
        assert_eq!(doc.iter_targets().count(), 0);
    }

    #[test]
    fn load_document_from_file() {
        let dir = crate::io::TempDir::new().unwrap();
        let path = dir.path.join("sync.json");
        std::fs::write(&path, FIXTURE).unwrap();

        let args = SyncArgs {
            config: Some(path),
            flake: None,
            no_flake: false,
            identities: vec![],
            dry_run: true,
            check: false,
            targets: Vec::new(),
            prune: false,
            verbose: false,
            state: None,
        };
        // Just verify load_document succeeds — dry-run doesn't need a store
        let doc = args.load_document().unwrap();
        assert_eq!(doc.total_targets(), 2);
    }

    #[test]
    fn target_filter_keeps_only_requested_targets() {
        let doc = SyncDocument::from_json(FIXTURE).unwrap();
        let filtered = filter_document_targets(doc, &["my-app-token".to_owned()]).unwrap();
        assert_eq!(filtered.total_targets(), 1);
        assert_eq!(
            filtered.iter_targets().next().map(|(_, name, _)| name),
            Some("my-app-token")
        );
    }

    #[test]
    fn target_filter_rejects_unknown_targets() {
        let doc = SyncDocument::from_json(FIXTURE).unwrap();
        let err = filter_document_targets(doc, &["missing".to_owned()]).unwrap_err();
        assert!(err.to_string().contains("unknown sync target(s): missing"));
    }

    #[test]
    fn prune_requires_the_complete_target_configuration() {
        assert!(validate_target_prune_args(&[], true).is_ok());
        assert!(validate_target_prune_args(&["ci-token".to_string()], false).is_ok());
        let err = validate_target_prune_args(&["ci-token".to_string()], true).unwrap_err();
        assert!(
            err.to_string()
                .contains("--prune cannot be combined with --target")
        );
    }

    #[test]
    fn flake_path_expression_uses_secret_manager_collect() {
        let flake = FlakeRef::Path(PathBuf::from("/tmp/example-flake"));
        let expr = flake.nix_expr();
        assert!(expr.contains("builtins.getFlake (toString /tmp/example-flake)"));
        assert!(expr.contains("flake.inputs.secret-manager.lib.collect"));
        assert!(expr.contains("inherit (flake) nixosConfigurations"));
    }

    #[test]
    fn fast_flake_path_targets_secret_sync_targets_output() {
        let flake = FlakeRef::Path(PathBuf::from("/tmp/example-flake"));
        assert_eq!(
            flake.secret_sync_targets_attr(),
            "/tmp/example-flake#secretSyncTargets"
        );
        let args = fast_nix_eval_args(&flake);
        assert_eq!(args[0], "eval");
        assert!(args.iter().any(|arg| arg == "--json"));
        assert!(args.iter().any(|arg| arg == "--no-update-lock-file"));
        assert!(args.iter().any(|arg| arg == "--accept-flake-config"));
        assert!(!args.iter().any(|arg| arg == "--expr"));
        assert!(!args.iter().any(|arg| arg == "--impure"));
        assert!(
            args.iter()
                .any(|arg| arg == "/tmp/example-flake#secretSyncTargets")
        );
    }

    #[test]
    fn explicit_flake_reference_is_quoted() {
        let flake = FlakeRef::Explicit("github:caniko/example".to_string());
        let expr = flake.nix_expr();
        assert!(expr.contains(r#"builtins.getFlake "github:caniko/example""#));
        assert_eq!(
            flake.secret_sync_targets_attr(),
            "github:caniko/example#secretSyncTargets"
        );
    }

    #[test]
    fn legacy_nix_eval_args_use_secret_manager_collect() {
        let flake = FlakeRef::Explicit("github:caniko/example".to_string());
        let args = legacy_nix_eval_args(&flake);
        assert_eq!(args[0], "eval");
        assert!(args.iter().any(|arg| arg == "--json"));
        assert!(args.iter().any(|arg| arg == "--no-update-lock-file"));
        let expr = args
            .iter()
            .position(|arg| arg == "--expr")
            .and_then(|idx| args.get(idx + 1))
            .expect("--expr should be followed by an expression");
        assert!(expr.contains("flake.inputs.secret-manager.lib.collect"));
        assert!(expr.contains("inherit (flake) nixosConfigurations"));
    }

    #[test]
    fn missing_secret_sync_targets_errors_are_fallback_eligible() {
        let stderr = "error: flake 'path:/repo' does not provide attribute \
            'packages.x86_64-linux.secretSyncTargets', \
            'legacyPackages.x86_64-linux.secretSyncTargets' or 'secretSyncTargets'";
        assert!(is_missing_secret_sync_targets(stderr));
    }

    #[test]
    fn non_missing_secret_sync_targets_errors_are_not_fallback_eligible() {
        assert!(!is_missing_secret_sync_targets(
            "error: evaluation aborted with assertion failure in secretSyncTargets"
        ));
        assert!(!is_missing_secret_sync_targets(
            "error: flake inputs.secret-manager.lib.collect is missing"
        ));
    }

    #[test]
    fn sync_args_accept_verbose_flag() {
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            sync: SyncArgs,
        }

        let cli = <TestCli as clap::Parser>::try_parse_from([
            "test",
            "--config",
            "sync-targets.json",
            "--verbose",
        ])
        .unwrap();

        assert!(cli.sync.verbose);
        assert_eq!(cli.sync.config, Some(PathBuf::from("sync-targets.json")));
    }

    #[test]
    fn document_summary_counts_enabled_hosts_and_targets() {
        let doc: SyncDocument = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(
            document_summary(&doc),
            SyncDocumentSummary {
                hosts: 1,
                targets: 2
            }
        );
    }

    #[test]
    fn records_need_decrypt_session_when_an_upload_is_encrypted() {
        let doc: SyncDocument = serde_json::from_str(FIXTURE).unwrap();
        assert!(records_need_decrypt_session(
            &desired_records(&doc).unwrap()
        ));

        let plaintext_only = r#"{"hosts":[{"targets":{"public-key":{"source":"public.asc","name":"PUBLIC","codeberg":[],"codebergOrgs":[],"codebergUser":false,"host":"codeberg.org"}}}]}"#;
        let doc: SyncDocument = serde_json::from_str(plaintext_only).unwrap();
        assert!(!records_need_decrypt_session(
            &desired_records(&doc).unwrap()
        ));
    }

    #[test]
    fn sync_value_cache_loads_duplicate_secret_path_once() {
        let mut cache = SyncValueCache::default();
        let key = SyncValueCacheKey::new(
            SyncValueCacheKind::Secret,
            PathBuf::from("/tmp/example-secret.age"),
        );
        let mut loads = 0;

        let first = cache
            .get_or_load(key.clone(), || {
                loads += 1;
                Ok("secret-value".to_string())
            })
            .unwrap();
        let second = cache
            .get_or_load(key, || {
                loads += 1;
                Ok("different-value".to_string())
            })
            .unwrap();

        assert_eq!(first.as_str(), "secret-value");
        assert_eq!(second.as_str(), "secret-value");
        assert_eq!(loads, 1);
    }

    #[test]
    fn sync_value_cache_keeps_secret_and_source_keys_separate() {
        let mut cache = SyncValueCache::default();
        let path = PathBuf::from("/tmp/shared-path");

        let secret = cache
            .get_or_load(
                SyncValueCacheKey::new(SyncValueCacheKind::Secret, path.clone()),
                || Ok("secret".to_string()),
            )
            .unwrap();
        let source = cache
            .get_or_load(
                SyncValueCacheKey::new(SyncValueCacheKind::Source, path),
                || Ok("source".to_string()),
            )
            .unwrap();

        assert_eq!(secret.as_str(), "secret");
        assert_eq!(source.as_str(), "source");
    }

    #[test]
    fn user_scope_push_label_names_account_and_secret() {
        assert_eq!(
            user_scope_push_label("codeberg.org", "caniko", "CHOCOLATEY_API_KEY"),
            "  codeberg/codeberg.org user → caniko as CHOCOLATEY_API_KEY"
        );
        assert_eq!(
            user_scope_push_label("codefloe.com", "caniko", "CHOCOLATEY_API_KEY"),
            "  codefloe/codefloe.com user → caniko as CHOCOLATEY_API_KEY"
        );
    }

    #[test]
    fn github_not_found_only_ignores_missing_remote_entries() {
        assert!(github_not_found(b"gh: HTTP 404: Not Found"));
        assert!(!github_not_found(b"gh: HTTP 403: Forbidden"));
    }

    #[test]
    fn no_flake_without_config_keeps_explicit_input_error() {
        let args = SyncArgs {
            config: None,
            flake: None,
            no_flake: true,
            identities: vec![],
            dry_run: true,
            check: false,
            targets: Vec::new(),
            prune: false,
            verbose: false,
            state: None,
        };
        let err = args.load_document().unwrap_err();
        assert!(err.to_string().contains("no input"));
        assert!(err.to_string().contains("--config"));
    }

    #[test]
    fn read_plaintext_source_preserves_content() {
        let dir = crate::io::TempDir::new().unwrap();
        let source = dir.path.join("public.asc");
        let content = "line one\nline two\n";
        std::fs::write(&source, content).unwrap();
        let store = Store {
            root: dir.path.clone(),
        };

        let got = read_plaintext_source_path(&validated_source_path(&store, "public.asc").unwrap())
            .unwrap();
        assert_eq!(got.as_str(), content);
    }

    #[test]
    fn sync_value_cache_reads_plaintext_source_without_decrypt_session() {
        let dir = crate::io::TempDir::new().unwrap();
        let content = "line one\nline two\n";
        std::fs::write(dir.path.join("public.asc"), content).unwrap();
        let store = Store {
            root: dir.path.clone(),
        };
        let mut cache = SyncValueCache::default();

        let got = cache
            .get(&store, &SyncValue::Source("public.asc".to_string()), None)
            .unwrap();

        assert_eq!(got.as_str(), content);
    }

    #[test]
    fn read_plaintext_source_rejects_empty_file() {
        let dir = crate::io::TempDir::new().unwrap();
        std::fs::write(dir.path.join("empty"), "").unwrap();
        let store = Store {
            root: dir.path.clone(),
        };

        let err = read_plaintext_source_path(&validated_source_path(&store, "empty").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("is empty"));
    }

    #[test]
    fn delete_dispatch_maps_every_scope_and_kind() {
        assert_eq!(
            delete_action_for(&repo_record(ManagedKind::Secret)).unwrap(),
            DeleteAction::RepoSecret {
                owner: "caniko",
                repo: "repo"
            }
        );
        assert_eq!(
            delete_action_for(&repo_record(ManagedKind::Variable)).unwrap(),
            DeleteAction::RepoVariable {
                owner: "caniko",
                repo: "repo"
            }
        );
        assert_eq!(
            delete_action_for(&org_record(ManagedKind::Secret)).unwrap(),
            DeleteAction::OrgSecret { org: "infra" }
        );
        assert_eq!(
            delete_action_for(&org_record(ManagedKind::Variable)).unwrap(),
            DeleteAction::OrgVariable { org: "infra" }
        );
        assert_eq!(
            delete_action_for(&user_record(ManagedKind::Secret)).unwrap(),
            DeleteAction::UserSecret
        );
        assert_eq!(
            delete_action_for(&user_record(ManagedKind::Variable)).unwrap(),
            DeleteAction::UserVariable
        );
    }

    #[test]
    fn stale_planning_output_distinguishes_report_from_prune() {
        let stale = vec![repo_record(ManagedKind::Secret)];
        let report = stale_record_lines(&stale, false).join("\n");
        assert!(report.contains("Stale managed entries (pass --prune to delete):"));
        assert!(report.contains("target: token"));
        assert!(report.contains("name:   TOKEN"));
        assert!(report.contains("codeberg/codeberg.org repo  caniko/repo"));

        let prune = stale_record_lines(&stale, true).join("\n");
        assert!(prune.contains("Planned prunes (--prune):"));
        assert!(!prune.contains("pass --prune"));
    }

    #[test]
    fn crow_secret_value_is_sent_over_stdin_and_restricted_to_tags() {
        let args = crow_secret_args("add", "caniko/regicide", "ATTIC_TOKEN", true);
        assert_eq!(
            args,
            [
                "--server",
                "https://ci.codefloe.com",
                "repo",
                "secret",
                "add",
                "--repo",
                "caniko/regicide",
                "--name",
                "ATTIC_TOKEN",
                "--value",
                "@/dev/stdin",
                "--event",
                "tag",
            ]
        );
        assert!(!args.iter().any(|arg| arg.contains("secret-value")));
    }

    #[test]
    fn environment_secret_arguments_never_fall_back_to_repository_or_foreign_host() {
        let record = ManagedRecord {
            provider: Provider::Github,
            host: "github.com".into(),
            scope: Scope::Environment,
            environment: Some("--prod / '${not-shell}'".into()),
            ..repo_record(ManagedKind::Secret)
        };
        let args = github_record_args(&record, "set").unwrap();
        assert_eq!(
            args,
            [
                "secret",
                "set",
                "TOKEN",
                "--repo",
                "github.com/caniko/repo",
                "--env=--prod / '${not-shell}'"
            ]
        );
        assert!(
            github_environment_endpoint(&record, Some(ManagedKind::Secret))
                .unwrap()
                .ends_with("/secrets/TOKEN")
        );
        let missing = ManagedRecord {
            environment: None,
            ..record.clone()
        };
        assert!(github_record_args(&missing, "delete").is_err());
        let wrong = ManagedRecord {
            provider: Provider::Forgejo,
            ..record.clone()
        };
        assert!(github_record_args(&wrong, "set").is_err());
        assert!(delete_action_for(&record).is_err());
        let mixed = ManagedRecord {
            scope: Scope::Repo,
            ..record
        };
        assert!(github_record_args(&mixed, "delete").is_err());
    }

    fn repo_record(kind: ManagedKind) -> ManagedRecord {
        ManagedRecord {
            provider: Provider::Forgejo,
            host: "codeberg.org".to_string(),
            scope: Scope::Repo,
            owner: Some("caniko".to_string()),
            repo: Some("repo".to_string()),
            org: None,
            environment: None,
            kind,
            name: "TOKEN".to_string(),
            target: "token".to_string(),
            source: "age/secrets/token.age".to_string(),
        }
    }

    fn org_record(kind: ManagedKind) -> ManagedRecord {
        ManagedRecord {
            provider: Provider::Forgejo,
            host: "codeberg.org".to_string(),
            scope: Scope::Org,
            owner: None,
            repo: None,
            org: Some("infra".to_string()),
            environment: None,
            kind,
            name: "TOKEN".to_string(),
            target: "token".to_string(),
            source: "age/secrets/token.age".to_string(),
        }
    }

    fn user_record(kind: ManagedKind) -> ManagedRecord {
        ManagedRecord {
            provider: Provider::Forgejo,
            host: "codeberg.org".to_string(),
            scope: Scope::User,
            owner: None,
            repo: None,
            org: None,
            environment: None,
            kind,
            name: "TOKEN".to_string(),
            target: "token".to_string(),
            source: "age/secrets/token.age".to_string(),
        }
    }
}
