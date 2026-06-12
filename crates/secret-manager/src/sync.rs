use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use std::fs;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::process::Command;

use crate::push::decrypt_store_secret;
use crate::store::{resolve_against, Store};
use crate::sync_state::{
    desired_records, retained_without_prune, stale_records, ManagedKind, ManagedRecord, Scope,
    SyncState,
};
use crate::sync_targets::{SyncDocument, SyncValue};
use nix_manager_core::{forge, ui};

/// Read collected sync targets and push each declared value to its
/// declared forge Actions destinations. When no explicit JSON input is passed,
/// the nearest flake is evaluated via `secret-manager.lib.collect`.
///
/// Encrypted agenix values are pushed as Actions secrets. Plaintext source
/// files are pushed as Actions variables. Reuses the same auth resolution as `push`:
/// the `fj` auth store.
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
    /// Repeatable. Defaults to the store's master identities.
    #[arg(long = "identity", value_name = "PATH")]
    pub identities: Vec<PathBuf>,

    /// Print planned pushes without decrypting or contacting any forge.
    #[arg(long)]
    pub dry_run: bool,

    /// Delete previously managed remote entries that are no longer declared.
    #[arg(long)]
    pub prune: bool,

    /// Path to the sync state TOML file.
    /// Defaults to <secret-store>/.secret-manager/sync-state.toml.
    #[arg(long, value_name = "PATH")]
    pub state: Option<PathBuf>,
}

impl SyncArgs {
    pub fn run(self) -> Result<()> {
        let doc = self.load_document()?;
        let total = doc.total_targets();
        let store = Store::discover()?;
        let state_path = self
            .state
            .clone()
            .unwrap_or_else(|| default_state_path(&store));
        let previous_state = SyncState::load(&state_path)?.unwrap_or_else(SyncState::empty);
        let desired_state = desired_records(&doc)?;
        let stale = stale_records(&previous_state.managed, &desired_state);

        if self.dry_run {
            println!("Planned pushes (--dry-run):");
            for (_, name, target) in doc.iter_targets() {
                println!();
                println!("  target: {name}");
                println!("  kind:   {}", target.value.kind());
                println!("  source: {}", target.value.path());
                println!("  name:   {}", target.name);
                for repo in &target.codeberg {
                    println!("  → codeberg/{} repo  {}", target.host, repo);
                }
                for org in &target.codeberg_orgs {
                    println!("  → codeberg/{} org   {}", target.host, org);
                }
                if target.codeberg_user {
                    println!("  → codeberg/{} user  authenticated", target.host);
                }
            }
            print_stale_records(&stale, self.prune);
            println!();
            println!("total targets: {total}");
            return Ok(());
        }

        for (_, name, target) in doc.iter_targets() {
            ui::step(format!(
                "sync: `{}` {} from {}",
                name,
                target.value.kind(),
                target.value.path()
            ));

            let value = sync_value(&store, &target.value, &self.identities)?;

            for repo in &target.codeberg {
                ui::step(format!(
                    "  codeberg/{} repo → {} as {}",
                    target.host, repo, target.name
                ));
                match &target.value {
                    SyncValue::Secret(_) => {
                        forge::push_codeberg_secret(&target.host, repo, &target.name, &value)?;
                    }
                    SyncValue::Source(_) => {
                        forge::push_codeberg_variable(&target.host, repo, &target.name, &value)?;
                    }
                }
            }

            for org in &target.codeberg_orgs {
                ui::step(format!(
                    "  codeberg/{} org → {} as {}",
                    target.host, org, target.name
                ));
                match &target.value {
                    SyncValue::Secret(_) => {
                        push_codeberg_organization_secret(&target.host, org, &target.name, &value)?;
                    }
                    SyncValue::Source(_) => {
                        push_codeberg_organization_variable(
                            &target.host,
                            org,
                            &target.name,
                            &value,
                        )?;
                    }
                }
            }

            if target.codeberg_user {
                ui::step(format!(
                    "  codeberg/{} user → authenticated as {}",
                    target.host, target.name
                ));
                match &target.value {
                    SyncValue::Secret(_) => {
                        push_codeberg_user_secret(&target.host, &target.name, &value)?;
                    }
                    SyncValue::Source(_) => {
                        push_codeberg_user_variable(&target.host, &target.name, &value)?;
                    }
                }
            }
        }

        if self.prune {
            for record in &stale {
                delete_managed_record(record)?;
            }
        } else {
            report_stale_records(&stale);
        }

        let next_records = if self.prune {
            desired_state
        } else {
            retained_without_prune(&previous_state.managed, &desired_state)
        };
        SyncState::new(next_records).write_atomic(&state_path)?;

        ui::success(format!("synced {total} target(s)"));
        Ok(())
    }

    fn load_document(&self) -> Result<SyncDocument> {
        match &self.config {
            Some(path) => SyncDocument::from_path(path).map_err(Into::into),
            None => {
                let stdin = std::io::stdin();
                if !stdin.is_terminal() {
                    let mut buf = String::new();
                    stdin
                        .lock()
                        .read_to_string(&mut buf)
                        .map_err(|e| anyhow!("reading stdin: {e}"))?;
                    if !buf.trim().is_empty() {
                        return SyncDocument::from_json(&buf).map_err(Into::into);
                    }
                }

                if self.no_flake {
                    bail!(NO_INPUT);
                }

                let flake = self.resolve_flake()?;
                let json = collect_flake_sync_targets(&flake)?;
                SyncDocument::from_json(&json).map_err(Into::into)
            }
        }
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
}

fn collect_flake_sync_targets(flake: &FlakeRef) -> Result<String> {
    ui::step(format!("collecting sync targets from {}", flake.label()));
    let output = Command::new("nix")
        .args([
            "eval",
            "--json",
            "--impure",
            "--expr",
            &flake.nix_expr(),
            "--accept-flake-config",
            "--no-update-lock-file",
        ])
        .output()
        .map_err(|e| anyhow!("failed to spawn nix: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("attribute 'secret-manager' missing")
            || stderr.contains("attribute 'collect' missing")
            || stderr.contains("attribute 'lib' missing")
        {
            bail!(
                "flake {} does not expose inputs.secret-manager.lib.collect; \
                 add the secret-manager input or pass --config <path>\n{}",
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

    String::from_utf8(output.stdout).context("nix eval returned non-UTF-8 JSON")
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

fn sync_value(store: &Store, value: &SyncValue, identities: &[PathBuf]) -> Result<String> {
    match value {
        SyncValue::Secret(secret) => decrypt_store_secret(store, secret, identities),
        SyncValue::Source(source) => read_plaintext_source(store, source),
    }
}

fn read_plaintext_source(store: &Store, source: &str) -> Result<String> {
    let source_path = resolve_against(&store.root, &PathBuf::from(source));
    if !source_path.is_file() {
        bail!("{} does not exist", source_path.display());
    }
    let value = fs::read_to_string(&source_path)
        .map_err(|e| anyhow::anyhow!("reading plaintext source {}: {e}", source_path.display()))?;
    if value.is_empty() {
        bail!("plaintext source {} is empty", source_path.display());
    }
    Ok(value)
}

fn codeberg_client(host: &str, bearer: &str) -> Result<forgejo_api::sync::Forgejo> {
    let base_url = url::Url::parse(&format!("https://{host}"))
        .map_err(|e| anyhow::anyhow!("invalid host `{host}`: {e}"))?;

    forgejo_api::sync::Forgejo::new(forgejo_api::Auth::Token(bearer), base_url)
        .map_err(|e| anyhow::anyhow!("failed to create forgejo client for {host}: {e}"))
}

fn delete_managed_record(record: &ManagedRecord) -> Result<()> {
    let action = delete_action_for(record)?;
    ui::step(format!(
        "  pruning codeberg/{} {} `{}`",
        record.host,
        action.description(),
        record.name
    ));
    let bearer = forge::codeberg_bearer_token(&record.host)?;
    let api = codeberg_client(&record.host, &bearer)?;

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

#[derive(Debug, PartialEq, Eq)]
enum DeleteAction<'a> {
    RepoSecret { owner: &'a str, repo: &'a str },
    RepoVariable { owner: &'a str, repo: &'a str },
    OrgSecret { org: &'a str },
    OrgVariable { org: &'a str },
    UserSecret,
    UserVariable,
}

impl DeleteAction<'_> {
    fn description(&self) -> &'static str {
        match self {
            Self::RepoSecret { .. } => "repo secret",
            Self::RepoVariable { .. } => "repo variable",
            Self::OrgSecret { .. } => "org secret",
            Self::OrgVariable { .. } => "org variable",
            Self::UserSecret => "user secret",
            Self::UserVariable => "user variable",
        }
    }
}

fn delete_action_for(record: &ManagedRecord) -> Result<DeleteAction<'_>> {
    match (record.scope, record.kind) {
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

fn push_codeberg_organization_secret(host: &str, org: &str, name: &str, value: &str) -> Result<()> {
    ui::step(format!(
        "codeberg/{host}: setting `{name}` organization secret on {org}"
    ));
    let bearer = forge::codeberg_bearer_token(host)?;
    let api = codeberg_client(host, &bearer)?;

    api.update_org_secret(
        org,
        name,
        forgejo_api::structs::CreateOrUpdateSecretOption {
            data: value.to_string(),
        },
    )
    .send()
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to set organization secret `{name}` on {host}/{org}: {e}\n\
             check that the stored token can manage organization Actions secrets for {org}"
        )
    })?;

    Ok(())
}

fn push_codeberg_organization_variable(
    host: &str,
    org: &str,
    name: &str,
    value: &str,
) -> Result<()> {
    ui::step(format!(
        "codeberg/{host}: setting `{name}` organization variable on {org}"
    ));
    let bearer = forge::codeberg_bearer_token(host)?;
    let api = codeberg_client(host, &bearer)?;

    let update = api
        .update_org_variable(
            org,
            name,
            forgejo_api::structs::UpdateVariableOption {
                name: None,
                value: value.to_string(),
            },
        )
        .send();

    if let Err(err) = update {
        if !is_not_found(&err) {
            return Err(anyhow::anyhow!(
                "failed to update organization variable `{name}` on {host}/{org}: {err}\n\
                 check that the stored token can manage organization Actions variables for {org}"
            ));
        }

        api.create_org_variable(
            org,
            name,
            forgejo_api::structs::CreateVariableOption {
                value: value.to_string(),
            },
        )
        .send()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to create organization variable `{name}` on {host}/{org}: {e}\n\
                 check that the stored token can manage organization Actions variables for {org}"
            )
        })?;
    }

    Ok(())
}

fn push_codeberg_user_secret(host: &str, name: &str, value: &str) -> Result<()> {
    ui::step(format!(
        "codeberg/{host}: setting `{name}` user secret on authenticated user"
    ));
    let bearer = forge::codeberg_bearer_token(host)?;
    let api = codeberg_client(host, &bearer)?;

    api.update_user_secret(
        name,
        forgejo_api::structs::CreateOrUpdateSecretOption {
            data: value.to_string(),
        },
    )
    .send()
    .map_err(|e| {
        anyhow::anyhow!(
            "failed to set user secret `{name}` on {host}: {e}\n\
             check that the stored token can manage authenticated-user Actions secrets"
        )
    })?;

    Ok(())
}

fn push_codeberg_user_variable(host: &str, name: &str, value: &str) -> Result<()> {
    ui::step(format!(
        "codeberg/{host}: setting `{name}` user variable on authenticated user"
    ));
    let bearer = forge::codeberg_bearer_token(host)?;
    let api = codeberg_client(host, &bearer)?;

    let update = api
        .update_user_variable(
            name,
            forgejo_api::structs::UpdateVariableOption {
                name: None,
                value: value.to_string(),
            },
        )
        .send();

    if let Err(err) = update {
        if !is_not_found(&err) {
            return Err(anyhow::anyhow!(
                "failed to update user variable `{name}` on {host}: {err}\n\
                 check that the stored token can manage authenticated-user Actions variables"
            ));
        }

        api.create_user_variable(
            name,
            forgejo_api::structs::CreateVariableOption {
                value: value.to_string(),
            },
        )
        .send()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to create user variable `{name}` on {host}: {e}\n\
                 check that the stored token can manage authenticated-user Actions variables"
            )
        })?;
    }

    Ok(())
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

    /// Contract fixture matching the shape nix/collect.nix produces.
    const FIXTURE: &str = r#"{
  "hosts": [
    {
      "targets": {
        "my-app-token": {
          "secret": "age/secrets/my-app-token.age",
          "name": "MY_APP_TOKEN",
          "codeberg": ["caniko/my-repo"],
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
                    .codeberg
                    .iter()
                    .map(move |repo| (kind, host, source, secret_name, "repo", repo.as_str()));
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
            "dry-run planning should expand all codeberg repos per target, \
             honoring each target's host"
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
            prune: false,
            state: None,
        };
        // Just verify load_document succeeds — dry-run doesn't need a store
        let doc = args.load_document().unwrap();
        assert_eq!(doc.total_targets(), 2);
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
    fn explicit_flake_reference_is_quoted() {
        let flake = FlakeRef::Explicit("github:caniko/example".to_string());
        let expr = flake.nix_expr();
        assert!(expr.contains(r#"builtins.getFlake "github:caniko/example""#));
    }

    #[test]
    fn no_flake_without_config_keeps_explicit_input_error() {
        let args = SyncArgs {
            config: None,
            flake: None,
            no_flake: true,
            identities: vec![],
            dry_run: true,
            prune: false,
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

        let got = read_plaintext_source(&store, "public.asc").unwrap();
        assert_eq!(got, content);
    }

    #[test]
    fn read_plaintext_source_rejects_empty_file() {
        let dir = crate::io::TempDir::new().unwrap();
        std::fs::write(dir.path.join("empty"), "").unwrap();
        let store = Store {
            root: dir.path.clone(),
        };

        let err = read_plaintext_source(&store, "empty").unwrap_err();
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

    fn repo_record(kind: ManagedKind) -> ManagedRecord {
        ManagedRecord {
            host: "codeberg.org".to_string(),
            scope: Scope::Repo,
            owner: Some("caniko".to_string()),
            repo: Some("repo".to_string()),
            org: None,
            kind,
            name: "TOKEN".to_string(),
            target: "token".to_string(),
            source: "age/secrets/token.age".to_string(),
        }
    }

    fn org_record(kind: ManagedKind) -> ManagedRecord {
        ManagedRecord {
            host: "codeberg.org".to_string(),
            scope: Scope::Org,
            owner: None,
            repo: None,
            org: Some("infra".to_string()),
            kind,
            name: "TOKEN".to_string(),
            target: "token".to_string(),
            source: "age/secrets/token.age".to_string(),
        }
    }

    fn user_record(kind: ManagedKind) -> ManagedRecord {
        ManagedRecord {
            host: "codeberg.org".to_string(),
            scope: Scope::User,
            owner: None,
            repo: None,
            org: None,
            kind,
            name: "TOKEN".to_string(),
            target: "token".to_string(),
            source: "age/secrets/token.age".to_string(),
        }
    }
}
