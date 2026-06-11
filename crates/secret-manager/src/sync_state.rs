use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::sync_targets::{SyncDocument, SyncValue};

pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    pub version: u32,
    #[serde(default)]
    pub managed: Vec<ManagedRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedRecord {
    pub host: String,
    pub scope: Scope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    pub kind: ManagedKind,
    pub name: String,
    pub target: String,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Repo,
    Org,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ManagedKind {
    Secret,
    Variable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordIdentity {
    host: String,
    scope: Scope,
    owner: Option<String>,
    repo: Option<String>,
    org: Option<String>,
    kind: ManagedKind,
    name: String,
}

impl ManagedRecord {
    pub fn identity(&self) -> RecordIdentity {
        RecordIdentity {
            host: self.host.clone(),
            scope: self.scope,
            owner: self.owner.clone(),
            repo: self.repo.clone(),
            org: self.org.clone(),
            kind: self.kind,
            name: self.name.clone(),
        }
    }

    pub fn destination_label(&self) -> String {
        match self.scope {
            Scope::Repo => format!(
                "codeberg/{} repo  {}/{}",
                self.host,
                self.owner.as_deref().unwrap_or("<missing-owner>"),
                self.repo.as_deref().unwrap_or("<missing-repo>")
            ),
            Scope::Org => format!(
                "codeberg/{} org   {}",
                self.host,
                self.org.as_deref().unwrap_or("<missing-org>")
            ),
            Scope::User => format!("codeberg/{} user  authenticated", self.host),
        }
    }

    fn sort_key(&self) -> RecordSortKey {
        RecordSortKey {
            identity: self.identity(),
            target: self.target.clone(),
            source: self.source.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RecordSortKey {
    identity: RecordIdentity,
    target: String,
    source: String,
}

impl SyncState {
    pub fn new(managed: Vec<ManagedRecord>) -> Self {
        Self {
            version: STATE_VERSION,
            managed: normalize_records(managed),
        }
    }

    pub fn empty() -> Self {
        Self {
            version: STATE_VERSION,
            managed: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading sync state {}", path.display()))?;
        let mut state: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing sync state {}", path.display()))?;
        if state.version != STATE_VERSION {
            bail!(
                "unsupported sync state version {} in {} (expected {})",
                state.version,
                path.display(),
                STATE_VERSION
            );
        }
        state.managed = normalize_records(state.managed);
        Ok(Some(state))
    }

    pub fn write_atomic(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating sync state dir {}", parent.display()))?;
        }

        let rendered = toml::to_string_pretty(&SyncState::new(self.managed.clone()))
            .context("rendering sync state TOML")?;
        let tmp = path.with_extension(format!("toml.tmp.{}", std::process::id()));
        fs::write(&tmp, rendered)
            .with_context(|| format!("writing temporary sync state {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| {
            format!(
                "renaming temporary sync state {} to {}",
                tmp.display(),
                path.display()
            )
        })?;
        Ok(())
    }
}

pub fn desired_records(doc: &SyncDocument) -> Result<Vec<ManagedRecord>> {
    let mut records = Vec::new();
    for (_, target_key, target) in doc.iter_targets() {
        let kind = match &target.value {
            SyncValue::Secret(_) => ManagedKind::Secret,
            SyncValue::Source(_) => ManagedKind::Variable,
        };
        let source = target.value.path().to_string();

        for repo in &target.codeberg {
            let (owner, repo_name) = parse_repo(repo)?;
            records.push(ManagedRecord {
                host: target.host.clone(),
                scope: Scope::Repo,
                owner: Some(owner.to_string()),
                repo: Some(repo_name.to_string()),
                org: None,
                kind,
                name: target.name.clone(),
                target: target_key.to_string(),
                source: source.clone(),
            });
        }

        for org in &target.codeberg_orgs {
            if org.is_empty() {
                bail!("sync target `{target_key}` has an empty Codeberg organization target");
            }
            records.push(ManagedRecord {
                host: target.host.clone(),
                scope: Scope::Org,
                owner: None,
                repo: None,
                org: Some(org.clone()),
                kind,
                name: target.name.clone(),
                target: target_key.to_string(),
                source: source.clone(),
            });
        }

        if target.codeberg_user {
            records.push(ManagedRecord {
                host: target.host.clone(),
                scope: Scope::User,
                owner: None,
                repo: None,
                org: None,
                kind,
                name: target.name.clone(),
                target: target_key.to_string(),
                source,
            });
        }
    }
    Ok(normalize_records(records))
}

pub fn stale_records(previous: &[ManagedRecord], desired: &[ManagedRecord]) -> Vec<ManagedRecord> {
    let desired_identities: BTreeSet<RecordIdentity> =
        desired.iter().map(ManagedRecord::identity).collect();
    normalize_records(
        previous
            .iter()
            .filter(|record| !desired_identities.contains(&record.identity()))
            .cloned()
            .collect(),
    )
}

pub fn retained_without_prune(
    previous: &[ManagedRecord],
    desired: &[ManagedRecord],
) -> Vec<ManagedRecord> {
    let mut by_identity: BTreeMap<RecordIdentity, ManagedRecord> = previous
        .iter()
        .cloned()
        .map(|record| (record.identity(), record))
        .collect();
    for record in desired {
        by_identity.insert(record.identity(), record.clone());
    }
    normalize_records(by_identity.into_values().collect())
}

fn normalize_records(records: Vec<ManagedRecord>) -> Vec<ManagedRecord> {
    let mut by_identity: BTreeMap<RecordIdentity, ManagedRecord> = BTreeMap::new();
    for record in records {
        by_identity
            .entry(record.identity())
            .and_modify(|existing| {
                if record.sort_key() < existing.sort_key() {
                    *existing = record.clone();
                }
            })
            .or_insert(record);
    }

    let mut normalized: Vec<ManagedRecord> = by_identity.into_values().collect();
    normalized.sort_by_key(ManagedRecord::sort_key);
    normalized
}

fn parse_repo(repo: &str) -> Result<(&str, &str)> {
    let Some((owner, name)) = repo.split_once('/') else {
        bail!("Codeberg repository target `{repo}` must be in owner/repo form");
    };
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        bail!("Codeberg repository target `{repo}` must be in owner/repo form");
    }
    Ok((owner, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
      "hosts": [{
        "targets": {
          "repo-secret": {
            "secret": "age/secrets/repo.age",
            "name": "REPO_SECRET",
            "codeberg": ["caniko/repo"],
            "host": "codeberg.org"
          },
          "org-variable": {
            "source": "age/secrets/public.txt",
            "name": "ORG_VARIABLE",
            "codebergOrgs": ["infra"],
            "host": "git.example.com"
          },
          "user-secret": {
            "secret": "age/secrets/user.age",
            "name": "USER_SECRET",
            "codebergUser": true
          }
        }
      }]
    }"#;

    #[test]
    fn desired_records_expand_all_destination_scopes() {
        let doc = SyncDocument::from_json(FIXTURE).unwrap();
        let records = desired_records(&doc).unwrap();
        assert_eq!(records.len(), 3);
        assert!(records.iter().any(|record| {
            record.scope == Scope::Repo
                && record.owner.as_deref() == Some("caniko")
                && record.repo.as_deref() == Some("repo")
                && record.kind == ManagedKind::Secret
                && record.name == "REPO_SECRET"
        }));
        assert!(records.iter().any(|record| {
            record.scope == Scope::Org
                && record.org.as_deref() == Some("infra")
                && record.kind == ManagedKind::Variable
                && record.name == "ORG_VARIABLE"
        }));
        assert!(records.iter().any(|record| {
            record.scope == Scope::User
                && record.kind == ManagedKind::Secret
                && record.name == "USER_SECRET"
        }));
    }

    #[test]
    fn state_toml_round_trips_in_deterministic_order() {
        let doc = SyncDocument::from_json(FIXTURE).unwrap();
        let state = SyncState::new(desired_records(&doc).unwrap());
        let rendered = toml::to_string_pretty(&state).unwrap();
        let reparsed: SyncState = toml::from_str(&rendered).unwrap();
        assert_eq!(reparsed, state);
        assert!(rendered.contains("version = 1"));
        assert!(rendered.contains("scope = \"repo\""));
        assert!(rendered.contains("scope = \"org\""));
        assert!(rendered.contains("scope = \"user\""));
    }

    #[test]
    fn missing_state_file_is_not_an_error() {
        let dir = crate::io::TempDir::new().unwrap();
        let loaded = SyncState::load(&dir.path.join("missing.toml")).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn removed_target_becomes_stale() {
        let previous = vec![record("old", Scope::User, ManagedKind::Secret, "OLD")];
        let desired = vec![record("new", Scope::User, ManagedKind::Secret, "NEW")];
        let stale = stale_records(&previous, &desired);
        assert_eq!(stale, previous);
    }

    #[test]
    fn moved_repo_target_to_user_scope_leaves_repo_stale() {
        let previous = vec![repo_record("old", "TOKEN")];
        let desired = vec![record("new", Scope::User, ManagedKind::Secret, "TOKEN")];
        let stale = stale_records(&previous, &desired);
        assert_eq!(stale, previous);
    }

    #[test]
    fn changed_source_for_same_destination_is_not_stale() {
        let previous = vec![ManagedRecord {
            source: "old.age".to_string(),
            ..record("old-target", Scope::User, ManagedKind::Secret, "TOKEN")
        }];
        let desired = vec![ManagedRecord {
            source: "new.age".to_string(),
            ..record("new-target", Scope::User, ManagedKind::Secret, "TOKEN")
        }];
        assert!(stale_records(&previous, &desired).is_empty());
        let retained = retained_without_prune(&previous, &desired);
        assert_eq!(retained, desired);
    }

    fn repo_record(target: &str, name: &str) -> ManagedRecord {
        ManagedRecord {
            host: "codeberg.org".to_string(),
            scope: Scope::Repo,
            owner: Some("caniko".to_string()),
            repo: Some("repo".to_string()),
            org: None,
            kind: ManagedKind::Secret,
            name: name.to_string(),
            target: target.to_string(),
            source: "age/secrets/token.age".to_string(),
        }
    }

    fn record(target: &str, scope: Scope, kind: ManagedKind, name: &str) -> ManagedRecord {
        ManagedRecord {
            host: "codeberg.org".to_string(),
            scope,
            owner: None,
            repo: None,
            org: if scope == Scope::Org {
                Some("infra".to_string())
            } else {
                None
            },
            kind,
            name: name.to_string(),
            target: target.to_string(),
            source: "age/secrets/token.age".to_string(),
        }
    }
}
