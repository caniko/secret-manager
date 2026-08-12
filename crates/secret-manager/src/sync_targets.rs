use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};

/// Top-level document produced by `nix/collect.nix` → `builtins.toJSON`.
///
/// Each host that has `services.secretSync.enable = true` contributes one
/// entry in `hosts`.
#[derive(Debug, Deserialize)]
pub struct SyncDocument {
    pub hosts: Vec<HostSyncConfig>,
}

/// Per-host sync-target configuration.
#[derive(Debug, Deserialize)]
pub struct HostSyncConfig {
    /// Targets keyed by an arbitrary name meaningful to the store operator.
    pub targets: HashMap<String, SyncTarget>,
}

/// A single declarative sync target — push one value to one or more forge
/// destinations. Encrypted agenix values become Actions secrets; plaintext
/// source files become Actions variables.
#[derive(Debug)]
pub struct SyncTarget {
    /// Source of the value to synchronize.
    pub value: SyncValue,

    /// Name of the Actions secret or variable to set on each target.
    pub name: String,

    /// Codeberg/Forgejo repositories (owner/repo) to push to.
    pub codeberg: Vec<String>,

    /// Codefloe repositories (owner/repo) to push to.
    pub codefloe: Vec<String>,

    /// GitHub repositories (owner/repo) to push to.
    pub github: Vec<String>,

    /// Codeberg/Forgejo organizations to push to at account scope.
    pub codeberg_orgs: Vec<String>,

    /// Whether to push to the authenticated user's account scope.
    pub codeberg_user: bool,

    /// Forge host for Codeberg/Forgejo token resolution.
    pub host: String,
}

/// A forge API used by a managed destination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    Forgejo,
    Github,
    Crow,
}

/// Where a sync target's value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncValue {
    /// Path to the agenix-encrypted `.age` file, relative to the store root.
    Secret(String),
    /// Path to a plaintext file, relative to the store root.
    Source(String),
}

impl SyncValue {
    pub fn path(&self) -> &str {
        match self {
            Self::Secret(path) | Self::Source(path) => path,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Secret(_) => "secret",
            Self::Source(_) => "variable",
        }
    }
}

impl SyncTarget {
    /// Repository destinations, normalized to the API and host that serve them.
    pub fn repo_destinations(&self) -> impl Iterator<Item = (Provider, &str, &str)> {
        self.codeberg
            .iter()
            .map(|repo| (Provider::Forgejo, self.host.as_str(), repo.as_str()))
            .chain(
                self.codefloe
                    .iter()
                    .map(|repo| (Provider::Crow, "ci.codefloe.com", repo.as_str())),
            )
            .chain(
                self.github
                    .iter()
                    .map(|repo| (Provider::Github, "github.com", repo.as_str())),
            )
    }
}

fn default_host() -> String {
    "codeberg.org".to_string()
}

impl<'de> Deserialize<'de> for SyncTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawSyncTarget {
            secret: Option<String>,
            source: Option<String>,
            name: String,
            #[serde(default)]
            codeberg: Vec<String>,
            #[serde(default)]
            codefloe: Vec<String>,
            #[serde(default)]
            github: Vec<String>,
            #[serde(default, rename = "codebergOrgs")]
            codeberg_orgs: Vec<String>,
            #[serde(default, rename = "codebergUser")]
            codeberg_user: bool,
            #[serde(default = "default_host")]
            host: String,
        }

        let raw = RawSyncTarget::deserialize(deserializer)?;
        let value = match (raw.secret, raw.source) {
            (Some(secret), None) if !secret.is_empty() => SyncValue::Secret(secret),
            (None, Some(source)) if !source.is_empty() => SyncValue::Source(source),
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom(
                    "sync target must set exactly one of `secret` or `source`",
                ));
            }
            _ => {
                return Err(serde::de::Error::custom(
                    "sync target must set exactly one non-empty `secret` or `source`",
                ));
            }
        };

        Ok(Self {
            value,
            name: raw.name,
            codeberg: raw.codeberg,
            codefloe: raw.codefloe,
            github: raw.github,
            codeberg_orgs: raw.codeberg_orgs,
            codeberg_user: raw.codeberg_user,
            host: raw.host,
        })
    }
}

impl SyncDocument {
    /// Deserialize from a JSON byte slice (the output of `builtins.toJSON`).
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Deserialize from a JSON file path.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, SyncDocumentError> {
        let bytes = std::fs::read(path.as_ref())?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Return the total number of sync targets across all hosts.
    pub fn total_targets(&self) -> usize {
        self.hosts.iter().map(|h| h.targets.len()).sum()
    }

    /// Return an iterator over `(host_index, target_name, &SyncTarget)`.
    ///
    /// This is the primary accessor for the sync command.
    pub fn iter_targets(&self) -> impl Iterator<Item = (usize, &str, &SyncTarget)> + '_ {
        self.hosts.iter().enumerate().flat_map(|(host_idx, host)| {
            host.targets
                .iter()
                .map(move |(name, target)| (host_idx, name.as_str(), target))
        })
    }
}

#[derive(Debug)]
pub enum SyncDocumentError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for SyncDocumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "failed to read sync document: {e}"),
            Self::Json(e) => write!(f, "failed to parse sync document: {e}"),
        }
    }
}

impl std::error::Error for SyncDocumentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for SyncDocumentError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for SyncDocumentError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract fixture: the exact JSON shape `nix/collect.nix` produces via
    /// `builtins.toJSON` for a two-target, one-host example. Every field is
    /// present because Nix serialises default values.
    ///
    /// If the module options or collect logic change, update this fixture AND
    /// both the Rust type and the Nix collect code simultaneously so all three
    /// stay in lockstep.
    const CONTRACT_JSON: &str = r#"{
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
        "public-key": {
          "source": "age/secrets/public-key.asc",
          "name": "PUBLIC_KEY",
          "codeberg": ["caniko/my-repo", "caniko/other-repo"],
          "codefloe": [],
          "github": ["caniko/github-public-repo"],
          "codebergOrgs": ["caniko"],
          "codebergUser": false,
          "host": "codeberg.org"
        }
      }
    }
  ]
}"#;

    #[test]
    fn round_trip_contract_fixture() {
        let doc: SyncDocument = serde_json::from_str(CONTRACT_JSON).unwrap();
        assert_eq!(doc.hosts.len(), 1);
        assert_eq!(doc.total_targets(), 2);

        // First target
        let t1 = doc.hosts[0].targets.get("my-app-token").unwrap();
        assert_eq!(
            t1.value,
            SyncValue::Secret("age/secrets/my-app-token.age".to_string())
        );
        assert_eq!(t1.name, "MY_APP_TOKEN");
        assert_eq!(t1.codeberg, vec!["caniko/my-repo"]);
        assert_eq!(t1.codefloe, vec!["caniko/codefloe-repo"]);
        assert_eq!(t1.github, vec!["caniko/github-repo"]);
        assert_eq!(t1.codeberg_orgs, vec!["caniko"]);
        assert!(t1.codeberg_user);
        assert_eq!(t1.host, "codeberg.org");

        // Second target
        let t2 = doc.hosts[0].targets.get("public-key").unwrap();
        assert_eq!(
            t2.value,
            SyncValue::Source("age/secrets/public-key.asc".to_string())
        );
        assert_eq!(t2.name, "PUBLIC_KEY");
        assert_eq!(t2.codeberg, vec!["caniko/my-repo", "caniko/other-repo"]);
        assert!(t2.codefloe.is_empty());
        assert_eq!(t2.github, vec!["caniko/github-public-repo"]);
        assert_eq!(t2.codeberg_orgs, vec!["caniko"]);
        assert!(!t2.codeberg_user);
        assert_eq!(t2.host, "codeberg.org");
    }

    #[test]
    fn empty_targets_produces_empty_hosts_list() {
        let json = r#"{"hosts": []}"#;
        let doc: SyncDocument = serde_json::from_str(json).unwrap();
        assert!(doc.hosts.is_empty());
        assert_eq!(doc.total_targets(), 0);
        assert_eq!(doc.iter_targets().count(), 0);
    }

    #[test]
    fn host_with_no_targets_is_ok() {
        let json = r#"{"hosts": [{"targets": {}}]}"#;
        let doc: SyncDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.hosts.len(), 1);
        assert!(doc.hosts[0].targets.is_empty());
        assert_eq!(doc.total_targets(), 0);
    }

    #[test]
    fn defaults_are_applied_to_absent_fields() {
        let json = r#"{
          "hosts": [{
            "targets": {
              "minimal": {
                "secret": "age/secrets/min.age",
                "name": "MIN"
              }
            }
          }]
        }"#;
        let doc: SyncDocument = serde_json::from_str(json).unwrap();
        let t = doc.hosts[0].targets.get("minimal").unwrap();
        assert!(t.codeberg.is_empty());
        assert!(t.codefloe.is_empty());
        assert!(t.github.is_empty());
        assert!(t.codeberg_orgs.is_empty());
        assert!(!t.codeberg_user);
        assert_eq!(t.host, "codeberg.org");
    }

    #[test]
    fn source_target_defaults_are_applied_to_absent_fields() {
        let json = r#"{
          "hosts": [{
            "targets": {
              "minimal": {
                "source": "age/secrets/public.asc",
                "name": "PUBLIC"
              }
            }
          }]
        }"#;
        let doc: SyncDocument = serde_json::from_str(json).unwrap();
        let t = doc.hosts[0].targets.get("minimal").unwrap();
        assert_eq!(
            t.value,
            SyncValue::Source("age/secrets/public.asc".to_string())
        );
        assert!(t.codeberg.is_empty());
        assert!(t.codefloe.is_empty());
        assert!(t.github.is_empty());
        assert!(t.codeberg_orgs.is_empty());
        assert!(!t.codeberg_user);
        assert_eq!(t.host, "codeberg.org");
    }

    #[test]
    fn account_scope_destinations_deserialize() {
        let json = r#"{
          "hosts": [{
            "targets": {
              "account": {
                "secret": "age/secrets/account.age",
                "name": "ACCOUNT_SECRET",
                "codebergOrgs": ["caniko", "infra"],
                "codebergUser": true
              }
            }
          }]
        }"#;
        let doc: SyncDocument = serde_json::from_str(json).unwrap();
        let t = doc.hosts[0].targets.get("account").unwrap();
        assert!(t.codeberg.is_empty());
        assert!(t.codefloe.is_empty());
        assert!(t.github.is_empty());
        assert_eq!(t.codeberg_orgs, vec!["caniko", "infra"]);
        assert!(t.codeberg_user);
    }

    #[test]
    fn repository_destinations_select_the_correct_provider_and_host() {
        let doc: SyncDocument = serde_json::from_str(CONTRACT_JSON).unwrap();
        let target = doc.hosts[0].targets.get("my-app-token").unwrap();
        let destinations: Vec<_> = target.repo_destinations().collect();
        assert_eq!(
            destinations,
            vec![
                (Provider::Forgejo, "codeberg.org", "caniko/my-repo"),
                (Provider::Crow, "ci.codefloe.com", "caniko/codefloe-repo"),
                (Provider::Github, "github.com", "caniko/github-repo"),
            ]
        );
    }

    #[test]
    fn target_with_both_secret_and_source_is_rejected() {
        let json = r#"{
          "hosts": [{
            "targets": {
              "bad": {
                "secret": "age/secrets/private.age",
                "source": "age/secrets/public.asc",
                "name": "BAD"
              }
            }
          }]
        }"#;
        let err = serde_json::from_str::<SyncDocument>(json).unwrap_err();
        assert!(
            err.to_string().contains("exactly one"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn target_with_neither_secret_nor_source_is_rejected() {
        let json = r#"{
          "hosts": [{
            "targets": {
              "bad": {
                "name": "BAD"
              }
            }
          }]
        }"#;
        let err = serde_json::from_str::<SyncDocument>(json).unwrap_err();
        assert!(
            err.to_string().contains("exactly one non-empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn iter_targets_yields_all_targets() {
        let doc: SyncDocument = serde_json::from_str(CONTRACT_JSON).unwrap();
        let mut names: Vec<&str> = doc.iter_targets().map(|(_, name, _)| name).collect();
        names.sort();
        assert_eq!(names, vec!["my-app-token", "public-key"]);

        let mut host_indices: Vec<usize> = doc.iter_targets().map(|(idx, _, _)| idx).collect();
        host_indices.sort();
        assert_eq!(host_indices, vec![0, 0]);
    }

    #[test]
    fn from_path_loads_and_parses() {
        let dir = crate::io::TempDir::new().unwrap();
        let path = dir.path.join("sync.json");
        std::fs::write(&path, CONTRACT_JSON).unwrap();
        let doc = SyncDocument::from_path(&path).unwrap();
        assert_eq!(doc.total_targets(), 2);
    }

    #[test]
    fn from_path_returns_error_on_missing_file() {
        let err = SyncDocument::from_path("/nonexistent/sync.json").unwrap_err();
        assert!(matches!(err, SyncDocumentError::Io(_)));
    }
}
