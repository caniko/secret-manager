use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

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

/// A single declarative sync target — push one decrypted secret to one or more
/// forge repositories as an Actions secret.
#[derive(Debug, Deserialize)]
pub struct SyncTarget {
    /// Path to the agenix-encrypted `.age` file, relative to the store root.
    pub secret: String,

    /// Name of the Actions secret to set on each target repository.
    pub name: String,

    /// Codeberg/Forgejo repositories (owner/repo) to push to.
    #[serde(default)]
    pub codeberg: Vec<String>,

    /// GitHub repositories (owner/repo) to push to.
    #[serde(default)]
    pub github: Vec<String>,

    /// Forge host for Codeberg/Forgejo token resolution.
    #[serde(default = "default_host")]
    pub host: String,
}

fn default_host() -> String {
    "codeberg.org".to_string()
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
    /// This is the primary accessor for the sync command (Phase 03).
    pub fn iter_targets(&self) -> impl Iterator<Item = (usize, &str, &SyncTarget)> + '_ {
        self.hosts
            .iter()
            .enumerate()
            .flat_map(|(host_idx, host)| {
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
          "github": [],
          "host": "codeberg.org"
        },
        "deploy-key": {
          "secret": "age/secrets/deploy-key.age",
          "name": "DEPLOY_KEY",
          "codeberg": ["caniko/my-repo", "caniko/other-repo"],
          "github": ["caniko/mirror-repo"],
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
        assert_eq!(t1.secret, "age/secrets/my-app-token.age");
        assert_eq!(t1.name, "MY_APP_TOKEN");
        assert_eq!(t1.codeberg, vec!["caniko/my-repo"]);
        assert!(t1.github.is_empty());
        assert_eq!(t1.host, "codeberg.org");

        // Second target
        let t2 = doc.hosts[0].targets.get("deploy-key").unwrap();
        assert_eq!(t2.secret, "age/secrets/deploy-key.age");
        assert_eq!(t2.name, "DEPLOY_KEY");
        assert_eq!(
            t2.codeberg,
            vec!["caniko/my-repo", "caniko/other-repo"]
        );
        assert_eq!(t2.github, vec!["caniko/mirror-repo"]);
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
        assert!(t.github.is_empty());
        assert_eq!(t.host, "codeberg.org");
    }

    #[test]
    fn iter_targets_yields_all_targets() {
        let doc: SyncDocument = serde_json::from_str(CONTRACT_JSON).unwrap();
        let mut names: Vec<&str> = doc.iter_targets().map(|(_, name, _)| name).collect();
        names.sort();
        assert_eq!(names, vec!["deploy-key", "my-app-token"]);

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
