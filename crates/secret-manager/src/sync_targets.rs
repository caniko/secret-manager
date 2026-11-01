use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize};

/// Top-level document produced by `nix/collect.nix` → `builtins.toJSON`.
///
/// Each host that has `services.secretSync.enable = true` contributes one
/// entry in `hosts`.
#[derive(Debug, Deserialize, Serialize)]
pub struct SyncDocument {
    pub hosts: Vec<HostSyncConfig>,
}

/// Per-host sync-target configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct HostSyncConfig {
    /// Targets keyed by an arbitrary name meaningful to the store operator.
    pub targets: HashMap<String, SyncTarget>,
}

/// A single declarative sync target — push one value to one or more forge
/// destinations. Encrypted agenix values become Actions secrets; plaintext
/// source files become Actions variables.
#[derive(Debug, Serialize)]
pub struct SyncTarget {
    /// Source of the value to synchronize.
    #[serde(flatten)]
    pub value: SyncValue,

    /// Name of the Actions secret or variable to set on each target.
    pub name: String,

    /// Codeberg/Forgejo repositories (owner/repo) to push to.
    pub codeberg: Vec<String>,

    /// Codefloe repositories (owner/repo) to push to.
    pub codefloe: Vec<String>,

    /// GitHub repositories (owner/repo) to push to.
    pub github: Vec<String>,

    /// GitHub environment destinations; never falls back to repository scope.
    #[serde(rename = "githubEnvironments")]
    pub github_environments: Vec<GithubEnvironment>,

    /// Kubernetes Secret destinations; encrypted sources only.
    pub kubernetes: Vec<KubernetesDestination>,

    /// Codeberg/Forgejo organizations to push to at account scope.
    #[serde(rename = "codebergOrgs")]
    pub codeberg_orgs: Vec<String>,

    /// Whether to push to the authenticated user's account scope.
    #[serde(rename = "codebergUser")]
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
    Kubernetes,
}

/// Where a sync target's value comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
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

/// An existing GitHub Actions environment in one repository.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GithubEnvironment {
    pub repository: String,
    pub environment: String,
}

impl GithubEnvironment {
    pub fn validate(&self) -> anyhow::Result<()> {
        let (owner, repo) = self.repository.split_once('/').ok_or_else(|| {
            anyhow::anyhow!("GitHub environment repository must be in owner/repo form")
        })?;
        if [owner, repo].iter().any(|part| {
            part.is_empty()
                || *part == "."
                || *part == ".."
                || part.starts_with('-')
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        }) {
            anyhow::bail!("GitHub environment repository must be in owner/repo form");
        }
        if self.environment.trim().is_empty()
            || matches!(self.environment.as_str(), "." | "..")
            || self.environment.chars().count() > 255
            || self.environment.chars().any(char::is_control)
        {
            anyhow::bail!(
                "GitHub environment name must be nonblank, at most 255 characters, and contain no control characters"
            );
        }
        Ok(())
    }
}

/// How a decrypted value is shaped into a Kubernetes Secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KubernetesFormat {
    /// `type: Opaque` with the value under one `data` key.
    Opaque,
    /// `type: kubernetes.io/dockerconfigjson` built from `username` and the value.
    Dockerconfigjson,
}

pub const DEFAULT_DOCKER_REGISTRY: &str = "https://index.docker.io/v1/";
pub const DEFAULT_FIELD_MANAGER: &str = "secret-manager";
pub const DOCKERCONFIGJSON_KEY: &str = ".dockerconfigjson";

/// A Kubernetes Secret written with `kubectl apply --server-side`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KubernetesDestination {
    pub context: String,
    pub namespace: String,
    pub secret: String,
    pub format: KubernetesFormat,
    /// `opaque` only; defaults to the target's `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// `dockerconfigjson` only; defaults to [`DEFAULT_DOCKER_REGISTRY`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// Required for `dockerconfigjson`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Defaults to [`DEFAULT_FIELD_MANAGER`].
    #[serde(
        default,
        rename = "fieldManager",
        skip_serializing_if = "Option::is_none"
    )]
    pub field_manager: Option<String>,
}

fn is_rfc1123_subdomain(name: &str) -> bool {
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 253
        && edge(bytes[0])
        && edge(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|byte| edge(*byte) || matches!(byte, b'-' | b'.'))
        && name
            .split('.')
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
}

fn is_plain_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max
        && !value.starts_with('-')
        && !value.chars().any(char::is_control)
}

impl KubernetesDestination {
    /// Effective `data` key: `.dockerconfigjson`, or `key` / the target `name`.
    pub fn data_key<'a>(&'a self, target_name: &'a str) -> &'a str {
        match self.format {
            KubernetesFormat::Dockerconfigjson => DOCKERCONFIGJSON_KEY,
            KubernetesFormat::Opaque => self.key.as_deref().unwrap_or(target_name),
        }
    }

    /// Reject malformed names and field combinations before any effect.
    pub fn validate(&self, target_name: &str) -> anyhow::Result<()> {
        use anyhow::bail;
        if !is_plain_text(&self.context, 253) {
            bail!("Kubernetes context must be nonblank and must not start with `-`");
        }
        for (what, value) in [("namespace", &self.namespace), ("secret", &self.secret)] {
            if !is_rfc1123_subdomain(value) {
                bail!("Kubernetes {what} `{value}` must be an RFC 1123 subdomain");
            }
        }
        if let Some(manager) = &self.field_manager
            && !is_plain_text(manager, 128)
        {
            bail!(
                "Kubernetes fieldManager must be nonblank, at most 128 bytes and not start with `-`"
            );
        }
        match self.format {
            KubernetesFormat::Opaque => {
                if self.registry.is_some() || self.username.is_some() {
                    bail!("Kubernetes `opaque` secrets do not take `registry` or `username`");
                }
                let key = self.data_key(target_name);
                if key.is_empty()
                    || key.len() > 253
                    || matches!(key, "." | "..")
                    || !key.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
                {
                    bail!("Kubernetes secret key `{key}` must match [-._a-zA-Z0-9]+");
                }
            }
            KubernetesFormat::Dockerconfigjson => {
                if self.key.is_some() {
                    bail!(
                        "Kubernetes `dockerconfigjson` secrets always use `{DOCKERCONFIGJSON_KEY}`; remove `key`"
                    );
                }
                match &self.username {
                    Some(user) if !user.is_empty() && !user.chars().any(char::is_control) => {}
                    _ => bail!("Kubernetes `dockerconfigjson` secrets require a `username`"),
                }
                if self
                    .username
                    .as_deref()
                    .is_some_and(|user| user.contains(':'))
                {
                    bail!("Kubernetes dockerconfigjson `username` must not contain `:`");
                }
                if let Some(registry) = &self.registry
                    && (registry.is_empty() || registry.chars().any(char::is_control))
                {
                    bail!("Kubernetes dockerconfigjson `registry` must be nonblank");
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_github_environment_value_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.as_bytes()[0].is_ascii_digit()
        || name.to_ascii_uppercase().starts_with("GITHUB_")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        anyhow::bail!(
            "GitHub environment secret or variable name must be an identifier without the reserved GITHUB_ prefix"
        );
    }
    Ok(())
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
            #[serde(default, rename = "githubEnvironments")]
            github_environments: Vec<GithubEnvironment>,
            #[serde(default)]
            kubernetes: Vec<KubernetesDestination>,
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
            github_environments: raw.github_environments,
            kubernetes: raw.kubernetes,
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
