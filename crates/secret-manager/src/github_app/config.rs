use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Component, PathBuf},
};

/// Public policy. Issued IDs and credentials are acquired from GitHub, never
/// synthesized from this declaration.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub slug: String,
    pub owner: String,
    pub repository: String,
    pub homepage: String,
    pub source: PathBuf,
    pub recipients: Vec<String>,
    pub permissions: BTreeMap<String, String>,
    pub key_secret_name: String,
    pub app_id_variable: String,
    pub app_slug_variable: String,
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported GitHub App policy version");
        ensure!(
            identifier(&self.owner) && identifier(&self.slug),
            "invalid owner or app slug"
        );
        ensure!(
            self.slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !self.slug.starts_with('-')
                && !self.slug.ends_with('-'),
            "app slug must be lowercase and GitHub-compatible"
        );
        let (owner, repo) = self.repository.split_once('/').unwrap_or(("", ""));
        ensure!(
            owner == self.owner,
            "repository owner must match the declared app owner"
        );
        ensure!(identifier(repo), "invalid repository name");
        let homepage = url::Url::parse(&self.homepage)?;
        ensure!(
            homepage.scheme() == "https"
                && homepage.host_str().is_some()
                && homepage.username().is_empty()
                && homepage.password().is_none(),
            "homepage must be an HTTPS URL"
        );
        ensure!(
            !self.source.is_absolute()
                && self
                    .source
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
                && self.source.starts_with("age/secrets")
                && self.source.extension().is_some_and(|e| e == "age"),
            "source must be a relative .age file under age/secrets"
        );
        ensure!(
            !self.recipients.is_empty()
                && self
                    .recipients
                    .iter()
                    .all(|r| (r.starts_with("age1") || r.starts_with("ssh-"))
                        && !r.contains(['\n', '\r'])),
            "explicit public age recipients are required"
        );
        ensure!(
            !self.permissions.is_empty()
                && self
                    .permissions
                    .iter()
                    .all(|(name, level)| identifier(name)
                        && matches!(level.as_str(), "read" | "write")),
            "invalid app permissions"
        );
        for name in [
            &self.key_secret_name,
            &self.app_id_variable,
            &self.app_slug_variable,
        ] {
            ensure!(
                identifier(name)
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                    && !name.starts_with("GITHUB_"),
                "invalid Actions secret/variable name"
            );
        }
        ensure!(
            self.key_secret_name != self.app_id_variable
                && self.key_secret_name != self.app_slug_variable
                && self.app_id_variable != self.app_slug_variable,
            "destination names must be distinct"
        );
        Ok(())
    }

    pub fn manifest(&self, redirect: &str) -> serde_json::Value {
        serde_json::json!({
            "name": self.slug, "url": self.homepage,
            "redirect_url": redirect, "public": false,
            "hook_attributes": {"url": self.homepage, "active": false},
            "default_events": [], "default_permissions": self.permissions,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Owner {
    pub login: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct App {
    pub id: u64,
    pub slug: String,
    pub owner: Owner,
    pub permissions: BTreeMap<String, String>,
}

impl App {
    pub fn validate(&self, policy: &Config) -> Result<()> {
        ensure!(
            self.id > 0 && self.slug == policy.slug && self.owner.login == policy.owner,
            "issued app identity does not match declared owner/slug"
        );
        check_permissions(&self.permissions, &policy.permissions)
    }
}

pub fn check_permissions(
    actual: &BTreeMap<String, String>,
    expected: &BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        expected.iter().all(|(k, v)| actual.get(k) == Some(v)),
        "required app permissions are absent or changed"
    );
    ensure!(
        actual
            .iter()
            .all(|(k, v)| expected.get(k) == Some(v) || (k == "metadata" && v == "read")),
        "app permissions exceed declared policy"
    );
    Ok(())
}
