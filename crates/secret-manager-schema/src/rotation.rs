//! Manual rotation guides: how to replace one credential, by slug. Mirrors the
//! `RotationGuide` and `RotationCatalogue` Pkl classes in
//! `pkl/SecretRegistry.pkl`.
//!
//! Guides hold identity and instructions only — never a value. The URLs are
//! handed to a browser launcher, so [`RotationCatalogue::validate`] re-checks
//! them (and the key shape) as a trust boundary.
use anyhow::{Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Credential slug to guide.
#[derive(Debug, Default, Deserialize)]
pub struct RotationCatalogue {
    #[serde(default)]
    pub guides: BTreeMap<String, RotationGuide>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationGuide {
    pub title: String,
    /// Store-relative path of the encrypted source, when the credential is one.
    #[serde(default)]
    pub secret: Option<String>,
    /// Provider pages where the new value is minted, opened in order.
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub steps: Vec<String>,
    /// Command that stores the new value.
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub cadence_days: Option<u32>,
    #[serde(default)]
    pub warn_days: Option<u32>,
}

impl RotationCatalogue {
    /// The first guide whose `secret` is the store-relative `path`.
    pub fn for_secret(&self, path: &str) -> Option<(&str, &RotationGuide)> {
        self.guides
            .iter()
            .find(|(_, guide)| guide.secret.as_deref() == Some(path))
            .map(|(key, guide)| (key.as_str(), guide))
    }

    /// Re-check what Pkl already types: slug-shaped keys and `https://` URLs.
    /// Data repositories may hand-write or generate this file, and the URLs
    /// reach `xdg-open`, so validation lives on this side too.
    pub fn validate(&self) -> Result<()> {
        for (key, guide) in &self.guides {
            if !is_key(key) {
                bail!("rotation guide key {key:?} must match ^[a-z0-9][a-z0-9._-]*$");
            }
            for url in &guide.urls {
                if !is_https_url(url) {
                    bail!(
                        "rotation guide {key}: url {url:?} must start with https:// and name a host"
                    );
                }
            }
        }
        Ok(())
    }
}

fn is_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// `https://` plus something that is not whitespace: a bare scheme would be
/// handed to the launcher just the same.
fn is_https_url(url: &str) -> bool {
    url.strip_prefix("https://").is_some_and(|rest| {
        !rest.is_empty() && !rest.chars().any(|c| c.is_whitespace() || c.is_control())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalogue() -> RotationCatalogue {
        serde_json::from_value(serde_json::json!({
            "guides": {
                "github-token": {
                    "title": "GitHub personal access token",
                    "secret": "age/secrets/users/can/github.age",
                    "urls": ["https://github.com/settings/tokens"],
                    "steps": ["Create a token."],
                    "command": "secret-manager github token --out age/secrets/users/can/github.age",
                    "cadenceDays": 90,
                    "warnDays": 14,
                    "__pkl_class": "RotationGuide"
                }
            }
        }))
        .unwrap()
    }

    #[test]
    fn decodes_pkl_camel_case_and_ignores_class_tags() {
        let c = catalogue();
        let guide = &c.guides["github-token"];
        assert_eq!(guide.cadence_days, Some(90));
        assert_eq!(guide.warn_days, Some(14));
        assert_eq!(guide.urls.len(), 1);
        assert_eq!(
            c.for_secret("age/secrets/users/can/github.age")
                .map(|(key, _)| key),
            Some("github-token")
        );
        assert!(c.for_secret("age/secrets/users/can/other.age").is_none());
        c.validate().unwrap();
    }

    #[test]
    fn validation_rejects_non_https_urls_and_bad_keys() {
        for url in ["http://github.com/tokens", "file:///etc/passwd", "https://"] {
            let mut c = catalogue();
            c.guides.get_mut("github-token").unwrap().urls = vec![url.into()];
            assert!(c.validate().is_err(), "{url} must be rejected");
        }
        for key in ["Github", "-github", "github token", ""] {
            let mut c = catalogue();
            let guide = c.guides.remove("github-token").unwrap();
            c.guides.insert(key.into(), guide);
            assert!(c.validate().is_err(), "{key:?} must be rejected");
        }
    }
}
