//! Switchable service accounts: several accounts per credential service, a
//! fleet default, and per-host and per-user overrides. Mirrors the
//! `AccountCatalogue` Pkl class in `pkl/SecretRegistry.pkl`.
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Service name to account name.
pub type Overrides = BTreeMap<String, String>;

#[derive(Debug, Deserialize)]
pub struct AccountCatalogue {
    pub services: BTreeMap<String, AccountService>,
    #[serde(default)]
    pub hosts: BTreeMap<String, AccountHost>,
    #[serde(default)]
    pub users: BTreeMap<String, Overrides>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountService {
    pub default_account: String,
    pub accounts: BTreeMap<String, Account>,
}

/// One account's encrypted source: a host-scoped agenix secret.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub source_host: String,
    pub secret_name: String,
}

/// A host's credential users and its overrides, which win over user overrides.
#[derive(Debug, Default, Deserialize)]
pub struct AccountHost {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub accounts: Overrides,
}

impl AccountCatalogue {
    pub fn service(&self, service: &str) -> Result<&AccountService> {
        self.services.get(service).with_context(|| {
            format!(
                "unknown service {service:?}; registered: {}",
                self.services.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })
    }

    /// The named account, or the service's fleet default.
    pub fn account(&self, service: &str, account: Option<&str>) -> Result<(&str, &Account)> {
        let svc = self.service(service)?;
        let name = account.unwrap_or(&svc.default_account);
        svc.accounts
            .get_key_value(name)
            .map(|(k, v)| (k.as_str(), v))
            .with_context(|| format!("{service} has no account {name:?}"))
    }

    /// The account `user` on `host` receives: the host override, else the
    /// user override, else the fleet default.
    pub fn select(&self, service: &str, host: &str, user: &str) -> Result<(&str, &Account)> {
        let chosen = self
            .hosts
            .get(host)
            .and_then(|h| h.accounts.get(service))
            .or_else(|| self.users.get(user).and_then(|u| u.get(service)));
        self.account(service, chosen.map(String::as_str))
    }

    /// Whether any user on any listed host receives the account.
    pub fn selects(&self, service: &str, account: &str) -> bool {
        self.hosts.iter().any(|(host, h)| {
            h.users.iter().any(|user| {
                self.select(service, host, user)
                    .is_ok_and(|(name, _)| name == account)
            })
        })
    }

    /// Every default and override names a registered service and account.
    pub fn validate(&self) -> Result<()> {
        for (name, svc) in &self.services {
            self.account(name, Some(&svc.default_account))?;
        }
        let scopes = self
            .hosts
            .iter()
            .map(|(host, h)| (format!("host {host}"), &h.accounts))
            .chain(
                self.users
                    .iter()
                    .map(|(user, o)| (format!("user {user}"), o)),
            );
        for (scope, overrides) in scopes {
            for (service, account) in overrides {
                self.account(service, Some(account))
                    .with_context(|| format!("{scope} override"))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalogue() -> AccountCatalogue {
        serde_json::from_value(serde_json::json!({
            "services": {"claude-code": {"defaultAccount": "shared", "__pkl_class": "AccountService", "accounts": {
                "shared": {"sourceHost": "atlas", "secretName": "claude-code-oauth"},
                "work": {"sourceHost": "atlas", "secretName": "claude-code-work"},
                "lab": {"sourceHost": "atlas", "secretName": "claude-code-lab"}}}},
            "hosts": {
                "atlas": {"users": ["can", "dejana"], "accounts": {}},
                "nomad": {"users": ["can", "dejana"], "accounts": {"claude-code": "lab"}}},
            "users": {"dejana": {"claude-code": "work"}}
        }))
        .unwrap()
    }

    #[test]
    fn host_beats_user_beats_default() {
        let c = catalogue();
        let pick = |host, user| c.select("claude-code", host, user).unwrap().0;
        assert_eq!(pick("atlas", "can"), "shared");
        assert_eq!(pick("atlas", "dejana"), "work");
        assert_eq!(pick("nomad", "dejana"), "lab");
        assert_eq!(pick("elsewhere", "dejana"), "work");
        assert!(c.select("missing", "atlas", "can").is_err());
        c.validate().unwrap();
    }

    #[test]
    fn selects_only_accounts_some_user_receives() {
        let mut c = catalogue();
        assert!(c.selects("claude-code", "shared") && c.selects("claude-code", "work"));
        c.hosts
            .get_mut("atlas")
            .unwrap()
            .accounts
            .insert("claude-code".into(), "lab".into());
        assert!(!c.selects("claude-code", "shared"));
        assert!(!c.selects("claude-code", "work"));
        assert!(c.selects("claude-code", "lab"));
    }

    #[test]
    fn validation_rejects_unknown_overrides() {
        let mut c = catalogue();
        c.users
            .get_mut("dejana")
            .unwrap()
            .insert("claude-code".into(), "gone".into());
        assert!(c.validate().is_err());
        let mut c = catalogue();
        c.services.get_mut("claude-code").unwrap().default_account = "gone".into();
        assert!(c.validate().is_err());
    }
}
