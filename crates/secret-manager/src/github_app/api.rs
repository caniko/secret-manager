use super::{
    config::{App, Config, Owner, check_permissions},
    crypto::Key,
    now,
};
use anyhow::{Result, ensure};
use reqwest::{Method, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, time::Duration};
use zeroize::Zeroizing;

pub(super) const MAX_BYTES: usize = 1024 * 1024;

pub(super) trait Api {
    fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&serde_json::Value>,
    ) -> Result<Zeroizing<Vec<u8>>>;
}

pub(super) struct Github(Client);

impl Github {
    pub fn new() -> Result<Self> {
        Ok(Self(
            Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(Policy::none())
                .user_agent("secret-manager-github-app")
                .build()?,
        ))
    }
}

impl Api for Github {
    fn request(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&serde_json::Value>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            path.starts_with('/') && !path.contains(['\r', '\n']),
            "invalid GitHub API path"
        );
        let mut request = self
            .0
            .request(method, format!("https://api.github.com{path}"))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        // reqwest errors contain the request URL, including one-use manifest
        // codes. Neither transport errors nor GitHub response bodies are logged.
        let response = request.send().map_err(|_| {
            anyhow::anyhow!("GitHub transport failed; request outcome may be ambiguous")
        })?;
        ensure!(
            response.status().is_success(),
            "GitHub request failed with HTTP {}",
            response.status().as_u16()
        );
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                anyhow::anyhow!(
                    "GitHub response could not be read; request outcome may be ambiguous"
                )
            })?;
        ensure!(
            bytes.len() <= MAX_BYTES,
            "GitHub response exceeds size limit"
        );
        Ok(bytes)
    }
}

#[derive(Deserialize)]
pub(super) struct Installation {
    pub id: u64,
    pub app_id: u64,
    pub account: Owner,
    pub permissions: BTreeMap<String, String>,
    pub repository_selection: String,
    pub suspended_at: Option<String>,
}

impl Installation {
    pub fn validate(&self, config: &Config, app: &App) -> Result<()> {
        ensure!(
            self.id > 0
                && self.app_id == app.id
                && self.account.login == config.owner
                && self.suspended_at.is_none(),
            "installation identity is mismatched or suspended"
        );
        ensure!(
            self.repository_selection == "selected",
            "installation must use selected repositories"
        );
        check_permissions(&self.permissions, &config.permissions)
    }
}

#[derive(Deserialize)]
struct Access {
    #[serde(deserialize_with = "super::secret_string")]
    token: Zeroizing<String>,
    expires_at: String,
    permissions: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct Repository {
    id: u64,
    full_name: String,
}

#[derive(Deserialize)]
struct Repositories {
    total_count: u64,
    repositories: Vec<Repository>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Verification {
    pub app_id: u64,
    pub app_slug: String,
    pub owner: String,
    pub installation_id: u64,
    pub repository: String,
    pub repository_id: u64,
    pub permissions: BTreeMap<String, String>,
    pub public_key_sha256: String,
    pub token_expires_at: String,
    pub verified_at: u64,
}

pub(super) fn authenticated_app(
    api: &impl Api,
    config: &Config,
    app: &App,
    key: &Key,
) -> Result<App> {
    app.validate(config)?;
    let jwt = key.jwt(app.id, now()?)?;
    let actual: App =
        serde_json::from_slice(&api.request(Method::GET, "/app", Some(&jwt), None)?)?;
    actual.validate(config)?;
    ensure!(actual.id == app.id, "key authenticated a different app ID");
    Ok(actual)
}

pub(super) fn verify(
    api: &impl Api,
    config: &Config,
    app: &App,
    key: &Key,
) -> Result<Verification> {
    authenticated_app(api, config, app, key)?;
    let jwt = key.jwt(app.id, now()?)?;
    let installation: Installation = serde_json::from_slice(&api.request(
        Method::GET,
        &format!("/repos/{}/installation", config.repository),
        Some(&jwt),
        None,
    )?)?;
    installation.validate(config, app)?;
    let scope = serde_json::json!({
        "repositories": [config.repository.split_once('/').map(|(_, r)| r).unwrap_or_default()],
        "permissions": config.permissions,
    });
    let access: Access = serde_json::from_slice(&api.request(
        Method::POST,
        &format!("/app/installations/{}/access_tokens", installation.id),
        Some(&jwt),
        Some(&scope),
    )?)?;
    ensure!(
        !access.token.is_empty(),
        "GitHub did not return an installation token"
    );
    let result = (|| {
        check_permissions(&access.permissions, &config.permissions)?;
        let repositories: Repositories = serde_json::from_slice(&api.request(
            Method::GET,
            "/installation/repositories",
            Some(&access.token),
            None,
        )?)?;
        ensure!(
            repositories.total_count == 1 && repositories.repositories.len() == 1,
            "installation token is not scoped to exactly one repository"
        );
        let repository = &repositories.repositories[0];
        ensure!(
            repository.full_name == config.repository && repository.id > 0,
            "installation token targets a different repository"
        );
        Ok(Verification {
            app_id: app.id,
            app_slug: app.slug.clone(),
            owner: config.owner.clone(),
            installation_id: installation.id,
            repository: repository.full_name.clone(),
            repository_id: repository.id,
            permissions: access.permissions.clone(),
            public_key_sha256: key.fingerprint(),
            token_expires_at: access.expires_at.clone(),
            verified_at: now()?,
        })
    })();
    // Always revoke the temporary verification token, including refusal paths.
    let revoked = api.request(
        Method::DELETE,
        "/installation/token",
        Some(&access.token),
        None,
    );
    let verification = result?;
    revoked?;
    Ok(verification)
}
