//! Reusable primitives for Docker Hub personal access token (PAT) enrollment
//! and registry-grant verification.

use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use reqwest::blocking::Client;
use reqwest::header::HeaderValue;
use reqwest::redirect::Policy;
use zeroize::Zeroizing;

/// Browser URL for creating a Docker Hub personal access token.
pub const CREATE_URL: &str = "https://app.docker.com/settings/personal-access-tokens/create";

const DOCKER_AUTH_BASE: &str = "https://auth.docker.io/token";
const MAX_DOCKER_BODY: u64 = 256 * 1024;

/// Validate a Docker Hub login (`letters, digits, '-', '_', '.'`).
pub fn validate_username(username: &str) -> Result<()> {
    ensure!(
        !username.is_empty()
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
        "username must be a Docker Hub login (letters, digits, '-', '_', '.')"
    );
    Ok(())
}

/// Validate a Docker Hub `OWNER/REPO` string before splicing it into a URL.
pub fn validate_repository(repo: &str) -> Result<()> {
    let ok = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    match repo.split_once('/') {
        Some((owner, name)) if ok(owner) && ok(name) => Ok(()),
        _ => bail!("repository must look like OWNER/REPO"),
    }
}

/// Validate the syntax of a Docker Hub PAT (`dckr_pat_` + alphanumerics, `-`,
/// or `_`), explicitly rejecting organization access tokens (`dckr_oat_`).
pub fn check_token_format(token: &str) -> Result<()> {
    ensure!(!token.is_empty(), "no token was pasted");
    if token.starts_with("dckr_oat_") {
        bail!(
            "organization access tokens are not supported; create a personal access token (dckr_pat_...)"
        );
    }
    ensure!(
        token.strip_prefix("dckr_pat_").is_some_and(|b| {
            !b.is_empty()
                && b.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        }),
        "not a Docker Hub personal access token (expected dckr_pat_ + letters, digits, '-' or '_')"
    );
    Ok(())
}

/// Build the Docker Hub registry auth probe URL for `repo` and `actions`.
pub fn probe_url(repo: &str, actions: &str) -> String {
    probe_url_at(DOCKER_AUTH_BASE, repo, actions)
}

fn probe_url_at(base: &str, repo: &str, actions: &str) -> String {
    format!("{base}?service=registry.docker.io&scope=repository:{repo}:{actions}")
}

/// Extract Docker Hub's non-secret refusal reason (e.g. `insufficient scopes`).
pub fn refusal_detail(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["details"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "no detail".to_owned())
}

/// Return the union of actions granted on `repo` by a registry JWT's `access`
/// claim.
pub fn granted_actions(jwt: &str, repo: &str) -> Result<BTreeSet<String>> {
    let payload = jwt
        .split('.')
        .nth(1)
        .context("registry token is not a JWT")?;
    let payload = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(payload)
            .context("decode JWT payload")?,
    );
    let claims: serde_json::Value = serde_json::from_slice(&payload)?;
    Ok(claims["access"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["type"] == "repository" && e["name"] == repo)
        .flat_map(|e| e["actions"].as_array().into_iter().flatten())
        .filter_map(|a| a.as_str().map(str::to_owned))
        .collect())
}

/// Verify a Docker Hub PAT against `https://auth.docker.io/token` and return
/// the comma-joined granted actions on `repo`.
///
/// Docker Hub refuses the whole request (401 `insufficient scopes`) when a
/// token lacks one requested action, so `pull` and `pull,push` are probed
/// separately: `pull` must succeed; a refused `pull,push` probe means `push`
/// is not granted.
pub fn verify(username: &str, token: &str, repo: &str, want: &BTreeSet<String>) -> Result<String> {
    let client = Client::builder()
        .redirect(Policy::none())
        .https_only(true)
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .user_agent("secret-manager-dockerhub-pat")
        .build()
        .context("build Docker Hub PAT verification HTTP client")?;
    verify_at(&client, DOCKER_AUTH_BASE, username, token, repo, want)
}

/// Verify a Docker Hub PAT against a custom `auth_base` URL using a
/// caller-supplied blocking client (for localhost `TcpListener` tests).
pub fn verify_at(
    client: &Client,
    auth_base: &str,
    username: &str,
    token: &str,
    repo: &str,
    want: &BTreeSet<String>,
) -> Result<String> {
    validate_username(username)?;
    validate_repository(repo)?;
    let credentials = Zeroizing::new(format!("{username}:{token}"));
    let encoded = Zeroizing::new(STANDARD.encode(credentials.as_bytes()));
    let auth_raw = Zeroizing::new(format!("Basic {}", encoded.as_str()));
    drop((credentials, encoded));
    let mut auth = HeaderValue::from_str(&auth_raw)
        .map_err(|_| anyhow::anyhow!("invalid Docker Hub auth header"))?;
    auth.set_sensitive(true);
    drop(auth_raw);

    // Ok(granted) on 200, Err(detail) on 401.
    let probe = |actions: &str| -> Result<std::result::Result<BTreeSet<String>, String>> {
        let resp = client
            .get(probe_url_at(auth_base, repo, actions))
            .header(reqwest::header::AUTHORIZATION, auth.clone())
            .send()
            .map_err(|_| anyhow::anyhow!("Docker Hub auth request failed"))?;
        let status = resp.status().as_u16();
        let mut bytes = Zeroizing::new(Vec::new());
        resp.take(MAX_DOCKER_BODY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("failed to read Docker Hub auth response"))?;
        ensure!(
            bytes.len() as u64 <= MAX_DOCKER_BODY,
            "Docker Hub auth response exceeded size limit; nothing stored"
        );
        if status == 401 {
            let text = std::str::from_utf8(&bytes).unwrap_or_default();
            return Ok(Err(refusal_detail(text)));
        }
        ensure!(
            status == 200,
            "unexpected Docker Hub auth status {status}; nothing stored"
        );
        #[derive(serde::Deserialize)]
        struct RegistryToken<'a> {
            token: Option<&'a str>,
            access_token: Option<&'a str>,
        }
        let reply: RegistryToken<'_> = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid Docker Hub auth JSON; nothing stored"))?;
        let jwt = reply
            .token
            .or(reply.access_token)
            .context("auth reply had no token")?;
        Ok(Ok(granted_actions(jwt, repo)?))
    };

    let mut got = probe("pull")?.map_err(|detail| {
        anyhow::anyhow!(
            "Docker Hub rejected the token for {username} on {repo} ({detail}); check that username is the Docker ID that created the token; nothing stored"
        )
    })?;
    if let Ok(full) = probe("pull,push")? {
        got.extend(full);
    }
    let join = |s: &BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>().join(",");
    ensure!(
        &got == want,
        "token grants [{}] on {repo}, expected [{}]; nothing stored",
        join(&got),
        join(want)
    );
    Ok(join(&got))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn jwt(claims: &serde_json::Value) -> String {
        format!(
            "e30.{}.sig",
            URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes())
        )
    }

    #[test]
    fn username_validation() {
        assert!(validate_username("caniko").is_ok());
        assert!(validate_username("can_1-a.b").is_ok());
        for bad in ["", "can/iko", "can iko", "can:iko"] {
            assert!(validate_username(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn token_format() {
        for ok in ["dckr_pat_a", "dckr_pat_Ab3-_xYz9"] {
            assert!(check_token_format(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "   ",
            "dckr_pat_",
            "dckr_pat_has space",
            "dckr_pat_new\nline",
            "dckr_pat_dot.dot",
            "ghp_abc",
        ] {
            assert!(check_token_format(bad).is_err(), "{bad:?}");
        }
        assert!(
            check_token_format("dckr_oat_abc")
                .unwrap_err()
                .to_string()
                .contains("organization")
        );
    }

    #[test]
    fn probe_url_scopes_pull_and_push() {
        assert_eq!(
            probe_url("caniko/syndb-etl", "pull,push"),
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:caniko/syndb-etl:pull,push"
        );
    }

    #[test]
    fn refusal_detail_is_extracted() {
        assert_eq!(
            refusal_detail(r#"{"details":"incorrect username or password"}"#),
            "incorrect username or password"
        );
        assert_eq!(refusal_detail("<html>"), "no detail");
    }

    #[test]
    fn repository_shape() {
        assert!(validate_repository("caniko/syndb-etl").is_ok());
        for bad in ["", "x", "a/b/c", "/b", "a/", "a/b&c", "a/b c"] {
            assert!(validate_repository(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn grant_must_match_exactly() {
        let repo = "caniko/syndb-etl";
        let pull = jwt(&serde_json::json!({"access": [
            {"type": "repository", "name": repo, "actions": ["pull"]},
            {"type": "repository", "name": "other/repo", "actions": ["push"]},
            {"type": "registry", "name": repo, "actions": ["push"]},
        ]}));
        assert_eq!(granted_actions(&pull, repo).unwrap(), set(&["pull"]));
        let both = jwt(&serde_json::json!({"access": [
            {"type": "repository", "name": repo, "actions": ["pull", "push"]},
        ]}));
        assert_eq!(
            granted_actions(&both, repo).unwrap(),
            set(&["pull", "push"])
        );
        assert_ne!(granted_actions(&both, repo).unwrap(), set(&["pull"]));
        // Entries for other repositories are ignored; no entry means no grant.
        assert!(granted_actions(&pull, "caniko/none").unwrap().is_empty());
        assert!(
            granted_actions(&jwt(&serde_json::json!({})), repo)
                .unwrap()
                .is_empty()
        );
        assert!(granted_actions("not-a-jwt", repo).is_err());
    }

    #[test]
    fn verify_at_probes_pull_and_push_over_localhost() {
        let repo = "caniko/syndb-etl";
        let pull_jwt = jwt(&serde_json::json!({"access": [
            {"type": "repository", "name": repo, "actions": ["pull"]}
        ]}));
        let expected_auth = format!("Basic {}", STANDARD.encode("caniko:dckr_pat_fixture"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/token", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for (expected_scope, status, body) in [
                (
                    "repository:caniko/syndb-etl:pull",
                    200u16,
                    serde_json::json!({"token": pull_jwt}).to_string(),
                ),
                (
                    "repository:caniko/syndb-etl:pull,push",
                    401u16,
                    r#"{"details":"insufficient scopes"}"#.to_owned(),
                ),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                assert!(req_line.contains(expected_scope), "{req_line}");
                let mut saw_auth = false;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((k, v)) = line.trim_end().split_once(':')
                        && k.eq_ignore_ascii_case("authorization")
                    {
                        assert_eq!(v.trim(), expected_auth);
                        saw_auth = true;
                    }
                }
                assert!(saw_auth);
                write!(
                    stream,
                    "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let granted = verify_at(
            &client,
            &base,
            "caniko",
            "dckr_pat_fixture",
            repo,
            &set(&["pull"]),
        )
        .unwrap();
        assert_eq!(granted, "pull");
        handle.join().unwrap();
    }
}
