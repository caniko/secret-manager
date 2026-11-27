//! Reusable primitives for classic GitHub PAT enrollment and verification.

use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use reqwest::blocking::Client;
use reqwest::header::HeaderValue;
use reqwest::redirect::Policy;
use zeroize::Zeroizing;

pub use crate::verify::{
    check_rotation, read_hidden_token, read_token, write_source_and_sidecar as write_pat_pair,
};

const GITHUB_USER_URL: &str = "https://api.github.com/user";
const MAX_GITHUB_BODY: u64 = 256 * 1024;

/// Slug rule shared by PAT enrollment commands: lowercase ASCII letters, digits,
/// and internal hyphens (no leading or trailing `-`).
pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && !name.starts_with('-')
            && !name.ends_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "secret name must use lowercase letters, digits and '-' (no leading or trailing '-')"
    );
    Ok(())
}

/// Prefilled GitHub classic PAT creation URL.
///
/// Query parameters use unreserved-only percent-encoding; scopes are
/// comma-joined.
pub fn creation_url(scopes: &BTreeSet<String>, description: &str) -> String {
    let scopes = scopes.iter().cloned().collect::<Vec<_>>().join(",");
    format!(
        "https://github.com/settings/tokens/new?scopes={}&description={}",
        encode(&scopes),
        encode(description)
    )
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Validate the syntax of a classic GitHub PAT (`ghp_` + alphanumerics, 36-255
/// chars), explicitly rejecting fine-grained `github_pat_` tokens.
pub fn check_token_format(token: &str) -> Result<()> {
    ensure!(!token.is_empty(), "no token was pasted");
    if token.starts_with("github_pat_") {
        bail!("fine-grained tokens are not supported; create a classic token (ghp_...)");
    }
    let body = token.strip_prefix("ghp_");
    ensure!(
        body.is_some_and(|b| b.bytes().all(|c| c.is_ascii_alphanumeric()))
            && (36..=255).contains(&token.len()),
        "not a classic GitHub token (expected ghp_ + alphanumerics, 36-255 chars)"
    );
    Ok(())
}

/// Check that the comma-separated `x-oauth-scopes` header equals `want`
/// exactly: extra scopes break least privilege, missing ones break consumers.
pub fn scopes_match(header: &str, want: &BTreeSet<String>) -> bool {
    let got: BTreeSet<String> = header
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    &got == want
}

/// Verified metadata for a classic GitHub PAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGithubPat {
    pub login: String,
    pub scopes: String,
    pub summary: String,
    pub expiry: String,
}

/// Verify a classic GitHub PAT against `https://api.github.com/user`, checking
/// HTTP status, exact scopes, optional login, and reported expiry date.
pub fn verify(
    token: &str,
    want: &BTreeSet<String>,
    login: Option<&str>,
) -> Result<VerifiedGithubPat> {
    let client = Client::builder()
        .redirect(Policy::none())
        .https_only(true)
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .user_agent("secret-manager-github-pat")
        .build()
        .context("build GitHub PAT verification HTTP client")?;
    verify_at(&client, GITHUB_USER_URL, token, want, login)
}

/// Verify a classic GitHub PAT against `url` using a caller-supplied blocking
/// client (for localhost `TcpListener` tests).
pub fn verify_at(
    client: &Client,
    url: &str,
    token: &str,
    want: &BTreeSet<String>,
    login: Option<&str>,
) -> Result<VerifiedGithubPat> {
    let auth_raw = Zeroizing::new(format!("token {token}"));
    let mut auth = HeaderValue::from_str(&auth_raw)
        .map_err(|_| anyhow::anyhow!("invalid GitHub token header"))?;
    auth.set_sensitive(true);
    let resp = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, auth)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .map_err(|_| anyhow::anyhow!("GitHub API request failed"))?;
    let status = resp.status().as_u16();
    ensure!(
        status != 401,
        "GitHub rejected the token (401); nothing stored"
    );
    ensure!(
        status == 200,
        "unexpected GitHub API status {status}; nothing stored"
    );
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .map(|v| {
                v.to_str().map(str::to_owned).with_context(|| {
                    format!("GitHub sent an unreadable {name} header; nothing stored")
                })
            })
            .transpose()
    };
    let scopes = header("x-oauth-scopes")?.unwrap_or_default();
    ensure!(
        scopes_match(&scopes, want),
        "token scopes [{scopes}] differ from requested [{}]; nothing stored",
        want.iter().cloned().collect::<Vec<_>>().join(", ")
    );
    let expiry_header = header("github-authentication-token-expiration")?;
    let mut bytes = Zeroizing::new(Vec::new());
    resp.take(MAX_GITHUB_BODY + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("failed to read GitHub API response; nothing stored"))?;
    ensure!(
        bytes.len() as u64 <= MAX_GITHUB_BODY,
        "GitHub API response exceeded size limit; nothing stored"
    );
    let body: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("GitHub API returned invalid JSON; nothing stored"))?;
    let actual = body["login"]
        .as_str()
        .context("API reply had no login")?
        .to_owned();
    if let Some(expected) = login {
        ensure!(
            actual.eq_ignore_ascii_case(expected),
            "token belongs to {actual}, expected {expected}; nothing stored"
        );
    }
    let (expiry_note, expiry) = match expiry_header {
        Some(e) => {
            // GitHub sends e.g. `2027-02-13 00:00:00 UTC`; the date is enough.
            let date = e.get(..10).filter(|d| crate::meta::valid_date(d));
            let date =
                date.context("GitHub reported an unreadable token expiry; nothing stored")?;
            (format!("expires {e}"), date.to_owned())
        }
        None => ("no expiry".to_owned(), "never".to_owned()),
    };
    let summary = format!("{actual}, scopes [{scopes}], {expiry_note}");
    Ok(VerifiedGithubPat {
        login: actual,
        scopes,
        summary,
        expiry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn validates_pat_names() {
        assert!(validate_name("winget-pat").is_ok());
        assert!(validate_name("my-pat-1").is_ok());
        for bad in [
            "",
            "-",
            "-leading",
            "trailing-",
            "Upper",
            "with_underscore",
            "with space",
            "a/b",
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn url_encodes_scopes_and_note() {
        assert_eq!(
            creation_url(
                &set(&["public_repo", "read:org"]),
                "wingetcreate (sorrel, modde-rs)"
            ),
            "https://github.com/settings/tokens/new?scopes=public_repo%2Cread%3Aorg\
             &description=wingetcreate%20%28sorrel%2C%20modde-rs%29"
        );
    }

    #[test]
    fn token_format() {
        let ok = format!("ghp_{}", "aB3".repeat(12));
        assert!(check_token_format(&ok).is_ok());
        for bad in [
            "",
            "   ",
            "ghp_short",
            "ghp_ spaced token with spaces inside 123456",
            &format!("github_pat_{}", "a".repeat(40)),
        ] {
            assert!(check_token_format(bad).is_err(), "{bad:?}");
        }
        assert!(
            check_token_format(&format!("github_pat_{}", "a".repeat(40)))
                .unwrap_err()
                .to_string()
                .contains("fine-grained")
        );
    }

    #[test]
    fn scopes_must_match_exactly() {
        let want = set(&["public_repo"]);
        assert!(scopes_match("public_repo", &want));
        assert!(!scopes_match("public_repo, repo", &want));
        assert!(!scopes_match("", &want));
        assert!(scopes_match(
            "read:org, public_repo",
            &set(&["public_repo", "read:org"])
        ));
    }

    #[test]
    fn verify_at_checks_scopes_login_and_expiry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/user", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            let mut saw_auth = false;
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((k, v)) = line.trim_end().split_once(':')
                    && k.eq_ignore_ascii_case("authorization")
                {
                    assert_eq!(v.trim(), "token ghp_fixture");
                    saw_auth = true;
                }
            }
            assert!(saw_auth);
            let body = r#"{"login":"caniko"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\n\
                 x-oauth-scopes: public_repo, read:org\r\n\
                 github-authentication-token-expiration: 2027-02-13 00:00:00 UTC\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let verified = verify_at(
            &client,
            &url,
            "ghp_fixture",
            &set(&["public_repo", "read:org"]),
            Some("Caniko"),
        )
        .unwrap();
        assert_eq!(verified.login, "caniko");
        assert_eq!(verified.scopes, "public_repo, read:org");
        assert_eq!(verified.expiry, "2027-02-13");
        assert!(verified.summary.contains("expires 2027-02-13"));
        handle.join().unwrap();
    }
}
