//! DNS provider credential verification, deSEC scoped-token minting with
//! drop-based revocation, and rekeyed-copy counting.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use reqwest::Method;
use reqwest::blocking::Client;
use reqwest::header::HeaderValue;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::io::validate_slug;

/// Default deSEC v1 API base URL.
pub const DESEC_API: &str = "https://desec.io/api/v1";

const MAX_DNS_BODY: u64 = 64 * 1024;

/// Supported DNS providers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum DnsProvider {
    Desec,
    Hetzner,
    Gcore,
    Bunny,
    Cloudflare,
}

impl DnsProvider {
    /// Canonical lowercase kebab-case provider name.
    pub fn name(self) -> String {
        self.to_possible_value()
            .expect("named provider")
            .get_name()
            .into()
    }

    /// `(verification_url, auth_header_name, auth_header_prefix)`.
    pub fn verification(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Desec => (
                "https://desec.io/api/v1/domains/",
                "Authorization",
                "Token ",
            ),
            Self::Hetzner => (
                "https://api.hetzner.cloud/v1/zones?per_page=1",
                "Authorization",
                "Bearer ",
            ),
            Self::Gcore => (
                "https://api.gcore.com/dns/v2/zones?limit=1",
                "Authorization",
                "APIKey ",
            ),
            Self::Bunny => (
                "https://api.bunny.net/dnszone?page=1&perPage=1",
                "AccessKey",
                "",
            ),
            Self::Cloudflare => (
                "https://api.cloudflare.com/client/v4/user/tokens/verify",
                "Authorization",
                "Bearer ",
            ),
        }
    }

    /// Conventional environment variable name for this provider's token.
    pub fn env_var(self) -> &'static str {
        match self {
            Self::Desec => "DESEC_TOKEN",
            Self::Hetzner => "HETZNER_API_TOKEN",
            Self::Gcore => "GCORE_API_KEY",
            Self::Bunny => "BUNNY_API_KEY",
            Self::Cloudflare => "CLOUDFLARE_API_TOKEN",
        }
    }

    /// Metadata project identifier (`dns-<provider>`).
    pub fn project(self) -> String {
        format!("dns-{}", self.name())
    }

    /// Whether the provider supports a separate read-only MCP token.
    pub fn offers_read_only(self) -> bool {
        matches!(self, Self::Hetzner | Self::Gcore)
    }
}

/// DNS credential role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum DnsSecretRole {
    Apply,
    Acme,
    Ddns,
    McpRo,
    Admin,
}

impl DnsSecretRole {
    /// Whether this role is stored under a user's home tree rather than system modules.
    pub fn user_owned(self) -> bool {
        matches!(self, Self::McpRo | Self::Admin)
    }
}

/// Validate a DNS profile slug: lowercase ASCII letters, digits, and hyphens
/// (at most 200 bytes) so `-` -> `_` mapping remains injective.
pub fn validate_profile(profile: &str) -> Result<()> {
    validate_slug(profile)?;
    ensure!(
        profile.len() <= 200
            && profile
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "DNS profiles must use lowercase letters, digits and hyphens"
    );
    Ok(())
}

/// Parse and validate a single-line, non-empty, control-char-free token of at
/// most `limit` bytes.
pub fn token_line(text: &str, limit: usize) -> Result<Zeroizing<String>> {
    let line = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let token = line.trim();
    ensure!(
        text.len() <= limit
            && !line.contains(['\r', '\n'])
            && !token.is_empty()
            && !token.chars().any(char::is_control),
        "expected one non-empty token line of at most {limit} bytes"
    );
    Ok(Zeroizing::new(token.into()))
}

fn token_header(prefix: &str, token: &str) -> Result<HeaderValue> {
    let value = Zeroizing::new(format!("{prefix}{token}"));
    let mut header =
        HeaderValue::from_str(&value).map_err(|_| anyhow::anyhow!("invalid DNS token header"))?;
    header.set_sensitive(true);
    Ok(header)
}

/// Build a blocking HTTP client for DNS provider calls: no proxy, no redirects,
/// 30-second timeout, and optional `https_only` (true in production; false for
/// localhost `TcpListener` tests).
pub fn dns_client(https_only: bool) -> Result<Client> {
    Client::builder()
        .https_only(https_only)
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent("secret-manager-dns")
        .build()
        .context("build DNS HTTP client")
}

/// Verify a DNS provider token against its production HTTPS endpoint.
pub fn verify_dns_token(provider: DnsProvider, token: &str) -> Result<()> {
    let client = dns_client(true)?;
    verify_dns_token_at(&client, provider, provider.verification().0, token)
}

/// Verify a DNS provider token against `url` using `client`.
pub fn verify_dns_token_at(
    client: &Client,
    provider: DnsProvider,
    url: &str,
    token: &str,
) -> Result<()> {
    let (_, name, prefix) = provider.verification();
    let response = client
        .get(url)
        .header(name, token_header(prefix, token)?)
        .send()
        .map_err(|_| anyhow::anyhow!("DNS token verification request to {url} failed"))?;
    ensure!(
        response.status().is_success(),
        "{url} rejected DNS token verification (HTTP {})",
        response.status()
    );
    if provider == DnsProvider::Cloudflare {
        #[derive(Deserialize)]
        struct Reply {
            success: Option<bool>,
        }
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take(MAX_DNS_BODY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| anyhow::anyhow!("invalid Cloudflare token verification response"))?;
        ensure!(
            bytes.len() as u64 <= MAX_DNS_BODY,
            "invalid Cloudflare token verification response"
        );
        let reply: Reply = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid Cloudflare token verification response"))?;
        ensure!(
            reply.success == Some(true),
            "Cloudflare rejected DNS token verification"
        );
    }
    Ok(())
}

/// Transactionally mint scoped deSEC API tokens.
///
/// Any tokens created by this handle are automatically revoked via `DELETE` on
/// [`Drop`] unless [`DesecMint::disarm`] is called after installation succeeds.
pub struct DesecMint<'a> {
    client: &'a Client,
    base: String,
    header: HeaderValue,
    ids: Vec<String>,
}

impl<'a> DesecMint<'a> {
    /// Create a new deSEC minting handle bound to `base` (e.g. [`DESEC_API`]).
    pub fn new(client: &'a Client, base: &str, bootstrap_token: &str) -> Result<Self> {
        Ok(Self {
            client,
            base: base.trim_end_matches('/').to_owned(),
            header: token_header("Token ", bootstrap_token)?,
            ids: Vec::new(),
        })
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::blocking::Response> {
        let mut req = self
            .client
            .request(method.clone(), format!("{}/{path}", self.base))
            .header(reqwest::header::AUTHORIZATION, self.header.clone());
        if let Some(body) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }
        req.send()
            .map_err(|_| anyhow::anyhow!("deSEC {method} {path} request failed"))
    }

    /// Probe `GET auth/tokens/` to check whether the bootstrap token has
    /// `perm_manage_tokens`. Returns `Ok(true)` on 200, `Ok(false)` on 403, and
    /// `Err` on any other HTTP status.
    pub fn can_manage_tokens(&self) -> Result<bool> {
        match self
            .request(Method::GET, "auth/tokens/", None)?
            .status()
            .as_u16()
        {
            200 => Ok(true),
            403 => Ok(false),
            status => anyhow::bail!("deSEC token management probe returned HTTP {status}"),
        }
    }

    /// Mint a scoped deSEC token and attach its default + per-record-type RRset
    /// policies.
    pub fn create(
        &mut self,
        name: &str,
        write_default: bool,
        record_types: &[&str],
    ) -> Result<Zeroizing<String>> {
        // https://desec.readthedocs.io/en/latest/auth/tokens.html#token-policy-management
        // A default policy must be created before any record-type exceptions.
        ensure!(name.len() <= 178, "deSEC token name exceeds 178 bytes");
        let response = self
            .request(
                Method::POST,
                "auth/tokens/",
                Some(json!({
                    "name": name,
                    "perm_create_domain": false,
                    "perm_delete_domain": false,
                    "perm_manage_tokens": false,
                })),
            )
            .with_context(|| {
                format!(
                    "could not confirm creation of deSEC token {name}; check the provider for it"
                )
            })?;
        ensure!(
            response.status().as_u16() == 201,
            "deSEC rejected token creation for {name} (HTTP {})",
            response.status()
        );
        let mut bytes = Zeroizing::new(Vec::new());
        response
            .take(MAX_DNS_BODY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                anyhow::anyhow!("cannot read new deSEC token {name}; check the provider for it")
            })?;
        ensure!(
            bytes.len() as u64 <= MAX_DNS_BODY,
            "cannot read new deSEC token {name}; check the provider for it"
        );
        #[derive(Deserialize)]
        struct Id {
            id: String,
        }
        #[derive(Deserialize)]
        struct Token<'b> {
            token: &'b str,
        }
        let Id { id } = serde_json::from_slice(&bytes).map_err(|_| {
            anyhow::anyhow!("missing deSEC token ID for {name}; check the provider for it")
        })?;
        ensure!(
            id.len() == 36
                && id.bytes().enumerate().all(|(i, byte)| {
                    if [8, 13, 18, 23].contains(&i) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit()
                    }
                }),
            "invalid deSEC token ID for {name}; check the provider for it"
        );
        let path = format!("auth/tokens/{id}/policies/rrsets/");
        self.ids.push(id);
        let Token { token } = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("missing deSEC token value for {name}"))?;
        let token = token_line(token, 16 * 1024)?;
        for (kind, perm_write) in std::iter::once((None, write_default))
            .chain(record_types.iter().map(|kind| (Some(*kind), true)))
        {
            let response = self.request(
                Method::POST,
                &path,
                Some(json!({
                    "domain": null,
                    "subname": null,
                    "type": kind,
                    "perm_write": perm_write,
                })),
            )?;
            ensure!(
                response.status().as_u16() == 201,
                "deSEC rejected an RRset policy for {name} (HTTP {})",
                response.status()
            );
        }
        Ok(token)
    }

    /// Disarm automatic token revocation on drop once the minted tokens have
    /// been safely installed.
    pub fn disarm(&mut self) {
        self.ids.clear();
    }

    /// IDs of tokens currently tracked for revocation on drop.
    pub fn tracked_ids(&self) -> &[String] {
        &self.ids
    }
}

impl Drop for DesecMint<'_> {
    fn drop(&mut self) {
        for id in self.ids.iter().rev() {
            let path = format!("auth/tokens/{id}/");
            match self.request(Method::DELETE, &path, None) {
                Ok(response) if response.status().as_u16() == 204 => {}
                Ok(response) => eprintln!(
                    "could not revoke new deSEC token {id} (HTTP {})",
                    response.status()
                ),
                Err(error) => eprintln!("could not revoke new deSEC token {id}: {error:#}"),
            }
        }
    }
}

/// Count rekeyed `.age` copies under `dir` up to `depth` directory levels,
/// keyed by exact secret name (stripping the 32-hex-char hash prefix and `.age`
/// suffix).
pub fn rekeyed_counts(dir: &Path, depth: usize, counts: &mut HashMap<String, usize>) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("list {}", dir.display())),
    };
    for entry in entries {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() && depth > 0 {
            rekeyed_counts(&entry.path(), depth - 1, counts)?;
        } else if kind.is_file()
            && let Some((hash, name)) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.split_once('-'))
            && hash.len() == 32
            && hash.bytes().all(|b| b.is_ascii_hexdigit())
            && let Some(name) = name.strip_suffix(".age")
        {
            *counts.entry(name.into()).or_default() += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    struct Exchange {
        request: String,
        header: String,
        body: Option<Value>,
        status: u16,
        reply: String,
    }

    fn serve(steps: Vec<Exchange>) -> (String, mpsc::Receiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, done) = mpsc::channel();
        std::thread::spawn(move || {
            for step in steps {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line.trim_end(), format!("{} HTTP/1.1", step.request));
                let mut headers = HashMap::new();
                loop {
                    line.clear();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.trim_end().split_once(':').unwrap();
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                }
                let (name, value) = step.header.split_once(": ").unwrap();
                assert_eq!(headers.get(name).map(String::as_str), Some(value));
                if let Some(body) = step.body {
                    let mut bytes = vec![0; headers["content-length"].parse().unwrap()];
                    reader.read_exact(&mut bytes).unwrap();
                    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), body);
                }
                write!(
                    stream,
                    "HTTP/1.1 {} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    step.status,
                    step.reply.len(),
                    step.reply
                )
                .unwrap();
            }
            tx.send(()).unwrap();
        });
        (base, done)
    }

    fn desec_step(method_path: &str, status: u16) -> Exchange {
        Exchange {
            request: method_path.into(),
            status,
            header: "authorization: Token main".into(),
            body: None,
            reply: String::new(),
        }
    }

    fn uuid(number: usize) -> String {
        format!("00112233-4455-4677-8899-{number:012}")
    }

    #[test]
    fn provider_request_mapping() {
        for (provider, url, header, prefix) in [
            (
                DnsProvider::Desec,
                "https://desec.io/api/v1/domains/",
                "Authorization",
                "Token ",
            ),
            (
                DnsProvider::Hetzner,
                "https://api.hetzner.cloud/v1/zones?per_page=1",
                "Authorization",
                "Bearer ",
            ),
            (
                DnsProvider::Gcore,
                "https://api.gcore.com/dns/v2/zones?limit=1",
                "Authorization",
                "APIKey ",
            ),
            (
                DnsProvider::Bunny,
                "https://api.bunny.net/dnszone?page=1&perPage=1",
                "AccessKey",
                "",
            ),
            (
                DnsProvider::Cloudflare,
                "https://api.cloudflare.com/client/v4/user/tokens/verify",
                "Authorization",
                "Bearer ",
            ),
        ] {
            assert_eq!(provider.verification(), (url, header, prefix));
        }
    }

    #[test]
    fn validates_profile_and_token_line() {
        assert!(validate_profile("hetzner-work").is_ok());
        assert!(validate_profile("bunny_alt").is_err());
        assert!(validate_profile("../escape").is_err());
        assert!(validate_profile("UPPER").is_err());

        assert_eq!(
            token_line(" \tfixture-token \r\n", 30).unwrap().as_str(),
            "fixture-token"
        );
        for text in ["", " \n", "first\nsecond", "token\n\n", "token\0"] {
            assert!(token_line(text, 30).is_err());
        }
        assert!(token_line("too long", 3).is_err());
    }

    #[test]
    fn verify_dns_token_at_handles_providers_and_cloudflare_success_flag() {
        let client = dns_client(false).unwrap();
        let (base, done) = serve(vec![
            Exchange {
                request: "GET /bunny".into(),
                header: "accesskey: b-tok".into(),
                body: None,
                status: 200,
                reply: String::new(),
            },
            Exchange {
                request: "GET /cf-ok".into(),
                header: "authorization: Bearer cf-tok".into(),
                body: None,
                status: 200,
                reply: r#"{"success":true}"#.into(),
            },
            Exchange {
                request: "GET /cf-bad".into(),
                header: "authorization: Bearer cf-tok".into(),
                body: None,
                status: 200,
                reply: r#"{"success":false}"#.into(),
            },
            Exchange {
                request: "GET /cf-missing".into(),
                header: "authorization: Bearer cf-tok".into(),
                body: None,
                status: 200,
                reply: r#"{}"#.into(),
            },
        ]);
        verify_dns_token_at(
            &client,
            DnsProvider::Bunny,
            &format!("{base}/bunny"),
            "b-tok",
        )
        .unwrap();
        verify_dns_token_at(
            &client,
            DnsProvider::Cloudflare,
            &format!("{base}/cf-ok"),
            "cf-tok",
        )
        .unwrap();
        assert!(
            verify_dns_token_at(
                &client,
                DnsProvider::Cloudflare,
                &format!("{base}/cf-bad"),
                "cf-tok",
            )
            .is_err()
        );
        assert!(
            verify_dns_token_at(
                &client,
                DnsProvider::Cloudflare,
                &format!("{base}/cf-missing"),
                "cf-tok",
            )
            .is_err()
        );
        done.recv_timeout(Duration::from_secs(3)).unwrap();
    }

    #[test]
    fn desec_mint_policy_failure_revokes_created_tokens_on_drop() {
        let id1 = uuid(1);
        let id2 = uuid(2);
        let steps = vec![
            desec_step("GET /auth/tokens/", 200),
            Exchange {
                body: Some(json!({
                    "name": "apply",
                    "perm_create_domain": false,
                    "perm_delete_domain": false,
                    "perm_manage_tokens": false,
                })),
                reply: json!({"id": id1, "token": "tok-apply"}).to_string(),
                ..desec_step("POST /auth/tokens/", 201)
            },
            Exchange {
                body: Some(
                    json!({"domain": null, "subname": null, "type": null, "perm_write": true}),
                ),
                ..desec_step(&format!("POST /auth/tokens/{id1}/policies/rrsets/"), 201)
            },
            Exchange {
                body: Some(json!({
                    "name": "acme",
                    "perm_create_domain": false,
                    "perm_delete_domain": false,
                    "perm_manage_tokens": false,
                })),
                reply: json!({"id": id2, "token": "tok-acme"}).to_string(),
                ..desec_step("POST /auth/tokens/", 201)
            },
            Exchange {
                body: Some(
                    json!({"domain": null, "subname": null, "type": null, "perm_write": false}),
                ),
                ..desec_step(&format!("POST /auth/tokens/{id2}/policies/rrsets/"), 201)
            },
            Exchange {
                body: Some(
                    json!({"domain": null, "subname": null, "type": "TXT", "perm_write": true}),
                ),
                ..desec_step(&format!("POST /auth/tokens/{id2}/policies/rrsets/"), 500)
            },
            // Auto-revocation in reverse order on drop:
            desec_step(&format!("DELETE /auth/tokens/{id2}/"), 204),
            desec_step(&format!("DELETE /auth/tokens/{id1}/"), 204),
        ];
        let (base, done) = serve(steps);
        let client = dns_client(false).unwrap();
        {
            let mut mint = DesecMint::new(&client, &base, "main").unwrap();
            assert!(mint.can_manage_tokens().unwrap());
            assert_eq!(
                mint.create("apply", true, &[]).unwrap().as_str(),
                "tok-apply"
            );
            assert!(mint.create("acme", false, &["TXT"]).is_err());
            assert_eq!(mint.tracked_ids().len(), 2);
        }
        done.recv_timeout(Duration::from_secs(3)).unwrap();
    }

    #[test]
    fn desec_mint_disarm_skips_revocation() {
        let id1 = uuid(1);
        let steps = vec![
            Exchange {
                body: Some(json!({
                    "name": "apply",
                    "perm_create_domain": false,
                    "perm_delete_domain": false,
                    "perm_manage_tokens": false,
                })),
                reply: json!({"id": id1, "token": "tok-apply"}).to_string(),
                ..desec_step("POST /auth/tokens/", 201)
            },
            Exchange {
                body: Some(
                    json!({"domain": null, "subname": null, "type": null, "perm_write": true}),
                ),
                ..desec_step(&format!("POST /auth/tokens/{id1}/policies/rrsets/"), 201)
            },
        ];
        let (base, done) = serve(steps);
        let client = dns_client(false).unwrap();
        {
            let mut mint = DesecMint::new(&client, &base, "main").unwrap();
            assert_eq!(
                mint.create("apply", true, &[]).unwrap().as_str(),
                "tok-apply"
            );
            mint.disarm();
            assert!(mint.tracked_ids().is_empty());
        }
        done.recv_timeout(Duration::from_secs(3)).unwrap();
    }

    #[test]
    fn rekeyed_counts_matches_exact_names() {
        let dir = tempfile::tempdir().unwrap();
        let copies = dir.path().join("root/atlas");
        fs::create_dir_all(&copies).unwrap();
        let hash = "0123456789abcdef0123456789abcdef";
        for name in [
            "can-dns-bunny-mcp-ro",
            "can-dns-bunny-mcp-ro-old",
            "dns-desec-apply",
        ] {
            fs::write(copies.join(format!("{hash}-{name}.age")), b"x").unwrap();
        }
        fs::write(copies.join("short-not-counted.age"), b"x").unwrap();
        let mut counts = HashMap::new();
        rekeyed_counts(dir.path(), 3, &mut counts).unwrap();
        assert_eq!(counts.get("can-dns-bunny-mcp-ro"), Some(&1));
        assert_eq!(counts.get("can-dns-bunny-mcp-ro-old"), Some(&1));
        assert_eq!(counts.get("dns-desec-apply"), Some(&1));
        assert_eq!(counts.get("not-counted"), None);
    }
}
