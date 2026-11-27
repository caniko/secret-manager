//! Purelymail API client, mailbox validation, password generation, and
//! transactional install-and-create rollback helpers.
//!
//! Callers should acquire [`crate::protection::CredentialProtection`] before
//! loading API tokens or generating mailbox passwords.

use std::fmt;
use std::fs;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use reqwest::blocking::Client;
use reqwest::header::HeaderValue;
use reqwest::redirect::Policy;
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::meta::{Kind, Metadata, sidecar_path, today};

/// Default Purelymail v0 API base URL.
pub const PURELYMAIL_API: &str = "https://purelymail.com/api/v0";

const MAX_REPLY_BYTES: u64 = 1024 * 1024;

/// Validate a DNS domain name (up to 253 bytes, at least two labels, each
/// 1..=63 ASCII alphanumerics or internal hyphens).
pub fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Validate a mailbox local part allowing ASCII alphanumerics plus the given
/// `punctuation` bytes, forbidding leading/trailing/consecutive dots.
pub fn valid_local(local: &str, punctuation: &[u8]) -> bool {
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.contains(&b))
}

/// Generate a 32-character uniform ASCII alphanumeric password from
/// `/dev/urandom` using rejection sampling.
pub fn generate_alphanumeric_password() -> std::io::Result<Zeroizing<String>> {
    let mut entropy = fs::File::open("/dev/urandom")?;
    let mut draw = Zeroizing::new([0u8; 64]);
    let mut password = Zeroizing::new(String::with_capacity(32));
    while password.len() < 32 {
        entropy.read_exact(&mut *draw)?;
        // Filtering uniform bytes keeps all 62 ASCII alphanumerics equiprobable.
        let remaining = 32 - password.len();
        password.extend(
            draw.iter()
                .copied()
                .filter(u8::is_ascii_alphanumeric)
                .map(char::from)
                .take(remaining),
        );
    }
    Ok(password)
}

/// Encrypt a new mailbox password, write its metadata sidecar, and invoke
/// `create`.
///
/// Confirmed API failures (`ApiError::Http` or `ApiError::Rejected`) roll back
/// both the `.age` file and `.meta.toml` sidecar. Ambiguous failures
/// (`ApiError::Transport` or `ApiError::InvalidReply`) keep the encrypted files
/// on disk because Purelymail may have created the mailbox.
pub fn install_and_create(
    source: &Path,
    encrypt: impl FnOnce() -> Result<()>,
    create: impl FnOnce() -> Result<(), ApiError>,
) -> Result<()> {
    encrypt()?;
    let metadata = Metadata {
        rotated_at: Some(today()),
        kind: Some(Kind::External),
        ..Default::default()
    };
    let save = || {
        let ciphertext = source.symlink_metadata()?;
        ensure!(
            ciphertext.is_file() && ciphertext.len() > 0,
            "encrypted source is missing or empty"
        );
        metadata.save(source)
    };
    if let Err(error) = save() {
        fs::remove_file(source)
            .with_context(|| format!("cannot roll back {} ({error:#})", source.display()))?;
        return Err(error);
    }
    match create() {
        Ok(()) => Ok(()),
        Err(error @ (ApiError::Http(_) | ApiError::Rejected)) => {
            let age = fs::remove_file(source);
            let meta = fs::remove_file(sidecar_path(source));
            age.and(meta).with_context(|| {
                format!("rollback failed for {} after {error}", source.display())
            })?;
            Err(error.into())
        }
        // A lost reply does not tell us whether Purelymail installed the
        // password. Keep the only copy and do not automatically retry.
        Err(error) => Err(error).with_context(|| {
            format!(
                "creation unconfirmed; kept {} for reconciliation",
                source.display()
            )
        }),
    }
}

/// Request payload for Purelymail's `createUser` endpoint.
///
/// Intentionally has no `Debug` implementation because it borrows a plaintext
/// password.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUser<'a> {
    pub user_name: &'a str,
    pub domain_name: &'a str,
    pub password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_email: Option<&'a str>,
    pub enable_password_reset: bool,
    pub enable_search_indexing: bool,
    pub send_welcome_email: bool,
}

/// Response payload from Purelymail's `listUser` endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct Users {
    pub users: Vec<String>,
}

#[derive(Deserialize)]
struct Reply<T> {
    #[serde(rename = "type")]
    kind: ReplyKind,
    result: Option<T>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ReplyKind {
    Success,
    Error,
    #[serde(other)]
    Unknown,
}

/// Redacted Purelymail API error. Never retains server response text, JSON
/// parser details, or request credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    Http(u16),
    Rejected,
    Transport,
    InvalidReply,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(status) => write!(f, "Purelymail HTTP {status}"),
            Self::Rejected => f.write_str("Purelymail api_error: request rejected"),
            Self::Transport => f.write_str("Purelymail transport failed"),
            Self::InvalidReply => f.write_str("Purelymail response missing or invalid"),
        }
    }
}

impl std::error::Error for ApiError {}

/// Decode a Purelymail JSON envelope without propagating server error strings
/// or parser diagnostics.
pub fn decode_reply<T: DeserializeOwned>(body: &[u8]) -> Result<Option<T>, ApiError> {
    // Never propagate server text, including error codes or JSON parser messages.
    let reply: Reply<T> = serde_json::from_slice(body).map_err(|_| ApiError::InvalidReply)?;
    match reply.kind {
        ReplyKind::Success => Ok(reply.result),
        ReplyKind::Error => Err(ApiError::Rejected),
        ReplyKind::Unknown => Err(ApiError::InvalidReply),
    }
}

/// Blocking HTTP client for Purelymail's v0 API.
pub struct PurelymailApi {
    client: Client,
    base_url: String,
    token: HeaderValue,
}

impl PurelymailApi {
    /// Load the Purelymail API token from a regular file (opened `O_NONBLOCK`,
    /// max 4096 bytes, ASCII graphic characters only) and build an HTTPS-only,
    /// no-proxy, no-redirect, 30s-timeout client targeting [`PURELYMAIL_API`].
    pub fn from_token_file(path: &Path) -> Result<Self> {
        Self::from_token_file_with_base(path, PURELYMAIL_API, true)
    }

    /// Like [`Self::from_token_file`], with a custom base URL and `https_only`
    /// flag (for localhost `TcpListener` tests).
    pub fn from_token_file_with_base(
        path: &Path,
        base_url: &str,
        https_only: bool,
    ) -> Result<Self> {
        let describe = || format!("read API key file {}", path.display());
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .with_context(describe)?;
        ensure!(
            file.metadata().with_context(describe)?.is_file(),
            "{} is not a regular API key file",
            path.display()
        );
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(4097)
            .read_to_end(&mut bytes)
            .with_context(describe)?;
        let invalid = || anyhow::anyhow!("invalid API key file {}", path.display());
        let value = std::str::from_utf8(&bytes).map_err(|_| invalid())?.trim();
        ensure!(
            bytes.len() <= 4096 && !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic()),
            "{}",
            invalid()
        );
        let mut token = HeaderValue::from_str(value).map_err(|_| invalid())?;
        token.set_sensitive(true);
        let client = Client::builder()
            .https_only(https_only)
            .no_proxy()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(30))
            .user_agent("secret-manager-purelymail")
            .build()
            .context("build Purelymail HTTP client")?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
            token,
        })
    }

    /// Call `POST <base>/listUser`.
    pub fn list_users(&self) -> Result<Users, ApiError> {
        self.post::<Users>("listUser", Zeroizing::new(b"{}".to_vec()))?
            .ok_or(ApiError::InvalidReply)
    }

    /// Call `POST <base>/createUser` with a pre-serialized JSON body.
    pub fn create_user(&self, request: &CreateUser<'_>) -> Result<(), ApiError> {
        // Reserve enough for validated fields so serialization does not
        // reallocate a buffer that already holds the password.
        let mut body = Zeroizing::new(Vec::with_capacity(1024));
        serde_json::to_writer(&mut *body, request).map_err(|_| ApiError::InvalidReply)?;
        self.post::<IgnoredAny>("createUser", body).map(|_| ())
    }

    /// Send a raw JSON `POST` to a Purelymail endpoint with bounded response
    /// reading into a zeroized buffer.
    pub fn post<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Option<T>, ApiError> {
        let len = body.len() as u64;
        let response = self
            .client
            .post(format!("{}/{endpoint}", self.base_url))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("Purelymail-Api-Token", self.token.clone())
            .body(reqwest::blocking::Body::sized(
                std::io::Cursor::new(body),
                len,
            ))
            .send()
            .map_err(|_| ApiError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(ApiError::Http(status.as_u16()));
        }
        let mut reply = Zeroizing::new(Vec::new());
        response
            .take(MAX_REPLY_BYTES + 1)
            .read_to_end(&mut reply)
            .map_err(|_| ApiError::InvalidReply)?;
        if reply.len() as u64 > MAX_REPLY_BYTES {
            return Err(ApiError::InvalidReply);
        }
        decode_reply(&reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    #[test]
    fn validates_domains_and_local_parts() {
        assert!(valid_domain("beloda.co"));
        assert!(valid_domain("sub.example-1.org"));
        assert!(!valid_domain("localhost"));
        assert!(!valid_domain("-bad.com"));
        assert!(!valid_domain("bad-.com"));
        assert!(!valid_domain("a..b.com"));

        assert!(valid_local("sorrel", b"-_."));
        assert!(valid_local("a.b_c-d", b"-_."));
        assert!(!valid_local("", b"-_."));
        assert!(!valid_local(".leading", b"-_."));
        assert!(!valid_local("trailing.", b"-_."));
        assert!(!valid_local("a..b", b"-_."));
        assert!(!valid_local("../escape", b"-_."));
    }

    #[test]
    fn serializes_create_user_and_omits_absent_recovery_email() {
        let req = CreateUser {
            user_name: "sorrel",
            domain_name: "beloda.co",
            password: "fixture-password",
            recovery_email: Some("outreach@beloda.co"),
            enable_password_reset: true,
            enable_search_indexing: true,
            send_welcome_email: false,
        };
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "userName": "sorrel",
                "domainName": "beloda.co",
                "password": "fixture-password",
                "recoveryEmail": "outreach@beloda.co",
                "enablePasswordReset": true,
                "enableSearchIndexing": true,
                "sendWelcomeEmail": false,
            })
        );
        let without_recovery = CreateUser {
            recovery_email: None,
            ..req
        };
        assert!(
            serde_json::to_value(&without_recovery)
                .unwrap()
                .get("recoveryEmail")
                .is_none()
        );
    }

    #[test]
    fn decodes_users_and_rejects_malformed_result() {
        let users: Users = decode_reply(
            br#"{"type":"success","result":{"users":["SORREL@beloda.co","phemus@example.org"]}}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(users.users.len(), 2);
        assert!(decode_reply::<Users>(br#"{"type":"success","result":{}}"#).is_err());
    }

    #[test]
    fn errors_never_include_reflected_credentials() {
        let error = decode_reply::<IgnoredAny>(
            br#"{"type":"error","code":"fixture-token","message":"fixture-password"}"#,
        )
        .unwrap_err();
        let output = format!("{error:?} {error}");
        assert!(!output.contains("fixture-token"));
        assert!(!output.contains("fixture-password"));
    }

    #[test]
    fn confirmed_failure_rolls_back_but_uncertain_creation_keeps_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("mail.age");
        let sidecar = sidecar_path(&source);
        let encrypt = || Ok(fs::write(&source, b"fixture ciphertext")?);
        for error in [ApiError::Http(403), ApiError::Rejected] {
            assert!(
                install_and_create(&source, encrypt, || {
                    assert!(source.is_file() && sidecar.is_file());
                    Err(error)
                })
                .is_err()
            );
            assert!(!source.exists() && !sidecar.exists());
        }
        let error = install_and_create(&source, encrypt, || Err(ApiError::Transport)).unwrap_err();
        assert!(error.to_string().contains("creation unconfirmed"));
        assert!(source.is_file() && sidecar.is_file());
    }

    #[test]
    fn generates_a_32_character_alphanumeric_password() {
        let password = generate_alphanumeric_password().unwrap();
        assert!(password.len() == 32 && password.bytes().all(|b| b.is_ascii_alphanumeric()));
    }

    #[test]
    fn api_list_users_and_create_user_over_localhost() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("api_key");
        fs::write(&key_file, "pm-secret-token\n").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for (expected_path, reply) in [
                (
                    "POST /listUser HTTP/1.1",
                    r#"{"type":"success","result":{"users":["a@example.com"]}}"#,
                ),
                ("POST /createUser HTTP/1.1", r#"{"type":"success"}"#),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line.trim_end(), expected_path);
                let mut content_len = 0usize;
                let mut saw_token = false;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((k, v)) = line.trim_end().split_once(':') {
                        if k.eq_ignore_ascii_case("purelymail-api-token") {
                            assert_eq!(v.trim(), "pm-secret-token");
                            saw_token = true;
                        } else if k.eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap();
                        }
                    }
                }
                assert!(saw_token);
                let mut body = vec![0u8; content_len];
                reader.read_exact(&mut body).unwrap();
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .unwrap();
            }
        });

        let api = PurelymailApi::from_token_file_with_base(&key_file, &base, false).unwrap();
        let users = api.list_users().unwrap();
        assert_eq!(users.users, vec!["a@example.com"]);
        api.create_user(&CreateUser {
            user_name: "sorrel",
            domain_name: "beloda.co",
            password: "fixture-password",
            recovery_email: None,
            enable_password_reset: true,
            enable_search_indexing: true,
            send_welcome_email: false,
        })
        .unwrap();
        handle.join().unwrap();
    }
}
