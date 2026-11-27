//! Reusable credential verification, hidden terminal input, atomic file
//! installation, yescrypt password hashing, and provider-specific verifiers.

pub mod atomic;
pub mod dns;
pub mod purelymail;
pub mod yescrypt;

pub use atomic::*;
pub use dns::*;
pub use purelymail::*;
pub use yescrypt::*;

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use reqwest::blocking::Client;
use reqwest::header::HeaderValue;
use reqwest::redirect::Policy;
use serde_json::Value;
use zeroize::Zeroizing;

const MAX_VERIFY_BODY: u64 = 256 * 1024;
const MAX_TOKEN_FILE_BYTES: u64 = 4096;
const MAX_HIDDEN_TOKEN_BYTES: usize = 4096;

/// Verify a bearer token against an HTTPS endpoint.
///
/// Enforces `https://`, disables redirects (`Policy::none()`), disables proxy
/// environment variables, uses a 30-second timeout, marks the `Authorization`
/// header as sensitive, bounds the response read, and returns `Ok(true)` when
/// the server replies with 2xx and does not include `"success": false` in a
/// JSON body. Never leaks the token or raw response body in errors.
pub fn verify_bearer_url(url: &str, token: &str) -> Result<bool> {
    ensure!(url.starts_with("https://"), "--verify-url must be https");
    let client = Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent("secret-manager-verify")
        .build()
        .context("build bearer verification HTTP client")?;
    verify_bearer_url_with_client(&client, url, token)
}

/// Verify a bearer token against `url` using a caller-supplied blocking client.
///
/// Production callers should prefer [`verify_bearer_url`]; this entry point
/// allows tests to supply a client configured for a local `TcpListener`.
pub fn verify_bearer_url_with_client(client: &Client, url: &str, token: &str) -> Result<bool> {
    let auth_raw = Zeroizing::new(format!("Bearer {token}"));
    let mut auth = HeaderValue::from_str(&auth_raw)
        .map_err(|_| anyhow::anyhow!("invalid bearer token header"))?;
    auth.set_sensitive(true);
    let response = client
        .get(url)
        .header(reqwest::header::AUTHORIZATION, auth)
        .send()
        .map_err(|_| anyhow::anyhow!("bearer verification request to {url} failed"))?;
    let status = response.status().as_u16();
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(MAX_VERIFY_BODY + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("failed to read bearer verification response"))?;
    ensure!(
        bytes.len() as u64 <= MAX_VERIFY_BODY,
        "bearer verification response exceeded size limit"
    );
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((200..300).contains(&status) && body.get("success") != Some(&Value::Bool(false)))
}

/// Read a token from `value_file` (trimmed) when provided, or from the
/// controlling terminal with echo disabled via [`read_hidden_token`].
pub fn read_token(value_file: Option<&Path>) -> Result<Zeroizing<String>> {
    let Some(file) = value_file else {
        return read_hidden_token();
    };
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(file)
        .with_context(|| format!("read {}", file.display()))?;
    ensure!(
        handle
            .metadata()
            .with_context(|| format!("stat {}", file.display()))?
            .is_file(),
        "{} is not a regular file",
        file.display()
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_FILE_BYTES as usize + 1));
    handle
        .take(MAX_TOKEN_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", file.display()))?;
    ensure!(
        bytes.len() as u64 <= MAX_TOKEN_FILE_BYTES,
        "{} exceeds maximum token size of {MAX_TOKEN_FILE_BYTES} bytes",
        file.display()
    );
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("{} is not valid UTF-8", file.display()))?;
    Ok(Zeroizing::new(value.trim().to_owned()))
}

/// Read one line from `/dev/tty` with terminal echo disabled, restoring the
/// original termios attributes on drop.
pub fn read_hidden_token() -> Result<Zeroizing<String>> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("a terminal is required to paste the token")?;
    let fd = tty.as_raw_fd();
    // SAFETY: termios is plain data and fd is an open terminal.
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::tcgetattr(fd, &mut original) } == 0,
        "cannot read terminal attributes"
    );
    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restores the attributes captured above on the same fd.
            unsafe { libc::tcsetattr(self.0, libc::TCSANOW, &self.1) };
        }
    }
    let _restore = Restore(fd, original);
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    ensure!(
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } == 0,
        "cannot disable terminal echo"
    );
    write!(tty, "Paste the token (input is hidden): ")?;
    tty.flush()?;
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_HIDDEN_TOKEN_BYTES));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match tty.read(&mut byte[..]) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() >= MAX_HIDDEN_TOKEN_BYTES {
                    let _ = writeln!(tty);
                    bail!("token input exceeds maximum size of {MAX_HIDDEN_TOKEN_BYTES} bytes");
                }
                buf.push(byte[0]);
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        }
    }
    writeln!(tty)?;
    let line =
        std::str::from_utf8(&buf).map_err(|_| anyhow::anyhow!("token input is not valid UTF-8"))?;
    Ok(Zeroizing::new(line.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    fn serve_once(status: u16, body: &'static str, expected_auth: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            let mut saw_auth = false;
            loop {
                line.clear();
                let n = reader.read_line(&mut line).unwrap();
                if n == 0 || line == "\r\n" {
                    break;
                }
                if let Some((k, v)) = line.trim_end().split_once(':')
                    && k.eq_ignore_ascii_case("authorization")
                {
                    assert_eq!(v.trim(), expected_auth);
                    saw_auth = true;
                }
            }
            assert!(saw_auth, "missing Authorization header");
            write!(
                stream,
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        format!("http://{addr}/verify")
    }

    #[test]
    fn verify_bearer_url_rejects_non_https() {
        let err = verify_bearer_url("http://example.invalid/verify", "secret-tok").unwrap_err();
        assert!(err.to_string().contains("https"));
        assert!(!err.to_string().contains("secret-tok"));
    }

    #[test]
    fn verify_bearer_url_with_client_checks_status_and_success_field() {
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let ok_url = serve_once(200, r#"{"success":true}"#, "Bearer tok-1");
        assert!(verify_bearer_url_with_client(&client, &ok_url, "tok-1").unwrap());

        let false_url = serve_once(200, r#"{"success":false}"#, "Bearer tok-2");
        assert!(!verify_bearer_url_with_client(&client, &false_url, "tok-2").unwrap());

        let unauth_url = serve_once(401, r#"{"error":"nope"}"#, "Bearer tok-3");
        assert!(!verify_bearer_url_with_client(&client, &unauth_url, "tok-3").unwrap());
    }

    #[test]
    fn read_token_trims_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("tok");
        std::fs::write(&file, "  my-secret-token \r\n").unwrap();
        let token = read_token(Some(&file)).unwrap();
        assert_eq!(token.as_str(), "my-secret-token");
    }
}
