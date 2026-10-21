//! Mint a GitHub OAuth token through `gh`'s device flow and store it as
//! agenix-encrypted sources without writing plaintext to the store.
//!
//! The operator authorizes in any browser signed in as the target account;
//! the command blocks until then, verifies the token's login and scopes, and
//! encrypts it with the store's agenix master policy. `gh` keeps its state in
//! a private temporary config directory that is removed on exit, so the token
//! never reaches the caller's `gh` login or keyring.
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use std::{
    collections::BTreeSet,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

use crate::credential_process::capture;
use crate::encryption::{StreamEncryptor, require_missing, with_store_write_lock};
use crate::store::{Store, resolve_against};

#[derive(Args)]
pub struct TokenArgs {
    /// GitHub login the authorized token must belong to.
    #[arg(long)]
    pub login: String,
    /// OAuth scope to request and require; repeatable.
    #[arg(long = "scope", required = true)]
    pub scopes: Vec<String>,
    /// Encrypted source receiving the bare token, relative to the store root.
    #[arg(long)]
    pub out: PathBuf,
    /// Optional encrypted source receiving `<ENV_NAME>=<token>` for systemd
    /// EnvironmentFile consumers.
    #[arg(long)]
    pub env_out: Option<PathBuf>,
    /// Variable name written to --env-out.
    #[arg(long, default_value = "GH_TOKEN", requires = "env_out")]
    pub env_name: String,
    /// Replace existing encrypted sources instead of refusing.
    #[arg(long)]
    pub rotate: bool,
    /// Secret-store root; defaults to normal SECRET_MANAGER_STORE discovery.
    #[arg(long)]
    pub store: Option<PathBuf>,
    /// lib.mkAgenixStreamEncryptor executable; defaults to SECRET_MANAGER_AGE_ENCRYPTOR.
    #[arg(long)]
    pub encryptor: Option<PathBuf>,
    /// How long to wait for the operator to authorize the device code.
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(30..=3600))]
    pub timeout_seconds: u64,
}

impl TokenArgs {
    pub fn run(self) -> Result<()> {
        ensure!(
            valid_login(&self.login),
            "--login must be a GitHub login (letters, digits and single hyphens)"
        );
        ensure!(
            valid_env_name(&self.env_name),
            "--env-name must be a shell variable name"
        );
        for scope in &self.scopes {
            ensure!(
                !scope.is_empty()
                    && scope
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b':' || b == b'_'),
                "unsupported OAuth scope {scope:?}"
            );
        }
        let store = match &self.store {
            Some(root) => Store { root: root.clone() },
            None => Store::discover()?,
        };
        let outputs: Vec<PathBuf> = std::iter::once(&self.out)
            .chain(self.env_out.as_ref())
            .map(|path| resolve_against(&store.root, path))
            .collect();
        ensure!(
            outputs.len() == outputs.iter().collect::<BTreeSet<_>>().len(),
            "--out and --env-out must differ"
        );
        // Fail before asking the operator to authorize anything.
        if !self.rotate {
            for path in &outputs {
                require_missing(path)
                    .with_context(|| format!("{} (pass --rotate to replace it)", path.display()))?;
            }
        }
        let encryptor = match &self.encryptor {
            Some(path) => StreamEncryptor::new(path.clone())?,
            None => StreamEncryptor::from_env()?,
        };

        let config = private_config_dir()?;
        let token = device_login(
            config.path(),
            &self.scopes,
            Duration::from_secs(self.timeout_seconds),
        )?;
        let (login, granted) = identity(config.path())?;
        ensure!(
            login.eq_ignore_ascii_case(&self.login),
            "authorized as {login}, not {}; nothing was stored",
            self.login
        );
        let missing = missing_scopes(&self.scopes, &granted);
        ensure!(
            missing.is_empty(),
            "token for {login} lacks scopes {missing:?}; nothing was stored"
        );

        let env_line = Zeroizing::new(format!("{}={}\n", self.env_name, token.as_str()));
        with_store_write_lock(&store.root, || {
            let write = |path: &Path, plaintext: &[u8]| {
                if self.rotate && path.exists() {
                    encryptor.encrypt_replace(path, plaintext)
                } else {
                    encryptor.encrypt_new(path, plaintext)
                }
                .with_context(|| format!("encrypting {}", path.display()))
            };
            write(&outputs[0], token.as_bytes())?;
            if let Some(path) = outputs.get(1) {
                write(path, env_line.as_bytes())?;
            }
            Ok(())
        })?;
        eprintln!(
            "GitHub token for {login} (scopes: {}) stored:",
            granted.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        for path in &outputs {
            eprintln!("  {}", path.display());
        }
        eprintln!("Stage the sources and run `agenix rekey` to distribute them.");
        Ok(())
    }
}

fn private_config_dir() -> Result<tempfile::TempDir> {
    // Prefer the per-user tmpfs so gh's hosts.yml never reaches persistent disk.
    let parent = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    tempfile::Builder::new()
        .prefix("secret-manager-gh-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .context("creating a private gh config directory")
}

fn gh(config: &Path) -> Command {
    let mut command = Command::new("gh");
    command
        .env("GH_CONFIG_DIR", config)
        .env("GH_HOST", "github.com")
        // The operator opens the device page in a browser signed in as the
        // target account; never launch the caller's (possibly other) session.
        .env("GH_BROWSER", "true")
        .env("BROWSER", "true")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN");
    command
}

fn device_login(config: &Path, scopes: &[String], timeout: Duration) -> Result<Zeroizing<String>> {
    eprintln!("Authorize in a browser signed in as the target account:");
    let mut child = gh(config)
        .args([
            "auth",
            "login",
            "--hostname",
            "github.com",
            "--git-protocol",
            "https",
            "--web",
            "--insecure-storage",
            "--scopes",
            &scopes.join(","),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("starting `gh auth login`; is gh installed?")?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!(
                "device authorization timed out after {}s",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(500));
    };
    ensure!(status.success(), "`gh auth login` failed: {status}");
    let raw = capture(gh(config).args(["auth", "token"]), None)?;
    let token = Zeroizing::new(
        std::str::from_utf8(&raw)
            .context("gh returned a non-UTF-8 token")?
            .trim()
            .to_owned(),
    );
    ensure!(
        !token.is_empty()
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "gh returned an unexpected token shape"
    );
    Ok(token)
}

/// Login and granted scopes of the token stored in `config`.
fn identity(config: &Path) -> Result<(String, BTreeSet<String>)> {
    let response = capture(gh(config).args(["api", "--include", "user"]), None)?;
    parse_identity(std::str::from_utf8(&response).context("non-UTF-8 API response")?)
}

fn parse_identity(response: &str) -> Result<(String, BTreeSet<String>)> {
    let (head, body) = response
        .split_once("\r\n\r\n")
        .or_else(|| response.split_once("\n\n"))
        .context("API response has no header block")?;
    let scopes = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("x-oauth-scopes").then(|| {
                value
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
        })
        .unwrap_or_default();
    let login = serde_json::from_str::<serde_json::Value>(body.trim())?
        .get("login")
        .and_then(|value| value.as_str())
        .context("API response has no login")?
        .to_owned();
    Ok((login, scopes))
}

/// Required scopes not covered by `granted`. `admin:x` implies `write:x` and
/// `read:x`; `write:x` implies `read:x`.
fn missing_scopes(required: &[String], granted: &BTreeSet<String>) -> Vec<String> {
    required
        .iter()
        .filter(|scope| {
            let covered = |level: &str| {
                scope
                    .split_once(':')
                    .is_some_and(|(_, object)| granted.contains(&format!("{level}:{object}")))
            };
            !(granted.contains(*scope)
                || (scope.starts_with("read:") && (covered("write") || covered("admin")))
                || (scope.starts_with("write:") && covered("admin")))
        })
        .cloned()
        .collect()
}

fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 39
        && !login.starts_with('-')
        && !login.ends_with('-')
        && !login.contains("--")
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_env_name(name: &str) -> bool {
    name.bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(scopes: &[&str]) -> BTreeSet<String> {
        scopes.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_login_and_scopes_from_included_headers() {
        let response = "HTTP/2.0 200 OK\r\nX-Oauth-Scopes: admin:public_key, gist, repo, write:gpg_key\r\nContent-Type: application/json\r\n\r\n{\"login\":\"canikroid\",\"id\":342496694}";
        let (login, scopes) = parse_identity(response).unwrap();
        assert_eq!(login, "canikroid");
        assert_eq!(
            scopes,
            set(&["admin:public_key", "gist", "repo", "write:gpg_key"])
        );
    }

    #[test]
    fn scope_check_honours_admin_and_write_implications() {
        let granted = set(&["repo", "admin:public_key", "write:gpg_key"]);
        let required = [
            "repo",
            "admin:public_key",
            "write:public_key",
            "read:gpg_key",
            "write:gpg_key",
        ]
        .map(str::to_owned);
        assert!(missing_scopes(&required, &granted).is_empty());
        let required = ["admin:gpg_key", "workflow"].map(str::to_owned);
        assert_eq!(
            missing_scopes(&required, &granted),
            ["admin:gpg_key", "workflow"]
        );
    }

    #[test]
    fn gh_config_dir_is_private() {
        let dir = private_config_dir().unwrap();
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn rejects_malformed_logins_and_env_names() {
        assert!(valid_login("canikroid") && valid_login("a-b1"));
        assert!(
            !valid_login("-a") && !valid_login("a--b") && !valid_login("a/b") && !valid_login("")
        );
        assert!(valid_env_name("GH_TOKEN") && !valid_env_name("1X") && !valid_env_name("A-B"));
    }
}
