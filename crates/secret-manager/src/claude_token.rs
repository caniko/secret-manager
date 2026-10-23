//! Store a Claude Code subscription token as an agenix-encrypted source.
//!
//! Claude Code's documented headless route is `claude setup-token`, which
//! runs a browser OAuth flow and prints a one-year token for
//! `CLAUDE_CODE_OAUTH_TOKEN`. It has no machine-readable output, so the
//! operator pastes the printed token into a no-echo prompt. The token is
//! validated, encrypted with the store's agenix master policy and
//! distributed; plaintext never reaches argv, disk or logs.
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use std::{
    io::{BufRead, BufReader, Write},
    os::fd::AsRawFd,
    path::PathBuf,
    process::{Command, Stdio},
};
use zeroize::Zeroizing;

use crate::encryption::{StreamEncryptor, require_missing, with_store_write_lock};
use crate::protection::{self, CredentialProtection};
use crate::rotate::{distribute, distribute_named, stage_source};
use crate::store::{Store, resolve_against};

const PREFIX: &str = "sk-ant-oat01-";

#[derive(Subcommand)]
pub enum ClaudeCmd {
    /// Run `claude setup-token` and encrypt the pasted token into the store.
    Token(TokenArgs),
}

impl ClaudeCmd {
    pub fn run(self) -> Result<()> {
        match self {
            Self::Token(args) => args.run(),
        }
    }
}

#[derive(Args)]
pub struct TokenArgs {
    /// Encrypted source receiving the token, relative to the store root.
    #[arg(long)]
    pub out: PathBuf,
    /// Replace an existing encrypted source instead of refusing.
    #[arg(long)]
    pub rotate: bool,
    /// Secret-store root; defaults to normal SECRET_MANAGER_STORE discovery.
    #[arg(long)]
    pub store: Option<PathBuf>,
    /// lib.mkAgenixStreamEncryptor executable; defaults to SECRET_MANAGER_AGE_ENCRYPTOR.
    #[arg(long)]
    pub encryptor: Option<PathBuf>,
    /// Claude Code executable.
    #[arg(long, default_value = "claude")]
    pub claude: PathBuf,
    /// Skip `agenix rekey`; distribute later with `agenix rekey -a`.
    #[arg(long)]
    pub no_rekey: bool,
    /// Do not stage the source or rekeyed copies.
    #[arg(long)]
    pub no_stage: bool,
    /// Agenix attribute name of the secret; stages only its rekeyed copies,
    /// leaving other uncommitted rekeyed changes untouched.
    #[arg(long)]
    pub secret: Option<String>,
}

impl TokenArgs {
    pub fn run(self) -> Result<()> {
        protection::with_protection(
            protection::enter_scope,
            CredentialProtection::acquire,
            || self.enroll(read_hidden_token),
        )
    }

    fn enroll(&self, read_token: impl FnOnce() -> Result<Zeroizing<String>>) -> Result<()> {
        let store = match &self.store {
            Some(root) => Store { root: root.clone() },
            None => Store::discover()?,
        };
        let out = resolve_against(&store.root, &self.out);
        let rel = out
            .strip_prefix(&store.root)
            .context("--out must be inside the store")?
            .to_path_buf();
        // Fail before asking the operator to authorize anything.
        if !self.rotate {
            require_missing(&out)
                .with_context(|| format!("{} (pass --rotate to replace it)", out.display()))?;
        }
        let encryptor = match &self.encryptor {
            Some(path) => StreamEncryptor::new(path.clone())?,
            None => StreamEncryptor::from_env()?,
        };

        let mut setup = Command::new(&self.claude);
        setup
            .arg("setup-token")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        protection::inherit_active_inhibitors(&mut setup)?;
        let status = setup
            .status()
            .with_context(|| format!("starting `{} setup-token`", self.claude.display()))?;
        ensure!(status.success(), "`claude setup-token` failed: {status}");

        let token = read_token()?;
        ensure!(
            valid_token(&token),
            "that is not a Claude Code OAuth token ({PREFIX}…); nothing was stored"
        );
        with_store_write_lock(&store.root, || {
            if self.rotate && out.exists() {
                encryptor.encrypt_replace(&out, token.as_bytes())
            } else {
                encryptor.encrypt_new(&out, token.as_bytes())
            }
            .with_context(|| format!("encrypting {}", out.display()))
        })?;
        drop(token);

        stage_source(&store.root, &rel, self.no_stage)?;
        if self.no_rekey {
            eprintln!("skipped rekey — run `agenix rekey -a` before deploying.");
        } else if let Some(secret) = &self.secret {
            distribute_named(&store.root, &rel, secret, self.no_stage)?;
        } else {
            distribute(&store.root, &rel, self.no_stage)?;
        }
        eprintln!("Claude Code token stored: {}", out.display());
        Ok(())
    }
}

fn valid_token(token: &str) -> bool {
    token.strip_prefix(PREFIX).is_some_and(|rest| {
        (20..=512).contains(&rest.len())
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// Read one line from the controlling terminal with echo disabled.
fn read_hidden_token() -> Result<Zeroizing<String>> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("a terminal is required to paste the token")?;
    write!(tty, "Paste the token printed above (input is hidden): ")?;
    tty.flush()?;
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
    let mut line = Zeroizing::new(String::new());
    BufReader::new(&tty).read_line(&mut line)?;
    writeln!(tty)?;
    Ok(Zeroizing::new(line.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    const TOKEN: &str = "sk-ant-oat01-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-";
    const CIPHERTEXT: &[u8] =
        b"age-encryption.org/v1\nciphertext-padded-above-minimum-supported-age-file-size";

    fn script(path: &Path, body: &str) -> PathBuf {
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        path.to_path_buf()
    }

    fn args(root: &Path) -> TokenArgs {
        TokenArgs {
            out: "age/secrets/claude.age".into(),
            rotate: false,
            store: Some(root.to_path_buf()),
            encryptor: Some(script(
                &root.join("encryptor"),
                "cat >/dev/null; printf 'age-encryption.org/v1\\nciphertext-padded-above-minimum-supported-age-file-size'",
            )),
            claude: script(
                &root.join("claude"),
                &format!("touch '{}'", root.join("ran").display()),
            ),
            no_rekey: true,
            no_stage: true,
            secret: None,
        }
    }

    fn contains_token(dir: &Path) -> bool {
        fs::read_dir(dir).unwrap().flatten().any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                contains_token(&path)
            } else {
                fs::read(&path)
                    .unwrap()
                    .windows(TOKEN.len())
                    .any(|w| w == TOKEN.as_bytes())
            }
        })
    }

    #[test]
    fn stores_only_ciphertext_for_a_valid_token() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("age/secrets")).unwrap();
        args(root.path())
            .enroll(|| Ok(Zeroizing::new(TOKEN.to_owned())))
            .unwrap();
        assert!(root.path().join("ran").exists());
        assert_eq!(
            fs::read(root.path().join("age/secrets/claude.age")).unwrap(),
            CIPHERTEXT
        );
        assert!(!contains_token(root.path()));
    }

    #[test]
    fn rejects_malformed_tokens_without_writing() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("age/secrets")).unwrap();
        for bad in [
            "",
            "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv",
            "sk-ant-oat01-short",
            "sk-ant-oat01-has space in it here",
        ] {
            let error = args(root.path())
                .enroll(|| Ok(Zeroizing::new(bad.to_owned())))
                .unwrap_err();
            assert!(!format!("{error:#}").contains("AbCdEf"));
            assert!(!root.path().join("age/secrets/claude.age").exists());
        }
    }

    /// Runs only inside `named_distribution_stages_only_its_copies`, whose
    /// fake `agenix` on PATH must not leak into other tests.
    #[test]
    fn named_distribution_fixture() {
        let Some(root) = std::env::var_os("SECRET_MANAGER_DISTRIBUTE_FIXTURE") else {
            return;
        };
        distribute_named(
            Path::new(&root),
            Path::new("age/secrets/claude.age"),
            "claude-oauth",
            false,
        )
        .unwrap();
    }

    #[test]
    fn named_distribution_stages_only_its_copies() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let git = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&repo)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        fs::create_dir_all(repo.join("age/rekeyed/atlas")).unwrap();
        git(&["init", "-q"]);
        // Another operation's uncommitted rekeyed change.
        fs::write(repo.join("age/rekeyed/atlas/aaa-other.age"), b"foreign").unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        script(
            &bin.join("agenix"),
            // `ddd-other-claude-oauth` belongs to the `other-claude-oauth` attribute.
            "printf rekeyed >age/rekeyed/atlas/bbb-claude-oauth.age; printf again >age/rekeyed/atlas/aaa-other.age; printf sibling >age/rekeyed/atlas/ddd-other-claude-oauth.age",
        );
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "claude_token::tests::named_distribution_fixture",
                "--quiet",
            ])
            .env("PATH", path)
            .env("SECRET_MANAGER_DISTRIBUTE_FIXTURE", &repo)
            .status()
            .unwrap();
        assert!(status.success());
        let staged = Command::new("git")
            .args(["diff", "--cached", "--name-only"])
            .current_dir(&repo)
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8(staged.stdout).unwrap(),
            "age/rekeyed/atlas/bbb-claude-oauth.age\n"
        );
    }

    #[test]
    fn named_distribution_rejects_an_undeclared_secret() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        fs::create_dir_all(repo.join("age/rekeyed")).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "-q"])
                .current_dir(&repo)
                .status()
                .unwrap()
                .success()
        );
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        script(&bin.join("agenix"), "true");
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "claude_token::tests::named_distribution_fixture",
                "--nocapture",
            ])
            .env("PATH", path)
            .env("SECRET_MANAGER_DISTRIBUTE_FIXTURE", &repo)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("declare the secret"));
    }

    #[test]
    fn refuses_existing_source_before_running_claude() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("age/secrets")).unwrap();
        fs::write(
            root.path().join("age/secrets/claude.age"),
            b"age-encryption.org/v1\nold-ciphertext-padded-above-minimum-supported-age-file-size",
        )
        .unwrap();
        assert!(args(root.path()).enroll(|| unreachable!()).is_err());
        assert!(!root.path().join("ran").exists());
        let mut rotate = args(root.path());
        rotate.rotate = true;
        rotate
            .enroll(|| Ok(Zeroizing::new(TOKEN.to_owned())))
            .unwrap();
        assert_eq!(
            fs::read(root.path().join("age/secrets/claude.age")).unwrap(),
            CIPHERTEXT
        );
    }
}
