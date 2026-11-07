//! Store a Claude Code subscription token as an agenix-encrypted source.
//!
//! Claude Code's documented headless route is `claude setup-token`, which
//! runs a browser OAuth flow and prints a one-year token for
//! `CLAUDE_CODE_OAUTH_TOKEN`. Its output is captured privately and parsed
//! conservatively, without printing or asking the operator to paste the token.
//! The token is validated, encrypted with the store's agenix master policy and
//! distributed; plaintext never reaches argv, disk or logs.
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use zeroize::Zeroizing;

use crate::encryption::{StreamEncryptor, require_missing, with_store_write_lock};
use crate::protection::{self, CredentialProtection};
use crate::rotate::{distribute, distribute_named, stage_source};
use crate::store::{Store, resolve_against};

const PREFIX: &str = "sk-ant-oat01-";

#[derive(Subcommand)]
pub enum ClaudeCmd {
    /// Authorize in the browser, then privately capture, encrypt and rekey the token.
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
            || self.enroll(|| mint_token(&self.claude)),
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

fn mint_token(claude: &Path) -> Result<Zeroizing<String>> {
    eprintln!(
        "Approve Claude authorization in your browser (15 minute deadline). Token output stays private."
    );
    let captured = crate::credential_process::capture_channels_with_timeout(
        Command::new(claude).arg("setup-token").env("NO_COLOR", "1"),
        Duration::from_secs(15 * 60),
    )
    .context("native Claude authorization failed; nothing was stored")?;
    token_from_output(&captured.stdout, &captured.stderr)
}

fn token_from_output(stdout: &[u8], stderr: &[u8]) -> Result<Zeroizing<String>> {
    let mut selected: Option<Zeroizing<String>> = None;
    for channel in [stdout, stderr] {
        // Native UI framing is not credential data. Preserve editing controls as
        // invalid-token markers instead of rejecting unrelated terminal output.
        // CR redraws can expand to two bytes; reserve once to avoid reallocations.
        let mut plain = Zeroizing::new(Vec::with_capacity(channel.len() * 2));
        let mut bytes = channel.iter().copied().enumerate();
        while let Some((start, byte)) = bytes.next() {
            if byte == 0x1b {
                let (_, kind) = bytes.next().context("incomplete native Claude escape")?;
                let decoration = match kind {
                    b'[' => {
                        let (end, kind) = bytes
                            .by_ref()
                            .find(|(_, b)| (0x40..=0x7e).contains(b))
                            .context(
                            "incomplete native Claude terminal control; nothing was stored",
                        )?;
                        let parameters = &channel[start + 2..end];
                        ensure!(
                            parameters.iter().all(|b| (0x20..=0x3f).contains(b)),
                            "malformed native Claude terminal control; nothing was stored"
                        );
                        let numbers = |bytes: &[u8]| {
                            bytes
                                .iter()
                                .all(|b| b.is_ascii_digit() || matches!(b, b';' | b':'))
                        };
                        (kind == b'm' && numbers(parameters))
                            || (matches!(kind, b'h' | b'l')
                                && parameters.strip_prefix(b"?").is_some_and(numbers))
                    }
                    b']' | b'P' | b'X' | b'^' | b'_' => {
                        let mut escape = false;
                        let terminated = bytes.by_ref().any(|(_, b)| {
                            let end = b == 7 || b == 0x9c || (escape && b == b'\\');
                            escape = b == 0x1b;
                            end
                        });
                        ensure!(
                            terminated,
                            "incomplete native Claude terminal string; nothing was stored"
                        );
                        false
                    }
                    mut kind => {
                        while (0x20..=0x2f).contains(&kind) {
                            kind = bytes.next().context("incomplete native Claude escape")?.1;
                        }
                        ensure!(
                            (0x30..=0x7e).contains(&kind),
                            "malformed native Claude escape; nothing was stored"
                        );
                        false
                    }
                };
                if !decoration {
                    plain.push(0);
                }
            } else if byte == b'\r' {
                if bytes.clone().next().is_some_and(|(_, b)| b == b'\n') {
                    bytes.next();
                } else {
                    plain.push(0);
                }
                plain.push(b'\n');
            } else {
                plain.push(byte);
            }
        }
        let text = std::str::from_utf8(&plain).context("invalid native Claude output encoding")?;
        let mut token = Zeroizing::new(String::with_capacity(PREFIX.len() + 512));
        for line in text.lines().map(str::trim).chain(std::iter::once("")) {
            // A redraw before the first token character cannot edit that token.
            let line = if token.is_empty() {
                line.trim_start_matches(|c: char| c == '\0' || c.is_whitespace())
            } else {
                line
            };
            if line.is_empty() && !token.is_empty() {
                ensure!(
                    valid_token(&token),
                    "unrecognized native Claude token output; nothing was stored"
                );
                ensure!(
                    selected
                        .as_ref()
                        .is_none_or(|previous| **previous == *token),
                    "ambiguous native Claude tokens; nothing was stored"
                );
                selected = Some(Zeroizing::new(token.to_string()));
                zeroize::Zeroize::zeroize(&mut *token);
            } else if !token.is_empty() || line.contains(PREFIX) {
                ensure!(
                    token.len() + line.len() <= PREFIX.len() + 512,
                    "native Claude token exceeds size limit; nothing was stored"
                );
                token.push_str(line);
            }
        }
    }
    selected.context("native Claude did not emit a recognized token; nothing was stored")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::Path};

    const TOKEN: &str = "sk-ant-oat01-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-";
    const CIPHERTEXT: &[u8] =
        b"age-encryption.org/v1\nciphertext-padded-above-minimum-supported-age-file-size";

    #[test]
    fn terminal_framing_outside_token_data_does_not_reject_authorization() {
        let output = format!(
            "\x1b[?2026h\x1b[2J\x1b[HWaiting for browser\r\x1b[2K\x1b[1G\x1b[>1u\x1b[>4;2mYour OAuth token\n\n\x1b[38:2:255:128:0m{TOKEN}\x1b[0m\n\n\x1b[<u\x1b[?2026l"
        );
        assert_eq!(&*token_from_output(output.as_bytes(), b"").unwrap(), TOKEN);
        assert_eq!(&*token_from_output(b"", output.as_bytes()).unwrap(), TOKEN);
        for framing in [
            "\x1b[2K\x1b[1G",
            "\x1b[?1049h\x1b[?1049l",
            "\x1b]8;;https://example.invalid\x07link\x1b]8;;\x07",
            "\x1b]0;public window title\x1b\\",
        ] {
            assert_eq!(
                &*token_from_output(TOKEN.as_bytes(), framing.as_bytes()).unwrap(),
                TOKEN
            );
            assert_eq!(
                &*token_from_output(format!("{framing}\n\n{TOKEN}\n\n").as_bytes(), b"").unwrap(),
                TOKEN
            );
        }
        assert_eq!(
            &*token_from_output(format!("\x1b[2K\x1b[1G{TOKEN}").as_bytes(), b"").unwrap(),
            TOKEN
        );
        for control in ["\x1b[2K", "\x1b[1A", "\x1b]0;title\x07"] {
            assert!(
                token_from_output(
                    format!("{}{control}{}", &TOKEN[..30], &TOKEN[30..]).as_bytes(),
                    b""
                )
                .is_err()
            );
        }
    }

    #[test]
    fn native_ink_modes_do_not_turn_private_token_capture_into_a_styling_error() {
        // Claude's bundled renderer uses these non-text controls independently
        // of color: cursor visibility and synchronized updates.
        for control in ["?25h", "?25l", "?2026h", "?2026l"] {
            let output = format!("\x1b[{control}Your OAuth token\n\n{TOKEN}\n\n\x1b[{control}");
            assert_eq!(&*token_from_output(output.as_bytes(), b"").unwrap(), TOKEN);
            assert_eq!(&*token_from_output(b"", output.as_bytes()).unwrap(), TOKEN);
        }
        let output = format!("\x1b[?2026h\x1b[?25l{TOKEN}\x1b[?25h\x1b[?2026l");
        assert_eq!(&*token_from_output(output.as_bytes(), b"").unwrap(), TOKEN);
    }

    #[test]
    fn extracts_one_native_token_across_terminal_wrapping_and_channels() {
        for output in [
            format!("Success\n\n{TOKEN}\n\nStore it securely.\n"),
            format!(
                "\x1b[32m{}\n  {}\x1b[0m\n\nUse this token.\n",
                &TOKEN[..30],
                &TOKEN[30..]
            ),
            format!("{TOKEN}\n\n{TOKEN}\n"),
            format!(
                "Your OAuth token (valid for 1 year)\r\n \r\n  {}\r\n  {}  \r\n \r\nStore this token securely.\r\n",
                &TOKEN[..30],
                &TOKEN[30..]
            ),
        ] {
            assert_eq!(&*token_from_output(output.as_bytes(), b"").unwrap(), TOKEN);
            assert_eq!(&*token_from_output(b"", output.as_bytes()).unwrap(), TOKEN);
        }
        assert_eq!(
            &*token_from_output(TOKEN.as_bytes(), TOKEN.as_bytes()).unwrap(),
            TOKEN
        );
        for output in [
            "no token".to_owned(),
            "sk-ant-oat01-short".to_owned(),
            format!("{TOKEN}\n\n{TOKEN}other\n"),
            format!("{TOKEN} {}", "unsafe"),
            format!("{TOKEN}\rhidden"),
            format!("{TOKEN}\x1b[2K"),
            format!("{TOKEN}\x1b[1A"),
            format!("{TOKEN}\x1b[?25m"),
            format!("{TOKEN}\x1b[??2027h"),
            format!("{TOKEN}\x1b[?25"),
            format!("{TOKEN}\nextra prose"),
            format!("{PREFIX}{}", "a".repeat(513)),
        ] {
            let error = token_from_output(output.as_bytes(), b"").unwrap_err();
            assert!(!format!("{error:#}").contains("AbCdEf"));
        }
        assert!(token_from_output(TOKEN.as_bytes(), format!("{TOKEN}other").as_bytes()).is_err());
        assert!(token_from_output(b"\xff", b"").is_err());
    }

    #[test]
    fn browser_only_capture_needs_no_terminal_and_native_failure_stores_nothing() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("age/secrets")).unwrap();
        let mut settings = args(root.path());
        settings.claude = script(
            &root.path().join("claude"),
            &format!(
                "[ \"$1\" = setup-token ] || exit 9\nif read -r unexpected; then exit 8; fi\nprintf '\\033[?2026h\\033[2J\\033[HWaiting\\r\\033[2KYour OAuth token\\n\\n\\033[38:2:255:128:0m%s%s\\033[0m\\n\\n' '{PREFIX}' '{}'\nprintf '\\033[<u\\033]0;done\\007\\033[?2026l' >&2",
                &TOKEN[PREFIX.len()..],
            ),
        );
        assert_eq!(&*mint_token(&settings.claude).unwrap(), TOKEN);
        settings.enroll(|| mint_token(&settings.claude)).unwrap();
        assert_eq!(
            fs::read(root.path().join("age/secrets/claude.age")).unwrap(),
            CIPHERTEXT
        );
        assert!(!contains_token(root.path()));
        fs::remove_file(root.path().join("age/secrets/claude.age")).unwrap();
        settings.claude = script(
            &root.path().join("claude"),
            &format!(
                "printf '%s%s\\n' '{PREFIX}' '{}' >&2\nexit 23",
                &TOKEN[PREFIX.len()..],
            ),
        );
        let error = settings
            .enroll(|| mint_token(&settings.claude))
            .unwrap_err();
        assert!(!format!("{error:#}").contains("AbCdEf"));
        assert!(!root.path().join("age/secrets/claude.age").exists());
    }

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
                &format!(
                    "touch '{}'\nprintf '%s%s\\n' '{PREFIX}' '{}'",
                    root.join("ran").display(),
                    &TOKEN[PREFIX.len()..]
                ),
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
        let settings = args(root.path());
        settings.enroll(|| mint_token(&settings.claude)).unwrap();
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
