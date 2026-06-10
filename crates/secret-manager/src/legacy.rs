use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use rand::{RngCore, rngs::OsRng};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use crate::io::TempDir;
use nix_manager_core::exec;

#[derive(Args)]
pub struct RauthyEnvArgs {
    /// Path to the agenix-tracked .age file
    #[arg(default_value = "age/secrets/hosts/thething/rauthy-env.age")]
    pub secret_path: String,

    /// Encryption key id (becomes ENC_KEY_ACTIVE; must match
    /// `[a-zA-Z0-9:_-]{2,20}`)
    #[arg(long, default_value = "k1")]
    pub key_id: String,

    /// Write the secret but skip the trailing `agenix rekey -a`
    #[arg(long)]
    pub no_rekey: bool,

    /// Replace the secret if it already exists.
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct GerritCookiesArgs {
    /// Path to a file containing the Gerrit snippet or raw cookie lines
    pub input_file: String,
    /// Path to the agenix-tracked .age file to write
    pub secret_path: String,
}

pub fn list() -> Result<()> {
    let mut entries: Vec<String> = walkdir::WalkDir::new(".")
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            name != ".git" && name != "target" && name != "result" && !name.starts_with(".direnv")
        })
        .filter_map(|r| r.ok())
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .map(|ext| ext == "age")
                    .unwrap_or(false)
        })
        .map(|e| {
            e.path()
                .strip_prefix(".")
                .unwrap_or(e.path())
                .display()
                .to_string()
        })
        .collect();
    entries.sort();
    if entries.is_empty() {
        println!("(no .age files found)");
    } else {
        for path in entries {
            println!("{path}");
        }
    }
    Ok(())
}

pub fn wg_keygen(secret_path: &str) -> Result<()> {
    let tmp = TempDir::new()?;
    let priv_path = tmp.path.join("privkey");

    let priv_file = fs::File::create(&priv_path)?;
    fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600))?;
    let status = Command::new("wg")
        .arg("genkey")
        .stdout(Stdio::from(priv_file))
        .status()?;
    if !status.success() {
        return Err(anyhow!("wg genkey failed: {status}"));
    }

    let priv_input = fs::File::open(&priv_path)?;
    let pubkey = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::from(priv_input))
        .output()?;
    if !pubkey.status.success() {
        return Err(anyhow!("wg pubkey failed: {}", pubkey.status));
    }
    print!("{}", String::from_utf8(pubkey.stdout)?);

    exec::run(
        "agenix",
        ["edit", "-i", priv_path.to_str().unwrap(), secret_path],
    )
}

pub fn gerrit_cookies(args: &GerritCookiesArgs) -> Result<()> {
    let raw = fs::read_to_string(&args.input_file)
        .map_err(|e| anyhow!("could not read {}: {e}", args.input_file))?;

    let body = extract_heredoc_body(&raw).unwrap_or(&raw);

    let mut cookie_lines: Vec<String> = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if !is_cookie_line(trimmed) {
            continue;
        }
        cookie_lines.push(trimmed.replace(',', "\t"));
    }

    if cookie_lines.is_empty() {
        return Err(anyhow!(
            "no cookie lines found on stdin (expected 7 comma- or tab-separated fields per line)"
        ));
    }

    let mut payload = cookie_lines.join("\n");
    payload.push('\n');

    let tmp = TempDir::new()?;
    let cookie_path = tmp.path.join("gitcookies");
    fs::write(&cookie_path, payload.as_bytes())?;
    fs::set_permissions(&cookie_path, fs::Permissions::from_mode(0o600))?;

    exec::run(
        "agenix",
        [
            "edit",
            "-i",
            cookie_path.to_str().unwrap(),
            &args.secret_path,
        ],
    )?;

    eprintln!();
    eprintln!(
        "wrote {} ({} cookie line{})",
        args.secret_path,
        cookie_lines.len(),
        if cookie_lines.len() == 1 { "" } else { "s" }
    );
    Ok(())
}

fn extract_heredoc_body(input: &str) -> Option<&str> {
    let marker_start = input.find("<<")?;
    let after_lt = &input[marker_start + 2..];
    let nl = after_lt.find('\n')?;
    let raw_marker = after_lt[..nl].trim().trim_start_matches('\\');
    if raw_marker.is_empty() {
        return None;
    }
    let body_start = marker_start + 2 + nl + 1;
    let rest = &input[body_start..];
    let end_idx = rest.find(&format!("\n{raw_marker}"))?;
    Some(&rest[..end_idx])
}

fn is_cookie_line(line: &str) -> bool {
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    let comma_fields = line.split(',').count();
    let tab_fields = line.split('\t').count();
    let fields = comma_fields.max(tab_fields);
    if fields != 7 {
        return false;
    }
    let first = line.split([',', '\t']).next().unwrap_or("");
    !first.is_empty()
        && first
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

pub fn rauthy_env(args: &RauthyEnvArgs) -> Result<()> {
    let secret_path = &args.secret_path;
    let key_id = &args.key_id;
    let secret_exists = std::path::Path::new(secret_path).exists();
    if secret_exists && !args.force {
        return Err(anyhow!(
            "secret already exists at {secret_path}\n  \
             pass --force to replace it (rotates ENC_KEYS + bootstrap admin password)"
        ));
    }

    eprintln!("Generating Rauthy encryption key (key id: {key_id})...");
    let enc_out = exec::capture(
        "nix",
        [
            "shell",
            "nixpkgs#rauthy",
            "--command",
            "rauthy",
            "generate-enc-key",
            "--with-key-id",
            key_id,
        ],
    )?;
    let enc_key = parse_enc_key(&enc_out, key_id)
        .ok_or_else(|| anyhow!("could not parse encryption key from rauthy output:\n{enc_out}"))?;

    eprintln!("Generating Rauthy cluster secrets...");
    let cluster_out = exec::capture(
        "nix",
        [
            "shell",
            "nixpkgs#rauthy",
            "--command",
            "rauthy",
            "generate-secrets",
        ],
    )?;
    let secret_raft = parse_toml_string(&cluster_out, "secret_raft")
        .ok_or_else(|| anyhow!("could not parse secret_raft from rauthy output:\n{cluster_out}"))?;
    let secret_api = parse_toml_string(&cluster_out, "secret_api")
        .ok_or_else(|| anyhow!("could not parse secret_api from rauthy output:\n{cluster_out}"))?;

    eprintln!();
    eprintln!("Set the bootstrap admin password.");
    eprintln!("  rauthy reads it from your terminal and enforces its policy");
    eprintln!("  (>=14 chars, upper + lower + digit). Its own prompts are");
    eprintln!("  suppressed, so: type the password, press Enter, then type it");
    eprintln!("  AGAIN and press Enter. Nothing echoes. A password-manager");
    eprintln!("  random value is recommended.");
    eprintln!();

    let tmp = TempDir::new()?;
    let hash_path = tmp.path.join("hash.out");
    let hash_file = fs::File::create(&hash_path)?;
    fs::set_permissions(&hash_path, fs::Permissions::from_mode(0o600))?;

    let status = Command::new("nix")
        .args([
            "shell",
            "nixpkgs#rauthy",
            "--command",
            "rauthy",
            "hash-password",
        ])
        .stdin(Stdio::inherit())
        .stderr(Stdio::inherit())
        .stdout(Stdio::from(hash_file))
        .status()
        .map_err(|e| anyhow!("failed to spawn rauthy hash-password: {e}"))?;
    if !status.success() {
        return Err(anyhow!("rauthy hash-password failed: {status}"));
    }

    let hash_out = fs::read_to_string(&hash_path)?;
    let hash = parse_argon2_hash(&hash_out).ok_or_else(|| {
        anyhow!(
            "no argon2id hash in rauthy output (password policy rejection?):\n{}",
            hash_out.trim()
        )
    })?;

    let bootstrap_api_key_secret = generate_base64(96);

    let env_body = format!(
        "ENC_KEYS={enc_key}\n\
         ENC_KEY_ACTIVE={key_id}\n\
         HQL_SECRET_RAFT={secret_raft}\n\
         HQL_SECRET_API={secret_api}\n\
         BOOTSTRAP_ADMIN_PASSWORD_ARGON2ID={hash}\n\
         BOOTSTRAP_API_KEY_SECRET={bootstrap_api_key_secret}\n"
    );
    let env_path = tmp.path.join("rauthy-env");
    fs::write(&env_path, env_body.as_bytes())?;
    fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600))?;

    if secret_exists {
        fs::remove_file(secret_path)
            .map_err(|e| anyhow!("could not remove existing {secret_path}: {e}"))?;
    }
    exec::run(
        "agenix",
        ["edit", "-i", env_path.to_str().unwrap(), secret_path],
    )?;

    exec::run("git", ["add", secret_path])?;

    if args.no_rekey {
        eprintln!();
        eprintln!(
            "wrote and staged {secret_path} (ENC_KEYS, ENC_KEY_ACTIVE, HQL_SECRET_RAFT, HQL_SECRET_API, BOOTSTRAP_ADMIN_PASSWORD_ARGON2ID, BOOTSTRAP_API_KEY_SECRET)"
        );
        eprintln!("skipped rekey (--no-rekey); run `agenix rekey -a` before deploying.");
    } else {
        eprintln!();
        eprintln!("Rekeying to host keys (touch your FIDO2 token when prompted)...");
        exec::run("agenix", ["rekey", "-a"])?;
        eprintln!();
        eprintln!("wrote and rekeyed {secret_path}");
    }
    Ok(())
}

fn parse_enc_key(output: &str, key_id: &str) -> Option<String> {
    let needle = format!("'{key_id}/");
    for line in output.lines() {
        if let Some(start) = line.find(&needle) {
            let after = &line[start + 1..];
            if let Some(end) = after.find('\'') {
                return Some(after[..end].to_string());
            }
        }
    }
    None
}

fn parse_toml_string(output: &str, key: &str) -> Option<String> {
    let needle = format!("{key} = '");
    for line in output.lines() {
        let line = line.trim();
        if let Some(after) = line.strip_prefix(&needle)
            && let Some(end) = after.find('\'')
        {
            return Some(after[..end].to_string());
        }
    }
    None
}

fn parse_argon2_hash(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("$argon2id$"))
        .map(str::to_string)
}

fn generate_base64(length: usize) -> String {
    let mut bytes = vec![0u8; length.div_ceil(4) * 3];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes).chars().take(length).collect()
}
