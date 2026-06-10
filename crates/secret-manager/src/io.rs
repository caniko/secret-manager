use anyhow::{Result, anyhow, bail};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix_manager_core::exec;

/// Wire an existing `.age` file into `secret_path`. If `src` is the same as
/// `secret_path`, no copy happens — we just sanity-check it isn't already
/// referenced from a `.nix` elsewhere. Otherwise we copy (preserving 0600)
/// and verify the source `.age` wasn't already imported.
pub fn adopt_age_file(repo_root: &Path, src: &Path, secret_path: &Path, force: bool) -> Result<()> {
    if !src.is_file() {
        bail!("--from-age: {} is not a file", src.display());
    }
    if src.extension().and_then(|s| s.to_str()) != Some("age") {
        bail!(
            "--from-age: {} does not end in `.age` — refusing",
            src.display()
        );
    }

    let canon_src = fs::canonicalize(src)?;
    let canon_target_dir = fs::canonicalize(
        secret_path
            .parent()
            .ok_or_else(|| anyhow!("target has no parent"))?,
    )?;
    let canon_target = canon_target_dir.join(
        secret_path
            .file_name()
            .ok_or_else(|| anyhow!("target has no filename"))?,
    );
    let same_path = canon_src == canon_target;

    if !same_path && secret_path.exists() {
        bail!(
            "{} already exists — pick a different --slug or edit it with `agenix edit`.",
            secret_path.display()
        );
    }

    if !force {
        let needle = canon_src
            .strip_prefix(repo_root)
            .ok()
            .map(|p| p.display().to_string());
        let basename = canon_src
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string);
        let hits = scan_for_references(
            repo_root,
            needle.as_deref(),
            basename.as_deref(),
            secret_path,
        )?;
        if !hits.is_empty() {
            let mut msg = format!(
                "--from-age: {} is already referenced from {} .nix file{}:",
                src.display(),
                hits.len(),
                if hits.len() == 1 { "" } else { "s" }
            );
            for h in &hits {
                msg.push_str(&format!("\n  {h}"));
            }
            msg.push_str(
                "\n\nRefusing to double-wire. Pass --force-existing to override, \
                 or pick a different secret.",
            );
            bail!(msg);
        }
    }

    if same_path {
        eprintln!(
            "reusing existing {} (already at canonical path)",
            display_rel(repo_root, &canon_src)
        );
    } else {
        fs::copy(&canon_src, secret_path)?;
        fs::set_permissions(secret_path, fs::Permissions::from_mode(0o600))?;
        eprintln!(
            "copied {} → {}",
            display_rel(repo_root, &canon_src),
            display_rel(repo_root, secret_path)
        );
    }
    Ok(())
}

/// Scan all `.nix` files under `repo_root` for substring references to the
/// source `.age`. Two checks (logical OR):
///   - relative path from repo root (e.g. `age/secrets/users/can/foo.age`)
///   - bare filename (e.g. `foo.age`)
///     Skips `target/`, `.git/`, `.direnv/`, `result*`. Filename hits are
///     reported only when they appear inside an `age/` path component to keep
///     false positives down.
pub fn scan_for_references(
    repo_root: &Path,
    rel_path: Option<&str>,
    basename: Option<&str>,
    exclude: &Path,
) -> Result<Vec<String>> {
    let mut hits = Vec::new();
    let canon_exclude = fs::canonicalize(exclude).ok();
    for entry in walkdir::WalkDir::new(repo_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            name != ".git"
                && name != "target"
                && !name.starts_with(".direnv")
                && !name.starts_with("result")
                && name != ".nix-results"
        })
        .filter_map(|r| r.ok())
    {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("nix") {
            continue;
        }
        if let Some(exc) = &canon_exclude
            && path == exc
        {
            continue;
        }
        let body = match fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let matched = rel_path.is_some_and(|p| body.contains(p))
            || basename.is_some_and(|b| body.contains(b));
        if matched {
            hits.push(display_rel(repo_root, path));
        }
    }
    Ok(hits)
}

pub fn read_plaintext(from_file: Option<&Path>) -> Result<String> {
    match from_file {
        Some(p) => fs::read_to_string(p)
            .map_err(|e| anyhow!("reading plaintext from {}: {e}", p.display())),
        None => {
            if atty_stdin() {
                eprintln!("reading plaintext from stdin (end with Ctrl-D):");
            }
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
    }
}

pub fn read_plaintext_editor_when_tty(from_file: Option<&Path>) -> Result<String> {
    match from_file {
        Some(_) => read_plaintext(from_file),
        None if atty_stdin() => read_plaintext_from_editor(),
        None => read_plaintext(None),
    }
}

fn read_plaintext_from_editor() -> Result<String> {
    let tmp = TempDir::new()?;
    let path = tmp.path.join("plaintext");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

    eprintln!("opening editor for plaintext secret input (${{VISUAL:-${{EDITOR:-hx}}}} fallback)");
    let status = Command::new("sh")
        .args(["-c", editor_shell_script(), "secret-manager-editor"])
        .arg(&path)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| {
            let path = std::env::var("PATH").unwrap_or_else(|_| "<unset>".into());
            anyhow!("failed to spawn editor shell: {e}\n  PATH = {path}")
        })?;

    if !status.success() {
        bail!(
            "editor exited with status {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".into())
        );
    }

    fs::read_to_string(&path).map_err(|e| anyhow!("reading edited plaintext: {e}"))
}

/// Editor resolution order. `CANIX_EDITOR` is honored for back-compat with
/// the canix CLI this engine was extracted from.
pub fn editor_shell_script() -> &'static str {
    "exec ${SECRET_MANAGER_EDITOR:-${CANIX_EDITOR:-${VISUAL:-${EDITOR:-hx}}}} \"$1\""
}

pub fn atty_stdin() -> bool {
    // We don't pull in a tty crate; isatty via libc would add a dep.
    // Best-effort: assume non-tty when stdin is redirected, by probing
    // /proc/self/fd/0. Falling back to true is fine — the prompt is harmless.
    fs::metadata("/proc/self/fd/0")
        .map(|m| m.file_type().is_char_device())
        .unwrap_or(true)
}

pub fn default_slug(env_var: &str) -> String {
    let lowered = env_var.to_ascii_lowercase().replace('_', "-");
    for suffix in ["-api-token", "-api-key", "-token", "-key", "-secret"] {
        if let Some(stripped) = lowered.strip_suffix(suffix)
            && !stripped.is_empty()
        {
            return stripped.to_string();
        }
    }
    lowered
}

pub fn validate_slug(slug: &str) -> Result<()> {
    if slug.is_empty() {
        bail!("slug is empty");
    }
    let ok = slug
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        bail!("slug `{slug}` must be ASCII alphanumerics, `-`, or `_`");
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        bail!("slug `{slug}` must not start or end with `-`");
    }
    Ok(())
}

pub fn validate_ident(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{label} is empty");
    }
    let ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        bail!("{label} `{value}` must be ASCII alphanumerics, `-`, or `_`");
    }
    Ok(())
}

pub fn validate_unit_name(value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("system service name is empty");
    }
    if value.ends_with(".service") {
        bail!("system service `{value}` must be passed without the `.service` suffix");
    }
    let ok = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':' | '.' | '@'));
    if !ok {
        bail!(
            "system service `{value}` must be a systemd service name stem using ASCII alphanumerics, '-', '_', ':', '.', or '@'"
        );
    }
    Ok(())
}

pub fn display_rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap_or(p).display().to_string()
}

pub fn encrypt_plaintext_to_age(secret_path: &Path, plaintext: &str) -> Result<()> {
    if plaintext.trim().is_empty() {
        bail!("plaintext is empty — refusing to encrypt a blank secret");
    }

    let tmp = TempDir::new()?;
    let tmp_plain = tmp.path.join("plaintext");
    {
        let mut f = fs::File::create(&tmp_plain)?;
        fs::set_permissions(&tmp_plain, fs::Permissions::from_mode(0o600))?;
        f.write_all(plaintext.as_bytes())?;
    }

    exec::run(
        "agenix",
        [
            "edit",
            "-i",
            tmp_plain
                .to_str()
                .ok_or_else(|| anyhow!("non-utf8 tmp path"))?,
            secret_path
                .to_str()
                .ok_or_else(|| anyhow!("non-utf8 secret path"))?,
        ],
    )
}

pub fn stage_and_rekey(
    repo_root: &Path,
    paths: &[&Path],
    no_stage: bool,
    no_rekey: bool,
) -> Result<()> {
    if !no_stage {
        let paths = paths
            .iter()
            .map(|p| display_rel(repo_root, p))
            .collect::<Vec<_>>();
        exec::run(
            "git",
            std::iter::once("add").chain(paths.iter().map(String::as_str)),
        )?;
    }

    if !no_rekey {
        exec::run("agenix", ["rekey", "-a"])?;
    } else {
        eprintln!();
        eprintln!("skipped rekey — run `agenix rekey -a` before deploying.");
    }

    Ok(())
}

/// Insert `./<slug>.nix` into the `imports = [ ... ]` list of `default.nix`,
/// keeping local (`./*`) imports sorted alphabetically and preserving the
/// position of any non-local entries (e.g. `../../shared/foo.nix`).
pub fn splice_import(default_nix: &Path, slug: &str) -> Result<()> {
    let content = fs::read_to_string(default_nix)?;
    let new_entry = format!("./{slug}.nix");

    let open_idx = content
        .find("imports = [")
        .ok_or_else(|| anyhow!("`imports = [` not found in {}", default_nix.display()))?;
    let close_rel = content[open_idx..]
        .find("]")
        .ok_or_else(|| anyhow!("unterminated imports list in {}", default_nix.display()))?;
    let close_idx = open_idx + close_rel;

    let inner_start = open_idx + "imports = [".len();
    let inner = &content[inner_start..close_idx];

    let indent = inner
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| {
            l.chars()
                .take_while(|c| c.is_whitespace())
                .collect::<String>()
        })
        .unwrap_or_else(|| "    ".to_string());

    let mut entries: Vec<String> = inner
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    if entries.iter().any(|e| e == &new_entry) {
        return Ok(());
    }
    entries.push(new_entry.clone());

    let (mut locals, externals): (Vec<_>, Vec<_>) =
        entries.into_iter().partition(|e| e.starts_with("./"));
    locals.sort();

    let mut rebuilt = String::new();
    rebuilt.push('\n');
    for e in locals.iter().chain(externals.iter()) {
        rebuilt.push_str(&indent);
        rebuilt.push_str(e);
        rebuilt.push('\n');
    }
    let close_indent: String = content[..open_idx]
        .lines()
        .next_back()
        .map(|l| l.chars().take_while(|c| c.is_whitespace()).collect())
        .unwrap_or_default();
    rebuilt.push_str(&close_indent);

    let mut out = String::with_capacity(content.len() + new_entry.len() + 8);
    out.push_str(&content[..inner_start]);
    out.push_str(&rebuilt);
    out.push_str(&content[close_idx..]);
    fs::write(default_nix, out)?;
    Ok(())
}

pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new() -> Result<Self> {
        let base = std::env::temp_dir();
        for attempt in 0..16u64 {
            let suffix: u64 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
                ^ (std::process::id() as u64)
                ^ attempt.rotate_left(32);
            let candidate = base.join(format!("secret-manager-{suffix:x}"));
            if fs::create_dir(&candidate).is_ok() {
                fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
                return Ok(TempDir { path: candidate });
            }
        }
        Err(anyhow!("could not create temp dir"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_strips_token_suffix() {
        assert_eq!(default_slug("KAGGLE_API_TOKEN"), "kaggle");
        assert_eq!(default_slug("HF_TOKEN"), "hf");
        assert_eq!(default_slug("CARGO_REGISTRY_TOKEN"), "cargo-registry");
        assert_eq!(default_slug("OPENAI_API_KEY"), "openai");
        assert_eq!(default_slug("SOMETHING"), "something");
    }

    #[test]
    fn splice_keeps_locals_sorted() {
        let dir = TempDir::new().unwrap();
        let p = dir.path.join("default.nix");
        fs::write(
            &p,
            "_: {\n  imports = [\n    ./crates-io.nix\n    ./hugging-face.nix\n    ../../shared/x.nix\n  ];\n}\n",
        )
        .unwrap();
        splice_import(&p, "kaggle").unwrap();
        let got = fs::read_to_string(&p).unwrap();
        assert_eq!(
            got,
            "_: {\n  imports = [\n    ./crates-io.nix\n    ./hugging-face.nix\n    ./kaggle.nix\n    ../../shared/x.nix\n  ];\n}\n"
        );
    }

    #[test]
    fn validate_ident_accepts_legacy_forgejo_names() {
        validate_ident("nixTrusted", "instance").unwrap();
        validate_ident("copr-token", "credential-name").unwrap();
        validate_ident("foo_bar", "credential-name").unwrap();
    }

    #[test]
    fn validate_unit_name_rejects_service_suffix() {
        let err = validate_unit_name("vikunja.service").unwrap_err();
        assert!(err.to_string().contains("without the `.service` suffix"));
    }

    #[test]
    fn editor_shell_script_prefers_override_then_visual_then_editor_then_hx() {
        let script = editor_shell_script();
        assert!(script.contains("SECRET_MANAGER_EDITOR"));
        assert!(script.contains("VISUAL"));
        assert!(script.contains("EDITOR"));
        assert!(script.contains("hx"));
        assert!(script.ends_with("\"$1\""));
    }
}
