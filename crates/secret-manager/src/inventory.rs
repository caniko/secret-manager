//! The value-free secret inventory: one JSON document describing every
//! source in the canonical layout, for expiry and rotation dashboards.
//!
//! It reads paths and `.meta.toml` sidecars only. No value, hash or length of
//! any secret is read or emitted.
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::layout::{self, Tree};
use crate::meta::{Kind, Metadata, sidecar_path};

const STORE: &str = "age/secrets";
const SIDECAR: &str = ".meta.toml";

/// Print the secret inventory, or check the store against the layout.
#[derive(clap::Args, Debug)]
pub struct InventoryArgs {
    /// Output format; JSON is the only one.
    #[arg(long, value_enum, default_value_t = Output::Json)]
    pub output: Output,
    /// Report layout and metadata violations instead of the inventory; exit
    /// non-zero if there is any.
    #[arg(long)]
    pub check: bool,
    /// Write the document atomically to PATH instead of stdout.
    #[arg(long, value_name = "PATH", requires = "mode")]
    pub write: Option<PathBuf>,
    /// Octal file mode for --write, e.g. 640.
    #[arg(long, value_name = "OCTAL", value_parser = parse_mode, requires = "write")]
    pub mode: Option<u32>,
    /// JSON object mapping a secret id to its consumers, copied verbatim.
    #[arg(long, value_name = "FILE")]
    pub consumers: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum Output {
    Json,
}

fn parse_mode(value: &str) -> std::result::Result<u32, String> {
    u32::from_str_radix(value, 8)
        .ok()
        .filter(|mode| *mode <= 0o777)
        .ok_or_else(|| "expected an octal mode such as 640".into())
}

impl InventoryArgs {
    pub fn run(&self) -> Result<()> {
        let root = crate::store::Store::discover()?.root;
        if self.check {
            let violations = check(&root);
            for violation in &violations {
                eprintln!("{violation}");
            }
            if !violations.is_empty() {
                bail!("{} inventory violation(s)", violations.len());
            }
            eprintln!("inventory check: no violations");
            return Ok(());
        }
        let consumers = match &self.consumers {
            Some(path) => serde_json::from_slice(
                &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
            )
            .with_context(|| {
                format!(
                    "{}: expected a JSON object of id → consumers",
                    path.display()
                )
            })?,
            None => BTreeMap::new(),
        };
        let document = serde_json::to_string_pretty(&build(&root, &consumers)?)? + "\n";
        match (&self.write, self.mode) {
            (Some(path), Some(mode)) => write_atomic(path, document.as_bytes(), mode),
            _ => {
                std::io::stdout().write_all(document.as_bytes())?;
                Ok(())
            }
        }
    }
}

/// One problem `check` found, with the store-relative path it concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub path: String,
    pub reason: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}

/// Files under `age/secrets`, store-relative, sorted; symlinks included.
/// A directory that cannot be read is returned as an error, never skipped:
/// an inventory missing a category would read as "nothing there".
fn store_files(root: &Path) -> (Vec<(PathBuf, bool)>, Vec<Violation>) {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    if !root.join(STORE).exists() {
        return (files, errors);
    }
    for entry in walkdir::WalkDir::new(root.join(STORE)).follow_links(false) {
        match entry {
            Ok(entry) if entry.file_type().is_dir() => {}
            Ok(entry) => {
                if let Ok(rel) = entry.path().strip_prefix(root) {
                    files.push((rel.to_path_buf(), entry.path_is_symlink()));
                }
            }
            Err(error) => errors.push(Violation {
                path: error
                    .path()
                    .and_then(|p| p.strip_prefix(root).ok())
                    .unwrap_or(Path::new(STORE))
                    .display()
                    .to_string(),
                reason: format!(
                    "unreadable: {}",
                    error
                        .io_error()
                        .map_or_else(|| error.to_string(), ToString::to_string)
                ),
            }),
        }
    }
    files.sort();
    (files, errors)
}

fn is_source(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "age")
}

/// Every layout and metadata problem in the store. Embedders may run it
/// warn-only; `inventory --check` fails on any.
pub fn check(root: &Path) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut names: BTreeMap<(String, String), BTreeSet<PathBuf>> = BTreeMap::new();
    let (files, errors) = store_files(root);
    violations.extend(errors);
    let sources: BTreeSet<&PathBuf> = files
        .iter()
        .filter(|(path, _)| is_source(path))
        .map(|(path, _)| path)
        .collect();
    let mut flag = |path: &Path, reason: &str| {
        violations.push(Violation {
            path: path.display().to_string(),
            reason: reason.into(),
        })
    };
    for (path, symlink) in &files {
        if let Some(stem) = path.to_str().and_then(|p| p.strip_suffix(SIDECAR)) {
            if !sources.contains(&PathBuf::from(format!("{stem}.age"))) {
                flag(path, "sidecar without its .age source");
            }
            continue;
        }
        if !is_source(path) {
            continue;
        }
        if *symlink {
            flag(
                path,
                "alias: a symlink to another source; remove once its consumers moved",
            );
            continue;
        }
        let Some(id) = layout::parse(path) else {
            flag(
                path,
                "outside the layout (home/<user>|root/hosts/<host>|root/modules)/<category>/<name>.age",
            );
            continue;
        };
        names
            .entry((tree_name(id.tree).into(), id.scope.clone()))
            .or_default()
            .insert(path.clone());
        let full = root.join(path);
        match Metadata::load(&full) {
            Err(error) => flag(
                &sidecar_path(path),
                &format!("unreadable sidecar: {error:#}"),
            ),
            Ok(metadata) => {
                if custodian(&id, &metadata).is_none() {
                    flag(
                        path,
                        "home/shared and root/* secrets need a custodian (classify --custodian)",
                    );
                }
            }
        }
    }
    for ((tree, scope), paths) in names {
        let mut by_name: BTreeMap<String, Vec<&PathBuf>> = BTreeMap::new();
        for path in &paths {
            if let Some(id) = layout::parse(path) {
                by_name.entry(id.name).or_default().push(path);
            }
        }
        for (name, duplicates) in by_name.into_iter().filter(|(_, d)| d.len() > 1) {
            for path in duplicates {
                flag(
                    path,
                    &format!("name `{name}` repeats within {tree}/{scope}"),
                );
            }
        }
    }
    violations
}

fn tree_name(tree: Tree) -> &'static str {
    match tree {
        Tree::Home => "home",
        Tree::Root => "root",
    }
}

/// `home/<user>` is held by that user unless the sidecar names someone else;
/// `home/shared` and `root/*` have no implicit custodian.
fn custodian(id: &layout::SourceId, metadata: &Metadata) -> Option<String> {
    metadata
        .custodian
        .clone()
        .or_else(|| (id.tree == Tree::Home && id.scope != "shared").then(|| id.scope.clone()))
}

/// The inventory document. Sources outside the layout, aliases and sources
/// with an unreadable sidecar are left to `check`; an unreadable sidecar's
/// source is still listed, with unknown metadata.
pub fn build(root: &Path, consumers: &BTreeMap<String, Value>) -> Result<Value> {
    let mut secrets = Vec::new();
    let (files, errors) = store_files(root);
    if let Some(error) = errors.first() {
        bail!("cannot list the store: {error}");
    }
    for (path, symlink) in files {
        if symlink || !is_source(&path) {
            continue;
        }
        let Some(id) = layout::parse(&path) else {
            continue;
        };
        let metadata = Metadata::load(&root.join(&path)).unwrap_or_default();
        let key = path
            .strip_prefix(STORE)
            .ok()
            .and_then(Path::to_str)
            .and_then(|p| p.strip_suffix(".age"))
            .context("source path is not UTF-8")?
            .to_owned();
        let kind = metadata
            .kind
            .unwrap_or_else(|| Kind::for_category(id.category));
        let expiry = match metadata.expiry.as_deref() {
            None => json!({ "type": "unknown" }),
            Some("never") => json!({ "type": "never" }),
            Some(date) => json!({ "type": "at", "date": date }),
        };
        let rotation = metadata.rotation.as_ref().map(|rotation| {
            json!({ "method": rotation.method, "command": rotation.command, "note": rotation.note })
        });
        secrets.push(json!({
            "id": key,
            "tree": tree_name(id.tree),
            "scope": id.scope,
            "category": id.category.to_string(),
            "project": metadata.project,
            "kind": kind,
            "custodian": custodian(&id, &metadata),
            "expiry": expiry,
            "rotatedAt": metadata.rotated_at,
            "rotation": rotation,
            "consumers": consumers.get(&key).cloned().unwrap_or_else(|| json!([])),
        }));
    }
    Ok(json!({
        "schemaVersion": 1,
        "generatedAt": crate::meta::utc_timestamp(),
        "secrets": secrets,
    }))
}

/// Replace `path` with `bytes` without a reader ever seeing a partial file.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating a temporary file in {}", parent.display()))?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| anyhow::anyhow!("replacing {}: {}", path.display(), error.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for rel in [
            "age/secrets/home/can/oauth/syndb_oa_github_secret.age",
            "age/secrets/home/shared/ai/deepseek.age",
            "age/secrets/root/hosts/thething/app/vikunja_mailer.age",
            "age/secrets/root/modules/cloud/cloudflare_candee_api_token.env.age",
            "age/secrets/root/modules/app/regicide.age",
            "age/secrets/root/modules/forge/regicide.age",
            "age/secrets/users/can/legacy.age",
        ] {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"age-encryption.org/v1 placeholder").unwrap();
        }
        let source = dir
            .path()
            .join("age/secrets/home/can/oauth/syndb_oa_github_secret.age");
        Metadata {
            expiry: Some("2027-02-13".into()),
            rotated_at: Some("2026-11-18".into()),
            project: Some("syndb".into()),
            ..Metadata::default()
        }
        .save(&source)
        .unwrap();
        Metadata {
            expiry: Some("never".into()),
            custodian: Some("can".into()),
            ..Metadata::default()
        }
        .save(
            &dir.path()
                .join("age/secrets/root/modules/cloud/cloudflare_candee_api_token.env.age"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("age/secrets/home/can/oauth/gone.meta.toml"),
            "schema = 1\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../../home/can/oauth/syndb_oa_github_secret.age",
            dir.path().join("age/secrets/users/can/alias.age"),
        )
        .unwrap();
        dir
    }

    #[test]
    fn document_shape_resolves_custodian_kind_and_expiry() {
        let dir = store();
        let consumers = BTreeMap::from([(
            "home/can/oauth/syndb_oa_github_secret".to_string(),
            json!([{ "type": "env", "name": "OA_GITHUB_SECRET" }]),
        )]);
        let document = build(dir.path(), &consumers).unwrap();
        assert_eq!(document["schemaVersion"], 1);
        let secrets = document["secrets"].as_array().unwrap();
        let ids: Vec<&str> = secrets.iter().map(|s| s["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            [
                "home/can/oauth/syndb_oa_github_secret",
                "home/shared/ai/deepseek",
                "root/hosts/thething/app/vikunja_mailer",
                "root/modules/app/regicide",
                "root/modules/cloud/cloudflare_candee_api_token.env",
                "root/modules/forge/regicide",
            ],
            "sorted; legacy, alias and sidecars excluded"
        );
        let github = &secrets[0];
        assert_eq!(github["custodian"], "can");
        assert_eq!(github["kind"], "external");
        assert_eq!(github["project"], "syndb");
        assert_eq!(
            github["expiry"],
            json!({ "type": "at", "date": "2027-02-13" })
        );
        assert_eq!(github["rotatedAt"], "2026-11-18");
        assert_eq!(github["consumers"][0]["name"], "OA_GITHUB_SECRET");
        assert_eq!(
            secrets[1]["custodian"],
            Value::Null,
            "shared has no implicit custodian"
        );
        assert_eq!(secrets[1]["expiry"], json!({ "type": "unknown" }));
        assert_eq!(secrets[2]["kind"], "generated");
        assert_eq!(secrets[4]["expiry"], json!({ "type": "never" }));
        assert_eq!(secrets[4]["consumers"], json!([]));
        let text = document.to_string();
        assert!(!text.contains("placeholder"), "no values");
    }

    #[test]
    fn check_reports_every_violation_kind() {
        let dir = store();
        let violations = check(dir.path());
        let has = |path: &str, reason: &str| {
            violations
                .iter()
                .any(|v| v.path.ends_with(path) && v.reason.contains(reason))
        };
        assert!(
            has("users/can/legacy.age", "outside the layout"),
            "{violations:#?}"
        );
        assert!(has("users/can/alias.age", "alias"), "{violations:#?}");
        assert!(
            has("oauth/gone.meta.toml", "sidecar without"),
            "{violations:#?}"
        );
        assert!(
            has("shared/ai/deepseek.age", "custodian"),
            "{violations:#?}"
        );
        assert!(
            has("thething/app/vikunja_mailer.age", "custodian"),
            "{violations:#?}"
        );
        assert!(
            has("modules/app/regicide.age", "repeats"),
            "{violations:#?}"
        );
        assert!(
            has("modules/forge/regicide.age", "repeats"),
            "{violations:#?}"
        );
        assert!(!has("syndb_oa_github_secret.age", ""), "{violations:#?}");
        assert!(
            !has("cloudflare_candee_api_token.env.age", ""),
            "{violations:#?}"
        );
        // The two regicide sources also lack a custodian: 9 in all.
        assert_eq!(violations.len(), 9, "{violations:#?}");
    }

    #[test]
    fn an_unreadable_directory_is_reported_not_skipped() {
        let dir = store();
        let category = dir.path().join("age/secrets/home/shared/ai");
        std::fs::set_permissions(&category, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read_dir(&category).is_ok(); // root ignores modes
        let violations = check(dir.path());
        let built = build(dir.path(), &BTreeMap::new());
        std::fs::set_permissions(&category, std::fs::Permissions::from_mode(0o755)).unwrap();
        if readable {
            return;
        }
        assert!(
            violations
                .iter()
                .any(|v| v.path.ends_with("home/shared/ai") && v.reason.contains("unreadable")),
            "{violations:#?}"
        );
        assert!(built.is_err(), "a partial inventory must not be emitted");
        assert!(build(tempfile::tempdir().unwrap().path(), &BTreeMap::new()).is_ok());
    }

    #[test]
    fn write_atomic_sets_the_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.json");
        write_atomic(&path, b"{}\n", 0o640).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        assert_eq!(std::fs::read(&path).unwrap(), b"{}\n");
        assert!(
            parse_mode("640").is_ok() && parse_mode("999").is_err() && parse_mode("1000").is_err()
        );
    }
}
