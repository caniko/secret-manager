use anyhow::{Result, bail};
use clap::Args;
use std::fs;
use std::io::Read;
use std::path::PathBuf;

use crate::push::decrypt_store_secret;
use crate::store::{Store, resolve_against};
use crate::sync_targets::{SyncDocument, SyncValue};
use nix_manager_core::{forge, ui};

/// Read collected sync targets and push each declared value to its
/// declared forge repository Actions destination. The JSON input comes from
/// `nix eval <flake>#nixosConfigurations.<host>.config.services.secretSync.targets --json`
/// piped through `collect.nix`.
///
/// Encrypted agenix values are pushed as Actions secrets. Plaintext source
/// files are pushed as Actions variables. Reuses the same auth resolution as `push`:
/// `$CODEBERG_TOKEN` env var, falling back to the forgejo-cli token file.
#[derive(Args)]
pub struct SyncArgs {
    /// Path to the collected sync-targets JSON document.
    /// If omitted, reads from stdin (for piping `nix eval` output).
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// age identity file(s) for decryption.
    /// Repeatable. Defaults to the store's master identities.
    #[arg(long = "identity", value_name = "PATH")]
    pub identities: Vec<PathBuf>,

    /// Print planned pushes without decrypting or contacting any forge.
    #[arg(long)]
    pub dry_run: bool,
}

impl SyncArgs {
    pub fn run(self) -> Result<()> {
        let doc = self.load_document()?;
        let total = doc.total_targets();

        if self.dry_run {
            println!("Planned pushes (--dry-run):");
            for (_, name, target) in doc.iter_targets() {
                println!();
                println!("  target: {name}");
                println!("  kind:   {}", target.value.kind());
                println!("  source: {}", target.value.path());
                println!("  name:   {}", target.name);
                for repo in &target.codeberg {
                    println!("  → codeberg/{}  {}", target.host, repo);
                }
            }
            println!();
            println!("total targets: {total}");
            return Ok(());
        }

        let store = Store::discover()?;

        for (_, name, target) in doc.iter_targets() {
            ui::step(format!(
                "sync: `{}` {} from {}",
                name,
                target.value.kind(),
                target.value.path()
            ));

            let value = sync_value(&store, &target.value, &self.identities)?;

            for repo in &target.codeberg {
                ui::step(format!(
                    "  codeberg/{} → {} as {}",
                    target.host, repo, target.name
                ));
                match &target.value {
                    SyncValue::Secret(_) => {
                        forge::push_codeberg_secret(&target.host, repo, &target.name, &value)?;
                    }
                    SyncValue::Source(_) => {
                        forge::push_codeberg_variable(&target.host, repo, &target.name, &value)?;
                    }
                }
            }
        }

        ui::success(format!("synced {total} target(s)"));
        Ok(())
    }

    fn load_document(&self) -> Result<SyncDocument> {
        match &self.config {
            Some(path) => SyncDocument::from_path(path).map_err(Into::into),
            None => {
                let mut buf = String::new();
                std::io::stdin()
                    .lock()
                    .read_to_string(&mut buf)
                    .map_err(|e| anyhow::anyhow!("reading stdin: {e}"))?;
                if buf.trim().is_empty() {
                    anyhow::bail!("no input — pipe a JSON document or pass --config <path>");
                }
                SyncDocument::from_json(&buf).map_err(Into::into)
            }
        }
    }
}

fn sync_value(store: &Store, value: &SyncValue, identities: &[PathBuf]) -> Result<String> {
    match value {
        SyncValue::Secret(secret) => decrypt_store_secret(store, secret, identities),
        SyncValue::Source(source) => read_plaintext_source(store, source),
    }
}

fn read_plaintext_source(store: &Store, source: &str) -> Result<String> {
    let source_path = resolve_against(&store.root, &PathBuf::from(source));
    if !source_path.is_file() {
        bail!("{} does not exist", source_path.display());
    }
    let value = fs::read_to_string(&source_path)
        .map_err(|e| anyhow::anyhow!("reading plaintext source {}: {e}", source_path.display()))?;
    if value.is_empty() {
        bail!("plaintext source {} is empty", source_path.display());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract fixture matching the shape nix/collect.nix produces.
    const FIXTURE: &str = r#"{
  "hosts": [
    {
      "targets": {
        "my-app-token": {
          "secret": "age/secrets/my-app-token.age",
          "name": "MY_APP_TOKEN",
          "codeberg": ["caniko/my-repo"],
          "host": "codeberg.org"
        },
        "deploy-key": {
          "source": "age/secrets/deploy-key.pub",
          "name": "DEPLOY_KEY",
          "codeberg": ["caniko/my-repo", "caniko/other-repo"],
          "host": "git.example.com"
        }
      }
    }
  ]
}"#;

    #[test]
    fn dry_run_lists_all_targets_and_repos() {
        let doc: SyncDocument = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(doc.total_targets(), 2);

        // Verify target expansion and per-target host handling
        let mut targets: Vec<(&str, &str, &str, &str, &str)> = doc
            .iter_targets()
            .flat_map(|(_, _name, target)| {
                let host: &str = &target.host;
                let source: &str = target.value.path();
                let kind: &str = target.value.kind();
                let secret_name: &str = &target.name;
                target
                    .codeberg
                    .iter()
                    .map(move |repo| (kind, host, source, secret_name, repo.as_str()))
            })
            .collect();
        targets.sort_by_key(|t| (t.3, t.4));

        assert_eq!(
            targets,
            vec![
                (
                    "variable",
                    "git.example.com",
                    "age/secrets/deploy-key.pub",
                    "DEPLOY_KEY",
                    "caniko/my-repo"
                ),
                (
                    "variable",
                    "git.example.com",
                    "age/secrets/deploy-key.pub",
                    "DEPLOY_KEY",
                    "caniko/other-repo"
                ),
                (
                    "secret",
                    "codeberg.org",
                    "age/secrets/my-app-token.age",
                    "MY_APP_TOKEN",
                    "caniko/my-repo"
                ),
            ],
            "dry-run planning should expand all codeberg repos per target, \
             honoring each target's host"
        );
    }

    #[test]
    fn dry_run_with_zero_targets_is_ok() {
        let json = r#"{"hosts": []}"#;
        let doc: SyncDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.total_targets(), 0);
        assert_eq!(doc.iter_targets().count(), 0);
    }

    #[test]
    fn load_document_from_file() {
        let dir = crate::io::TempDir::new().unwrap();
        let path = dir.path.join("sync.json");
        std::fs::write(&path, FIXTURE).unwrap();

        let args = SyncArgs {
            config: Some(path),
            identities: vec![],
            dry_run: true,
        };
        // Just verify load_document succeeds — dry-run doesn't need a store
        let doc = args.load_document().unwrap();
        assert_eq!(doc.total_targets(), 2);
    }

    #[test]
    fn read_plaintext_source_preserves_content() {
        let dir = crate::io::TempDir::new().unwrap();
        let source = dir.path.join("public.asc");
        let content = "line one\nline two\n";
        std::fs::write(&source, content).unwrap();
        let store = Store {
            root: dir.path.clone(),
        };

        let got = read_plaintext_source(&store, "public.asc").unwrap();
        assert_eq!(got, content);
    }

    #[test]
    fn read_plaintext_source_rejects_empty_file() {
        let dir = crate::io::TempDir::new().unwrap();
        std::fs::write(dir.path.join("empty"), "").unwrap();
        let store = Store {
            root: dir.path.clone(),
        };

        let err = read_plaintext_source(&store, "empty").unwrap_err();
        assert!(err.to_string().contains("is empty"));
    }
}
