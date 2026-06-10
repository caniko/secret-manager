use anyhow::Result;
use clap::Args;
use std::io::Read;
use std::path::PathBuf;

use crate::push::decrypt_store_secret;
use crate::store::Store;
use crate::sync_targets::SyncDocument;
use nix_manager_core::{forge, ui};

/// Read collected sync targets and push each declared secret to its
/// declared forge repository Actions secrets. The JSON input comes from
/// `nix eval <flake>#nixosConfigurations.<host>.config.services.secretSync.targets --json`
/// piped through `collect.nix`.
///
/// Reuses the same auth resolution as `push`:
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
                println!("  secret: {}", target.secret);
                println!("  name:   {}", target.name);
                for repo in &target.codeberg {
                    println!("  → codeberg/{}  {}", target.host, repo);
                }
                for repo in &target.github {
                    println!("  → github       {}", repo);
                }
            }
            println!();
            println!("total targets: {total}");
            return Ok(());
        }

        let store = Store::discover()?;

        for (_, name, target) in doc.iter_targets() {
            ui::step(format!("sync: `{}` from {}", name, target.secret));

            let value = decrypt_store_secret(&store, &target.secret, &self.identities)?;

            for repo in &target.codeberg {
                ui::step(format!(
                    "  codeberg/{} → {} as {}",
                    target.host, repo, target.name
                ));
                forge::push_codeberg_secret(&target.host, repo, &target.name, &value)?;
            }
            for repo in &target.github {
                ui::step(format!("  github → {} as {}", repo, target.name));
                forge::push_github_secret(repo, &target.name, &value)?;
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
                    anyhow::bail!(
                        "no input — pipe a JSON document or pass --config <path>"
                    );
                }
                SyncDocument::from_json(&buf).map_err(Into::into)
            }
        }
    }
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
          "github": [],
          "host": "codeberg.org"
        },
        "deploy-key": {
          "secret": "age/secrets/deploy-key.age",
          "name": "DEPLOY_KEY",
          "codeberg": ["caniko/my-repo", "caniko/other-repo"],
          "github": ["caniko/mirror-repo"],
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
        let mut targets: Vec<(&str, &str, &str, &str)> = doc
            .iter_targets()
            .flat_map(|(_, _name, target)| {
                let host: &str = &target.host;
                let secret: &str = &target.secret;
                let secret_name: &str = &target.name;
                target
                    .codeberg
                    .iter()
                    .map(move |repo| (host, secret, secret_name, repo.as_str()))
            })
            .collect();
        targets.sort_by_key(|t| (t.2, t.3));

        assert_eq!(
            targets,
            vec![
                ("git.example.com", "age/secrets/deploy-key.age", "DEPLOY_KEY", "caniko/my-repo"),
                ("git.example.com", "age/secrets/deploy-key.age", "DEPLOY_KEY", "caniko/other-repo"),
                ("codeberg.org", "age/secrets/my-app-token.age", "MY_APP_TOKEN", "caniko/my-repo"),
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
}
