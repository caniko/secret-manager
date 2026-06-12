use anyhow::{Result, bail};
use clap::Args;
use std::path::PathBuf;

use crate::age;
use crate::store::{Store, resolve_against};
use nix_manager_core::{forge, ui};

/// Decrypt an agenix-encrypted secret and push it to repository Actions
/// secret stores (Codeberg/Forgejo and/or GitHub). The plaintext only ever
/// lives in process memory — it is never written to disk or echoed.
#[derive(Args)]
pub struct PushArgs {
    /// Path to the agenix-encrypted `.age` file, relative to the store root.
    pub secret: String,

    /// Name of the Actions secret to set on each target repo.
    #[arg(long)]
    pub name: String,

    /// Codeberg repo (owner/repo) to push to. Repeat for multiple repos.
    /// Auth: `fj` auth store at
    /// `${XDG_DATA_HOME:-$HOME/.local/share}/forgejo-cli/keys.json`.
    #[arg(long = "codeberg", value_name = "OWNER/REPO")]
    pub codeberg: Vec<String>,

    /// GitHub repo (owner/repo) to push to via `gh secret set`. Repeatable.
    #[arg(long = "github", value_name = "OWNER/REPO")]
    pub github: Vec<String>,

    /// age identity file for decryption. Repeat to try several. Defaults to
    /// SECRET_MANAGER_AGE_IDENTITIES (colon-separated), then the store's
    /// master identities (hardware key; rage will prompt).
    #[arg(long = "identity", value_name = "PATH")]
    pub identities: Vec<PathBuf>,
}

/// Decrypt an agenix-encrypted secret and print the plaintext to stdout.
/// Meant for piping into other tools (e.g. CI secret substitution);
/// diagnostics and hardware-key prompts stay on stderr.
#[derive(Args)]
pub struct DecryptArgs {
    /// Path to the agenix-encrypted `.age` file, relative to the store root.
    pub secret: String,

    /// age identity file for decryption. Repeat to try several. Defaults to
    /// SECRET_MANAGER_AGE_IDENTITIES (colon-separated), then the store's
    /// master identities (hardware key; rage will prompt).
    #[arg(long = "identity", value_name = "PATH")]
    pub identities: Vec<PathBuf>,
}

impl PushArgs {
    pub fn run(self) -> Result<()> {
        if self.codeberg.is_empty() && self.github.is_empty() {
            bail!("no targets — pass --codeberg owner/repo and/or --github owner/repo");
        }

        let store = Store::discover()?;
        let value = decrypt_store_secret(&store, &self.secret, &self.identities)?;

        for repo in &self.codeberg {
            forge::push_codeberg_org_secret(repo, &self.name, &value)?;
        }
        for repo in &self.github {
            forge::push_github_secret(repo, &self.name, &value)?;
        }

        ui::success(format!(
            "pushed `{}` to {} repo(s)",
            self.name,
            self.codeberg.len() + self.github.len()
        ));
        Ok(())
    }
}

impl DecryptArgs {
    pub fn run(self) -> Result<()> {
        let store = Store::discover()?;
        let value = decrypt_store_secret(&store, &self.secret, &self.identities)?;
        println!("{value}");
        Ok(())
    }
}

pub(crate) fn decrypt_store_secret(
    store: &Store,
    secret: &str,
    identities: &[PathBuf],
) -> Result<String> {
    let secret_path = resolve_against(&store.root, &PathBuf::from(secret));
    if !secret_path.is_file() {
        bail!("{} does not exist", secret_path.display());
    }
    if secret_path.extension().and_then(|s| s.to_str()) != Some("age") {
        bail!(
            "{} does not end in `.age` — refusing",
            secret_path.display()
        );
    }

    let identities = store.resolve_identities(identities)?;
    let value = age::decrypt_with_identities(&secret_path, &identities)?;
    if value.is_empty() {
        bail!("decrypted payload is empty");
    }
    Ok(value)
}
