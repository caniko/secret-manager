//! Print how to rotate one credential, and open its provider pages.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Args;
use secret_manager_schema::rotation::{RotationCatalogue, RotationGuide};

use crate::pkl;

#[derive(Args, Debug)]
pub struct GuideArgs {
    /// Pkl catalogue that defines `guides` (for example `lib/secrets/Rotations.pkl`).
    #[arg(long, value_name = "PATH")]
    pub catalogue: PathBuf,

    /// Guide to print. Without a key, list every key and title.
    pub key: Option<String>,

    /// Print the provider pages without opening them.
    #[arg(long, default_value_t = false)]
    pub no_browser: bool,
}

impl GuideArgs {
    pub fn run(self) -> Result<()> {
        let catalogue = load(&self.catalogue)?;
        let Some(key) = self.key else {
            for (key, guide) in &catalogue.guides {
                println!("{key}: {}", guide.title);
            }
            return Ok(());
        };
        let Some((key, guide)) = catalogue.guides.get_key_value(&key) else {
            let known = catalogue
                .guides
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            bail!("no rotation guide {key:?}; registered: {known}");
        };
        print!("{}", render(key, guide));
        open(guide, !self.no_browser);
        Ok(())
    }
}

/// Load a catalogue through the same Pkl path as the secret registry, then
/// re-check what the launcher will receive.
pub fn load(path: &Path) -> Result<RotationCatalogue> {
    let catalogue: RotationCatalogue = pkl::load_sync(path)
        .with_context(|| format!("loading rotation catalogue {}", path.display()))?;
    catalogue
        .validate()
        .with_context(|| format!("invalid rotation catalogue {}", path.display()))?;
    Ok(catalogue)
}

/// The operator-facing text: title, numbered steps, pages, command, cadence.
pub fn render(key: &str, guide: &RotationGuide) -> String {
    let mut out = format!("{key}: {}\n", guide.title);
    for (idx, step) in guide.steps.iter().enumerate() {
        out.push_str(&format!("  {}. {step}\n", idx + 1));
    }
    if !guide.urls.is_empty() {
        out.push_str("  pages:\n");
        for url in &guide.urls {
            out.push_str(&format!("    {url}\n"));
        }
    }
    if let Some(command) = &guide.command {
        out.push_str(&format!("  command:\n    {command}\n"));
    }
    if let Some(days) = guide.cadence_days {
        match guide.warn_days {
            Some(warn) => out.push_str(&format!(
                "  cadence: every {days} days, warn {warn} days before\n"
            )),
            None => out.push_str(&format!("  cadence: every {days} days\n")),
        }
    }
    out
}

/// Hand each provider page to the desktop's opener. A missing or failing
/// `xdg-open` is not an error: the URLs are already printed.
pub fn open(guide: &RotationGuide, browser: bool) {
    if !browser {
        return;
    }
    for url in &guide.urls {
        println!("opening {url}");
        let _ = Command::new("xdg-open").arg(url).spawn();
    }
}
