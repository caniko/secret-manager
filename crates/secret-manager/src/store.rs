use anyhow::{Result, anyhow, bail};
use std::path::{Path, PathBuf};

/// Colon-separated list of age identity paths consulted when no explicit
/// `--identity` flags are passed. Same env-var contract as the DNS flow's
/// `CANIX_DNS_AGE_IDENTITIES`: relative entries resolve against the store
/// root.
pub const IDENTITIES_ENV: &str = "SECRET_MANAGER_AGE_IDENTITIES";

/// The data repository ("store") whose age secrets this engine manages.
///
/// secret-manager is the engine; the store repo (e.g. canix) owns the data:
/// `age/secrets/**`, `age/rekeyed/**`, and the master identity stubs used
/// for decryption. Plan execution treats all paths as relative to
/// [`Store::root`].
#[derive(Debug, Clone)]
pub struct Store {
    pub root: PathBuf,
}

impl Store {
    /// Store rooted at the current directory. Matches the historical
    /// behaviour of `add`-family commands, which treat the cwd as the
    /// repo root.
    pub fn current_dir() -> Result<Self> {
        Ok(Store {
            root: std::env::current_dir()?,
        })
    }

    /// Discover the store root: `$SECRET_MANAGER_STORE` if set, otherwise
    /// walk up from the cwd to the nearest `flake.nix`.
    pub fn discover() -> Result<Self> {
        if let Ok(root) = std::env::var("SECRET_MANAGER_STORE") {
            let root = PathBuf::from(root);
            if !root.is_dir() {
                return Err(anyhow!(
                    "SECRET_MANAGER_STORE={} is not a directory",
                    root.display()
                ));
            }
            return Ok(Store { root });
        }
        Ok(Store {
            root: nix_manager_core::repo::find_flake_root()?,
        })
    }

    /// Resolve the identities to decrypt with, in precedence order:
    /// explicit `--identity` flags, then the colon-separated
    /// [`IDENTITIES_ENV`] environment variable, then the store's
    /// `age/master*identity.pub` stubs. Relative paths resolve against
    /// the store root; entries that are not files are dropped.
    pub fn resolve_identities(&self, explicit: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let env_value = std::env::var(IDENTITIES_ENV).ok();
        self.resolve_identities_from(explicit, env_value.as_deref())
    }

    fn resolve_identities_from(
        &self,
        explicit: &[PathBuf],
        env_value: Option<&str>,
    ) -> Result<Vec<PathBuf>> {
        let env_value = env_value.filter(|value| !value.trim().is_empty());
        let (candidates, source) = if !explicit.is_empty() {
            (explicit.to_vec(), "--identity".to_string())
        } else if let Some(value) = env_value {
            (split_identity_list(value), IDENTITIES_ENV.to_string())
        } else {
            (
                self.master_identities(),
                format!(
                    "master identity stubs in {}",
                    self.root.join("age").display()
                ),
            )
        };

        let usable: Vec<PathBuf> = candidates
            .iter()
            .map(|p| resolve_against(&self.root, p))
            .filter(|p| p.is_file())
            .collect();
        if usable.is_empty() {
            bail!(
                "no usable age identity files found via {source} — pass --identity, \
                 set {IDENTITIES_ENV} to a colon-separated list of identity paths, \
                 or add age/master*identity.pub stubs to the store"
            );
        }
        Ok(usable)
    }

    /// Master identity stubs used for decryption, sorted for a stable
    /// fallback order. These are typically hardware-key (age plugin)
    /// identity files; rage prompts on the controlling terminal.
    pub fn master_identities(&self) -> Vec<PathBuf> {
        let dir = self.root.join("age");
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if is_master_identity_stub(&name) && path.is_file() {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }
}

fn is_master_identity_stub(name: &str) -> bool {
    (name.starts_with("master-") || name.starts_with("master_")) && name.ends_with(".pub")
}

fn split_identity_list(value: &str) -> Vec<PathBuf> {
    value
        .split(':')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Resolve a path argument against a base when relative.
pub fn resolve_against(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn master_identities_globs_and_sorts() {
        let tmp = crate::io::TempDir::new().unwrap();
        let age = tmp.path.join("age");
        fs::create_dir_all(&age).unwrap();
        fs::write(age.join("master-b-identity.pub"), "").unwrap();
        fs::write(age.join("master-a-identity.pub"), "").unwrap();
        fs::write(age.join("master_nitro3c_identity.pub"), "").unwrap();
        fs::write(age.join("not-a-master.pub"), "").unwrap();
        fs::write(age.join("master-c-identity.txt"), "").unwrap();

        let store = Store {
            root: tmp.path.clone(),
        };
        let names: Vec<String> = store
            .master_identities()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                "master-a-identity.pub",
                "master-b-identity.pub",
                "master_nitro3c_identity.pub"
            ]
        );
    }

    fn touch(path: &Path) {
        fs::write(path, "").unwrap();
    }

    #[test]
    fn explicit_flags_win_over_env_and_stubs() {
        let tmp = crate::io::TempDir::new().unwrap();
        let age = tmp.path.join("age");
        fs::create_dir_all(&age).unwrap();
        touch(&age.join("master-stub-identity.pub"));
        touch(&tmp.path.join("explicit.pub"));
        touch(&tmp.path.join("from-env.pub"));

        let store = Store {
            root: tmp.path.clone(),
        };
        let resolved = store
            .resolve_identities_from(&[PathBuf::from("explicit.pub")], Some("from-env.pub"))
            .unwrap();
        assert_eq!(resolved, vec![tmp.path.join("explicit.pub")]);
    }

    #[test]
    fn env_list_wins_over_stubs_and_resolves_against_root() {
        let tmp = crate::io::TempDir::new().unwrap();
        let age = tmp.path.join("age");
        fs::create_dir_all(&age).unwrap();
        touch(&age.join("master-stub-identity.pub"));
        touch(&tmp.path.join("first.pub"));
        touch(&tmp.path.join("second.pub"));

        let store = Store {
            root: tmp.path.clone(),
        };
        let resolved = store
            .resolve_identities_from(&[], Some("first.pub:second.pub:missing.pub"))
            .unwrap();
        assert_eq!(
            resolved,
            vec![tmp.path.join("first.pub"), tmp.path.join("second.pub")]
        );
    }

    #[test]
    fn blank_env_falls_back_to_master_stubs() {
        let tmp = crate::io::TempDir::new().unwrap();
        let age = tmp.path.join("age");
        fs::create_dir_all(&age).unwrap();
        touch(&age.join("master_nitro3c_identity.pub"));

        let store = Store {
            root: tmp.path.clone(),
        };
        let resolved = store.resolve_identities_from(&[], Some("  ")).unwrap();
        assert_eq!(resolved, vec![age.join("master_nitro3c_identity.pub")]);
    }

    #[test]
    fn unusable_env_entries_error_with_source_and_remedies() {
        let tmp = crate::io::TempDir::new().unwrap();
        let store = Store {
            root: tmp.path.clone(),
        };
        let err = store
            .resolve_identities_from(&[], Some("missing.pub"))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains(IDENTITIES_ENV), "unexpected error: {msg}");
        assert!(msg.contains("--identity"), "unexpected error: {msg}");
    }

    #[test]
    fn no_identities_anywhere_names_the_stub_fallback() {
        let tmp = crate::io::TempDir::new().unwrap();
        let store = Store {
            root: tmp.path.clone(),
        };
        let err = store.resolve_identities_from(&[], None).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("master identity stubs"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn split_identity_list_trims_and_drops_empty_entries() {
        assert_eq!(
            split_identity_list(" a.pub : :b.pub:"),
            vec![PathBuf::from("a.pub"), PathBuf::from("b.pub")]
        );
    }

    #[test]
    fn discover_honors_env_override() {
        let tmp = crate::io::TempDir::new().unwrap();
        // SAFETY-free std API misuse note: tests run single-threaded enough
        // for env mutation here; restore afterwards.
        unsafe {
            std::env::set_var("SECRET_MANAGER_STORE", &tmp.path);
        }
        let store = Store::discover().unwrap();
        unsafe {
            std::env::remove_var("SECRET_MANAGER_STORE");
        }
        assert_eq!(store.root, tmp.path);
    }
}
