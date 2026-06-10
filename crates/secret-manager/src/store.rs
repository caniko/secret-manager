use anyhow::{Result, anyhow};
use std::path::{Path, PathBuf};

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
                if name.starts_with("master-") && name.ends_with(".pub") && path.is_file() {
                    out.push(path);
                }
            }
        }
        out.sort();
        out
    }
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
            vec!["master-a-identity.pub", "master-b-identity.pub"]
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
