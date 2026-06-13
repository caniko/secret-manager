use anyhow::{Result, anyhow};
use std::path::PathBuf;

use nix_manager_core::age;

pub use nix_manager_core::age::resolve_against;

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
        age::resolve_identities(&self.root, explicit, IDENTITIES_ENV)
    }

    /// Master identity stubs used for decryption, sorted for a stable
    /// fallback order. These are typically hardware-key (age plugin)
    /// identity files; rage prompts on the controlling terminal.
    pub fn master_identities(&self) -> Vec<PathBuf> {
        age::master_identity_stubs(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn touch(path: &Path) {
        fs::write(path, "").unwrap();
    }

    #[test]
    fn master_identities_globs_and_sorts() {
        let tmp = crate::io::TempDir::new().unwrap();
        let age = tmp.path.join("age");
        fs::create_dir_all(&age).unwrap();
        touch(&age.join("master-b-identity.pub"));
        touch(&age.join("master-a-identity.pub"));
        touch(&age.join("master_nitro3c_identity.pub"));
        touch(&age.join("not-a-master.pub"));
        touch(&age.join("master-c-identity.txt"));

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

    #[test]
    fn resolve_identities_uses_the_engine_env_contract() {
        let tmp = crate::io::TempDir::new().unwrap();
        let age = tmp.path.join("age");
        fs::create_dir_all(&age).unwrap();
        touch(&age.join("master_nitro3c_identity.pub"));

        let store = Store {
            root: tmp.path.clone(),
        };
        // The store-repo dev shell exports IDENTITIES_ENV; clear it so the
        // test exercises the stub fallback deterministically.
        unsafe {
            std::env::remove_var(IDENTITIES_ENV);
        }
        let resolved = store.resolve_identities(&[]).unwrap();
        assert_eq!(resolved, vec![age.join("master_nitro3c_identity.pub")]);
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
