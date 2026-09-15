use std::path::PathBuf;

use anyhow::{Result, anyhow};

/// Default directory (relative to the store repo root) under which
/// host-scoped `.age` sources live. Store repos whose Nix side resolves
/// host secrets elsewhere override [`StoreEnv::host_secret_dir`].
pub const DEFAULT_HOST_SECRET_DIR: &str = "age/secrets/hosts";

/// Host-environment hooks the engine consults while building plans.
///
/// The store repo's tooling (e.g. the canix CLI) injects implementations
/// that validate against its fleet registry and home-manager profiles.
/// The standalone `secret-manager` binary uses [`LocalEnv`], which trusts
/// the caller.
pub trait StoreEnv {
    /// Validate that `host` is a known deploy target for system secrets.
    fn validate_host(&self, _host: &str) -> Result<()> {
        Ok(())
    }

    /// Resolve the home-manager user a secret targets when the caller did
    /// not pass one explicitly.
    fn resolve_home_user(&self) -> Result<String> {
        std::env::var("USER")
            .map_err(|_| anyhow!("--user is required (USER is not set in the environment)"))
    }

    /// Directory (relative to the store repo root) under which host-scoped
    /// `.age` sources live. Must agree with the path the store repo's Nix
    /// side resolves for host secrets; a mismatch orphans sources the CLI
    /// creates (the generator runs, but declarations point elsewhere).
    fn host_secret_dir(&self) -> PathBuf {
        PathBuf::from(DEFAULT_HOST_SECRET_DIR)
    }
}

/// Permissive environment for standalone use: any host name is accepted
/// and the login user is taken from `$USER`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalEnv;

impl StoreEnv for LocalEnv {}

#[cfg(test)]
pub(crate) struct TestEnv;

#[cfg(test)]
impl StoreEnv for TestEnv {
    fn resolve_home_user(&self) -> Result<String> {
        Ok("can".to_string())
    }
}
