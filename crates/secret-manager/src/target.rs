//! Generic host-targeting argument group and via-enum for CLI tools that
//! operate on NixOS hosts through multiple network substrates.
//!
//! This module provides the reusable clap scaffolding — the `Target` struct
//! with `--via`, `--prefix`, and `--addr` flags — without tying it to any
//! particular host registry or route-resolver implementation. Downstream
//! consumers (e.g. the canix CLI) add their own `resolve()` / `ssh()` methods
//! that plug in fleet data.

use anyhow::{Result, anyhow};
use clap::{Args, ValueEnum};

/// Reusable host-targeting argument group. Positional `host` names the
/// target; `--via` picks the network substrate; `--addr` overrides registry
/// resolution with a literal SSH address; `--prefix` adds a user prefix.
#[derive(Debug, Args, Clone)]
pub struct Target {
    /// Host name as declared in the fleet registry, or an SSH alias.
    #[arg(value_name = "HOST", help_heading = "Host targeting")]
    pub host: String,

    /// Network to reach the host over (auto, lan, wg, direct).
    #[arg(
        long,
        value_enum,
        default_value_t = Via::Auto,
        help_heading = "Host targeting"
    )]
    pub via: Via,

    /// Optional ssh user prefix (e.g. `root@`).
    #[arg(
        long,
        default_value = "",
        value_name = "PREFIX",
        help_heading = "Host targeting"
    )]
    pub prefix: String,

    /// Override registry resolution with a literal address.
    #[arg(long, value_name = "ADDR", help_heading = "Host targeting")]
    pub addr: Option<String>,
}

/// Network substrate for reaching a host.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Via {
    /// Pick the best route by host-registry rules (direct → lan → wg).
    Auto,
    /// Reach the host over its LAN address.
    Lan,
    /// Reach the host over its WireGuard home address.
    Wg,
    /// Reach the host over a direct-link interface.
    Direct,
}

impl Target {
    /// Split `user@host` into `--prefix` and the bare hostname.
    ///
    /// When the input is `dejana@murph` and no explicit `--prefix` was
    /// passed, sets `prefix = "dejana@"` and `host = "murph"`. If a prefix
    /// was already set explicitly it is preserved.
    pub fn normalize_user_host(&mut self) {
        let Some((user, host)) = self.host.split_once('@') else {
            return;
        };
        if user.is_empty() || host.is_empty() {
            return;
        }
        if self.prefix.is_empty() {
            self.prefix = format!("{user}@");
        }
        self.host = host.to_string();
    }

    /// Build an SSH target string: `<prefix><addr>` using the explicitly
    /// provided `--addr` or falling back to the passed `resolved_addr`.
    ///
    /// This is a building-block — it does not perform host-registry lookups.
    /// Downstream callers resolve the address themselves and pass it here.
    pub fn ssh_addr(&self, resolved_addr: &str) -> String {
        format!("{}{}", self.prefix, resolved_addr)
    }

    /// Shortcut: produce an SSH string from the explicit `addr` field.
    /// Returns an error when `addr` is `None`.
    pub fn ssh_from_addr(&self) -> Result<String> {
        let addr = self
            .addr
            .as_deref()
            .ok_or_else(|| anyhow!("--addr is required when no registry resolver is available"))?;
        Ok(format!("{}{}", self.prefix, addr))
    }
}
