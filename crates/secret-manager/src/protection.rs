//! Protect interactive credential handlers, including their helper subprocesses.
use anyhow::{Context, Result, ensure};
use dbus::blocking::Connection;
use std::{
    fs,
    path::Path,
    process::{Command, ExitStatus},
    time::Duration,
};

/// Holds a logind block inhibitor while plaintext is in use. Swap protection is
/// a kernel cgroup limit, so it also covers libraries, GUI widgets and children.
pub struct CredentialProtection {
    _sleep: dbus::arg::OwnedFd,
}

/// Returns whether this process has a zero effective cgroup-v2 swap allowance.
/// Missing, unsupported or unreadable controls fail closed.
pub fn swap_disabled() -> Result<bool> {
    let cgroup = fs::read_to_string("/proc/self/cgroup").context("inspect credential cgroup")?;
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .context("credential handling requires cgroup v2")?;
    swap_disabled_at(Path::new("/sys/fs/cgroup"), relative)
}

fn swap_disabled_at(root: &Path, relative: &str) -> Result<bool> {
    let path = Path::new(
        relative
            .strip_prefix('/')
            .context("invalid credential cgroup")?,
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, std::path::Component::Normal(_))),
        "invalid credential cgroup path"
    );
    let own = root.join(path);
    for directory in own
        .ancestors()
        .take_while(|directory| directory.starts_with(root))
    {
        match fs::read_to_string(directory.join("memory.swap.max")) {
            Ok(value) if value.trim() == "0" => return Ok(true),
            Ok(_) => {}
            Err(error) if directory == root && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect credential swap protection"),
        }
    }
    Ok(false)
}

/// Reexecute the current public command in a no-swap user scope before collecting
/// credentials. None means the kernel already enforces the required protection.
pub fn enter_scope() -> Result<Option<ExitStatus>> {
    if swap_disabled()? {
        return Ok(None);
    }
    ensure!(
        std::env::var_os("SECRET_MANAGER_SCOPE_ATTEMPT").is_none(),
        "no-swap credential scope did not establish its kernel limit"
    );
    let status = Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "--collect",
            "--quiet",
            "--property=MemorySwapMax=0",
            "--",
        ])
        .arg(std::env::current_exe().context("resolve credential command")?)
        .args(std::env::args_os().skip(1))
        .env("SECRET_MANAGER_SCOPE_ATTEMPT", "1")
        .status()
        .context("start no-swap credential scope")?;
    Ok(Some(status))
}

impl CredentialProtection {
    /// Acquire all protections before credentials enter memory. The caller must
    /// keep this guard until all plaintext buffers and children have been dropped.
    pub fn acquire() -> Result<Self> {
        ensure!(
            swap_disabled()?,
            "credential handling requires a no-swap cgroup"
        );
        crate::credential_process::disable_core_dumps()?;
        let connection =
            Connection::new_system().context("contact logind for credential protection")?;
        let proxy = connection.with_proxy(
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            Duration::from_secs(3),
        );
        let (sleep,): (dbus::arg::OwnedFd,) = proxy
            .method_call(
                "org.freedesktop.login1.Manager",
                "Inhibit",
                (
                    "sleep",
                    "secret-manager",
                    "Protect transient credentials",
                    "block",
                ),
            )
            .context("inhibit sleep while handling credentials")?;
        Ok(Self { _sleep: sleep })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_parent_limit_protects_children_but_missing_controls_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("slice/worker")).unwrap();
        fs::write(root.path().join("slice/memory.swap.max"), "0\n").unwrap();
        fs::write(root.path().join("slice/worker/memory.swap.max"), "max\n").unwrap();
        assert!(swap_disabled_at(root.path(), "/slice/worker").unwrap());
        fs::write(root.path().join("slice/memory.swap.max"), "1048576\n").unwrap();
        assert!(!swap_disabled_at(root.path(), "/slice/worker").unwrap());
        fs::remove_file(root.path().join("slice/worker/memory.swap.max")).unwrap();
        assert!(swap_disabled_at(root.path(), "/slice/worker").is_err());
        assert!(swap_disabled_at(root.path(), "/../foreign").is_err());
    }
}
