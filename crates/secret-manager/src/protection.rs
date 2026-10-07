//! Protect interactive credential handlers, including their helper subprocesses.
use anyhow::{Context, Result, ensure};
use dbus::blocking::Connection;
use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
use std::{
    fs,
    os::fd::AsRawFd,
    os::unix::process::CommandExt,
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
    /// Run a trusted foreground helper and keep sleep inhibited in its children
    /// too. Consume the command so its post-fork descriptor setup cannot outlive
    /// this guard or be reused after the inhibitor descriptor has been closed.
    pub fn run(&self, mut command: Command) -> Result<ExitStatus> {
        let fd = self._sleep.as_raw_fd();
        let parent = std::process::id();
        // SAFETY: the guard owns fd throughout spawn/wait. The post-fork closure
        // uses only libc calls and immutable integers, without Rust allocation
        // or synchronization. Descriptor flags change only in the child.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() as u32 != parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ECANCELED));
                }
                Ok(())
            });
        }
        struct Helper {
            child: std::process::Child,
            reaped: bool,
        }
        impl Drop for Helper {
            fn drop(&mut self) {
                if !self.reaped {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                }
            }
        }
        let mut helper = Helper {
            child: command
                .spawn()
                .context("start protected credential helper")?,
            reaped: false,
        };
        let status = helper
            .child
            .wait()
            .context("wait for protected credential helper")?;
        helper.reaped = true;
        Ok(status)
    }

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
        ensure!(
            !proxy
                .get::<bool>("org.freedesktop.login1.Manager", "PreparingForSleep")
                .context("check credential sleep transition")?,
            "credential handling cannot start during a sleep transition"
        );
        Ok(Self { _sleep: sleep })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreground_helpers_inherit_the_inhibitor_without_changing_parent_flags() {
        use std::os::fd::IntoRawFd;
        let file = fs::File::open("/dev/null").unwrap();
        // SAFETY: into_raw_fd transfers this live descriptor's sole ownership.
        let sleep = unsafe { dbus::arg::OwnedFd::new(file.into_raw_fd()) };
        let protection = CredentialProtection { _sleep: sleep };
        let fd = protection._sleep.as_raw_fd();
        // SAFETY: fd belongs to the live protection guard; F_GETFD only reads flags.
        let before = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let mut command = Command::new("python3");
        command
            .args(["-c", "import os, sys; os.fstat(int(sys.argv[1]))"])
            .arg(fd.to_string());
        assert!(protection.run(command).unwrap().success());
        // SAFETY: same live descriptor and read-only operation as above.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, before);
    }

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
