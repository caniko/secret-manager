//! Private, bounded subprocess pipes shared by credential integrations.
use anyhow::{Context, Result, ensure};
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(crate) const MAX_BYTES: usize = 1024 * 1024;

pub(crate) fn capture(command: &mut Command, input: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    capture_with_timeout(command, input, Duration::from_secs(90))
}

pub fn capture_with_timeout(
    command: &mut Command,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    capture_inner(command, input, timeout, true)
}

/// Capture a native helper that prompts on the controlling terminal. Keep its
/// foreground process group so terminal reads cannot stop it with SIGTTIN.
/// The selected helper must not spawn credential-bearing descendants.
pub fn capture_prompt_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    capture_inner(command, None, timeout, false)
}

fn capture_inner(
    command: &mut Command,
    input: Option<&[u8]>,
    timeout: Duration,
    group: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    command
        .env_remove("GH_DEBUG")
        .env_remove("AGEDEBUG")
        .env_remove("RUST_LOG")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if group {
        command.process_group(0);
    }
    let parent = std::process::id();
    // SAFETY: only async-signal-safe libc calls occur between fork and exec.
    // No Rust allocation, locking or environment access is performed.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() as u32 != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ECANCELED));
            }
            Ok(())
        });
    }
    struct Cleanup {
        child: std::process::Child,
        group: bool,
        workers: Vec<thread::JoinHandle<()>>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            // The process group remains ours until its pipes settle, including
            // descendants retaining pipes after the direct child exits.
            // SAFETY: kill accepts a negative process-group ID and retains no pointer.
            if self.group {
                unsafe {
                    libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                }
            } else {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
            // All plaintext-bearing pipe threads settle before returning to a
            // GUI that may remain open after failure, timeout or cancellation.
            for worker in self.workers.drain(..) {
                let _ = worker.join();
            }
        }
    }
    let mut child = Cleanup {
        child: command.spawn().context("start credential helper")?,
        group,
        workers: Vec::new(),
    };
    let output = child
        .child
        .stdout
        .take()
        .context("helper stdout unavailable")?;
    let errors = child
        .child
        .stderr
        .take()
        .context("helper stderr unavailable")?;
    let read = |mut stream: Box<dyn Read + Send>| -> Result<Zeroizing<Vec<u8>>> {
        // Reserve the full bound so reallocations do not leave old plaintext
        // allocations behind before the final zeroizing drop.
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BYTES + 1));
        (&mut stream)
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_BYTES,
            "credential helper output exceeds size limit"
        );
        Ok(bytes)
    };
    let (output_send, output_recv) = mpsc::channel();
    let (error_send, error_recv) = mpsc::channel();
    child.workers.push(
        thread::Builder::new()
            .spawn(move || {
                let _ = output_send.send(read(Box::new(output)));
            })
            .context("start credential output reader")?,
    );
    child.workers.push(
        thread::Builder::new()
            .spawn(move || {
                let _ = error_send.send(read(Box::new(errors)));
            })
            .context("start credential diagnostics reader")?,
    );
    let writer = if let Some(mut stdin) = child.child.stdin.take() {
        let bytes = Zeroizing::new(input.unwrap_or_default().to_vec());
        let (send, recv) = mpsc::channel();
        child.workers.push(
            thread::Builder::new()
                .spawn(move || {
                    let _ = send.send(stdin.write_all(&bytes));
                })
                .context("start credential input writer")?,
        );
        Some(recv)
    } else {
        None
    };
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            anyhow::bail!("credential helper exceeded its execution deadline");
        }
        thread::sleep(Duration::from_millis(20));
    };
    ensure!(
        status.success(),
        "credential helper failed with {status}; diagnostics suppressed to protect secrets"
    );
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let bytes = output_recv.recv_timeout(remaining()).map_err(|_| {
        anyhow::anyhow!("credential helper stdout did not settle before deadline")
    })??;
    let _errors = error_recv.recv_timeout(remaining()).map_err(|_| {
        anyhow::anyhow!("credential helper stderr did not settle before deadline")
    })??;
    if let Some(writer) = writer {
        writer.recv_timeout(remaining()).map_err(|_| {
            anyhow::anyhow!("credential helper stdin did not settle before deadline")
        })??;
    }
    Ok(bytes)
}

pub(crate) fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid rlimit; it retains no pointer.
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0,
        "cannot disable credential-process core dumps"
    );
    // SAFETY: prctl consumes integer arguments and retains no pointers.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "cannot protect credential-process memory from dumps"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descendant_retaining_stdout_cannot_outlive_helper_deadline() {
        let start = Instant::now();
        let result = capture_with_timeout(
            Command::new("sh").args(["-c", "sleep 10 & exit 0"]),
            None,
            Duration::from_millis(150),
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn child_errors_are_redacted_and_output_is_bounded() {
        let error = capture(
            Command::new("sh").args(["-c", "echo fixture-secret >&2; exit 1"]),
            None,
        )
        .unwrap_err();
        assert!(!format!("{error:#}").contains("fixture-secret"));
        let result = capture(
            Command::new("sh").args(["-c", "head -c 1100000 /dev/zero"]),
            None,
        );
        assert!(result.is_err());
    }
}
