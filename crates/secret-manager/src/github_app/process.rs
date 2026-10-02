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

/// Bound output and execution time, drain both pipes, never display child
/// diagnostics (gh debug output can contain keys and Authorization headers).
pub(super) fn capture(command: &mut Command, input: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    capture_with_timeout(command, input, Duration::from_secs(90))
}

fn capture_with_timeout(
    command: &mut Command,
    input: Option<&[u8]>,
    timeout: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    command
        .env_remove("GH_DEBUG")
        .env_remove("AGEDEBUG")
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("start credential helper")?;
    struct Cleanup(std::process::Child);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            // Descendants can retain stdin/stdout after their parent exits.
            // Own the process group until every pipe has settled.
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
    let output = child.stdout.take().context("helper stdout unavailable")?;
    let errors = child.stderr.take().context("helper stderr unavailable")?;
    let read = |mut stream: Box<dyn Read + Send>| -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut stream)
            .take((super::api::MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= super::api::MAX_BYTES,
            "credential helper output exceeds size limit"
        );
        Ok(bytes)
    };
    let (output_send, output_recv) = mpsc::channel();
    let (error_send, error_recv) = mpsc::channel();
    thread::spawn(move || {
        let _ = output_send.send(read(Box::new(output)));
    });
    thread::spawn(move || {
        let _ = error_send.send(read(Box::new(errors)));
    });
    let writer = child.stdin.take().map(|mut stdin| {
        let bytes = Zeroizing::new(input.unwrap_or_default().to_vec());
        let (send, recv) = mpsc::channel();
        thread::spawn(move || {
            let _ = send.send(stdin.write_all(&bytes));
        });
        recv
    });
    let mut child = Cleanup(child);
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
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

pub(super) fn gh(args: &[&str], input: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    capture(
        Command::new("gh")
            .env("GH_HOST", "github.com")
            .env("GH_PROMPT_DISABLED", "1")
            .args(args),
        input,
    )
}

pub(super) fn encrypt(config: &super::config::Config, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut command = Command::new("rage");
    command.arg("--encrypt");
    for recipient in &config.recipients {
        command.arg("--recipient").arg(recipient);
    }
    let encrypted = capture(&mut command, Some(bytes))?;
    ensure!(
        encrypted.starts_with(b"age-encryption.org/v1\n"),
        "helper did not produce an age ciphertext"
    );
    Ok(encrypted)
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
}
