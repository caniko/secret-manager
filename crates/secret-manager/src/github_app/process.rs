use anyhow::{Result, ensure};
use std::process::Command;
use zeroize::Zeroizing;

pub(super) use crate::credential_process::capture;

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
