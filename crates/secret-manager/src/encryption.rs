//! Direct stdin encryption with the consumer's agenix-rekey master policy.
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::credential_process::{MAX_BYTES, capture_with_timeout, disable_core_dumps};

/// Executable produced by `lib.mkAgenixStreamEncryptor`, accepting `encrypt`
/// followed by native age arguments. It carries public policy, never plaintext.
#[derive(Debug, Clone)]
pub struct StreamEncryptor {
    executable: PathBuf,
    timeout: Duration,
}

/// Serialize source installation and distribution with the same store lock as
/// generated-secret rotation. Prepare public encryption policy and retrieve
/// vault data before entering this closure; hold it through staging/rekey.
pub fn with_store_write_lock<T>(root: &Path, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let _guard = crate::rotate::acquire_lock(root)?;
    operation()
}

impl StreamEncryptor {
    pub fn new(executable: PathBuf) -> Result<Self> {
        ensure!(
            executable.is_absolute() && executable.is_file(),
            "agenix stream encryptor must be an existing absolute executable path"
        );
        Ok(Self {
            executable,
            timeout: Duration::from_secs(90),
        })
    }

    pub fn from_env() -> Result<Self> {
        let executable = std::env::var_os("SECRET_MANAGER_AGE_ENCRYPTOR")
            .context("direct imports require SECRET_MANAGER_AGE_ENCRYPTOR pointing to lib.mkAgenixStreamEncryptor's executable")?;
        Self::new(PathBuf::from(executable))
    }

    /// Allows an embedding application to validate/project a login document
    /// in memory before encryption. No plaintext file or command argument.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            !plaintext.is_empty() && plaintext.len() <= MAX_BYTES / 2,
            "credential payload must be nonempty and at most 512 KiB"
        );
        disable_core_dumps()?;
        let encrypted = capture_with_timeout(
            Command::new(&self.executable).arg("encrypt"),
            Some(plaintext),
            self.timeout,
        )
        .context("agenix master encryption failed; encrypted sources were not replaced")?;
        ensure!(
            encrypted.starts_with(b"age-encryption.org/v1\n") && encrypted.len() > 64,
            "agenix backend did not produce an age ciphertext"
        );
        Ok(encrypted)
    }

    /// Persist a completely encrypted new source without replacing existing
    /// ciphertext, a symlink, or a source concurrently created by another writer.
    pub fn encrypt_new(&self, path: &Path, plaintext: &[u8]) -> Result<()> {
        require_missing(path)?;
        let ciphertext = self.encrypt(plaintext)?;
        persist(path, &ciphertext, None)
    }

    /// Explicit rotation. Callers serialize source/rekey operations with the
    /// store lock. The old ciphertext stays in place until encryption succeeds.
    pub fn encrypt_replace(&self, path: &Path, plaintext: &[u8]) -> Result<()> {
        let previous = existing_ciphertext(path)?;
        let ciphertext = self.encrypt(plaintext)?;
        persist(path, &ciphertext, Some(&previous))
    }
}

pub(crate) fn require_missing(path: &Path) -> Result<()> {
    ensure!(
        path.symlink_metadata()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "encrypted source already exists or cannot be inspected; use --rbw-rotate for explicit rotation"
    );
    Ok(())
}

pub(crate) fn existing_ciphertext(path: &Path) -> Result<Vec<u8>> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("rotation requires an existing regular encrypted source")?;
    ensure!(
        file.metadata()?.is_file(),
        "rotation requires a regular encrypted source"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_BYTES && bytes.starts_with(b"age-encryption.org/v1\n"),
        "rotation source is not a supported age ciphertext"
    );
    Ok(bytes)
}

fn persist(path: &Path, ciphertext: &[u8], previous: Option<&[u8]>) -> Result<()> {
    let parent = path
        .parent()
        .context("encrypted source needs a parent directory")?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(ciphertext)?;
    temporary.as_file().sync_all()?;
    if let Some(previous) = previous {
        ensure!(
            existing_ciphertext(path)? == previous,
            "encrypted source changed during encryption; refusing replacement"
        );
        temporary
            .persist(path)
            .map_err(|_| anyhow::anyhow!("cannot install replacement ciphertext"))?;
    } else {
        temporary.persist_noclobber(path).map_err(|_| {
            anyhow::anyhow!("cannot install ciphertext without replacing an existing source")
        })?;
    }
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn backend(root: &Path, script: &str) -> StreamEncryptor {
        let executable = root.join("encryptor");
        fs::write(&executable, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        StreamEncryptor::new(executable).unwrap()
    }

    #[test]
    fn real_age_round_trip_and_explicit_rotation_keep_only_ciphertext() {
        let root = tempfile::tempdir().unwrap();
        let identity =
            crate::credential_process::capture(&mut Command::new("rage-keygen"), None).unwrap();
        let recipient = crate::credential_process::capture(
            Command::new("rage-keygen").arg("-y"),
            Some(&identity),
        )
        .unwrap();
        let identity_path = root.path().join("identity");
        fs::write(&identity_path, &identity).unwrap();
        let encryptor = backend(
            root.path(),
            &format!(
                "[ \"$1\" = encrypt ] || exit 2\nshift\nexec rage --encrypt -r '{}' \"$@\"",
                std::str::from_utf8(&recipient).unwrap().trim()
            ),
        );
        let path = root.path().join("credential.age");
        encryptor.encrypt_new(&path, b"fixture-password").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let previous = fs::read(&path).unwrap();
        assert!(
            !previous
                .windows(16)
                .any(|window| window == b"fixture-password")
        );
        assert!(encryptor.encrypt_new(&path, b"other-password").is_err());
        assert_eq!(fs::read(&path).unwrap(), previous);
        let decrypt = || {
            crate::credential_process::capture(
                Command::new("rage")
                    .arg("--decrypt")
                    .arg("-i")
                    .arg(&identity_path)
                    .arg(&path),
                None,
            )
            .unwrap()
        };
        assert_eq!(decrypt().as_slice(), b"fixture-password");
        encryptor
            .encrypt_replace(&path, b"rotated-password")
            .unwrap();
        assert_eq!(decrypt().as_slice(), b"rotated-password");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 3);
    }

    #[test]
    fn failed_or_malformed_encryption_preserves_existing_source_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("credential.age");
        let previous = b"age-encryption.org/v1\nprevious-ciphertext";
        fs::write(&path, previous).unwrap();
        for script in ["cat >/dev/null; echo fixture-secret >&2; exit 1", "cat"] {
            let encryptor = backend(root.path(), script);
            let error = encryptor
                .encrypt_replace(&path, b"fixture-secret")
                .unwrap_err();
            assert!(!format!("{error:#}").contains("fixture-secret"));
            assert_eq!(fs::read(&path).unwrap(), previous);
            assert!(
                encryptor
                    .encrypt_new(&root.path().join("missing.age"), b"fixture-secret")
                    .is_err()
            );
            assert!(!root.path().join("missing.age").exists());
        }
        let link = root.path().join("link.age");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let encryptor = backend(root.path(), "cat");
        assert!(encryptor.encrypt_new(&link, b"fixture-secret").is_err());
        assert!(encryptor.encrypt_replace(&link, b"fixture-secret").is_err());
        assert_eq!(fs::read(&path).unwrap(), previous);
    }

    #[test]
    fn concurrent_source_changes_are_not_clobbered() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("credential.age");
        let previous = b"age-encryption.org/v1\nold-ciphertext";
        let changed = b"age-encryption.org/v1\nconcurrent-ciphertext";
        fs::write(&path, changed).unwrap();
        let output = b"age-encryption.org/v1\nnew-ciphertext";
        assert!(persist(&path, output, Some(previous)).is_err());
        assert!(persist(&path, output, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), changed);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}
