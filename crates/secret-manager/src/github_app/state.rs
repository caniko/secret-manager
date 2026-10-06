use super::{
    api::MAX_BYTES,
    config::{App, Config},
    crypto::sha256,
    now,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct State {
    pub version: u32,
    pub policy_sha256: String,
    pub store_root: PathBuf,
    pub created_at: u64,
    pub nonce: String,
    #[serde(default)]
    pub callback_port: Option<u16>,
    pub phase: String,
    pub app: Option<App>,
    pub checkpoint_sha256: Option<String>,
    pub public_key_sha256: Option<String>,
    pub published_slots: Vec<String>,
}

pub(super) struct Transaction {
    pub directory: PathBuf,
    pub state: State,
    _lock: File,
}

impl Drop for Transaction {
    fn drop(&mut self) {
        // Close alone leaves a flock held by a helper's inherited open file
        // description until exec. Release this owner's lock before closing it.
        let _ = flock(&self._lock, libc::LOCK_UN);
    }
}

// These locks must also work for consumers using Rust 1.88, before std's
// File locking API was stabilized. Keep the nonblocking flock semantics and
// explicit unlock of the shared open file description.
pub(super) fn try_lock_exclusive(file: &File) -> std::io::Result<()> {
    flock(file, libc::LOCK_EX | libc::LOCK_NB)
}

fn flock(file: &File, operation: libc::c_int) -> std::io::Result<()> {
    loop {
        // SAFETY: file owns a live descriptor throughout this call. flock
        // borrows that descriptor and does not consume or access Rust memory.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

impl Transaction {
    pub fn open(directory: &Path, store: &Path, config: &Config) -> Result<Self> {
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => {
                return Err(e)
                    .context("create transaction directory; its parent must already exist");
            }
        }
        private_metadata(directory, true)?;
        let directory = directory.canonicalize()?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(directory.join("lock"))?;
        private_metadata(&directory.join("lock"), false)?;
        try_lock_exclusive(&lock).context("GitHub App transaction is busy")?;
        let policy_sha256 = sha256(&serde_json::to_vec(config)?);
        let path = directory.join("state.json");
        let state = if path.exists() {
            private_metadata(&path, false)?;
            let state: State = serde_json::from_slice(&read_bounded(&path)?)?;
            ensure!(
                state.version == 1
                    && state.policy_sha256 == policy_sha256
                    && state.store_root == store,
                "transaction belongs to a different policy or store; use a new private transaction directory"
            );
            state
        } else {
            ensure!(
                !directory.join("issued.age").exists(),
                "orphaned encrypted checkpoint requires explicit recovery"
            );
            State {
                version: 1,
                policy_sha256,
                store_root: store.to_owned(),
                created_at: now()?,
                nonce: super::random_nonce(),
                callback_port: None,
                phase: "prepared".into(),
                app: None,
                checkpoint_sha256: None,
                public_key_sha256: None,
                published_slots: Vec::new(),
            }
        };
        let transaction = Self {
            directory,
            state,
            _lock: lock,
        };
        transaction.save()?;
        Ok(transaction)
    }

    pub fn save(&self) -> Result<()> {
        atomic_write(
            &self.directory.join("state.json"),
            &serde_json::to_vec_pretty(&self.state)?,
        )
    }

    pub fn checkpoint(&mut self, ciphertext: &[u8]) -> Result<()> {
        let path = self.directory.join("issued.age");
        ensure!(
            !path.exists(),
            "encrypted enrollment already exists; refusing to overwrite it"
        );
        atomic_write(&path, ciphertext)?;
        self.state.checkpoint_sha256 = Some(sha256(ciphertext));
        self.save()
    }

    pub fn checked_checkpoint(&mut self) -> Result<PathBuf> {
        let path = self.directory.join("issued.age");
        private_metadata(&path, false)?;
        let digest = sha256(&read_bounded(&path)?);
        // Ciphertext is durable before its hash is checkpointed. Resume only
        // that pending capture window; an enrolled transaction must stay bound
        // to its previously recorded ciphertext, including on refusal paths.
        if self.state.checkpoint_sha256.is_none()
            && matches!(
                self.state.phase.as_str(),
                "capture-started" | "exchange-started"
            )
        {
            self.state.checkpoint_sha256 = Some(digest.clone());
            self.save()?;
        }
        ensure!(
            self.state.checkpoint_sha256.as_ref() == Some(&digest),
            "encrypted enrollment checkpoint hash does not match transaction"
        );
        Ok(path)
    }
}

pub(super) fn private_metadata(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink()
            && (if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            })
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0,
        "credential/transaction path must be an operator-owned private regular file or directory"
    );
    Ok(())
}

pub(super) fn read_bounded(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_BYTES, "file exceeds size limit");
    Ok(bytes)
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output needs a parent directory")?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "refusing to replace a non-regular output"
        );
    }
    let mut staging = tempfile::NamedTempFile::new_in(parent)?;
    staging.write_all(bytes)?;
    staging.as_file().sync_all()?;
    staging.persist(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) fn source_path(store: &Path, config: &Config) -> Result<PathBuf> {
    let mut path = store.to_owned();
    let parent = config.source.parent().context("source needs a parent")?;
    for component in parent.components() {
        path.push(component);
        if !path.exists() {
            fs::create_dir(&path)?;
        }
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o022 == 0,
            "source parent must be operator-owned, non-writable by others and not a symlink"
        );
    }
    path.push(
        config
            .source
            .file_name()
            .context("source needs a filename")?,
    );
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "source must be a regular file"
        );
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_transaction_releases_lock_with_an_inherited_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("transaction");
        let config = super::super::tests::policy();
        let transaction = Transaction::open(&directory, root.path(), &config).unwrap();
        // A concurrent helper can inherit the open file description between
        // fork and exec, even though Rust opens the descriptor CLOEXEC.
        let inherited = transaction._lock.try_clone().unwrap();
        assert!(Transaction::open(&directory, root.path(), &config).is_err());
        drop(transaction);
        let reopened = Transaction::open(&directory, root.path(), &config).unwrap();
        assert!(Transaction::open(&directory, root.path(), &config).is_err());
        drop(inherited);
        assert!(Transaction::open(&directory, root.path(), &config).is_err());
        drop(reopened);
        assert!(Transaction::open(&directory, root.path(), &config).is_ok());
    }
}
