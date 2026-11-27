use super::{
    api::MAX_BYTES,
    config::{App, Config},
    crypto::sha256,
    now,
};
use anyhow::{Context, Result, ensure};
use nix_manager_core::fs::ExclusiveFileLock;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
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
    _lock: ExclusiveFileLock,
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
        let lock_path = directory.join("lock");
        let lock = acquire_private_lock(&lock_path, "GitHub App transaction")
            .context("GitHub App transaction is busy")?;
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

/// Create a private lock anchor, acquire an exclusive nonblocking flock via
/// `ExclusiveFileLock`, and verify descriptor-level ownership and mode on the
/// held file descriptor (eliminating path-level TOCTOU between anchor checks
/// and lock acquisition).
pub(super) fn acquire_private_lock(path: &Path, operation: &str) -> Result<ExclusiveFileLock> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let lock = ExclusiveFileLock::acquire(path, operation)?;
    private_fd_metadata(lock.as_fd())?;
    Ok(lock)
}

fn private_fd_metadata(fd: BorrowedFd<'_>) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `fd` is a valid borrowed descriptor for this call and
    // `stat.as_mut_ptr()` points to writable stack storage for `libc::stat`.
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("inspect lock descriptor metadata");
    }
    // SAFETY: `libc::fstat` succeeded and initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    ensure!(
        (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
            && stat.st_uid == unsafe { libc::geteuid() }
            && stat.st_mode & 0o077 == 0,
        "credential/transaction path must be an operator-owned private regular file or directory"
    );
    Ok(())
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
        let inherited = transaction._lock.as_fd().try_clone_to_owned().unwrap();
        assert!(Transaction::open(&directory, root.path(), &config).is_err());
        drop(transaction);
        let reopened = Transaction::open(&directory, root.path(), &config).unwrap();
        assert!(Transaction::open(&directory, root.path(), &config).is_err());
        drop(inherited);
        assert!(Transaction::open(&directory, root.path(), &config).is_err());
        drop(reopened);
        assert!(Transaction::open(&directory, root.path(), &config).is_ok());
    }

    #[test]
    fn acquire_private_lock_refuses_symlinks_and_non_private_modes() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::write(&target, []).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.path().join("link.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(acquire_private_lock(&link, "test").is_err());

        let loose = root.path().join("loose.lock");
        fs::write(&loose, []).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(acquire_private_lock(&loose, "test").is_err());
        // Failed acquisition must not leave the file locked.
        assert!(ExclusiveFileLock::try_acquire(&loose).unwrap().is_some());
    }

    #[test]
    fn acquire_private_lock_is_nonblocking_and_releases_on_drop() {
        let root = tempfile::tempdir().unwrap();
        let lock_path = root.path().join("private.lock");
        let lock = acquire_private_lock(&lock_path, "test").unwrap();
        assert!(
            ExclusiveFileLock::try_acquire(&lock_path)
                .unwrap()
                .is_none()
        );
        assert!(acquire_private_lock(&lock_path, "test").is_err());
        drop(lock);
        assert!(
            ExclusiveFileLock::try_acquire(&lock_path)
                .unwrap()
                .is_some()
        );
    }
}
