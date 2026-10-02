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
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
        lock.try_lock().context("GitHub App transaction is busy")?;
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

    pub fn checked_checkpoint(&self) -> Result<PathBuf> {
        let path = self.directory.join("issued.age");
        private_metadata(&path, false)?;
        ensure!(
            self.state.checkpoint_sha256.as_ref() == Some(&sha256(&read_bounded(&path)?)),
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
