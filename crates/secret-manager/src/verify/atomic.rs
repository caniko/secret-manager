//! Atomic and transactional file installation helpers for encrypted sources
//! and their metadata sidecars.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail, ensure};

use crate::meta::{Metadata, sidecar_path};

/// Atomically replace an existing encrypted file with backup and rollback.
///
/// Copies the existing file to a unique sibling backup (with `sync_all` and
/// preserved permissions), removes the target, runs `encrypt`, and then runs
/// `post_hook` (e.g. rekey). If `encrypt` fails, the original file is restored.
/// If `post_hook` fails, the original file is restored and `post_hook` is run
/// a second time to recover downstream outputs.
pub fn replace_encrypted_file<E, R>(
    age_path: &Path,
    plaintext: &str,
    encrypt: E,
    mut post_hook: R,
) -> Result<()>
where
    E: FnOnce(&Path, &str) -> Result<()>,
    R: FnMut() -> Result<()>,
{
    if plaintext.trim().is_empty() {
        bail!("plaintext is empty — refusing to encrypt a blank secret");
    }
    let parent = age_path
        .parent()
        .ok_or_else(|| anyhow!("age secret has no parent directory"))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let name = age_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("age secret path is not UTF-8"))?;
    let metadata = fs::symlink_metadata(age_path).context("stat existing age secret")?;
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        age_path.display()
    );
    let original = fs::read(age_path).context("read existing age secret")?;
    let mut backup = tempfile::Builder::new()
        .prefix(&format!(".{name}.rollback-"))
        .tempfile_in(parent)
        .context("create age rollback file")?;
    backup.write_all(&original)?;
    backup.as_file().set_permissions(metadata.permissions())?;
    backup.as_file().sync_all()?;
    let (_, backup_path) = backup.keep().context("retain age rollback file")?;
    fs::File::open(parent)
        .context("open age secret parent directory")?
        .sync_all()
        .context("sync age secret parent directory")?;

    let restore = || -> Result<()> {
        fs::rename(&backup_path, age_path).with_context(|| {
            format!("restore original age secret from {}", backup_path.display())
        })?;
        fs::File::open(parent)
            .context("open age secret parent directory")?
            .sync_all()
            .context("sync age secret parent directory after restore")?;
        Ok(())
    };

    if let Err(err) = fs::remove_file(age_path) {
        let _ = fs::remove_file(&backup_path);
        return Err(err).context("prepare age secret replacement");
    }
    if let Err(err) = encrypt(age_path, plaintext) {
        restore()?;
        return Err(err).context("encrypt replacement; original age secret restored");
    }
    if let Err(err) = post_hook() {
        restore()?;
        if let Err(recovery_err) = post_hook() {
            bail!(
                "rekey replacement failed: {err:#}; original source restored, but rekey recovery failed: {recovery_err:#}"
            );
        }
        return Err(err).context("rekey replacement; original secret and rekey outputs restored");
    }
    fs::remove_file(&backup_path)
        .with_context(|| format!("remove rollback file {}", backup_path.display()))?;
    fs::File::open(parent)
        .context("open age secret parent directory")?
        .sync_all()
        .context("sync age secret parent directory after cleanup")?;
    Ok(())
}

/// Preflight a source path before PAT/credential enrollment or rotation.
///
/// Rejects lingering transaction markers (`.age.pat-txn`), stale `.age.bak`
/// files, non-regular targets, and existing files when `replace` is `false`.
pub fn check_rotation(source: &Path, replace: bool) -> Result<()> {
    let marker = transaction_marker(source);
    match marker.symlink_metadata() {
        Ok(_) => bail!("{}", recovery_message(&marker)),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("inspect {}", marker.display())),
    }
    let backup = source.with_extension("age.bak");
    match backup.symlink_metadata() {
        Ok(_) => bail!(
            "existing backup at {}; resolve it before enrolling the PAT",
            backup.display()
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("inspect {}", backup.display())),
    }
    match source.symlink_metadata() {
        Ok(info) => {
            ensure!(info.is_file(), "{} is not a regular file", source.display());
            ensure!(
                replace,
                "{} already exists; refusing to overwrite without replace",
                source.display()
            );
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("inspect {}", source.display())),
    }
    Ok(())
}

fn transaction_marker(source: &Path) -> PathBuf {
    source.with_extension("age.pat-txn")
}

fn recovery_message(marker: &Path) -> String {
    format!(
        "PAT transaction marker at {}; inspect and recover the encrypted source and metadata before removing the marker and retrying",
        marker.display()
    )
}

fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match path.symlink_metadata() {
        Ok(info) if info.is_file() => Ok(Some(fs::read(path)?)),
        Ok(_) => bail!("{} is not a regular file", path.display()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("inspect {}", path.display())),
    }
}

/// Restore a file to its previous bytes (via atomic temp-file + `sync_all` +
/// persist) or remove it if it did not previously exist.
pub fn restore_file(path: &Path, before: Option<&[u8]>) -> Result<()> {
    if read_optional_file(path)?.as_deref() == before {
        return Ok(());
    }
    if let Some(bytes) = before {
        let mut temp = tempfile::NamedTempFile::new_in(path.parent().context("missing parent")?)?;
        temp.write_all(bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Create `parent` and any missing ancestors, then `sync_all` each newly
/// created directory and the pre-existing ancestor that gained the top-most
/// new entry.
pub fn ensure_parent_dir_durable(parent: &Path) -> Result<()> {
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let mut created = Vec::new();
    let mut cursor = parent;
    while !cursor.exists() {
        created.push(cursor.to_path_buf());
        cursor = match cursor.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            Some(_) => Path::new("."),
            None => bail!("missing existing ancestor for source directory"),
        };
    }
    if created.is_empty() {
        return Ok(());
    }
    let existing_ancestor = cursor.to_path_buf();
    fs::create_dir_all(parent)?;
    for dir in created.into_iter().rev() {
        fs::File::open(&dir)?.sync_all()?;
    }
    fs::File::open(&existing_ancestor)?.sync_all()?;
    Ok(())
}

/// Write an encrypted source and its metadata sidecar as a guarded pair.
///
/// Creates a durable transaction marker before invoking `write(exists)`.
/// On error, both files are restored to their prior contents (or removed if
/// newly created) before clearing the marker. If rollback fails, the marker
/// remains on disk to block retries until recovered.
pub fn write_source_and_sidecar(
    [source, sidecar]: &[PathBuf; 2],
    write: impl FnOnce(bool) -> Result<()>,
) -> Result<()> {
    let old_source = read_optional_file(source)?;
    let old_sidecar = read_optional_file(sidecar)?;
    let dir = fs::File::open(source.parent().context("missing source directory")?)?;
    let marker = transaction_marker(source);
    let transaction = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .with_context(|| recovery_message(&marker))?;
    transaction.sync_all()?;
    dir.sync_all()?;

    let finish = || -> Result<()> {
        dir.sync_all()?;
        fs::remove_file(&marker)?;
        dir.sync_all()?;
        Ok(())
    };
    if let Err(mut error) = write(old_source.is_some()) {
        let mut restored = true;
        for (path, before) in [(source, old_source), (sidecar, old_sidecar)] {
            if let Err(restore) = restore_file(path, before.as_deref()) {
                restored = false;
                error = error.context(format!("could not restore {}: {restore:#}", path.display()));
            }
        }
        if !restored {
            return Err(error.context(recovery_message(&marker)));
        }
        if let Err(cleanup) = finish() {
            return Err(error.context(format!(
                "could not clear PAT transaction marker {} after rollback: {cleanup:#}",
                marker.display()
            )));
        }
        return Err(error);
    }
    finish().with_context(|| format!("finalize PAT transaction at {}", marker.display()))
}

/// One staged credential (encrypted source + metadata sidecar) prepared in a
/// sibling temporary directory for transactional multi-file installation.
pub struct StagedCredential {
    pub source: PathBuf,
    pub new: PathBuf,
    pub previous: PathBuf,
    staging: Option<tempfile::TempDir>,
}

impl StagedCredential {
    /// Stage a new encrypted source and its metadata sidecar inside `parent`,
    /// hard-linking any existing source/sidecar to `previous` for rollback.
    pub fn stage(
        source: PathBuf,
        parent: &Path,
        exists: bool,
        has_meta: bool,
        metadata: &Metadata,
        encrypt: impl FnOnce(&Path) -> Result<()>,
    ) -> Result<Self> {
        let staging = tempfile::tempdir_in(parent)?;
        let new = staging.path().join("new.age");
        let previous = staging.path().join("previous.age");
        if exists {
            ensure!(
                fs::symlink_metadata(&source)
                    .with_context(|| format!("inspect {}", source.display()))?
                    .is_file(),
                "{} is not a regular file",
                source.display()
            );
            fs::hard_link(&source, &previous)?;
        }
        if has_meta {
            let sidecar = sidecar_path(&source);
            ensure!(
                fs::symlink_metadata(&sidecar)
                    .with_context(|| format!("inspect {}", sidecar.display()))?
                    .is_file(),
                "{} is not a regular file",
                sidecar.display()
            );
            fs::hard_link(&sidecar, sidecar_path(&previous))?;
        }
        metadata.save(&new)?;
        encrypt(&new)?;
        Ok(Self {
            source,
            new,
            previous,
            staging: Some(staging),
        })
    }

    /// The `(target, new, previous)` path triples for the source and its sidecar.
    pub fn files(&self) -> [(PathBuf, PathBuf, PathBuf); 2] {
        [
            (self.source.clone(), self.new.clone(), self.previous.clone()),
            (
                sidecar_path(&self.source),
                sidecar_path(&self.new),
                sidecar_path(&self.previous),
            ),
        ]
    }
}

/// Publish a batch of [`StagedCredential`]s atomically, rolling back every
/// already-installed file if any step fails.
///
/// New files are installed via `hard_link` so a concurrent creation at the same
/// path fails with `AlreadyExists` rather than clobbering it; replacements use
/// `rename`. If rollback itself fails, staging directories are retained on disk.
pub fn publish_staged(staged: &mut [StagedCredential]) -> Result<()> {
    let files: Vec<_> = staged.iter().flat_map(StagedCredential::files).collect();
    let mut installed = Vec::new();
    for (target, new, previous) in &files {
        let result = (|| -> Result<()> {
            if previous.symlink_metadata().is_ok() {
                fs::rename(new, target)?;
            } else {
                fs::hard_link(new, target)?;
            }
            installed.push((target, previous));
            let parent = target.parent().context("missing source parent")?;
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if let Err(error) = result {
            let mut rollback_failed = false;
            for (target, previous) in installed.into_iter().rev() {
                let restored = (|| -> std::io::Result<()> {
                    if previous.symlink_metadata().is_ok() {
                        fs::rename(previous, target)?;
                    } else {
                        fs::remove_file(target)?;
                    }
                    if let Some(parent) = target.parent() {
                        let parent = if parent.as_os_str().is_empty() {
                            Path::new(".")
                        } else {
                            parent
                        };
                        fs::File::open(parent)?.sync_all()?;
                    }
                    Ok(())
                })();
                if let Err(error) = restored {
                    rollback_failed = true;
                    eprintln!("could not restore {}: {error}", target.display());
                }
            }
            if rollback_failed {
                for s in staged {
                    if let Some(dir) = s.staging.take() {
                        eprintln!("retained recovery files at {}", dir.keep().display());
                    }
                }
            }
            return Err(error).with_context(|| format!("install source {}", target.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn rollback_files(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains(".rollback-")
            })
            .collect()
    }

    #[test]
    fn replaces_encrypted_file_after_successful_post_hook() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.age");
        fs::write(&path, b"old").unwrap();

        replace_encrypted_file(
            &path,
            "new",
            |path, plaintext| {
                fs::write(path, plaintext)?;
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert!(rollback_files(dir.path()).is_empty());
    }

    #[test]
    fn restore_encrypted_file_on_encrypt_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.age");
        fs::write(&path, b"old").unwrap();

        let err = replace_encrypted_file(
            &path,
            "new",
            |path, _| {
                fs::write(path, b"partial")?;
                bail!("encrypt failed")
            },
            || Ok(()),
        )
        .unwrap_err();

        assert!(err.to_string().contains("original age secret restored"));
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(rollback_files(dir.path()).is_empty());
    }

    #[test]
    fn does_not_clobber_existing_backup_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.age");
        let old_backup = path.with_extension("age.bak");
        fs::write(&path, b"old").unwrap();
        fs::write(&old_backup, b"keep").unwrap();

        replace_encrypted_file(
            &path,
            "new",
            |path, plaintext| {
                fs::write(path, plaintext)?;
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();

        assert_eq!(fs::read(&old_backup).unwrap(), b"keep");
        assert!(rollback_files(dir.path()).is_empty());
    }

    #[test]
    fn restores_original_and_rekeys_after_post_hook_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.age");
        fs::write(&path, b"old").unwrap();
        let attempts = Cell::new(0);

        let err = replace_encrypted_file(
            &path,
            "new",
            |path, plaintext| {
                fs::write(path, plaintext)?;
                Ok(())
            },
            || {
                attempts.set(attempts.get() + 1);
                if attempts.get() == 1 {
                    bail!("rekey failed")
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("rekey outputs restored"));
        assert_eq!(attempts.get(), 2);
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(rollback_files(dir.path()).is_empty());
    }

    #[test]
    fn refuses_empty_plaintext_without_touching_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.age");
        fs::write(&path, b"old").unwrap();

        let err = replace_encrypted_file(&path, " \n", |_, _| unreachable!(), || unreachable!())
            .unwrap_err();

        assert!(err.to_string().contains("plaintext is empty"));
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert!(rollback_files(dir.path()).is_empty());
    }

    #[test]
    fn pair_write_restores_both_previous_files_or_their_absence() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("token.age");
        let paths = [source.clone(), sidecar_path(&source)];
        for existed in [false, true] {
            if existed {
                fs::write(&paths[0], b"old ciphertext").unwrap();
                fs::write(&paths[1], b"# original metadata with comments\n").unwrap();
            }
            let before = paths
                .each_ref()
                .map(|path| read_optional_file(path).unwrap());
            let error = write_source_and_sidecar(&paths, |replacing| {
                assert_eq!(replacing, existed);
                fs::write(&paths[0], b"new ciphertext")?;
                fs::write(&paths[1], b"new metadata")?;
                bail!("injected write error")
            })
            .unwrap_err();
            assert_eq!(error.to_string(), "injected write error");
            assert_eq!(
                paths
                    .each_ref()
                    .map(|path| read_optional_file(path).unwrap()),
                before
            );
            assert!(!paths[0].with_extension("age.pat-txn").exists());
        }
    }

    #[test]
    fn interrupted_write_blocks_retry_and_success_removes_marker() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("token.age");
        let paths = [source.clone(), sidecar_path(&source)];
        let marker = paths[0].with_extension("age.pat-txn");
        fs::write(&marker, b"").unwrap();
        let error = check_rotation(&paths[0], true).unwrap_err();
        assert!(error.to_string().contains("token.age.pat-txn"));
        assert!(write_source_and_sidecar(&paths, |_| panic!("wrote despite marker")).is_err());
        assert!(marker.is_file());

        fs::remove_file(&marker).unwrap();
        write_source_and_sidecar(&paths, |_| {
            assert!(marker.is_file());
            fs::write(&paths[0], b"ciphertext")?;
            fs::write(&paths[1], b"metadata")?;
            Ok(())
        })
        .unwrap();
        assert!(!marker.exists());
    }

    #[test]
    fn stale_backup_refuses_rotation_even_when_source_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("token.age");
        fs::write(dir.path().join("token.age.bak"), b"old ciphertext").unwrap();
        for replace in [false, true] {
            assert!(
                check_rotation(&source, replace)
                    .unwrap_err()
                    .to_string()
                    .contains("token.age.bak")
            );
        }
    }

    #[test]
    fn publish_staged_collision_restores_previous_source_and_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let first = root.join("first.age");
        let second = root.join("second.age");
        fs::write(&first, "original ciphertext").unwrap();
        Metadata {
            expiry: Some("2027-01-01".into()),
            ..Metadata::default()
        }
        .save(&first)
        .unwrap();

        let meta_new = Metadata {
            expiry: Some("2028-01-01".into()),
            ..Metadata::default()
        };
        let mut staged = vec![
            StagedCredential::stage(first.clone(), root, true, true, &meta_new, |path| {
                fs::write(path, "new ciphertext")?;
                Ok(())
            })
            .unwrap(),
            StagedCredential::stage(second.clone(), root, false, false, &meta_new, |path| {
                fs::write(path, "new second")?;
                Ok(())
            })
            .unwrap(),
        ];

        // Simulate concurrent creation of `second.age` before publish.
        fs::write(&second, "concurrent ciphertext").unwrap();
        assert!(publish_staged(&mut staged).is_err());

        assert_eq!(fs::read_to_string(&first).unwrap(), "original ciphertext");
        assert_eq!(
            Metadata::load(&first).unwrap().expiry.as_deref(),
            Some("2027-01-01")
        );
        assert_eq!(
            fs::read_to_string(&second).unwrap(),
            "concurrent ciphertext"
        );
        assert!(!sidecar_path(&second).exists());
    }
}
