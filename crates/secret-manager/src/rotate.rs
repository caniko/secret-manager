//! Idempotent provisioning and on-demand rotation for generated agenix
//! secret sources.
//!
//! Shape-agnostic: works for any `.age` source whose Nix declaration carries
//! a `generator`, whether the declaration was rendered by
//! `canix secret ... password` or written by hand. Rotation never observes
//! key material — generation runs inside `agenix generate`, so the operator
//! (and this process) stays zero-knowledge.
//!
//! Lifecycle: without `--force` this is ensure-or-preserve (a missing source
//! is created, an existing one is left byte-identical); `--force` replaces
//! an existing source. Failure safety comes in two separate stages:
//!
//! 1. Source replacement. The existing source is *copied* aside (never
//!    moved), then regenerated with `agenix generate --force-generate`.
//!    Generation flags are passed explicitly — never `-a` — and inherited
//!    auto-staging (`AGENIX_REKEY_ADD_TO_GIT`) is always stripped from
//!    rotation children, so staging happens only through the explicit
//!    `git add` calls below. A failed run leaves both worktree and index
//!    exactly as found, and the backup restores the previous bytes atomically
//!    (temp file plus rename). Fresh
//!    output must parse as an age file (binary header plus plausible body,
//!    or armored output with both delimiters), not merely be non-empty.
//!    A repo-local kernel lock — inherited by spawned children so it
//!    outlives a killed wrapper until orphans finish — serializes whole
//!    runs; existence is re-read under the lock, and preserve mode refuses
//!    ambiguous interrupted state instead of blessing it.
//! 2. Distribution. `agenix rekey` fans the new source out to rekeyed
//!    copies. If this fails, the new source is *kept*: the failure reports
//!    "distribution incomplete" with a rekey-only retry command, instead of
//!    pretending a multi-file operation was rolled back by restoring one
//!    file.

use anyhow::{Result, anyhow, bail};
use clap::Args;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use nix_manager_core::exec;

use crate::io::display_rel;

/// Suffix for the in-flight rotation backup. Deliberately not `.age`, so
/// agenix globs and `secret list` never pick it up.
const BACKUP_SUFFIX: &str = "rotbak";

/// Store subdirectory (relative to the repo root) that `agenix rekey`
/// fans sources out to. Used to scope distribution staging.
const REKEYED_DIR: &str = "age/rekeyed";

/// Marker the store repo root must contain. Rotation refuses to run
/// anywhere else so a stray invocation cannot scatter backups.
const REPO_MARKER: &str = "flake.nix";

/// Name of the repo-local mutual-exclusion anchor. Lives inside `.git` so
/// it never shows up in status output; on a bare checkout without a `.git`
/// directory it falls back to a dotfile at the repo root. The anchor file
/// itself persists; only the kernel lock on it serializes runs.
const LOCK_NAME: &str = "secret-manager-rotate.lock";

/// Inherited setting that makes agenix stage on its own. Stripped from
/// child environments whenever `--no-stage` is passed.
const ADD_TO_GIT_ENV: &str = "AGENIX_REKEY_ADD_TO_GIT";

/// Every age v1 file starts with this header line. Armor uses the
/// standard PEM-style prelude instead. A "successful" generate that
/// produces neither is a partial write, not a key.
const AGE_MAGIC: &[u8] = b"age-encryption.org v1\n";
const AGE_ARMOR_BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

#[derive(Args, Debug)]
pub struct RotateArgs {
    /// Repo-relative path to the agenix-tracked .age source. A missing
    /// source is created; an existing one is preserved unless `--force`
    /// is given (the declaration must carry a `generator` either way).
    pub secret_path: String,

    /// Replace an existing source instead of preserving it.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Skip the trailing `agenix rekey`. Generation is touchless; rekey
    /// needs the FIDO2 master key, so split them when batching touches.
    #[arg(long, default_value_t = false)]
    pub no_rekey: bool,

    /// Skip `git add` staging of the rotated source and rekeyed copies.
    /// Inherited agenix auto-staging is always suppressed for rotation
    /// children; only the explicit staging calls in this command stage.
    #[arg(long, default_value_t = false)]
    pub no_stage: bool,
}

impl RotateArgs {
    pub fn run(&self) -> Result<()> {
        let repo_root = discover_root()?;
        let rel = contained_rel(&repo_root, &self.secret_path)?;
        let secret_path = ensure_parent(&repo_root, &rel)?;

        // Serialize whole runs (create and replace alike, across sources)
        // with a kernel-held lock BEFORE reading source state: rekey is
        // repository-wide, so per-source backups alone cannot exclude
        // interleaving, and an existence check outside the lock is stale
        // the moment another rotation starts. The lock file itself is a
        // persistent anchor and is never unlinked; the kernel releases the
        // lock when the holder exits, including on crash or kill.
        let _guard = acquire_lock(&repo_root)?;
        // Re-read under the lock: a concurrent run may have created,
        // replaced, or removed the source since any earlier observation.
        let existed = try_is_regular_file(&secret_path)?;
        if !existed && secret_path.symlink_metadata().is_ok() {
            bail!(
                "refusing to rotate {}: not a regular file",
                display_rel(&repo_root, &secret_path)
            );
        }

        if existed && !self.force {
            // Preserve means "leave byte-identical" — but only when the
            // on-disk state is unambiguous. A leftover backup means an
            // earlier run died mid-replacement (we cannot tell which copy
            // is good), and a source without an age header is already
            // damaged. Reporting either as "preserved" would bless an
            // unknown state as healthy.
            let backup_path = backup_path_for(&secret_path);
            if backup_path.exists() {
                bail!(
                    "refusing to preserve {}: leftover backup {} means a previous rotation was interrupted; inspect both files, restore or remove the backup manually, then retry",
                    display_rel(&repo_root, &secret_path),
                    display_rel(&repo_root, &backup_path)
                );
            }
            validate_usable(&repo_root, &secret_path).map_err(|e| {
                anyhow!(
                    "refusing to preserve {}: {e}\n  pass --force to replace it, or restore a known-good copy first",
                    display_rel(&repo_root, &secret_path)
                )
            })?;
            eprintln!(
                "preserved {} (already exists; pass --force to rotate)",
                display_rel(&repo_root, &secret_path)
            );
            eprintln!(
                "distribution untouched; run `agenix rekey -a` if recipients may be out of date."
            );
            return Ok(());
        }

        let result = self.run_locked(&repo_root, &rel, &secret_path, existed);
        result
    }

    fn run_locked(
        &self,
        repo_root: &Path,
        rel: &Path,
        secret_path: &Path,
        existed: bool,
    ) -> Result<()> {
        let backup_path = backup_path_for(secret_path);
        // Copy (never move) the working source aside. Exclusive creation
        // fails fast on a leftover backup instead of interleaving with it.
        if existed {
            create_backup(secret_path, &backup_path, repo_root)?;
        }

        let outcome = regenerate(repo_root, rel, existed)
            .and_then(|()| validate_fresh(repo_root, secret_path))
            .and_then(|()| stage_source(repo_root, rel, self.no_stage));
        if let Err(e) = outcome {
            if existed {
                // Keep the original failure visible when recovery fails
                // too: a bare restore error would hide what went wrong.
                restore(secret_path, &backup_path, repo_root).map_err(|r| {
                    anyhow!("{e}\n  and restoration of the previous source also failed: {r}")
                })?;
            } else {
                remove_partial(secret_path);
            }
            return Err(e);
        }
        if existed {
            remove_backup(&backup_path, repo_root)?;
        }

        if !self.no_rekey {
            distribute(repo_root, rel, self.no_stage)?;
        } else {
            eprintln!("skipped rekey — run `agenix rekey -a` before deploying.");
        }
        eprintln!(
            "{} {} (new key material generated by `agenix generate`)",
            if existed { "rotated" } else { "created" },
            display_rel(repo_root, secret_path)
        );
        Ok(())
    }
}

/// Walk up from the working directory to the store repo root. Refuses to
/// guess: without the marker there is no evidence the mutations below
/// would land in a store repo.
fn discover_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir()?;
    loop {
        if dir.join(REPO_MARKER).is_file() {
            return Ok(dir);
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => bail!(
                "no {REPO_MARKER} found above the working directory; run rotate inside the store repo"
            ),
        }
    }
}

/// Resolve a caller-supplied path against the repo root, refusing anything
/// that is not a plain in-tree `.age` file. Symlink sources are refused:
/// rotation must never follow a redirect it did not create.
fn contained_rel(repo_root: &Path, input: &str) -> Result<PathBuf> {
    if input.is_empty() {
        bail!("rotate needs a repo-relative .age path, got an empty string");
    }
    let rel = PathBuf::from(input);
    if rel.is_absolute() {
        bail!("rotate takes a repo-relative path, got {}", rel.display());
    }
    if rel.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("rotate takes a path inside the repo, got {}", rel.display());
    }
    if rel.extension().is_none_or(|ext| ext != "age") {
        bail!("rotate expects an .age source, got {}", rel.display());
    }
    let abs = repo_root.join(&rel);
    if abs
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        bail!(
            "refusing to rotate symlink {}; point rotate at the real file",
            display_rel(repo_root, &abs)
        );
    }
    // Canonicalize the nearest existing ancestor: the parent itself may
    // not exist yet on the create path. `..` is already rejected above,
    // so walking up from an in-root lexical path always reaches the root.
    let canon_root = repo_root
        .canonicalize()
        .map_err(|e| anyhow!("cannot resolve repo root {}: {e}", repo_root.display()))?;
    let mut ancestor = abs
        .parent()
        .ok_or_else(|| anyhow!("cannot resolve parent of {}", display_rel(repo_root, &abs)))?;
    loop {
        match ancestor.canonicalize() {
            Ok(canon) => {
                if !canon.starts_with(&canon_root) {
                    bail!("rotate takes a path inside the repo, got {}", rel.display());
                }
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ancestor = ancestor.parent().ok_or_else(|| {
                    anyhow!("cannot resolve parent of {}", display_rel(repo_root, &abs))
                })?;
            }
            Err(e) => {
                return Err(anyhow!(
                    "parent directory of {} is unreachable: {e}",
                    display_rel(repo_root, &abs)
                ));
            }
        }
    }
    Ok(rel)
}

/// Create the source's parent directory (create path), re-verifying
/// containment afterwards so a planted symlink cannot redirect it.
fn ensure_parent(repo_root: &Path, rel: &Path) -> Result<PathBuf> {
    let abs = repo_root.join(rel);
    let parent = abs
        .parent()
        .ok_or_else(|| anyhow!("cannot resolve parent of {}", display_rel(repo_root, &abs)))?;
    fs::create_dir_all(parent)?;
    let canon_root = repo_root
        .canonicalize()
        .map_err(|e| anyhow!("cannot resolve repo root {}: {e}", repo_root.display()))?;
    if !parent.canonicalize()?.starts_with(&canon_root) {
        bail!("rotate takes a path inside the repo, got {}", rel.display());
    }
    Ok(abs)
}

/// Repo-local mutual exclusion for whole runs, held via a kernel `flock`
/// on a persistent anchor file. The anchor is created on first use and
/// never unlinked; the kernel releases the lock when the last holder
/// exits, including on crash or kill.
///
/// The lock fd is deliberately left inheritable (CLOEXEC cleared): every
/// `agenix`/`git` child spawned below shares the same open file
/// description, so killing the wrapper does NOT release the lock while an
/// orphaned child may still be mutating the repo. A competing run then
/// keeps refusing until the orphan finishes. Dropping the guard in the
/// wrapper only closes our own fd.
struct RotationLock {
    _file: fs::File,
}

fn lock_path(repo_root: &Path) -> PathBuf {
    // Resolve through Git so linked worktrees (whose `.git` is a pointer
    // file) get their own private git dir instead of colliding on — or
    // failing to create — a shared anchor. Falls back to the old
    // `.git`-directory probe when Git itself is unavailable.
    let git_dir = exec::cap_in(repo_root, "git", ["rev-parse", "--absolute-git-dir"]);
    if git_dir.exit_code == 0 {
        let dir = PathBuf::from(git_dir.stdout.trim());
        let abs = if dir.is_absolute() {
            dir
        } else {
            repo_root.join(dir)
        };
        if abs.is_dir() {
            return abs.join(LOCK_NAME);
        }
    }
    let dotgit = repo_root.join(".git");
    if dotgit.is_dir() {
        dotgit.join(LOCK_NAME)
    } else {
        repo_root.join(format!(".{LOCK_NAME}"))
    }
}

fn acquire_lock(repo_root: &Path) -> Result<RotationLock> {
    use std::os::unix::io::AsRawFd;

    let path = lock_path(repo_root);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| {
            anyhow!(
                "cannot open rotation lock {}: {e}",
                display_rel(repo_root, &path)
            )
        })?;
    // Non-blocking: a second rotation fails fast instead of queueing
    // behind a rekey that may wait on a hardware touch.
    // ponytail: raw libc instead of an flock crate; the call is three
    // lines and the crate would exist only for this.
    //
    // CLOEXEC must stay CLEAR on this fd (Rust leaves inherited fds
    // alone across spawn): children share the open file description, so
    // the kernel lock outlives a killed wrapper until its orphaned
    // children finish mutating. Rust's std sets CLOEXEC on files it
    // opens, so clear it explicitly. A competing run that only probes
    // the lock then observes the orphan, not a false free.
    let rc = unsafe {
        libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0);
        libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::WouldBlock {
            bail!(
                "another rotation is running (lock {} is held); wait for it to finish and retry",
                display_rel(repo_root, &path)
            );
        }
        bail!("cannot lock {}: {e}", display_rel(repo_root, &path));
    }
    Ok(RotationLock { _file: file })
}

fn backup_path_for(secret_path: &Path) -> PathBuf {
    let mut name = secret_path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    name.push(format!(".{BACKUP_SUFFIX}"));
    secret_path.with_file_name(name)
}

fn try_is_regular_file(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(m) => Ok(m.is_file() && !m.file_type().is_symlink()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(anyhow!("cannot stat {}: {e}", path.display())),
    }
}

/// Copy the working source to the backup path, creating it exclusively so
/// a leftover backup fails fast instead of being silently overwritten.
fn create_backup(secret_path: &Path, backup_path: &Path, repo_root: &Path) -> Result<()> {
    let mut backup = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(backup_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow!(
                    "stale rotation backup {} — a previous rotation was interrupted; inspect it, restore or remove it manually, then retry",
                    display_rel(repo_root, backup_path)
                )
            } else {
                anyhow!(
                    "cannot create rotation backup {}: {e}",
                    display_rel(repo_root, backup_path)
                )
            }
        })?;
    let bytes = fs::read(secret_path)?;
    backup.write_all(&bytes)?;
    backup.sync_all()?;
    Ok(())
}

/// Spawn a child with inherited stdio, mirroring exec::run_in's reporting.
/// exec's runners cannot drop inherited environment entries, and agenix
/// honors auto-staging (`AGENIX_REKEY_ADD_TO_GIT`) from the environment, so
/// rotation always strips it: staging happens only through the explicit
/// `git add` calls below, on both the default and the `--no-stage` path.
fn run_child(repo_root: &Path, program: &str, args: &[&str]) -> Result<()> {
    eprintln!("$ ({}) {} {}", repo_root.display(), program, args.join(" "));
    let mut cmd = std::process::Command::new(program);
    cmd.args(args).current_dir(repo_root);
    cmd.env_remove(ADD_TO_GIT_ENV);
    let status = cmd
        .status()
        .map_err(|e| anyhow!("failed to spawn {program} in {}: {e}", repo_root.display()))?;
    if !status.success() {
        return Err(anyhow!(
            "{program} exited with status {} in {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "<signal>".into()),
            repo_root.display()
        ));
    }
    Ok(())
}

/// Same shape `run_plan` uses for fresh generated secrets, minus `-a`:
/// staging is done explicitly afterwards so `--no-stage` is honored and a
/// failed run stages nothing.
fn regenerate(repo_root: &Path, rel: &Path, existed: bool) -> Result<()> {
    let rel = rel
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 secret path"))?;
    let mut args = vec!["generate"];
    if existed {
        args.push("--force-generate");
    }
    args.push(rel);
    run_child(repo_root, "agenix", &args).map_err(|e| {
        anyhow!(
            "{e}\n  hint: rotation needs a `generator` on the secret's Nix declaration (e.g. `generator.script = \"strong-passphrase-64\"`); the previous source is untouched"
        )
    })
}

/// Smallest plausible age file: the 23-byte magic plus one recipient
/// stanza, one body line, and the MAC line total well over a hundred
/// bytes. Anything shorter with a valid header is a torn write.
/// (Full integrity still needs decryption; this is a truncation detector.)
const MIN_AGE_BYTES: usize = 64;

/// Armored age files must open AND close. A BEGIN without END is a torn
/// write even when the prefix check passes.
const AGE_ARMOR_END: &[u8] = b"-----END AGE ENCRYPTED FILE-----";

/// Check that an existing source is worth preserving: present, non-empty,
/// and carrying an age header. Used on the preserve path so an
/// interrupted earlier run is never blessed as healthy.
fn validate_usable(repo_root: &Path, secret_path: &Path) -> Result<()> {
    let bytes = fs::read(secret_path)
        .map_err(|e| anyhow!("cannot read {}: {e}", display_rel(repo_root, secret_path)))?;
    check_age_shape(&bytes).map_err(|why| {
        anyhow!(
            "{} looks damaged ({why})",
            display_rel(repo_root, secret_path)
        )
    })
}

fn check_age_shape(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.is_empty() {
        return Err("empty file");
    }
    if bytes.starts_with(AGE_MAGIC) {
        if bytes.len() < MIN_AGE_BYTES {
            return Err("binary header with truncated body");
        }
        return Ok(());
    }
    if bytes.starts_with(AGE_ARMOR_BEGIN) {
        if !bytes
            .windows(AGE_ARMOR_END.len())
            .any(|w| w == AGE_ARMOR_END)
        {
            return Err("armored file without END delimiter");
        }
        return Ok(());
    }
    Err("no age file header (binary or armored)")
}

fn validate_fresh(repo_root: &Path, secret_path: &Path) -> Result<()> {
    let bytes = fs::read(secret_path).map_err(|e| {
        anyhow!(
            "`agenix generate` reported success but {} is missing ({e}); the previous source is untouched",
            display_rel(repo_root, secret_path)
        )
    })?;
    check_age_shape(&bytes).map_err(|why| {
        anyhow!(
            "`agenix generate` wrote {} that fails structural checks ({why}); treating it as a partial write, the previous source is untouched",
            display_rel(repo_root, secret_path)
        )
    })?;
    Ok(())
}

fn stage_source(repo_root: &Path, rel: &Path, no_stage: bool) -> Result<()> {
    if no_stage {
        return Ok(());
    }
    let rel = rel
        .to_str()
        .ok_or_else(|| anyhow!("non-utf8 secret path"))?;
    exec::run_in(repo_root, "git", ["add", rel])
}

/// Content snapshot of status-listed files, keyed by repo-relative path.
/// Read failures fail the whole snapshot — except for files that simply
/// do not exist (a rekey may legitimately delete a copy, and staging that
/// deletion is correct). Staging on a guessed file set would be worse
/// than refusing.
fn snapshot_content(
    repo_root: &Path,
    names: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<PathBuf, Option<u64>>> {
    let mut snapshot = BTreeMap::new();
    for name in names {
        let abs = repo_root.join(name);
        match fs::read(&abs) {
            Ok(bytes) => {
                let mut hasher = DefaultHasher::new();
                bytes.hash(&mut hasher);
                snapshot.insert(name.clone(), Some(hasher.finish()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                snapshot.insert(name.clone(), None);
            }
            Err(e) => {
                bail!("cannot read {}: {e}", display_rel(repo_root, &abs));
            }
        }
    }
    Ok(snapshot)
}

/// Fan the new source out to rekeyed copies. On failure the new source is
/// deliberately kept: restoring one file cannot roll back a multi-file
/// distribution, so report it as incomplete with a rekey-only retry.
/// Staging compares file *contents* before and after, so pre-existing dirt
/// and concurrent-but-identical writes are never swept in, and genuinely
/// redistributed copies are never missed.
fn distribute(repo_root: &Path, rel: &Path, no_stage: bool) -> Result<()> {
    let before_names = status_names(repo_root).map_err(|e| {
        anyhow!(
            "source {} updated, but distribution state is unknown: {e}; verify with `git status` and distribute with `agenix rekey -a`",
            display_rel(repo_root, &repo_root.join(rel))
        )
    })?;
    // Refuse to auto-stage into a dirty scope: with pre-existing changes
    // we cannot attribute staged bytes to this operation, and the hash
    // diff below could sweep unrelated work into the commit. The operator
    // either commits first or takes staging over with --no-stage.
    if !no_stage && !before_names.is_empty() {
        let mut listed: Vec<_> = before_names.iter().take(5).collect();
        listed.sort();
        let listed: Vec<_> = listed.iter().filter_map(|p| p.to_str()).collect();
        bail!(
            "source {} updated, but {REKEYED_DIR} already has uncommitted changes ({}); commit, stash, or re-run with --no-stage and stage manually, then distribute with `agenix rekey -a`",
            display_rel(repo_root, &repo_root.join(rel)),
            listed.join(", ")
        );
    }
    let before = snapshot_content(repo_root, &before_names).map_err(|e| {
        anyhow!(
            "source {} updated, but distribution state is unknown: {e}; verify with `git status` and distribute with `agenix rekey -a`",
            display_rel(repo_root, &repo_root.join(rel))
        )
    })?;
    // No `-a`, and inherited auto-staging is always stripped in
    // run_child: rekeyed copies are staged explicitly below.
    if let Err(e) = run_child(repo_root, "agenix", &["rekey"]) {
        return Err(anyhow!(
            "source {} updated, but distribution is incomplete: {e}\n  retry with `agenix rekey -a` (no new key will be generated)",
            display_rel(repo_root, &repo_root.join(rel))
        ));
    }
    if no_stage {
        return Ok(());
    }
    let after_names = status_names(repo_root).map_err(|e| {
        anyhow!(
            "rekey completed, but changed files could not be determined: {e}; inspect `git status` under {REKEYED_DIR} and stage the redistributed copies"
        )
    })?;
    let after = snapshot_content(repo_root, &after_names).map_err(|e| {
        anyhow!(
            "rekey completed, but changed files could not be read back: {e}; inspect `git status` under {REKEYED_DIR} and stage the redistributed copies"
        )
    })?;
    let mut fresh: Vec<&Path> = after
        .iter()
        .filter(|&(path, hash)| {
            // Scope staging to the distribution tree; the source itself was
            // staged (or deliberately not) in the replacement stage.
            path.starts_with(REKEYED_DIR) && before.get(path) != Some(hash)
        })
        .map(|(path, _)| path.as_path())
        .collect();
    fresh.sort();
    if !fresh.is_empty() {
        let refs: Vec<&str> = fresh.iter().filter_map(|p| p.to_str()).collect();
        exec::run_in(repo_root, "git", std::iter::once("add").chain(refs))?;
    }
    Ok(())
}

/// Repo-relative paths with worktree or index changes, parsed from
/// NUL-delimited porcelain output. Git failures propagate: staging on a
/// guessed file set would be worse than refusing.
fn status_names(repo_root: &Path) -> Result<BTreeSet<PathBuf>> {
    let out = exec::cap_in(
        repo_root,
        "git",
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            REKEYED_DIR,
        ],
    );
    if out.exit_code != 0 {
        bail!(
            "git status failed in {}: {}",
            repo_root.display(),
            out.stderr.trim()
        );
    }
    Ok(parse_status_z(&out.stdout))
}

fn parse_status_z(output: &str) -> BTreeSet<PathBuf> {
    let mut paths = BTreeSet::new();
    // NUL-delimited v1 records look like `XY path`; renames contribute a
    // second bare path field. Both sides are staged-relevant (old deleted,
    // new added), so order questions do not matter. Paths are literal
    // here: never trim or unquote them.
    let mut fields = output.split('\0').peekable();
    while let Some(field) = fields.next() {
        if field.is_empty() {
            continue;
        }
        let (status, path) = field.split_at(field.len().min(2));
        let path = path.strip_prefix(' ').unwrap_or(path);
        if path.is_empty() {
            continue;
        }
        paths.insert(PathBuf::from(path));
        if status.starts_with(['R', 'C']) {
            if let Some(other) = fields.next() {
                if !other.is_empty() {
                    paths.insert(PathBuf::from(other));
                }
            }
        }
        let _ = status;
    }
    paths
}

/// Restore the backup over a failed replacement atomically: bytes go to a
/// sibling temp file first, then rename over the destination, so a crash
/// mid-restore cannot leave a truncated source. The backup is kept unless
/// the rename completes; only then is it removed.
fn restore(secret_path: &Path, backup_path: &Path, repo_root: &Path) -> Result<()> {
    let mut tmp_name = secret_path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();
    tmp_name.push(".restore-tmp");
    let tmp_path = secret_path.with_file_name(tmp_name);
    // Best effort: a stale temp file from a killed run must not block us.
    let _ = fs::remove_file(&tmp_path);
    let restore_err = (|| -> Result<()> {
        let bytes = fs::read(backup_path)?;
        let mut tmp = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)?;
        tmp.write_all(&bytes)?;
        tmp.sync_all()?;
        drop(tmp);
        fs::rename(&tmp_path, secret_path)?;
        Ok(())
    })();
    if let Err(e) = restore_err {
        let _ = fs::remove_file(&tmp_path);
        return Err(anyhow!(
            "ROTATION FAILED AND RESTORE FAILED: working source is at {}; copy it back to {} manually ({e})",
            display_rel(repo_root, backup_path),
            display_rel(repo_root, secret_path)
        ));
    }
    remove_backup(backup_path, repo_root)?;
    eprintln!(
        "rotation failed; restored {}",
        display_rel(repo_root, secret_path)
    );
    Ok(())
}

fn remove_partial(secret_path: &Path) {
    // Best effort: a failed create must not leave a partial file behind.
    if secret_path.is_file() {
        let _ = fs::remove_file(secret_path);
    }
}

fn remove_backup(backup_path: &Path, repo_root: &Path) -> Result<()> {
    fs::remove_file(backup_path).map_err(|e| {
        anyhow!(
            "source updated, but could not drop backup {}: {e}\n  remove it manually once the new source is confirmed deployed",
            display_rel(repo_root, backup_path)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::TempDir;

    fn rooted() -> TempDir {
        TempDir::new().expect("test tempdir")
    }

    #[test]
    fn contained_rel_rejects_escapes_absolutes_and_non_age() {
        let repo = rooted();
        for bad in [
            "../outside.age",
            "a/../../outside.age",
            "/tmp/abs.age",
            "",
            "token.txt",
            "no-extension",
        ] {
            assert!(
                contained_rel(&repo.path, bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn contained_rel_accepts_in_tree_path_with_existing_parent() {
        let repo = rooted();
        fs::create_dir_all(repo.path.join("age/secrets/hosts/atlas")).expect("mkdir");
        let rel = contained_rel(&repo.path, "age/secrets/hosts/atlas/token.age").unwrap();
        assert_eq!(rel, PathBuf::from("age/secrets/hosts/atlas/token.age"));
    }

    #[test]
    fn contained_rel_accepts_missing_parent_and_ensure_parent_creates_it() {
        let repo = rooted();
        let rel = contained_rel(&repo.path, "age/secrets/hosts/atlas/token.age").unwrap();
        let abs = ensure_parent(&repo.path, &rel).unwrap();
        assert!(abs.parent().expect("parent").is_dir());
        assert_eq!(abs, repo.path.join(&rel));
    }

    #[test]
    fn contained_rel_refuses_symlink_source() {
        let repo = rooted();
        fs::create_dir_all(repo.path.join("age/secrets/hosts/atlas")).expect("mkdir");
        fs::write(repo.path.join("real.age"), b"bytes").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            repo.path.join("real.age"),
            repo.path.join("age/secrets/hosts/atlas/link.age"),
        )
        .expect("symlink");
        let err = contained_rel(&repo.path, "age/secrets/hosts/atlas/link.age").unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err:?}");
    }

    #[test]
    fn contained_rel_refuses_parent_symlinked_outside() {
        let repo = rooted();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/", repo.path.join("linkdir")).expect("symlink");
        let err = contained_rel(&repo.path, "linkdir/token.age").unwrap_err();
        assert!(err.to_string().contains("inside the repo"), "{err:?}");
    }

    #[test]
    fn validate_fresh_accepts_binary_and_armored_age() {
        let repo = rooted();
        let binary = repo.path.join("binary.age");
        fs::write(
            &binary,
            b"age-encryption.org v1\n-> X25519 abcdefghijklmnopqrstuvwxyz0123456789ABC\nZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA==\n--- c29tZS1tYWMtdmhpY2gtaXMtNDMtd2hhdGV2ZXItY2hhcnMtbG9uZw==\n",
        )
        .expect("write");
        assert!(validate_fresh(&repo.path, &binary).is_ok());
        let armored = repo.path.join("armored.age");
        fs::write(
            &armored,
            b"-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCg==\n-----END AGE ENCRYPTED FILE-----\n",
        )
        .expect("write");
        assert!(validate_fresh(&repo.path, &armored).is_ok());
        let garbage = repo.path.join("garbage.age");
        fs::write(&garbage, b"truncated-garbage").expect("write");
        assert!(validate_fresh(&repo.path, &garbage).is_err());
    }

    #[test]
    fn validate_fresh_rejects_header_only_and_unclosed_armor() {
        let repo = rooted();
        // Magic alone is a torn write, not a key.
        let header_only = repo.path.join("header.age");
        fs::write(&header_only, b"age-encryption.org v1\n").expect("write");
        let err = validate_fresh(&repo.path, &header_only).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err:?}");
        // Armor without its END delimiter is a torn write too.
        let unclosed = repo.path.join("unclosed.age");
        fs::write(&unclosed, b"-----BEGIN AGE ENCRYPTED FILE-----\nYWdlCg==\n").expect("write");
        let err = validate_fresh(&repo.path, &unclosed).unwrap_err();
        assert!(err.to_string().contains("END"), "{err:?}");
    }

    #[test]
    fn backup_path_keeps_sibling_name_without_age_suffix() {
        let path = Path::new("age/secrets/root/hosts/atlas/colibri_atlas_api_key.age");
        assert_eq!(
            backup_path_for(path),
            PathBuf::from("age/secrets/root/hosts/atlas/colibri_atlas_api_key.age.rotbak")
        );
    }

    #[test]
    fn parse_status_z_reads_plain_renamed_and_odd_names() {
        // `R  new` first, `old` second: both sides land in the set, so the
        // field order question cannot cause a miss either way.
        let out = "A  age/new.age\0 M age/sp ace.age\0R  age/n2.age\0age/n1.age\0?? age/u.age\0";
        let paths = parse_status_z(out);
        for want in [
            "age/new.age",
            "age/sp ace.age",
            "age/n2.age",
            "age/n1.age",
            "age/u.age",
        ] {
            assert!(paths.contains(&PathBuf::from(want)), "missing {want}");
        }
        assert_eq!(paths.len(), 5);
    }

    #[test]
    fn parse_status_z_ignores_blank_fields() {
        assert!(parse_status_z("").is_empty());
        assert!(parse_status_z("\0\0").is_empty());
    }
}
