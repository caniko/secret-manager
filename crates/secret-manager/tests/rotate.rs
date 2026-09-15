//! End-to-end regression tests for `secret-manager rotate`.
//!
//! A stub `agenix` (behavior driven by marker files) and a real throwaway
//! git repo let these tests assert worktree *and* index state for every
//! path: create, replace, generate failure, rekey failure, staging flags,
//! containment, symlinks, and concurrent runs. The binary under test runs
//! in a child process, so stub PATH overrides stay hermetic.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const STUB_AGENIX: &str = r#"#!/usr/bin/env bash
# Stub agenix for rotate integration tests. Behavior driven by marker
# files in $STUB_DIR; every invocation is appended to $STUB_DIR/log.
set -u
log="$STUB_DIR/log"
printf '%s\n' "agenix $*" >>"$log"
printf 'env ADD_TO_GIT=%s\n' "${AGENIX_REKEY_ADD_TO_GIT-unset}" >>"$log"
cmd="${1:-}"
if [ "$cmd" = "generate" ]; then
  if [ -e "$STUB_DIR/fail-generate" ]; then
    echo "stub: generate failed" >&2
    exit 1
  fi
  rel="${@: -1}"
  mkdir -p "$(dirname "$rel")"
  if [ -e "$STUB_DIR/sleep-generate" ]; then
    # Simulate a slow generation so a second process can race us.
    sleep 6
  fi
  if [ -e "$STUB_DIR/fail-generate-partial" ]; then
    # Lies about success the way a torn write would: non-empty output
    # without the age file header.
    printf 'truncated-garbage' >"$rel"
    exit 0
  fi
  printf 'age-encryption.org v1\nstub-material\n' >"$rel"
  exit 0
fi
if [ "$cmd" = "rekey" ]; then
  if [ -e "$STUB_DIR/fail-rekey" ]; then
    echo "stub: rekey failed" >&2
    exit 1
  fi
  mkdir -p age/rekeyed/root/atlas
  printf 'stub-rekeyed\n' > age/rekeyed/root/atlas/stub_copy.age
  # An untracked directory: without --untracked-files=all this collapses
  # to one entry and files get dropped from staging.
  mkdir -p age/rekeyed/root/atlas/bundle
  printf 'one\n' > age/rekeyed/root/atlas/bundle/one.age
  printf 'two\n' > age/rekeyed/root/atlas/bundle/two.age
  exit 0
fi
echo "stub: unknown command $cmd" >&2
exit 1
"#;

struct TempRepo {
    dir: PathBuf,
    stub: PathBuf,
}

impl TempRepo {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "sm-rotate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        // World-readable temp dirs would leak key material; the stub only
        // writes fixtures, but keep the habit the real flow requires.
        fs::create_dir_all(&dir).expect("temp repo");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("temp perms");
        }
        let bin = dir.join("bin");
        fs::create_dir_all(&bin).expect("stub bin dir");
        let stub = dir.join("repo");
        fs::create_dir_all(&stub).expect("repo dir");
        fs::write(stub.join("flake.nix"), "{}\n").expect("marker");
        fs::write(bin.join("agenix"), STUB_AGENIX).expect("stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(bin.join("agenix"), fs::Permissions::from_mode(0o755))
                .expect("stub perms");
        }
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&stub)
            .status()
            .expect("git init");
        assert!(status.success(), "git init failed");
        fs::create_dir_all(dir.join("stub-state")).expect("stub state dir");
        Self { dir, stub }
    }

    fn repo(&self) -> &Path {
        &self.stub
    }

    fn run(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        self.command(args, extra_env)
            .output()
            .expect("spawn rotate binary")
    }

    fn spawn(&self, args: &[&str]) -> std::process::Child {
        self.command(args, &[])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn rotate binary")
    }

    fn command(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Command {
        let path = format!(
            "{}:{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_secret-manager"));
        cmd.args(args)
            .current_dir(self.repo())
            .env("PATH", path)
            .env("STUB_DIR", self.dir.join("stub-state").as_os_str());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        fs::create_dir_all(self.dir.join("stub-state")).expect("stub state dir");
        cmd
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.join("stub-state").join("log")).unwrap_or_default()
    }

    fn marker(&self, name: &str) {
        fs::write(self.dir.join("stub-state").join(name), "").expect("marker");
    }

    fn porcelain(&self) -> BTreeSet<String> {
        let out = Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(self.repo())
            .output()
            .expect("git status");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn cached_names(&self) -> BTreeSet<String> {
        let out = Command::new("git")
            .args(["diff", "--cached", "--name-only"])
            .current_dir(self.repo())
            .output()
            .expect("git diff --cached");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect()
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

const REL: &str = "age/secrets/hosts/atlas/token.age";

/// What the stub writes on a successful generate: age magic header plus a
/// body the assertions can recognize.
const STUB_MATERIAL: &str = "age-encryption.org v1\nstub-material\n";

fn read(repo: &TempRepo, rel: &str) -> String {
    fs::read_to_string(repo.repo().join(rel)).expect("read fixture")
}

#[test]
fn create_when_absent_stages_source_and_rekeys() {
    let repo = TempRepo::new();
    let out = repo.run(&["rotate", REL], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&repo, REL), STUB_MATERIAL);
    assert!(
        repo.porcelain().contains(&format!("A  {REL}")),
        "source must be staged, got: {:?}",
        repo.porcelain()
    );
    let log = repo.log();
    assert!(log.contains("agenix generate"), "generate must run: {log}");
    assert!(
        !log.contains("--force-generate"),
        "create must not force: {log}"
    );
    assert!(!log.contains("-a"), "staging is explicit, never -a: {log}");
    assert!(log.contains("agenix rekey"), "rekey must run: {log}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("created"),
        "report must say created"
    );
}

#[test]
fn rotate_replaces_source_and_leaves_no_backup() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    let out = repo.run(&["rotate", "--force", REL], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&repo, REL), STUB_MATERIAL);
    assert!(
        !repo.repo().join(format!("{REL}.rotbak")).exists(),
        "backup must be dropped on success"
    );
    assert!(repo.log().contains("--force-generate"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rotated"),
        "report must say rotated"
    );
}

#[test]
fn generate_failure_preserves_bytes_and_index() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    repo.marker("fail-generate");
    let out = repo.run(&["rotate", "--force", REL], &[]);
    assert!(!out.status.success(), "generate failure must fail");
    assert_eq!(
        read(&repo, REL),
        "old-material\n",
        "bytes must be preserved"
    );
    assert!(
        repo.cached_names().is_empty(),
        "index must be untouched, got: {:?}",
        repo.cached_names()
    );
    assert!(
        !repo.repo().join(format!("{REL}.rotbak")).exists(),
        "backup must be cleaned up after restore"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("generator"), "hint at generator: {stderr}");
}

#[test]
fn rekey_failure_keeps_new_source_and_reports_incomplete() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    repo.marker("fail-rekey");
    let out = repo.run(&["rotate", "--force", REL], &[]);
    assert!(!out.status.success(), "rekey failure must fail");
    // The new source is kept: restoring one file cannot roll back distribution.
    assert_eq!(read(&repo, REL), STUB_MATERIAL);
    assert!(
        !repo.repo().join(format!("{REL}.rotbak")).exists(),
        "no stale guard may block the rekey retry"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("distribution is incomplete") && stderr.contains("agenix rekey -a"),
        "must report incomplete + retry, got: {stderr}"
    );
    // Source (valid update) staged; the un-distributed copy left unstaged.
    assert!(repo.cached_names().contains(REL), "source stays staged");
    assert!(
        !repo
            .cached_names()
            .contains("age/rekeyed/root/atlas/stub_copy.age"),
        "failed distribution stages nothing"
    );
}

#[test]
fn no_stage_leaves_index_empty() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    let out = repo.run(&["rotate", "--force", REL, "--no-stage"], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&repo, REL), STUB_MATERIAL);
    assert!(
        repo.cached_names().is_empty(),
        "index must stay empty, got: {:?}",
        repo.cached_names()
    );
    assert!(!repo.log().contains("-a"), "no -a anywhere: {}", repo.log());
}

#[test]
fn no_rekey_skips_distribution_with_pointer() {
    let repo = TempRepo::new();
    let out = repo.run(&["rotate", REL, "--no-rekey"], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!repo.log().contains("agenix rekey"), "rekey must not run");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("agenix rekey -a"),
        "must point at manual rekey"
    );
}

#[test]
fn escape_and_absolute_paths_are_rejected() {
    let repo = TempRepo::new();
    for arg in ["../outside.age", "/tmp/abs.age", "", "no-extension.txt"] {
        let out = repo.run(&["rotate", arg], &[]);
        assert!(!out.status.success(), "{arg:?} must fail");
    }
    assert!(
        !repo.dir.join("outside.age").exists(),
        "nothing may be created outside the repo"
    );
}

#[test]
fn symlink_source_is_refused_and_target_untouched() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join("real.age"), "target-bytes\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "real.age",
        repo.repo().join("age/secrets/hosts/atlas/link.age"),
    )
    .unwrap();
    let out = repo.run(&["rotate", "age/secrets/hosts/atlas/link.age"], &[]);
    assert!(!out.status.success(), "symlink must fail");
    assert_eq!(
        fs::read_to_string(repo.repo().join("real.age")).unwrap(),
        "target-bytes\n"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("symlink"), "got: {stderr}");
}

#[test]
fn existing_backup_blocks_concurrent_run() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    fs::write(repo.repo().join(format!("{REL}.rotbak")), "in-flight\n").unwrap();
    let out = repo.run(&["rotate", "--force", REL], &[]);
    assert!(!out.status.success(), "concurrent run must fail");
    assert_eq!(read(&repo, REL), "old-material\n", "source untouched");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("backup") || stderr.contains("rotation"),
        "got: {stderr}"
    );
}

#[test]
fn existing_source_is_preserved_without_force() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    let out = repo.run(&["rotate", REL], &[]);
    assert!(
        out.status.success(),
        "preserve must succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&repo, REL), "old-material\n", "bytes unchanged");
    assert!(
        !repo.log().contains("agenix generate"),
        "no generation on preserve: {}",
        repo.log()
    );
    assert!(
        repo.cached_names().is_empty(),
        "index untouched, got: {:?}",
        repo.cached_names()
    );
    assert!(
        !repo.repo().join(format!("{REL}.rotbak")).exists(),
        "no backup on preserve"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("preserved") && stderr.contains("--force"),
        "must report preserved + force pointer, got: {stderr}"
    );
}

#[test]
fn no_rekey_and_no_stage_combined_leave_index_empty() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    let out = repo.run(&["rotate", "--force", REL, "--no-rekey", "--no-stage"], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&repo, REL), STUB_MATERIAL);
    assert!(!repo.log().contains("agenix rekey"), "rekey must not run");
    assert!(
        repo.cached_names().is_empty(),
        "index must stay empty, got: {:?}",
        repo.cached_names()
    );
}

#[test]
fn partial_write_passing_exit_code_is_rejected_by_magic() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    repo.marker("fail-generate-partial");
    let out = repo.run(&["rotate", "--force", REL], &[]);
    assert!(!out.status.success(), "torn write must fail");
    assert_eq!(read(&repo, REL), "old-material\n", "bytes must be restored");
    assert!(
        repo.cached_names().is_empty(),
        "index untouched, got: {:?}",
        repo.cached_names()
    );
    assert!(
        !repo.repo().join(format!("{REL}.rotbak")).exists(),
        "backup cleaned up after restore"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("age-encryption") || stderr.contains("partial"),
        "must name the header check, got: {stderr}"
    );
}

#[test]
fn stale_lock_file_does_not_block() {
    // The lock is kernel-held, not file-existence-held: a leftover anchor
    // from a dead process must not block recovery.
    let repo = TempRepo::new();
    fs::write(
        repo.repo().join(".git/secret-manager-rotate.lock"),
        "stale\n",
    )
    .unwrap();
    let out = repo.run(&["rotate", REL], &[]);
    assert!(
        out.status.success(),
        "stale anchor must not block, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&repo, REL), STUB_MATERIAL);
}

/// A `git` wrapper that breaks `status` only, delegating everything else
/// to the real binary. Proves status failures propagate instead of
/// degrading to an empty (and wrong) staging set.
fn install_failing_status_wrapper(repo: &TempRepo) {
    let real_git = String::from_utf8(
        Command::new("sh")
            .args(["-c", "command -v git"])
            .output()
            .expect("resolve git")
            .stdout,
    )
    .expect("git path utf8")
    .trim()
    .to_string();
    assert!(!real_git.is_empty(), "git must resolve");
    fs::write(
        repo.dir.join("bin/git"),
        format!(
            "#!/usr/bin/env bash\nif [ \"${{1:-}}\" = \"status\" ]; then echo \"wrapper: status broken\" >&2; exit 1; fi\nexec \"{real_git}\" \"$@\"\n"
        ),
    )
    .expect("wrapper");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(repo.dir.join("bin/git"), fs::Permissions::from_mode(0o755))
            .expect("wrapper perms");
    }
}

#[test]
fn git_status_failure_fails_distribution_with_source_kept() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    install_failing_status_wrapper(&repo);
    let out = repo.run(&["rotate", "--force", REL], &[]);
    assert!(!out.status.success(), "status failure must fail");
    // Replacement completed before distribution started: the new source
    // stays, and no stale backup may block the rekey retry.
    assert_eq!(read(&repo, REL), STUB_MATERIAL);
    assert!(
        !repo.repo().join(format!("{REL}.rotbak")).exists(),
        "no stale guard may block the rekey retry"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown") || stderr.contains("git status"),
        "must report unverifiable distribution, got: {stderr}"
    );
}

#[test]
fn auto_staging_env_never_reaches_agenix() {
    // Inherited AGENIX_REKEY_ADD_TO_GIT is stripped on every rotation
    // invocation; staging happens only through explicit `git add`.
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    let out = repo.run(
        &["rotate", "--force", REL],
        &[("AGENIX_REKEY_ADD_TO_GIT", "1")],
    );
    assert!(out.status.success());
    assert!(
        !repo.log().contains("ADD_TO_GIT=1"),
        "auto-staging must be stripped by default: {}",
        repo.log()
    );
    // ... while explicit staging still happens on the default path.
    assert!(
        repo.cached_names().contains(REL),
        "source must be staged, got: {:?}",
        repo.cached_names()
    );
    // With --no-stage the setting must not reach agenix at all, in a fresh
    // repo so earlier staging cannot pollute the index assertion.
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    let out = repo.run(
        &["rotate", "--force", REL, "--no-stage"],
        &[("AGENIX_REKEY_ADD_TO_GIT", "1")],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !repo.log().contains("ADD_TO_GIT=1"),
        "auto-staging must be stripped under --no-stage: {}",
        repo.log()
    );
    assert!(
        repo.cached_names().is_empty(),
        "index must stay empty, got: {:?}",
        repo.cached_names()
    );
}

#[test]
fn concurrent_creates_serialize_to_one_create_and_one_preserve() {
    let repo = TempRepo::new();
    // Slow generation keeps the winner inside the lock while the loser
    // arrives, so the outcome is deterministic, not scheduling luck.
    repo.marker("sleep-generate");
    // NB: TempRepo is not Sync; drive both children from scoped threads
    // that only borrow it. The lock is fail-fast (a queued run could wait
    // on a hardware touch), so the loser reports the live lock and a
    // plain retry then preserves.
    let (first, second) = std::thread::scope(|scope| {
        let a = scope.spawn(|| repo.run(&["rotate", REL], &[]));
        let b = scope.spawn(|| repo.run(&["rotate", REL], &[]));
        (
            a.join().expect("first thread"),
            b.join().expect("second thread"),
        )
    });
    let reports = [
        String::from_utf8_lossy(&first.stderr).into_owned(),
        String::from_utf8_lossy(&second.stderr).into_owned(),
    ];
    let outs = [&first, &second];
    let succeeded = outs.iter().filter(|o| o.status.success()).count();
    assert_eq!(
        succeeded, 1,
        "exactly one run must win the lock, got: {reports:?}"
    );
    assert!(
        reports.iter().any(|s| s.contains("created")),
        "winner must create: {reports:?}"
    );
    assert!(
        reports
            .iter()
            .any(|s| s.contains("another rotation is running")),
        "loser must fail fast on the live lock: {reports:?}"
    );
    // Retry after the winner finishes: idempotent preserve, no rotation.
    let retry = repo.run(&["rotate", REL], &[]);
    assert!(
        retry.status.success(),
        "retry must succeed, stderr: {}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert!(
        String::from_utf8_lossy(&retry.stderr).contains("preserved"),
        "retry must preserve: {}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert_eq!(read(&repo, REL), STUB_MATERIAL);
    assert!(
        !repo.repo().join(format!("{REL}.rotbak")).exists(),
        "no leftover backup"
    );
}

#[test]
fn kill_while_holding_lock_releases_and_recovers() {
    let repo = TempRepo::new();
    repo.marker("sleep-generate");
    let mut child = repo.spawn(&["rotate", REL]);
    // Wait until the child is inside generation (past lock acquisition).
    let mut waited = 0;
    while waited < 50 && !repo.log().contains("agenix generate") {
        std::thread::sleep(std::time::Duration::from_millis(100));
        waited += 1;
    }
    assert!(
        repo.log().contains("agenix generate"),
        "child never reached generation"
    );
    // A second rotation must fail fast with the lock message, not hang.
    let raced = repo.run(&["rotate", REL], &[]);
    assert!(!raced.status.success(), "racy run must fail");
    assert!(
        String::from_utf8_lossy(&raced.stderr).contains("another rotation is running"),
        "must name the live lock, got: {}",
        String::from_utf8_lossy(&raced.stderr)
    );
    // SIGKILL the holder: the kernel must release the lock even though no
    // userspace cleanup ran.
    child.kill().expect("kill holder");
    let _ = child.wait_with_output();
    let flock_probe = Command::new("flock")
        .args([
            "-n",
            repo.repo()
                .join(".git/secret-manager-rotate.lock")
                .to_str()
                .expect("utf8 lock path"),
            "true",
        ])
        .status()
        .expect("flock probe");
    assert!(
        flock_probe.success(),
        "kernel must have released the lock on kill"
    );
    // Recovery is an ordinary run: no manual lock removal needed.
    let out = repo.run(&["rotate", REL], &[]);
    assert!(
        out.status.success(),
        "recovery run must succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&repo, REL), STUB_MATERIAL);
}

#[test]
fn pre_existing_staged_work_survives_rotation() {
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    // Unrelated staged work, tracked and untracked.
    fs::write(repo.repo().join("notes.txt"), "do not touch\n").unwrap();
    assert!(
        Command::new("git")
            .args(["add", "notes.txt"])
            .current_dir(repo.repo())
            .status()
            .expect("git add")
            .success()
    );
    let out = repo.run(&["rotate", "--force", REL], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(repo.repo().join("notes.txt")).unwrap(),
        "do not touch\n"
    );
    let cached = repo.cached_names();
    assert!(
        cached.contains("notes.txt"),
        "unrelated staged work must stay staged, got: {cached:?}"
    );
    assert!(
        cached.contains(REL),
        "rotated source staged, got: {cached:?}"
    );
}

#[test]
fn untracked_rekeyed_directory_stages_every_file() {
    // Without --untracked-files=all, `age/rekeyed/.../bundle/` collapses
    // to one status entry and files get dropped from staging.
    let repo = TempRepo::new();
    fs::create_dir_all(repo.repo().join("age/secrets/hosts/atlas")).unwrap();
    fs::write(repo.repo().join(REL), "old-material\n").unwrap();
    let out = repo.run(&["rotate", "--force", REL], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cached = repo.cached_names();
    for want in [
        REL,
        "age/rekeyed/root/atlas/stub_copy.age",
        "age/rekeyed/root/atlas/bundle/one.age",
        "age/rekeyed/root/atlas/bundle/two.age",
    ] {
        assert!(cached.contains(want), "missing {want}, got: {cached:?}");
    }
}
