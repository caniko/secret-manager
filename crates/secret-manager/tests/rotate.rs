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
cmd="${1:-}"
if [ "$cmd" = "generate" ]; then
  if [ -e "$STUB_DIR/fail-generate" ]; then
    echo "stub: generate failed" >&2
    exit 1
  fi
  rel="${@: -1}"
  mkdir -p "$(dirname "$rel")"
  printf 'stub-material\n' >"$rel"
  exit 0
fi
if [ "$cmd" = "rekey" ]; then
  if [ -e "$STUB_DIR/fail-rekey" ]; then
    echo "stub: rekey failed" >&2
    exit 1
  fi
  mkdir -p age/rekeyed/root/atlas
  printf 'stub-rekeyed\n' > age/rekeyed/root/atlas/stub_copy.age
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
        cmd.output().expect("spawn rotate binary")
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
    assert_eq!(read(&repo, REL), "stub-material\n");
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
    let out = repo.run(&["rotate", REL], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&repo, REL), "stub-material\n");
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
    let out = repo.run(&["rotate", REL], &[]);
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
    let out = repo.run(&["rotate", REL], &[]);
    assert!(!out.status.success(), "rekey failure must fail");
    // The new source is kept: restoring one file cannot roll back distribution.
    assert_eq!(read(&repo, REL), "stub-material\n");
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
    let out = repo.run(&["rotate", REL, "--no-stage"], &[]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&repo, REL), "stub-material\n");
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
    let out = repo.run(&["rotate", REL], &[]);
    assert!(!out.status.success(), "concurrent run must fail");
    assert_eq!(read(&repo, REL), "old-material\n", "source untouched");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("backup") || stderr.contains("rotation"),
        "got: {stderr}"
    );
}
