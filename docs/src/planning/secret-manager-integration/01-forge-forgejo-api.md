# Phase 01 — Push Codeberg/Forgejo secrets through the `forgejo-api` crate

## Working tree

External repo: **`/data/nvme0/can/Projects/nix-manager-core`**. This is *not*
the secret-manager repo. All edits in this phase happen here. The crate of
interest is `crates/nix-manager-core/`.

## Goal

`nix_manager_core::forge::push_codeberg_secret` sets a repository Actions secret
on a Codeberg/Forgejo instance by calling the **`forgejo-api`** crate (the Rust
library backing Cyborus's `forgejo-cli`), instead of constructing a raw `ureq`
PUT against `/api/v1/repos/{repo}/actions/secrets/{name}`. Token resolution,
the public function signatures, and the GitHub path are unchanged. The crate
builds and its tests pass.

## Why this matters now

The user's design has secret synchronization go "through the forgejo CLI" — and
specifically, per the locked decision, **through the forgejo CLI crate
directly**. Today `forge.rs` only borrows the forgejo-cli *token file* and then
talks REST by hand:

```rust
// crates/nix-manager-core/src/forge.rs (current)
let url = format!("https://{host}/api/v1/repos/{repo}/actions/secrets/{name}");
let resp = ureq::put(&url)
    .header("Authorization", format!("token {bearer}"))
    .send_json(serde_json::json!({ "data": value }))
    .map_err(|e| anyhow!("PUT {url}: {e}"))?;
```

This duplicates request shaping the forgejo-api crate already does correctly
(endpoint paths, API versioning, response decoding), and is the integration the
rest of the plan's `sync` command (Phase 03) builds on. Doing it now, in the
shared crate, means both `secret-manager` and `canix` inherit the fix via a
single git-rev bump.

## Out of scope

- **Do not touch `push_github_secret`** — the `gh`-based path stays exactly as
  is (locked decision: GitHub left as-is).
- Do not change the public function names/signatures
  (`push_codeberg_secret(host, repo, name, value)`,
  `push_codeberg_org_secret(repo, name, value)`,
  `codeberg_bearer_token(host)`). Phase 03 and canix call these.
- Do not change the auth resolution order (`$CODEBERG_TOKEN` → token file).
- Do not add a runtime dependency on the `forgejo-cli` *binary*. Use the crate.
- No new CLI surface in this repo.

## Plan

1. **Identify the crate + entrypoint.** Add the dependency:
   ```console
   $ cd /data/nvme0/can/Projects/nix-manager-core
   $ cargo add forgejo-api -p nix-manager-core
   ```
   If `forgejo-api` is not the correct/available crate name, confirm via
   `cargo search forgejo` and the forgejo-cli source
   (`https://codeberg.org/Cyborus/forgejo-cli` → its `Cargo.toml` names the API
   crate it depends on). Pin a version that exposes a Forgejo client constructed
   from a base URL + token and a "create or update repo actions secret"
   operation. Record the exact crate + version in the commit message.
2. **Determine the API surface** for setting a repo Actions secret. The
   underlying Forgejo endpoint is `PUT /repos/{owner}/{repo}/actions/secrets/{secretname}`
   with body `{ "data": "<value>" }`. Find the `forgejo-api` method that wraps it
   (search the crate docs / source for `actions`, `secret`, `update_repo_secret`,
   or similar). Construct the client with `https://{host}` as the base URL and
   the bearer token from `codeberg_bearer_token(host)`.
3. **Rewrite `push_codeberg_secret`** to use the client. Because `forgejo-api` is
   almost certainly `async` (it builds on `reqwest`), bridge to the synchronous
   signature with a small blocking executor rather than making the whole forge
   API async (callers in `secret-manager`/`canix` are sync). Two acceptable
   approaches — pick the one with the smaller dependency footprint:
   - Build a current-thread `tokio` runtime inside the function
     (`tokio::runtime::Builder::new_current_thread().enable_all().build()?`) and
     `block_on` the call. Add `tokio` with only the `rt`/`net` features needed.
   - Or use `pollster::block_on` if the crate's futures don't require a tokio
     reactor (verify — `reqwest` does need tokio, so the runtime approach is the
     safe default).
   Keep `ui::step(...)` progress line intact.
4. **Preserve error quality.** On failure, the error must still name the repo and
   surface the `write:repository` scope hint that the current code emits, so
   operators get the same actionable message. Map `forgejo-api` errors through
   `anyhow!` with context including `{host}`, `{repo}`, `{name}`.
5. **Keep `serde_json` only if still used.** If the rewrite removes the last
   `serde_json::json!` / `ureq` use in this file, drop the now-dead `ureq`
   dependency from `crates/nix-manager-core/Cargo.toml` (and workspace
   `Cargo.toml` if it was added solely for this) — but first
   `grep -rn "ureq" crates/` to confirm no other module needs it.
6. **Build & test.**
   ```console
   $ cargo build -p nix-manager-core
   $ cargo nextest run -p nix-manager-core   # or `cargo test -p nix-manager-core`
   ```
   The four `codeberg_bearer_token_*` tests must still pass (they exercise token
   resolution, which you did not change). Add a focused unit test only if you
   extracted a pure helper (e.g. base-URL construction); do not add network
   tests.
7. **Commit** (signed, plain `git commit`). Note the `forgejo-api` crate +
   version in the message. Push only if the user authorizes — Phase 03 needs
   this commit on the codeberg remote to bump its git dependency.

## Acceptance criteria

- [ ] `crates/nix-manager-core/Cargo.toml` lists `forgejo-api` (or the confirmed
      correct crate) as a dependency.
- [ ] `push_codeberg_secret` contains **no** `ureq::put` / raw
      `/api/v1/.../actions/secrets/` URL construction; it issues the request via
      the `forgejo-api` client.
- [ ] `codeberg_bearer_token` is unchanged and the four existing
      `codeberg_bearer_token_*` tests pass.
- [ ] `push_github_secret` is byte-for-byte unchanged.
- [ ] Public signatures of `push_codeberg_secret`, `push_codeberg_org_secret`,
      `codeberg_bearer_token` are unchanged.
- [ ] `cargo build -p nix-manager-core` is clean (zero warnings introduced) and
      `cargo nextest run -p nix-manager-core` is green.
- [ ] If `ureq` is now unused crate-wide, it is removed; otherwise it is left in
      place — `grep -rn "ureq" crates/` justifies the choice.

## Files likely touched

Repo: `/data/nvme0/can/Projects/nix-manager-core`
- `crates/nix-manager-core/Cargo.toml` — add `forgejo-api`, maybe `tokio`;
  maybe drop `ureq`.
- `Cargo.toml` (workspace) — workspace dep entries if used.
- `crates/nix-manager-core/src/forge.rs` — rewrite `push_codeberg_secret`.
- `Cargo.lock` — regenerated.

## Pitfalls

- **Async/sync mismatch.** `forgejo-api` is async over `reqwest`; the forge API
  is sync. Symptom: "cannot block the current thread from within a runtime" or
  needing `.await` in a non-async fn. Cause: missing/incorrect runtime. Recovery:
  build a dedicated current-thread tokio runtime inside the function and
  `block_on`; do not make the public fn async (it would cascade into
  secret-manager and canix).
- **Wrong crate / wrong method.** Symptom: a 2xx response but the secret isn't
  actually set, or a compile error on the method name. Cause: forgejo-api version
  skew or guessing the method. Recovery: read the crate's generated docs
  (`cargo doc -p forgejo-api --open`) and match the `PUT
  /repos/{owner}/{repo}/actions/secrets/{name}` operation by its OpenAPI
  operation id; pin the version you verified.
- **Base URL vs host.** The current code uses bare `host` (e.g. `codeberg.org`)
  and prefixes `https://`. forgejo-api wants a full base URL. Symptom: requests
  to the wrong scheme/host. Recovery: pass `https://{host}` explicitly.
- **Dropping the scope hint.** Symptom: operators get a bare HTTP error and can't
  tell the token lacks `write:repository`. Cause: not reproducing the existing
  error context. Recovery: include the hint in the `anyhow` context on the error
  arm.
- **Feature creep on tokio.** Pulling `tokio` with `features = ["full"]` bloats
  the dependency tree. Use the minimal feature set (`rt` + whatever reqwest
  needs).

## Reference

- Current implementation: `crates/nix-manager-core/src/forge.rs`
  (`push_codeberg_secret`, `codeberg_bearer_token`).
- forgejo-cli (source of the token-file path + the crate it builds on):
  `https://codeberg.org/Cyborus/forgejo-cli`.
- Consumers that must keep compiling: `secret-manager`'s
  `crates/secret-manager/src/push.rs` and canix's
  `cli/src/commands/secret/mod.rs`.
- Next phase consuming this: [03-sync-command.md](./03-sync-command.md).
- Plan index: [README.md](./README.md).
