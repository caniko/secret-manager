# Phase 03 — Add a `secret-manager sync` command driven by declared targets

## Working tree

This repo: **`/data/nvme0/can/Projects/secret-manager`**, `crates/secret-manager/`.

**Prerequisites (both must be satisfied before starting):**
- Phase 01 is committed **and pushed** to the `nix-manager-core` codeberg
  remote — the new `forgejo-api`-backed `push_codeberg_secret` must be reachable
  via the git dependency. The first step of this phase bumps that rev.
- Phase 02 is committed in this repo — `crates/secret-manager/src/sync_targets.rs`
  (the `SyncDocument`/`SyncTarget` types + loader) and `nix/collect.nix` exist.

## Goal

A new `secret-manager sync` subcommand reads the collected declarative
sync-target document (produced by Phase 02's `collect.nix`, deserialized by
`sync_targets.rs`), and for each declared target decrypts the named `.age`
secret once and pushes it to each declared codeberg/forgejo repo under the
declared Actions-secret name, via the Phase 01 forgejo-api-backed forge.
`secret-manager sync --help` documents it.

## Why this matters now

After Phase 02 a store can *declare* "secret S → repo R as secret N", but
nothing consumes that declaration — syncing still requires hand-typing
`secret-manager push --codeberg owner/repo --name N S.age` per secret. This
phase closes the loop the user described: "when activated from the CLI, the
secrets get synchronized to the targets". It is the manual-invocation half of
the "module options only" decision — the module declares, `sync` executes on
demand.

## Out of scope

- No automatic execution at nixos-rebuild / home-switch time (locked decision:
  module options only — sync stays a manual CLI call).
- Do not change `push` / `decrypt` behavior or remove them — `sync` is additive
  and reuses their internals.
- Do not touch GitHub push (decision: GitHub left as-is). `sync` targets
  codeberg/forgejo only, matching the Phase 02 schema.
- Do not redefine the sync-target schema — consume the Phase 02 types verbatim.

## Plan

1. **Bump the `nix-manager-core` git rev** in
   `crates/secret-manager/Cargo.toml` (and `Cargo.lock` via `cargo update -p
   nix-manager-core`) to the Phase 01 commit, so the new forge API is available.
   Verify `cargo build` picks up the forgejo-api-backed `push_codeberg_secret`.
2. **Add `SyncArgs`** in a new `crates/secret-manager/src/sync.rs` (or extend
   `push.rs`; a new module is cleaner). Inputs:
   - Source of the collected document: a `--config <path>` to a JSON file
     (the `builtins.toJSON` of `lib.collect …`), defaulting to reading stdin if
     omitted, OR a documented `nix eval`-pipe convention. Pick the simplest that
     matches how Phase 04/canix will invoke it; document it in the `--help`.
   - `--identity` passthrough (same as `PushArgs`) for decryption.
   - A `--dry-run` flag that prints the planned (secret → repo/name) pushes
     without decrypting or pushing.
3. **Implement `SyncArgs::run`:**
   - `Store::discover()` for the store root (reuse existing logic).
   - Load + deserialize the document via Phase 02's
     `sync_targets::load(...)`.
   - For each `SyncTarget`: decrypt the secret **once** by reusing the existing
     `decrypt_store_secret` helper in `push.rs` (make it `pub(crate)` if needed —
     do not copy it), then loop its `codeberg` repos calling
     `nix_manager_core::forge::push_codeberg_secret(&target.host, repo,
     &target.name, &value)`.
   - Use `target.host` (default `codeberg.org` from Phase 02) — do not hardcode
     `push_codeberg_org_secret`, since a target may name a different forgejo host.
   - Emit `ui::step`/`ui::success` progress consistent with `push`.
4. **Register the subcommand** in `crates/secret-manager/src/main.rs`: add a
   `Sync(sync::SyncArgs)` variant to the `Command` enum with a doc comment, and a
   match arm `Command::Sync(args) => args.run()`. Export `sync` from `lib.rs`.
5. **Tests.** Add a unit test that, given a `SyncDocument` fixture and a stubbed
   push sink, plans the correct (host, repo, name, secret) tuples — at minimum
   test the `--dry-run` planning path (which needs no decryption or network) so
   target expansion and per-target `host` handling are covered.
6. **Build & verify.**
   ```console
   $ cargo build && cargo nextest run
   $ cargo run -- sync --help            # lists sync + its flags
   $ cargo run -- sync --dry-run --config <fixture.json>   # prints plan
   ```
7. **Commit** (signed). Push only if the user authorizes — Phase 04 (canix)
   needs this commit on the codeberg remote to bump its git dependency.

## Acceptance criteria

- [ ] `crates/secret-manager/Cargo.toml` pins the Phase 01 `nix-manager-core`
      rev and `cargo build` resolves the forgejo-api-backed forge.
- [ ] `secret-manager sync` exists; `secret-manager sync --help` lists it with
      `--config`, `--identity`, and `--dry-run`.
- [ ] `sync` decrypts each declared secret exactly once and pushes to every
      declared codeberg/forgejo repo under the declared name, honoring each
      target's `host`.
- [ ] `sync` reuses `decrypt_store_secret` (no duplicated decryption logic) and
      `nix_manager_core::forge::push_codeberg_secret` (no new HTTP code here).
- [ ] `--dry-run` prints the planned pushes without decrypting or contacting any
      forge; a unit test covers the planning path.
- [ ] `push`, `decrypt`, and the GitHub path are unchanged.
- [ ] `cargo build` clean, `cargo nextest run` green.

## Files likely touched

Repo: `/data/nvme0/can/Projects/secret-manager`
- `crates/secret-manager/Cargo.toml` — bump `nix-manager-core` rev.
- `Cargo.lock` — updated.
- `crates/secret-manager/src/sync.rs` — **new**, `SyncArgs` + `run`.
- `crates/secret-manager/src/push.rs` — expose `decrypt_store_secret` for reuse.
- `crates/secret-manager/src/main.rs` — register `Sync` subcommand.
- `crates/secret-manager/src/lib.rs` — `pub mod sync;`.
- `docs/src/reference/cli.md` / `docs/src/guides/` — document `sync` (optional
  but nice; keep mdBook building).

## Pitfalls

- **Re-decrypting per repo.** Symptom: the hardware-key prompt fires once per
  repo instead of once per secret. Cause: decrypting inside the repo loop.
  Recovery: decrypt once per `SyncTarget`, then loop repos over the cached
  plaintext.
- **Reimplementing decryption.** Symptom: subtle divergence from `push`'s
  identity-resolution / `.age` validation. Cause: copying instead of reusing.
  Recovery: make `decrypt_store_secret` `pub(crate)` and call it.
- **Ignoring `host`.** Symptom: a target naming a self-hosted forgejo instance
  pushes to codeberg.org. Cause: calling `push_codeberg_org_secret`. Recovery:
  call `push_codeberg_secret(&target.host, …)`.
- **Stale forge API.** Symptom: `cargo build` still uses the old `ureq` path or
  fails to find the new method. Cause: rev bump not applied / not pushed.
  Recovery: confirm Phase 01 is pushed and `cargo update -p nix-manager-core`
  pulled the right rev (`cargo tree -p nix-manager-core` shows the commit).
- **Config source ambiguity.** Symptom: canix (Phase 04) can't figure out how to
  feed the collected JSON. Cause: undocumented input convention. Recovery: pick
  one (`--config <path>` with stdin fallback) and document it in `--help` and the
  CLI reference so Phase 04 wires to it directly.

## Reference

- Decrypt/push internals to reuse: `crates/secret-manager/src/push.rs`
  (`decrypt_store_secret`, `PushArgs::run`).
- CLI registration pattern: `crates/secret-manager/src/main.rs`.
- Sync-target types: `crates/secret-manager/src/sync_targets.rs` (Phase 02).
- Forge API: `nix_manager_core::forge::push_codeberg_secret` (Phase 01).
- Prerequisite phases: [01-forge-forgejo-api.md](./01-forge-forgejo-api.md),
  [02-sync-target-module.md](./02-sync-target-module.md).
- Plan index: [README.md](./README.md).
