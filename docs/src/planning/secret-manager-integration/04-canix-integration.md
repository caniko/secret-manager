# Phase 04 — Integrate the activation + `sync` command into canix

> **Recommended model: gpt-5.4-mini (codex) — effort `medium`**
>
> Routed: `carter route -c moderate -r subagent --needs coding --provider codex`
> → `gpt-5.4-mini` / `medium`
> (`codex --model gpt-5.4-mini -c model_reasoning_effort=medium`)
>
> Moderate, coding-dominated integration: a lockstep git-rev bump of two inputs,
> one new clap variant wired into the existing `canix secret` shim, and a module
> import that must keep canix evaluating. The risk is the coordinated bump — both
> inputs must move together and the flake.lock + Cargo.lock must agree. A weaker
> model tends to bump one input and not the other, or break the `#[cfg(feature =
> "admin")]` gating on the new subcommand.

## Working tree

External repo: **`/data/nvme0/can/Projects/canix`**. The clap shim lives in
`cli/src/commands/secret/mod.rs`; flake inputs in `flake.nix`; the secrets Nix
adapter in `lib/secrets/default.nix`.

**Prerequisites:** Phases 01 and 03 must be committed **and pushed** to their
codeberg remotes (canix resolves `nix-manager-core` and `secret-manager` as git
inputs / Cargo git deps). Phase 02's outputs ship inside the Phase 03
`secret-manager` commit.

## Goal

canix consumes the new `secret-manager` capabilities end to end: (1) the
`nix-manager-core` and `secret-manager` git revs are bumped in lockstep so the
forgejo-api forge and the `sync` command are present; (2) `canix secret sync`
surfaces the new subcommand through the existing `StoreEnv` shim; (3)
`secret-manager`'s `nixosModules` is imported as a separate activation surface
so a host can declare sync targets; (4) canix still evaluates and builds.

## Why this matters now

canix is the home of this project — secret-manager "is supposed to live inside
canix, but as a separate nix activation", and "the dedicated clap CLI should
also be integrated into the canix CLI". canix already embeds the library
(`canix secret …`) and consumes `secret-manager.lib`, so this phase is the
last mile: pick up the new rev, expose `sync` in the canix command tree, and
import the activation module. Until this lands, the work in Phases 01–03 exists
only in the standalone project and isn't reachable from the fleet repo.

## Out of scope

- Do not auto-run sync at activation (locked decision: module options only). The
  module import declares options; operators run `canix secret sync` by hand.
- Do not change canix's `StoreEnv` (`CanixEnv`) host/home validation semantics.
- Do not modify `secret-manager` or `nix-manager-core` here — only consume them.
  If a bug surfaces, file it back to the relevant phase, don't patch in canix.
- Do not alter the GitHub push path or canix's existing secret subcommands
  beyond adding `Sync`.

## Plan

1. **Bump both inputs in lockstep.**
   - Flake: `flake.nix` already declares `nix-manager-core` (via `secret-manager`'s
     follows) and `secret-manager` inputs. Run:
     ```console
     $ cd /data/nvme0/can/Projects/canix
     $ nix flake update secret-manager nix-manager-core
     ```
     Confirm `flake.lock` moved both to the Phase 01 / Phase 03 revs.
   - Cargo: `cli/Cargo.toml` pins `secret-manager` by `rev`. Update that `rev` to
     the Phase 03 commit and `cargo update -p secret-manager`. If canix also pins
     `nix-manager-core` directly, bump it to the Phase 01 rev too.
   - Both ecosystems (Nix input + Cargo dep) must point at commits that contain
     the respective work. Verify with `cargo tree -p secret-manager` and
     `nix flake metadata`.
2. **Surface `canix secret sync`.** In `cli/src/commands/secret/mod.rs`:
   - Add a `Sync(secret_manager::sync::SyncArgs)` variant to `SecretCmd`. Gate it
     with `#[cfg(feature = "admin")]` to match `Push` (sync is an admin/push-class
     operation), unless the user wants it unconditional — match `Push`'s gating by
     default.
   - Add the match arm `SecretCmd::Sync(args) => args.run()` under the same
     `#[cfg(feature = "admin")]`.
   - Add `use secret_manager::sync;` (gated like the existing `use ... push;`).
3. **Import the activation module.** Wherever canix wires flake-input NixOS
   modules into hosts, add `inputs.secret-manager.nixosModules.default` (the name
   chosen in Phase 02) as an importable module — mirror how `dns-manager`'s module
   is imported. If no host should declare sync targets yet, importing the module
   (which is inert until `services.secretSync.enable = true`) is enough; do not
   force-enable it on any host. If canix has a central module-list, add it there;
   otherwise document the one-line import for hosts that opt in.
4. **Verify the CLI.**
   ```console
   $ cargo build -p canix --features admin    # or canix's default admin build
   $ cargo run -p canix -- secret sync --help
   ```
5. **Verify Nix eval/build.**
   ```console
   $ nix flake check        # if fast enough; otherwise:
   $ nix eval .#nixosConfigurations.<host>.config.system.build.toplevel.drvPath
   ```
   for at least one host (use a representative host from `lib/hosts.nix`). The
   eval must succeed with the module imported. If you enabled
   `services.secretSync` on a host as a smoke test, eval its config too, then
   leave it disabled unless the user asked to declare real targets.
6. **Commit** (signed): the `flake.lock`, `Cargo.toml`/`Cargo.lock` rev bumps,
   the CLI shim change, and the module import together — one coherent commit (or
   two: "bump inputs" + "wire sync command + module"). Push per the user's call.

## Acceptance criteria

- [ ] `flake.lock` has `secret-manager` at the Phase 03 rev and `nix-manager-core`
      at the Phase 01 rev; `cli/Cargo.toml` pins `secret-manager` at the Phase 03
      rev and `Cargo.lock` agrees.
- [ ] `canix secret sync --help` works and shows the same flags as
      `secret-manager sync` (`--config`, `--identity`, `--dry-run`).
- [ ] `cargo build -p canix` (admin build) is clean; the new variant respects the
      existing `#[cfg(feature = "admin")]` gating.
- [ ] `inputs.secret-manager.nixosModules.default` is importable by canix hosts;
      at least one host config evaluates successfully with it imported.
- [ ] `nix eval`/`nix flake check` for a representative host succeeds with the
      bumped revs; no eval regression in the existing `canix secret` commands.
- [ ] canix's existing `secret` subcommands (Hm/Nixos/Forgejo/Push/List/…) still
      build and behave unchanged.

## Pitfalls

- **Half-bumped inputs.** Symptom: `cargo build` sees the new `secret-manager`
  but `nix` evals the old one (or vice versa), giving "method not found" or
  module-missing errors. Cause: bumping the Cargo rev but not the flake input, or
  one input but not the other. Recovery: bump flake input *and* Cargo rev for
  *both* crates; verify with `nix flake metadata` + `cargo tree`.
- **Feature-gate mismatch.** Symptom: build error referencing `sync` when
  `admin` is off, or `sync` missing when it should be present. Cause: the new
  variant/arm/`use` aren't all gated identically. Recovery: gate the `use`, the
  enum variant, and the match arm with the same `#[cfg(feature = "admin")]` as
  `Push`.
- **Module name drift.** Symptom: `inputs.secret-manager.nixosModules.default`
  doesn't exist. Cause: Phase 02 named it differently (e.g. `secretSync`).
  Recovery: read `secret-manager`'s `nix/default.nix` `extraOutputs` to learn the
  exact attribute names before importing.
- **Eval cost.** Symptom: `nix flake check` takes too long / OOMs on the full
  fleet. Cause: evaluating every host. Recovery: eval one representative host's
  `toplevel.drvPath` instead of a full `flake check`.
- **Cargo git rev not on remote.** Symptom: `cargo update` can't fetch the rev.
  Cause: Phase 03 committed locally but not pushed. Recovery: ensure Phases 01
  and 03 are pushed to codeberg before starting (see Prerequisites).

## Files likely touched

Repo: `/data/nvme0/can/Projects/canix`
- `flake.nix` / `flake.lock` — input rev bumps.
- `cli/Cargo.toml` / `Cargo.lock` — `secret-manager` (and maybe
  `nix-manager-core`) rev bump.
- `cli/src/commands/secret/mod.rs` — `Sync` variant + arm + `use`.
- The host/module wiring file that imports flake-input NixOS modules (mirror the
  `dns-manager` import site) — add `secret-manager.nixosModules.default`.

## Reference

- canix secret shim: `cli/src/commands/secret/mod.rs` (`SecretCmd`, `CanixEnv`).
- canix secret lib adapter: `lib/secrets/default.nix`
  (`inherit (inputs.secret-manager.lib) …`).
- canix flake inputs: `flake.nix` (`dns-manager`, `secret-manager` declarations).
- The `sync` command being surfaced: [03-sync-command.md](./03-sync-command.md).
- The module being imported: [02-sync-target-module.md](./02-sync-target-module.md).
- Plan index: [README.md](./README.md).
