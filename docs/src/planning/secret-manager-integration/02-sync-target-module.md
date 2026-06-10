# Phase 02 — Expose a declarative sync-target NixOS/HM module (dns-manager style)

## Working tree

This repo: **`/data/nvme0/can/Projects/secret-manager`**. Both the `nix/` Nix
code and the `crates/secret-manager/` Rust code are edited here.

## Goal

`secret-manager`'s flake exposes a `nixosModules.<name>` (and `default`, and a
home-manager equivalent if cheap to share) that lets a store **declaratively
declare which secrets synchronize to which codeberg/forgejo repositories** —
i.e. the imperative `secret-manager push --codeberg owner/repo --name NAME
secret.age` flags, lifted into Nix options. A `lib.collect` function reduces a
config into a JSON document, and a Rust type deserializes that exact document.
This is "module options only": the module declares data; nothing runs at
activation time. Phase 03 makes the CLI consume the collected document.

## Why this matters now

`secret-manager` is meant to live inside canix "as a separate nix activation,
just [like] dns-manager". `dns-manager` achieves that by exposing
`nixosModules.dns` + `lib.collect`, with the binary consuming the collected
data (`/data/nvme0/can/Projects/dns-manager/nix/{module.nix,collect.nix,default.nix}`).
`secret-manager` currently exposes only `lib` (the `mkSecret` helpers) and
`docs` — **no module, no collect, no activation surface**. Without this phase
there is nothing for canix to import as an activation and nothing declarative
for a `sync` command to read; sync targets would stay scattered across
ad-hoc CLI flags.

Note the distinction this phase must respect: `nix/lib.nix`'s `mkSecret`
*delivery* targets (`home` env/file, `system` env/file, `forgejo` runner
`credential`) describe how a decrypted secret reaches a consumer **on a host**.
This phase adds a *separate* concept: **sync targets** = "push this secret's
plaintext into repo X's Actions secret store under name N". Do not overload
`mkSecret`'s `targets.forgejo.credential` for this — runner credentials and
Actions-secret sync are different delivery paths.

## Out of scope

- No `sync` CLI command yet — that is Phase 03. This phase only produces the
  module, the collect contract, and the Rust type that reads it.
- Do not modify `mkSecret` / `mkSharedSecret` / `pubOf` in `nix/lib.nix`.
- No auto-activation: no systemd unit, no `system.activationScripts`, no
  home-manager activation step. (Locked decision: module options only.)
- Do not touch `nix-manager-core` (Phase 01) or canix (Phase 04).

## Plan

1. **Design the option schema** in a new `nix/module.nix` (mirror dns-manager's
   thin-module style — declare data, no logic). Suggested shape under a stable
   namespace, e.g. `services.secretSync` (pick a name and use it consistently):
   ```nix
   options.services.secretSync = {
     enable = lib.mkEnableOption "declarative secret synchronization to forges";
     targets = lib.mkOption {
       type = lib.types.attrsOf (lib.types.submodule { options = {
         secret    = lib.mkOption { type = lib.types.str; };  # .age path, store-relative
         name      = lib.mkOption { type = lib.types.str; };  # Actions secret name
         codeberg  = lib.mkOption { type = lib.types.listOf lib.types.str; default = []; };  # owner/repo
         host      = lib.mkOption { type = lib.types.str; default = "codeberg.org"; };
       }; });
       default = {};
     };
   };
   ```
   Choose option names deliberately — they become the public contract. Document
   each option with `description`.
2. **Write `nix/collect.nix`** following the dns-manager pattern: `{lib}:
   syncConfig: { ... }`, filtering to enabled hosts/configs and reducing to a
   plain JSON-serializable attrset. The `builtins.toJSON` of this output is
   exactly the binary's input — keep it flat and explicit. Decide and document
   whether collection is per-host (walk `nixosConfigurations` like dns-manager)
   or a single flat target list; per-host mirroring dns-manager is preferred for
   consistency.
3. **Wire flake outputs** in `nix/default.nix`'s `extraOutputs`:
   ```nix
   nixosModules = { secretSync = module; default = module; };
   # home-manager variant only if the same module evaluates under HM unchanged;
   # otherwise expose homeManagerModules separately or defer it (note in commit).
   lib = (import ./lib.nix) // { collect = import ./collect.nix { inherit lib; }; };
   ```
   Keep the existing `lib` (mkSecret etc.) and `docs` outputs intact — extend,
   don't replace.
4. **Add the Rust deserialization type.** Create
   `crates/secret-manager/src/sync_targets.rs` with `serde` types matching the
   collected JSON exactly (e.g. `SyncDocument { targets: Vec<SyncTarget> }`,
   `SyncTarget { secret, name, codeberg: Vec<String>, host }`). Add a function to
   load it from a path or from stdin JSON. Register the module in
   `crates/secret-manager/src/lib.rs`. Confirm `serde` + `serde_json` are
   available as deps (add if missing — check `crates/secret-manager/Cargo.toml`).
5. **Round-trip test.** Add a unit test in `sync_targets.rs` that deserializes a
   JSON literal matching `collect.nix`'s `builtins.toJSON` output for a small
   example, asserting the fields land correctly. Keep a copy of that JSON literal
   as the contract fixture.
6. **Provide an example.** Add a minimal `example/` (or a doc snippet in
   `docs/src/concepts/`) showing a store declaring one sync target, so Phase 04
   and humans have a reference. If you add `example/flake.nix`, keep it eval-only.
7. **Validate Nix eval.**
   ```console
   $ nix eval .#nixosModules.default --apply 'm: builtins.typeOf m'
   $ nix build .#docs    # ensure docs still build if you touched docs/
   ```
8. **Build & test Rust.** `cargo build && cargo nextest run` (the new test must
   pass). Commit (signed). Push only if the user authorizes — Phase 03 builds on
   this within the same repo, so a local commit is enough for sequential work.

## Acceptance criteria

- [ ] `nix/module.nix` exists and declares a sync-target option schema with
      documented options; it does **not** modify `mkSecret`.
- [ ] `nix/collect.nix` exists, takes `{lib}` and a config, and returns a
      JSON-serializable attrset; `nix eval` of a sample through it succeeds.
- [ ] `nix eval .#nixosModules.default` succeeds and `nix eval .#lib.collect`
      resolves to a function.
- [ ] Existing `lib` (mkSecret/mkSharedSecret/pubOf) and `packages.docs` outputs
      still resolve unchanged (`nix eval .#lib.mkSecret` succeeds).
- [ ] `crates/secret-manager/src/sync_targets.rs` deserializes the exact
      `builtins.toJSON` shape from `collect.nix`; its round-trip unit test passes.
- [ ] `cargo build` clean and `cargo nextest run` green in `secret-manager`.
- [ ] An example (flake or doc snippet) declares at least one sync target.

## Pitfalls

- **Conflating sync targets with mkSecret delivery.** Symptom: you extend
  `targets.forgejo.credential` and the schema gets muddy. Cause: the two forge
  concepts (runner LoadCredential vs Actions-secret push) look similar. Recovery:
  keep `services.secretSync` entirely separate from `nix/lib.nix`.
- **JSON shape drift.** Symptom: Phase 03 / the Rust loader fails to deserialize.
  Cause: `collect.nix` emits a shape the `serde` type doesn't match (e.g. attrset
  vs list, missing `host` default). Recovery: define the JSON literal fixture
  first, make `collect.nix` produce it and the Rust type consume it — both sides
  reference the same fixture.
- **HM vs NixOS module divergence.** Symptom: the module evaluates under NixOS
  but errors under home-manager (or vice versa). Cause: referencing
  `config.nixosConfigurations` or NixOS-only types. Recovery: keep the module
  pure data (mkOption only, no `config =` logic) so it loads in both contexts; if
  it can't be shared cleanly, expose only `nixosModules` this phase and note HM
  as deferred in the commit message.
- **Breaking the existing `lib` output.** Symptom: canix's
  `lib/secrets/default.nix` (which does `inherit (inputs.secret-manager.lib)
  mkSecret mkSharedSecret pubOf`) breaks. Cause: replacing `lib` instead of
  merging. Recovery: `lib = (import ./lib.nix) // { collect = ...; }`.

## Files likely touched

Repo: `/data/nvme0/can/Projects/secret-manager`
- `nix/module.nix` — **new**, option schema.
- `nix/collect.nix` — **new**, JSON producer.
- `nix/default.nix` — add `nixosModules` + `lib.collect` to `extraOutputs`.
- `crates/secret-manager/src/sync_targets.rs` — **new**, serde types + loader.
- `crates/secret-manager/src/lib.rs` — register the new module.
- `crates/secret-manager/Cargo.toml` — ensure `serde`/`serde_json` deps.
- `example/` and/or `docs/src/concepts/` — example sync-target declaration.

## Reference

- Exemplar: `/data/nvme0/can/Projects/dns-manager/nix/module.nix`,
  `/data/nvme0/can/Projects/dns-manager/nix/collect.nix`,
  `/data/nvme0/can/Projects/dns-manager/nix/default.nix`.
- Existing helper not to break: `nix/lib.nix` (`mkSecret`).
- Existing flake assembly: `nix/default.nix` (`extraOutputs`).
- Downstream consumers: [03-sync-command.md](./03-sync-command.md) (reads the
  collected document), [04-canix-integration.md](./04-canix-integration.md)
  (imports `nixosModules`).
- Plan index: [README.md](./README.md).
