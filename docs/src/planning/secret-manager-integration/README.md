# Plan: secret-manager-integration

> **Plan-set orchestration model: gpt-5.4-mini (codex) — effort `high`**
>
> Routed: `carter route -c moderate -r planner --provider codex`
> → `gpt-5.4-mini` / `high`
> (`codex --model gpt-5.4-mini -c model_reasoning_effort=high`)
>
> Four phases, three repos, two dependency waves. Coordination complexity
> (a cross-repo git-rev bump that must land in lockstep) is moderate; the
> planner tier is enough to keep the wave ordering and the rev-bump gate
> straight.

## Scope and current state

`secret-manager` is the Rust crate (`crates/secret-manager/`) extracted from
canix's `secret` command family (commit `026d90a`). Its **code is complete** —
there are no `todo!()` / `unimplemented!()` stubs. What is missing is the
*integration architecture* the project is meant to have: living inside canix as
a separate nix activation (mirroring `dns-manager`), sharing the agenix store,
exposing a CLI that is also wired into the canix CLI, and synchronizing secrets
to codeberg/forgejo targets.

Confirmed current state (from source inspection):

- **Flake outputs** (`nix/default.nix`): `mkManagerOutputs` from `nix-manager-core`
  gives `packages.default` (the CLI binary), `checks`, `devShells`, `formatter`.
  `extraOutputs` adds `lib` (the `mkSecret`/`mkSharedSecret`/`pubOf` helpers in
  `nix/lib.nix`) and a `docs` package. **There is no `nixosModules` /
  `homeManagerModules` output** — unlike `dns-manager`, which exposes
  `nixosModules.dns` + `lib.collect` and has the binary consume the collected
  module data.
- **Sync mechanism**: `secret-manager push` decrypts a secret and calls
  `nix_manager_core::forge::push_codeberg_org_secret` /
  `push_github_secret`. The Codeberg path in `nix-manager-core`
  (`crates/nix-manager-core/src/forge.rs`) **crafts a `ureq` PUT against the
  Forgejo REST API directly** — it only *reads* the `forgejo-cli` token file at
  `~/.local/share/forgejo-cli/<host>/TOKEN`; it does not go through the forgejo
  CLI / its crate.
- **canix integration**: canix already embeds the `secret-manager` library
  (`canix/cli/src/commands/secret/mod.rs`) behind `canix secret …`, implementing
  `secret_manager::env::StoreEnv` to bind fleet/home semantics. canix consumes
  `secret-manager.lib` (`canix/lib/secrets/default.nix`) and pins it by git rev
  (`canix/cli/Cargo.toml`). canix's `flake.nix` already declares both
  `dns-manager` and `secret-manager` as inputs.

### Decisions locked with the user (2026-06-10)

1. **Activation = module options only.** Expose a `nixosModule` /
   `homeManagerModule` (dns-manager style) declaring sync-target options the CLI
   reads. Syncing stays a manual CLI invocation — **no** auto-run at
   nixos-rebuild / home switch time.
2. **Sync via the forgejo CLI crate directly.** Replace the direct `ureq` REST
   call with the `forgejo-api` crate (the Rust library Cyborus's `forgejo-cli`
   — owner of the `~/.local/share/forgejo-cli/<host>/TOKEN` path — is built on),
   used as a library dependency. Not REST-by-hand, not shelling out to a binary.
3. **Forge change lands in `nix-manager-core`** (the shared crate), so every
   consumer benefits; secret-manager + canix then bump the git rev in lockstep.
4. **GitHub push left as-is.** The `gh`-based `push_github_secret` keeps working
   and is not extended; codeberg/forgejo is the focus, GitHub is not removed.

## Phase table

| Phase | File | Depends on | Touches (repo) | Can parallel with | Model / Effort |
|---|---|---|---|---|---|
| 01 | [01-forge-forgejo-api.md](./01-forge-forgejo-api.md) | — | `nix-manager-core` | 02 | gpt-5.4-mini / medium |
| 02 | [02-sync-target-module.md](./02-sync-target-module.md) | — | `secret-manager` (nix + rust) | 01 | gpt-5.3-codex / medium |
| 03 | [03-sync-command.md](./03-sync-command.md) | 01, 02 | `secret-manager` (rust) | — | gpt-5.4-mini / medium |
| 04 | [04-canix-integration.md](./04-canix-integration.md) | 01, 02, 03 | `canix` (flake + cli + nix) | — | gpt-5.4-mini / medium |

## Parallelism layer

**Wave 0 — start from the current tree (run concurrently):**
- **Phase 01** (`nix-manager-core` forge → `forgejo-api`). Self-contained in a
  different repo. Output: a forgejo-api-backed `push_codeberg_secret` plus a new
  commit/rev to pin later.
- **Phase 02** (`secret-manager` sync-target module + collect + JSON reader).
  Different repo from Phase 01; touches only `secret-manager`'s `nix/` and adds
  a new Rust module. No file overlap with Phase 01.

These two share no files and no repo, so they fully overlap.

**Wave 1 — unlocked once 01 and 02 are committed:**
- **Phase 03** (`secret-manager sync` command). Needs Phase 01's new forge API
  available — bump the `nix-manager-core` git rev in `secret-manager`'s
  `Cargo.toml` as the first step of this phase. Needs Phase 02's collected
  sync-target shape (the `SyncTargets` deserialization type) to drive what gets
  pushed. Single coherent stream; one agent.

**Wave 2 — unlocked once 03 is committed and green:**
- **Phase 04** (canix integration). Bumps the `secret-manager` **and**
  `nix-manager-core` git revs in canix in lockstep (Phase 01 + 03 must both be
  pushed to codeberg first), surfaces the new `sync` subcommand under
  `canix secret`, imports `secret-manager.nixosModules` as a separate
  activation, and proves canix still evaluates and builds.

**Serialization points:**
- 03 must rebase onto 01's pushed commit (Cargo git dependency on
  `nix-manager-core`).
- 04 must rebase onto 03's pushed commit (Cargo git dependency on
  `secret-manager`) and re-run `nix flake update` for both inputs.
- Within each repo, only one phase touches its `Cargo.toml` / `flake.lock` at a
  time, so there are no intra-repo merge conflicts.

Plan exhausted after Wave 2.

## Whole-set acceptance criteria

- [ ] `nix-manager-core` builds and `cargo nextest run -p nix-manager-core`
      passes with `push_codeberg_secret` implemented over `forgejo-api` (no
      remaining `ureq::put` against `/api/v1/.../actions/secrets/`). GitHub path
      unchanged and still compiles.
- [ ] `secret-manager`'s flake exposes `nixosModules.<name>` (+ `default`) and a
      `lib.collect`; `nix eval .#nixosModules.default` succeeds and the example
      declares at least one sync target.
- [ ] `secret-manager sync` exists, reads collected declarative sync targets,
      and pushes each declared secret to its declared codeberg/forgejo repo(s)
      through the forgejo-api-backed forge. `secret-manager sync --help` lists it.
- [ ] `cargo build` + `cargo nextest run` are green in `secret-manager` against
      the bumped `nix-manager-core` rev.
- [ ] canix: `canix secret sync --help` works; `nix flake check` (or at least
      `nix eval .#nixosConfigurations.<host>.config.system.build.toplevel` for
      one host importing the module) succeeds with the bumped revs.

## Global constraints (apply to every phase)

- **Signed commits.** Use the user's global Git signing defaults as-is — plain
  `git commit` / `git tag`, no `--no-gpg-sign`, no overriding `commit.gpgsign`.
  If the hardware token / pinentry is unavailable and signing blocks, **stop and
  report** — do not bypass signing.
- **Commit/push only when asked.** Phases 03 and 04 depend on prior phases being
  *pushed* to codeberg (Cargo git deps resolve from the remote). Each phase
  should commit its own work; pushing is the user's call unless they say
  otherwise. Flag in the phase when a downstream phase is blocked on a push.
- **Don't touch GitHub push behavior** (decision 4).
- **Auth model is unchanged**: `$CODEBERG_TOKEN` → forgejo-cli token file. The
  forgejo-api migration must preserve this resolution order.

## Reference

- Originating request & decisions: this planning session (2026-06-10).
- Exemplar for the module/collect pattern: `dns-manager`
  (`/data/nvme0/can/Projects/dns-manager/nix/{module.nix,collect.nix,default.nix}`).
- carter (model routing): `https://codeberg.org/caniko/rs-carter`.
