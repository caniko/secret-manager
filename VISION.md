# secret-manager vision

secret-manager is declarative secret management for NixOS. It resolves age/agenix
secrets from shared Nix declarations, generates the agenix module fragments, and
pushes decrypted values to the remote stores that need them: Forgejo/Codeberg,
Codefloe, and GitHub Actions. It was extracted from the canix CLI, and canix's
`secret` command family is built on this library.

## Problem

A fleet keeps the same secret in several places at once: an encrypted `.age` file
in a Nix data repository, a Home Manager environment variable, a systemd
environment file, a Forgejo runner credential, and a GitHub Actions secret. If
each destination is maintained by hand, they drift, rotation is partial, and
nothing states which declarations produced which ciphertext.

## Principles

- The store owns the secrets. secret-manager operates on a Nix data repository
  that holds the agenix tree; it does not host secrets itself. Store discovery
  walks up from the working directory to the nearest `flake.nix` or uses
  `$SECRET_MANAGER_STORE`.
- Declarations are the source of truth. Every secret targets a stack — home,
  system, or Forgejo — and the stack fixes the generated module path and the
  secret path under `age/`.
- Remote writes are reviewable and repeatable: sync targets are declared, prune
  support is explicit, and sync and push commands report their targets and
  results.
- Credential work is fail-closed. Helper processes that may hold plaintext run
  under a no-swap cgroup with a logind sleep inhibitor, use bounded private
  pipes, and settle pipe workers before cancellation or timeout cleanup returns.
- Writes are atomic. Ciphertext installation is atomic, and GitHub App imports
  persist encrypted checkpoints so an interrupted import can resume without
  losing app identity or key-fingerprint bindings.
- The library and the CLI are separate products: the crate publishes as
  `caniko-secret-manager`, the executable stays `secret-manager`, and the Rust
  library import stays `secret_manager`.

## Scope

- Generating agenix secret modules for home-manager profiles, NixOS hosts, and
  Forgejo Actions runners.
- Managing `.age` files in a Nix store repository, including import and rotation.
- Sync targets for Forgejo, Codefloe, and GitHub Actions, including repository
  variables and pruning.
- Importing selected Bitwarden fields through `rbw`.
- WireGuard key generation.
- GitHub App lifecycle: `enroll`, `import`, `installation`, `publish`, and
  `verify`, with ownership, permission, and repository-scope checks before the
  PEM and public identity reach Actions slots.
- Publishing public GPG signing keys to forge accounts.
- A Pkl secret registry with `registry check`/`export`.

## Non-goals

- It does not replace agenix; it generates modules and drives agenix-managed
  ciphertext.
- It does not keep a secrets server or vault of its own. Bitwarden is reached
  through `rbw` as an import source, not as a runtime store.

## Direction

The checked-out `feat/github-app-lifecycle` branch is the current work:
repository-scoped GitHub App enrollment and publication, resumable encrypted
imports, and hardened credential helpers. The 0.3.0 release moved the library to
published `nix-manager-core` and `nix-pklx` dependencies and kept Rust 1.88 as
the minimum compiler.

## Place in the fleet

Canix consumes secret-manager as a flake input and as the engine behind its
`secret` command family, with the CLI and library documented in canix's CLI
product notes. Canix home profiles reference generated secret environment
modules for `can` and `dejana`, and the store layout it operates on is the
canix `age/` tree.
