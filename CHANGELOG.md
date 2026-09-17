# Changelog

## [Unreleased]

### Added

- Declarative Codefloe and GitHub Actions repository sync targets, including
  GitHub variable and prune support.
- Pkl secret registry schema (`pkl/SecretRegistry.pkl`) with Rust types, CLI
  subcommands (`secret-manager registry check|export`, `secret-manager forgejo
runner-env add`), and Pkl evaluation via nix-pklx.
- Nix `mkForgejoRunnerFileEnv` library function for declarative runner file-env
  secret delivery through agenix + systemd-tmpfiles + container volume mounts.
- `rotate` operation for generated agenix secret sources: idempotent
  ensure-or-preserve by default, explicit `--force` rotation on demand.
  Replacement copies (never moves) the source aside, regenerates without
  `-a`, validates binary or armored age shape with a plausible minimum
  size, and stages explicitly; inherited `AGENIX_REKEY_ADD_TO_GIT` is
  always suppressed for rotation children. Rekey runs as a separate
  distribution step with content-hash staging over a pre-checked clean
  scope; failures keep the new source and report distribution-incomplete
  with a rekey-only retry. A kernel-held, inheritable lock serializes
  whole runs including orphaned children and releases on crash with
  nothing to clean up; preserve mode refuses leftover backups and
  damaged sources instead of blessing them. Zero-knowledge — key
  material is never printed or observed.
- `StoreEnv::host_secret_dir` hook so store repos whose Nix side resolves
  host secrets outside `age/secrets/hosts` create sources where their
  declarations point.

### Fixed

- Nix library wiring now exposes the shared Forgejo runner file-environment
  helper from the expected module surface.
- Corrected "foregejo" typos to "forgejo" in Nix module paths and source
  references.
