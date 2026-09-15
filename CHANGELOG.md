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
- `rotate` operation for on-demand rotation of generated agenix secret
  sources: copies the existing source aside (never moves it), regenerates
  with `agenix generate --force-generate` without `-a`, validates the fresh
  file, and stages explicitly so `--no-stage` is honored and failures leave
  worktree and index untouched. Rekey runs as a separate distribution step:
  on failure the new source is kept and reported as distribution-incomplete
  with a rekey-only retry. Zero-knowledge — key material is never printed
  or observed. Missing sources are created.
- `StoreEnv::host_secret_dir` hook so store repos whose Nix side resolves
  host secrets outside `age/secrets/hosts` (e.g. under `age/secrets/root`)
  create sources where their declarations point.

### Fixed

- Nix library wiring now exposes the shared Forgejo runner file-environment
  helper from the expected module surface.
- Corrected "foregejo" typos to "forgejo" in Nix module paths and source
  references.
