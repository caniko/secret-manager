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
  sources: moves the existing source aside, regenerates with
  `agenix generate`, and restores the backup on any failure, so the repo is
  either rotated or untouched. Zero-knowledge — key material is never
  printed or observed.

### Fixed

- Nix library wiring now exposes the shared Forgejo runner file-environment
  helper from the expected module surface.
- Corrected "foregejo" typos to "forgejo" in Nix module paths and source
  references.
