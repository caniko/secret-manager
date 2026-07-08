# Changelog

## [Unreleased]

### Added

- Pkl secret registry schema (`pkl/SecretRegistry.pkl`) with Rust types, CLI
  subcommands (`secret-manager registry check|export`, `secret-manager forgejo
  runner-env add`), and Pkl evaluation via nix-pklx.
- Nix `mkForgejoRunnerFileEnv` library function for declarative runner file-env
  secret delivery through agenix + systemd-tmpfiles + container volume mounts.

### Fixed

- Corrected "foregejo" typos to "forgejo" in Nix module paths and source
  references.
