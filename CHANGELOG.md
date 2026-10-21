# Changelog

## [Unreleased]

### Added

- `secret-manager github token` mints an account token through `gh`'s device
  flow, verifies its login and scopes, and encrypts it (bare and/or as an
  `ENV=token` file) with the store's agenix master policy. `gh` state lives in
  a private temporary directory, so the token never reaches the caller's login.

### Fixed

- `mkAgenixStreamEncryptor` kept only a dangling symlink to agenix-rekey's age
  wrapper because `builtins.match` dropped its string context; the wrapper is
  now a runtime dependency of the encryptor package.

- `mkSecret` now forwards `userId` to `age.secrets.<name>.settings.userId` for
  the `gpg-key-pair` generator; it was previously accepted and silently
  dropped. The default is `null`, leaving the generator's own UID in place.

## [0.3.1] - 2026-10-20

### Security

- Consume pklx 0.2 (pklr 5, zip 9), removing zip 8.6.0 and its advisories RUSTSEC-2026-0367, RUSTSEC-2026-0368 and RUSTSEC-2026-0369 from the dependency graph. The public API is unchanged.
- Update rustls-webpki to 0.103.16 and webpki-root-certs to 1.0.10 for RUSTSEC-2026-0382 and RUSTSEC-2026-0383.

## [0.3.0] - 2026-10-12

### Changed

- Publish the Rust package as `caniko-secret-manager`, distinguishing this
  project from the unrelated `secret-manager` crate. The executable remains
  `secret-manager` and the library remains `secret_manager`.
- Consume nix-manager-core 0.4.1 and forgejo-api 0.11 with reqwest 0.13.5 and
  base64 0.23, preserving the synchronous client and Rustls TLS backend while
  converging on one base64 dependency generation.
- Declare and verify Rust 1.88 as the minimum supported toolchain.
- Use the maintained TOML 1.1 generation so persisted sync-state serialization
  shares the same datetime dependency generation as current Cargo metadata tools.

### Migration

- Registry consumers use
  `secret-manager = { package = "caniko-secret-manager", version = "0.3.0" }`.
  Existing `secret_manager` imports, CLI commands and Nix output names remain
  valid. Consumers using the public Forgejo authentication type must also
  upgrade forgejo-api to 0.11.

### Fixed

- Resume interrupted GitHub App imports after encrypted checkpoint persistence,
  retaining the original app identity and key fingerprint bindings.

### Added

- Reusable fail-closed credential-process protection using a no-swap cgroup and
  a logind sleep inhibitor, plus bounded terminal-prompt pipes. Cancellation and
  timeout cleanup settles plaintext-bearing pipe workers before returning.

- Import selected Bitwarden fields through `rbw` into new or explicitly rotated
  agenix sources using bounded private pipes and atomic ciphertext installation.
- Expose in-memory item projection and the consumer-configured agenix master
  encryption backend for authenticated-application adapters.
- Validate projected vault documents with application-owned helpers over bounded
  private pipes, reusing one item snapshot and redacting child diagnostics.

- `github app enroll|import|installation|publish|verify` manages GitHub-issued
  App keys through encrypted, policy-bound transactions. Verifies app ownership,
  exact permissions, selected installations and repository-scoped tokens before
  publishing the PEM and public identity to configured Actions slots.

- `gpg publish` registers public signing keys on Codefloe, GitHub, Codeberg,
  and additional Forgejo accounts. Supports offline dry-runs, read-only checks,
  full-fingerprint duplicate detection, and retryable per-platform results.
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

- Patched HTTP/TLS dependencies and `anyhow` to address the RustSec findings
  reported by hosted qualification.

- Nix library wiring now exposes the shared Forgejo runner file-environment
  helper from the expected module surface.
- Corrected "foregejo" typos to "forgejo" in Nix module paths and source
  references.

[Unreleased]: https://github.com/caniko/secret-manager/compare/0.3.1...HEAD
[0.3.1]: https://github.com/caniko/secret-manager/compare/0.3.0...0.3.1
