# Changelog

## [Unreleased]

## [0.8.0] - 2026-11-27

### Added

- `passphrase` and the standalone `secret-manager-passphrase` Nix package
  generate strong passphrases without building the full CLI.
- The `cifs-credentials` and `detritus-tokens` agenix-rekey generators render
  CIFS login files and Detritus token configuration. `detritus-tokens` stores
  the Argon2id hash, not the plaintext bearer token.
- `layout::Category::Dns` gives DNS credentials their own store category.
  Rust callers with exhaustive category matches must handle the new variant.
- `graph` runs reusable secret-management actions in dependency order.
  `release_signing` handles minisign key onboarding, and `github_pat` and
  `dockerhub_pat` provide enrollment and verification helpers.
- `verify` provides credential checks and hidden terminal input. Its `atomic`,
  `yescrypt`, `purelymail`, and `dns` modules cover transactional file installs,
  password hashing, mailbox operations, and DNS credential verification.

### Changed

- Documented the ownership boundary: `secret-manager` owns protected `rbw`
  imports and `age` store operations, `nix-provenance` owns desktop login and
  provisioning, and consumer repositories own ciphertext and recipient policy.

### Fixed

- GitHub App operations now use `ExclusiveFileLock` and validate the opened
  descriptor before using the lock.

## [0.7.1] - 2026-11-19

### Fixed

- Unrelated subprocesses no longer inherit the store write lock. Rotation,
  staging, and encryption helpers still retain it if the caller exits early.

## [0.7.0] - 2026-11-19

Additive for the command line: without `--category`, every writer produces the
same paths and Nix as before. Breaking for Rust callers: `render_modules` takes a
category and returns a `Result`, `CommonSourceArgs` gains `category` and
`expires`, `KubernetesDestination` gains `allow_empty`, and the Forgejo key-pair
plan functions take a category and an expiry.

### Added

- `layout`: the canonical source layout,
  `age/secrets/{home/<user>,home/shared,root/hosts/<host>,root/modules}/<category>/<name>.age`,
  over nine categories (`signing`, `ssh`, `ai`, `forge`, `registry`, `oauth`,
  `cloud`, `app`, `system`). `source_path` builds and `parse` recognises these
  paths; source names may contain dots.
- `--category` on every writer: the source is placed in the layout and the
  generated module names it with the category-taking resolver
  (`secrets.user USER CATEGORY NAME`, `secrets.host HOST CATEGORY NAME`,
  `secrets.module CATEGORY NAME`).
- Versioned `<name>.meta.toml` sidecars (`schema = 1`): `expiry` (`YYYY-MM-DD` or
  `never`; absent is unknown), `rotated_at`, `project`, `custodian`, `kind` and
  `[rotation]`. Every write stamps `rotated_at`; `--expires` on every writer
  records the expiry. `sync --import` writes neither, since an imported value's
  age is unknown.
- `classify`: edits a sidecar without reading the value.
- `inventory`: one value-free JSON document of every source in the layout, with
  tree, scope, category, project, kind, custodian, expiry (`at`, `never` or
  `unknown`), rotation date and guide, and optional consumers
  (`--consumers FILE`). `--write PATH --mode OCTAL` replaces a file atomically.
  `--check` reports sources outside the layout, symlink aliases, orphan
  sidecars, repeated names, missing custodians and unreadable sidecars; embedders
  call `inventory::check` warn-only.
- `allowEmpty` on opaque Kubernetes destinations: an empty value is delivered
  instead of refused, in the same single-touch decrypt (nix-manager-core 0.4.7).

## [0.6.1] - 2026-11-18

### Added

- `social` module: a platform registry for social publishing credentials
  (`platform`, `render` of n8n credentials) and identity verification
  (`verify`, `parse_identity`). Bluesky resolves the account's PDS and
  `did:web` documents only at public addresses and sends an app password only
  to an approved, pinned PDS.

### Fixed

- `StreamEncryptor::encrypt_new` removes the new ciphertext when the
  post-install directory sync fails, instead of leaving an unsynced source.

## [0.6.0] - 2026-11-16

### Changed

- Breaking: the sync state file is version 2. Kubernetes destinations naming
  one `(context, namespace, secret)` are one record with `members` (key, target,
  source). A version 1 file upgrades when read (each Kubernetes record becomes a
  one-member record, key from `KubernetesDestination::data_key`) and is
  rewritten after the next successful sync; a version 1 binary refuses a
  version 2 file, so upgrade every workstation that syncs.
- Breaking for Rust callers: `ManagedRecord` gains `members`,
  `KubernetesDestination` gains `render`, and `SyncArgs` gains
  `verify`, `import`, `adopt` and `encryptor`; exhaustive struct literals must
  add them.
- A Kubernetes Secret may now be declared by several destinations, across
  targets: its members are decrypted in one unlock and applied as one
  server-side apply, so a failure applies nothing and the Secret holds exactly
  the declared keys. Members need distinct keys and one format and field
  manager; a `dockerconfigjson` Secret has one member. `--target` selects every
  target sharing a Secret with a selected one. Removing a member keeps the
  Secret and drops the key.

### Added

- `render = "raw" | "sha256-hex"` on `opaque` Kubernetes destinations, in the
  Rust schema, the NixOS module and `SecretRegistry.pkl`. Empty values are
  refused.
- `sync --verify`: prints `equal`, `different`, `missing-live` or
  `undeclared-live` per key and `foreign-manager` for other data owners; key
  names only, nothing applied.
- `sync --import`: encrypts a live key into a missing `raw` opaque source at
  its declared path, creating the directory; never overwrites, no hardware key.
  The stored plaintext ends in one newline, which decryption strips, so a live
  value that itself ends in a newline verifies `equal`.
- `sync --adopt`: re-verifies, applies under the read `resourceVersion`, then
  hands `data` ownership to this field manager with a `resourceVersion`-tested
  JSON patch of `managedFields`.
- An apiserver integration test (etcd + kube-apiserver, envtest-style) covering
  adoption, the ownership handoff, the `resourceVersion` precondition and member
  removal. It runs when `SECRET_MANAGER_TEST_KUBE_APISERVER` and
  `SECRET_MANAGER_TEST_ETCD` name the binaries.

## [0.5.0] - 2026-11-15

### Changed

- Breaking for Rust callers: `RotationGuide` gains the public `expiry` and
  `provider` fields, so exhaustive struct literals and patterns must add them.
  Catalogues are unaffected: both fields are optional and absent means
  `cadence`.

### Added

- Rotation guides name their expiry kind. `RotationGuide` gains
  `expiry: "cadence"|"never"|"provider"` (default `cadence`, so existing
  catalogues keep their meaning) and `provider: String?`. `never` is an
  explicit kind for a credential created without an end date, distinct from an
  undeclared expiry; `provider` names the provider that reports the expiry.
  `validate` requires `provider` exactly for `provider` and rejects
  `cadenceDays`/`warnDays` on `never`, and `secret-manager guide` prints
  `expiry: never expires` or `expiry: provider-reported (<id>)` for the two new
  kinds.

## [0.4.8] - 2026-11-15

### Added

- Rotation guides: `pkl/SecretRegistry.pkl` gains the `RotationGuide` and
  `RotationCatalogue` classes (title, store-relative secret, `https://` provider
  URLs, steps, storing command, cadence), mirrored by the new
  `secret_manager_schema::rotation` module. `validate` re-checks the key slug
  and the URLs, and `for_secret` maps a secret path to its guide.
- `secret-manager guide --catalogue FILE [KEY] [--no-browser]` prints one
  guide's numbered steps, pages and command, and opens the pages with
  `xdg-open` unless `--no-browser` is given. Without a key it lists the
  catalogue. A missing browser never fails the command.

## [0.4.7] - 2026-11-12

### Fixed

- Release archives: the GitHub release now builds and publishes the signed
  cargo-binstall archives (the previous tag's release workflow failed).

## [0.4.6] - 2026-11-12

### Security

- Release checksums are minisign-signed: the release workflow signs
  `SHA256SUMS.txt` with the canix-managed key published as `keys/minisign.pub`
  and publishes `SHA256SUMS.txt.minisig` next to the cargo-binstall archives.

## [0.4.5] - 2026-11-11

### Added

- New workspace crate `caniko-secret-manager-schema` for registry data types,
  starting with switchable service accounts: several accounts per credential
  service, a fleet default, and per-host and per-user overrides resolved host
  first. `pkl/SecretRegistry.pkl` gains the matching `Account`,
  `AccountService`, `AccountHost` and `AccountCatalogue` classes.
- CI and crate publishing now run per workspace member.

## [0.4.4] - 2026-11-07

### Fixed

- Claude browser enrollment no longer treats native terminal presentation as
  credential data. CSI framing, keyboard modes, OSC links/titles and CR redraws
  outside token paragraphs no longer reject successful authorization. Numeric
  SGR styling (including colon colors) and private display modes are handled
  without changing token text. Editing controls inside token data, incomplete
  sequences and ambiguous tokens remain rejected; output stays private.

## [0.4.3] - 2026-11-07

### Fixed

- `claude token` now captures native `claude setup-token` output privately and
  encrypts the token directly after browser authorization, removing the terminal
  token display and hidden paste prompt. Both output channels are bounded and
  zeroized, with a 15-minute deadline and existing credential protection. ANSI
  styling and hard-wrapped token paragraphs are supported; malformed or differing
  tokens fail closed without storage or secret-bearing diagnostics. Rekeying and
  scoped staging are unchanged.

## [0.4.2] - 2026-11-03

### Fixed

- `kubernetes` sync with the `dockerconfigjson` format now refuses an empty
  value or one containing whitespace or control characters (such as an
  editor-added trailing newline) before any `kubectl` call, so a malformed
  value can no longer overwrite a working pull secret. The error names the
  context, namespace and Secret, never the value, and suggests re-enrolling
  with `canix secret dockerhub-pat --replace`. `opaque` values are unchanged.

## [0.4.1] - 2026-11-03

### Added

- `secret-manager hm text --bare` writes only the encrypted source (requires
  `--name`, no `--env`) for consumers that read the `.age` file directly, such
  as Kubernetes sync targets.

## [0.4.0] - 2026-11-01

### Added

- `kubernetes` sync destinations write an encrypted value to a Kubernetes
  Secret with `kubectl apply --server-side --force-conflicts` in a named
  context and namespace. Formats: `opaque` (one data key, default the target
  `name`) and `dockerconfigjson` (registry login built from `username` and the
  decrypted value). Plaintext `source` values are refused. The manifest is built
  in zeroized memory and reaches `kubectl` on stdin only; the value is never in
  argv or the child environment, `-o`/`-v` are never passed, and child output
  is bounded and redacted of the value and its base64 forms before any report.
  Dry-run and `--check` print the destination and data key names only. Available
  in the `services.secretSync` module, `mkSecretSyncTargets` and the Pkl
  `SyncTarget.kubernetes` schema. `--prune` removes a Secret that is no longer
  declared with `kubectl delete secret --ignore-not-found`.
- Sync state records Kubernetes destinations (provider `kubernetes`, scope
  `namespace`). Older binaries reject these records; do not reuse such a state
  file with an older release.

## [0.3.3] - 2026-10-27

### Changed

- Requires `nix-manager-core` 0.4.5, which refreshes expired `fj` OAuth tokens
  before Forgejo and Codeberg pushes.

### Added

- `lib.mkGenerators` provides the agenix-rekey generators behind the names
  `mkSecret` emits, plus `minisign-key-pair`, with flake checks for the
  passphrase alphabet and minisign failure handling. Moved from canix.

### Fixed

- `sync` planned twice when any record was an encrypted secret: the parent
  discovered the store, loaded state and checked stale entries, then re-ran
  everything in the no-swap scope child, so those steps printed twice. The
  parent now decides from the loaded document alone and re-executes before any
  planning; the child plans once. `--check` and `--dry-run` are unchanged.
- `sync` lost its state when a forge call failed part-way (for example an
  expired token): records already pushed in that run were not recorded. The
  state is now written for the pushed records before the error is returned, and
  a partial run never prunes entries from it.
- `rotate` no longer claims the secret lacks a generator whenever `agenix generate`
  fails (for example a failed FIDO2 assertion while decrypting a dependency).
  agenix skips secrets without a generator and exits 0, so the hint now rides
  on the "reported success but the source is missing" error instead.
- `rotate` failure messages state the recovery that actually completed: a
  rotation restores the previous source, while creating a new source removes
  the partial file or names it when removal fails (they previously claimed
  "the previous source is untouched" in every case, before recovery ran).
  Structural rejections report the file's size and echo its first line only
  when it is a known age header or a version-only variant of one, so
  misplaced plaintext never reaches logs.
- `sync --target` judged staleness against the selected targets only, so every
  other still-declared managed entry was reported as stale (and suggested for
  `--prune`) in `--check`, `--dry-run` and real runs. Stale detection now
  always compares against the complete collected config, including inside the
  no-swap credential scope; `--target` only narrows which targets are pushed.

## [0.3.2] - 2026-10-23

### Added

- `secret-manager github token` mints an account token through `gh`'s device
  flow, verifies its login and scopes, and encrypts it (bare and/or as an
  `ENV=token` file) with the store's agenix master policy. `gh` state lives in
  a private temporary directory, so the token never reaches the caller's login.
- `secret-manager claude token` runs `claude setup-token`, reads the printed
  token from a hidden prompt, validates it and encrypts it with the store's
  agenix master policy, then stages and rekeys it inside the no-swap
  credential scope. With `--secret <attr>`, staging is limited to that
  attribute's rekeyed copies, so unrelated changes in a shared store stay
  untouched.

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

[Unreleased]: https://github.com/caniko/secret-manager/compare/0.8.0...HEAD
[0.8.0]: https://github.com/caniko/secret-manager/compare/0.7.1...0.8.0
[0.7.1]: https://github.com/caniko/secret-manager/compare/0.7.0...0.7.1
[0.7.0]: https://github.com/caniko/secret-manager/compare/0.6.1...0.7.0
[0.6.1]: https://github.com/caniko/secret-manager/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/caniko/secret-manager/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/caniko/secret-manager/compare/0.4.8...0.5.0
[0.4.8]: https://github.com/caniko/secret-manager/compare/0.4.7...0.4.8
[0.4.7]: https://github.com/caniko/secret-manager/compare/0.4.6...0.4.7
[0.4.6]: https://github.com/caniko/secret-manager/compare/0.4.5...0.4.6
[0.4.5]: https://github.com/caniko/secret-manager/compare/0.4.4...0.4.5
[0.4.4]: https://github.com/caniko/secret-manager/compare/0.4.3...0.4.4
[0.4.3]: https://github.com/caniko/secret-manager/compare/0.4.2...0.4.3
[0.4.2]: https://github.com/caniko/secret-manager/compare/0.4.1...0.4.2
[0.4.1]: https://github.com/caniko/secret-manager/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/caniko/secret-manager/compare/0.3.3...0.4.0
[0.3.3]: https://github.com/caniko/secret-manager/compare/0.3.2...0.3.3
[0.3.2]: https://github.com/caniko/secret-manager/compare/0.3.1...0.3.2
[0.3.1]: https://github.com/caniko/secret-manager/compare/0.3.0...0.3.1
