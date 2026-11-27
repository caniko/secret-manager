# Importing from Bitwarden

Install and authenticate rbw 1.15 or later. Pass `--from-rbw` with the exact
Bitwarden item UUID to `hm file`, `nixos file`, or `forgejo file`. rbw and
pinentry unlock the vault; the bridge never asks for or stores its password.
See [Ownership Boundary](../concepts/ownership-boundary.md) for the split between
`secret-manager` (vault import and store encryption), `nix-provenance`, and
consumer `age/secrets/` repositories.

```sh
secret-manager hm file --shared --name service-token \
  --from-rbw 12345678-1234-1234-1234-123456789abc --rbw-field password
```

Built-in fields include `username`, `password` (default), `totp`, and `notes`.
Use `custom:NAME` for custom fields; ambiguous or empty fields fail.
`totp` returns the stored seed or URI, not a current one-time code.

Repeat `--rbw-map` to build JSON from one item snapshot:

```sh
secret-manager hm file --shared --name application-account \
  --from-rbw 12345678-1234-1234-1234-123456789abc \
  --rbw-map username=username --rbw-map password=password \
  --rbw-map totpSecret=totp
```

Only mapped fields enter the JSON, with automatic escaping and unchanged
values. Mapped fields are required; omit mappings for absent optional fields.
Each application adapter must validate its own document and TOTP parameters
before encryption.

rbw defaults to its encrypted local cache. `--rbw-sync` syncs first; failure
blocks stale imports. `--rbw-timeout-seconds` sets a 1–300 second deadline per
invocation, including pinentry (default 120 seconds). Limits: 1 MiB of helper
output and 512 KiB per selected document. The bridge suppresses child
diagnostics because they may contain secrets.

## Encryption policy

Consumers export an `agenix-stream-encryptor` package using
`secret-manager.lib.mkAgenixStreamEncryptor`:

```nix
packages.agenix-stream-encryptor = secret-manager.lib.mkAgenixStreamEncryptor {
  inherit pkgs;
  agenixRekey = inputs.agenix-rekey;
  userFlake = self;
  nixosConfigurations = self.nixosConfigurations;
};
```

The adapter uses agenix-rekey's native master-encryption backend: master
identities, extra encryption recipients, and configured age plugins. Match
the rekey workflow's nodes and `agePackage`. Evaluation rejects unsupported
backend contracts.

For the standalone CLI, set `SECRET_MANAGER_AGE_ENCRYPTOR` to the absolute
encryptor path. Embedders can implement `StoreEnv::stream_encryptor` instead.
Resolve and realize public encryption policy before vault reads; release any
Nix evaluation lease before running subprocesses.

The bridge uses private stdout/stdin pipes and owned, zeroizing credential
buffers. It disables core dumps and writes only ciphertext to a mode-0600
temporary file beside the destination. Installation is atomic and rejects
existing sources by default. No vault contents enter command arguments, Nix
expressions, or plaintext temporary files. Scoped staging and `agenix rekey`
follow encryption, subject to `--no-stage` and `--no-rekey`. The bridge disables
inherited agenix auto-staging, stages only newly distributed copies, and
preserves existing work in the distribution directory.

After preparing public encryption policy, standalone RBW imports rerun the
original command in a no-swap user scope if needed. Before vault lookup, they
verify the effective kernel limit and acquire a logind sleep inhibitor. Without
protection they abort before affecting the vault; otherwise they hold the guard
through field projection, encryption, installation, and rekey.

## Rotation and recovery

`--rbw-rotate` requires an existing binary age v1 source and replaces it in
place. Rotation preserves module wiring and cannot add home/system/runner
targets. RBW imports, generated rotations, and adapters using
`with_store_write_lock` share the secret-manager kernel lock.

Missing fields, lookup failures, and encryption failures leave ciphertext
intact. Replacement aborts if it detects a source change before vault lookup,
after locking, or before installation. Direct editors and raw `agenix` calls
do not automatically lock; concurrent writes through them are outside the
cooperative guarantee. Installation uses atomic rename, not filesystem
compare-and-swap. If rekey fails, the newly encrypted source remains in place;
retry staging and `agenix rekey -a` before deploying. Never restore the old
source after any consumer receives the new one.

Library adapters must establish no-swap protection and acquire
`protection::CredentialProtection` before `RbwSource::read()`. Hold the guard
until you drop plaintext and credential helpers. Select `RbwItem::field()`,
validate the document in memory, then call `StreamEncryptor::encrypt_new()` or
`encrypt_replace()`. Constrain destinations to the intended store. Use
`encryption::with_store_write_lock(root, operation)` to serialize installation,
staging, and rekey with the generic import/rotation path.
