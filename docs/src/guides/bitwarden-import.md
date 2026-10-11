# Importing from Bitwarden

The `hm file`, `nixos file`, and `forgejo file` commands accept `--from-rbw`
with an exact Bitwarden item UUID. Unlocking belongs to rbw and pinentry; the
bridge never asks for or stores the vault password. Install rbw 1.15 or later
and authenticate it before importing.

```sh
secret-manager hm file --shared --name service-token \
  --from-rbw 12345678-1234-1234-1234-123456789abc --rbw-field password
```

The default field is `password`. Built-ins include `username`, `password`,
`totp`, and `notes`. Select custom fields with `custom:NAME`; ambiguous or empty
fields fail. `totp` returns the stored seed or URI, not a current one-time code.

Build a JSON document from one item snapshot with repeated mappings:

```sh
secret-manager hm file --shared --name application-account \
  --from-rbw 12345678-1234-1234-1234-123456789abc \
  --rbw-map username=username --rbw-map password=password \
  --rbw-map totpSecret=totp
```

Only mapped fields enter the document. JSON escaping is automatic. All mapped
fields are required; omit an optional mapping when it is absent. Application
adapters own validation of their document and TOTP parameters before encryption.
This generic projection preserves field values exactly.

By default rbw uses its encrypted local cache. `--rbw-sync` explicitly syncs
first; a failed sync prevents importing stale data. `--rbw-timeout-seconds`
sets a 1–300 second deadline per invocation, including pinentry interaction
(default 120 seconds). Helper output is capped at 1 MiB and a selected document
at 512 KiB. Child diagnostics are suppressed because they may contain secrets.

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

This adapter uses agenix-rekey's native master-encryption backend, including
master identities, extra encryption recipients and configured age plugins.
Select the same nodes and `agePackage` as the existing rekey workflow. Unsupported
backend contracts fail during evaluation.

Set `SECRET_MANAGER_AGE_ENCRYPTOR` to its absolute executable path for the
standalone CLI. Embedders can instead implement `StoreEnv::stream_encryptor`;
resolve and realize public encryption policy before reading the vault, and
release any Nix evaluation lease before subprocess work.

The bridge uses private stdout/stdin pipes and zeroizing owned credential
buffers, disables core dumps, and writes only ciphertext to a mode-0600
temporary file beside the destination. Installation is atomic and refuses an
existing source by default. Vault contents never enter command arguments, Nix
expressions, or a plaintext temporary file. Scoped staging and `agenix rekey`
follow encryption; `--no-stage` and `--no-rekey` retain their existing meaning.
Inherited agenix auto-staging is disabled; only newly distributed copies are
staged, and existing work in the distribution directory is preserved.

Standalone RBW imports reexecute the original command in a no-swap user scope
when needed, then verify the effective kernel limit and acquire a logind sleep
inhibitor before vault lookup. The guard remains held through field projection,
encryption, installation and rekey; unavailable protection fails before vault
effects. Public encryption-policy preparation precedes this boundary.

## Rotation and recovery

Repeat the same import with `--rbw-rotate` to replace an existing source. Rotation
requires an existing binary age v1 file and preserves module wiring. It cannot
add a new home/system/runner target. RBW imports, generated rotations and adapters
using `with_store_write_lock` share the existing secret-manager kernel lock.

Missing fields, lookup failure and encryption failure leave existing ciphertext
intact. Source changes observed before vault lookup, after acquiring the lock,
or before installation abort replacement. Direct editors and raw `agenix` calls
do not automatically acquire this lock; concurrent writes through those paths
are outside the cooperative preservation guarantee. Installation is an atomic
rename, not filesystem compare-and-swap. A failed rekey retains the newly
encrypted source: retry staging and `agenix rekey -a` before deploying. Never
restore the old source after distributing a new one to some consumers.

Library adapters must establish no-swap protection and acquire
`protection::CredentialProtection` before `RbwSource::read()`, retain the guard
until plaintext and credential helpers have been dropped, select `RbwItem::field()`, validate
their own document in memory, then call `StreamEncryptor::encrypt_new()` or
`encrypt_replace()`. Use `encryption::with_store_write_lock(root, operation)` to
serialize installation, staging and rekey with the generic import/rotation path.
Constrain destination paths to the intended store.
