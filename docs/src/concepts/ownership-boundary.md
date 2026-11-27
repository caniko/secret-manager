# Ownership Boundary

`secret-manager` is the engine for age-encrypted secret stores and their
generators, sync targets, and vault imports. It is intentionally separated from
both the data repositories that hold ciphertext and the desktop application
provisioning tool (`nix-provenance`).

## `secret-manager`

`secret-manager` owns:

- **Vault read and import (`rbw`)**: reading selected fields from Bitwarden via
  `rbw` under no-swap / sleep-inhibit protection (`RbwSource`, `RbwItem`,
  `CredentialProtection`), projecting fields into plaintext or JSON documents,
  and never storing or prompting for the vault master password.
- **Store encryption and locking (`age`)**: encrypting plaintext into binary
  age v1 files through `agenix-stream-encryptor` (`StreamEncryptor`),
  serializing store mutations with the shared kernel `flock`, staging scoped
  changes, and driving `agenix rekey`.
- **Secret generators and sync**: the standalone `secret-manager-passphrase`
  generator, agenix-rekey generator library (`mkGenerators`), and CI/forge/k8s
  sync targets.

## `nix-provenance`

`nix-provenance` owns desktop application auto-login and account provisioning,
including:

- **Desktop `rbw` daemon lifecycle**: configuring, unlocking, and managing the
  desktop `rbw` agent/pinentry integration for interactive user sessions.
- **In-process OAuth recovery checkpoint encryption**: encrypting short-lived,
  app-local OAuth / enrollment recovery state inside the provenance workflow
  rather than writing it to the shared agenix store.
- **Application-specific credential adapters**: validating app-specific JSON
  schemas and TOTP parameters before handing the validated document to
  `secret-manager` for store encryption.

## Data repositories (`age/secrets/`)

Consumer repositories (such as a NixOS fleet flake) own:

- **Ciphertext and public halves**: `age/secrets/**/*.age`, `.pub`, `.asc`, and
  `.fingerprint` files, plus host/user rekeyed outputs.
- **Policy and declarations**: which recipients, master identities, sync
  targets, and rotation policies apply to each secret.

`secret-manager` never embeds fleet-specific paths or recipients; consumers
wire its Nix library functions and pass their store root and encryptor package.
