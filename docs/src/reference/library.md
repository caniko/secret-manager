# Library API

The CLI uses the `secret_manager` library.

## Schema crate

Data repositories can decode registry types without the engine using a
separate, dependency-light schema crate:

```toml
[dependencies]
secret-manager-schema = { package = "caniko-secret-manager-schema", version = "0.7.1" }
```

`secret_manager_schema::accounts::AccountCatalogue` decodes multiple switchable
accounts per credential service, with a fleet default and per-host and per-user
overrides. `select(service, host, user)` picks host override → user override →
default. `validate` requires each default and override to name a registered
account. Pkl counterparts: `Account`, `AccountService`, `AccountHost`, and
`AccountCatalogue` in `pkl/SecretRegistry.pkl`.

`secret_manager_schema::rotation::RotationCatalogue` decodes manual guides:
title, numbered steps, provider URLs, the command to store the new value, and
expiry (`Expiry::Cadence` by default, `Never` if created without an end date,
`Provider` with the ID of the provider reporting expiry). `for_secret(path)`
looks up a guide by store-relative secret path. `validate` rechecks the key slug,
requires every catalogue URL to start with `https://`, requires `provider`
exactly for `Expiry::Provider`, and forbids cadence fields for `Expiry::Never`.
Pkl counterparts: `RotationGuide` and `RotationCatalogue`
in `pkl/SecretRegistry.pkl`.

## Engine crate

Alias the `caniko-secret-manager` Cargo package to keep existing library imports:

```toml
[dependencies]
secret-manager = { package = "caniko-secret-manager", version = "0.4.0" }
```

Minimum Rust: 1.88. Callers exchanging public Forgejo authentication types must
match Forgejo API 0.11. The Reqwest 0.13 blocking client retains JSON, Rustls,
HTTP/2, charset decoding, and system proxy discovery. The TOML 1.1 migration
preserves destination identities in persisted version-1 sync-state records,
including GitHub environment ownership.

## Modules

| Module   | Description                                                                                                   |
| -------- | ------------------------------------------------------------------------------------------------------------- |
| `add`    | CLI argument types and plan-building for all secret types                                                     |
| `env`    | `StoreEnv` trait for host validation and user resolution                                                      |
| `gpg`    | `GpgCmd` / `PublishArgs`: validate and publish public account signing keys on Forgejo/GitHub                  |
| `guide`  | Rotation guides: load a catalogue, render one guide, and open its provider pages                              |
| `io`     | File I/O, temp dirs, editor integration, validation                                                           |
| `legacy` | Legacy workflows (WireGuard, Rauthy, Gerrit cookies)                                                          |
| `plan`   | Plan execution engine — source prep, module writing, rekey                                                    |
| `push`   | Decrypt and push secrets to Codeberg/Codefloe/GitHub Actions                                                  |
| `render` | Nix module rendering — `TargetSpec`, `render_body`, `camel`                                                   |
| `store`  | `Store` discovery, master identity resolution                                                                 |
| `age`    | Re-export of `nix_manager_core::age` — rage decryption and the shared flags → env → stubs identity resolution |

## Core types

### `Store`

```rust,ignore
pub struct Store {
    pub root: PathBuf,
}
```

- `Store::current_dir()` — root at cwd
- `Store::discover()` — from `$SECRET_MANAGER_STORE` or nearest `flake.nix`
- `store.master_identities()` — sorted `age/master-*.pub` / `age/master_*.pub` stubs
- `store.resolve_identities(flags)` — flags → `SECRET_MANAGER_AGE_IDENTITIES` → stubs

### `TargetSpec`

```rust,ignore
pub enum TargetSpec {
    Home(HomeTarget),
    SharedHome(SharedHomeTarget),
    System(SystemTarget),
    Forgejo(ForgejoTarget),
}
```

Each variant holds the source expression, secret and module paths, and delivery targets.

### `RenderedModule`

Nix module file rendered from a target spec:

```rust,ignore
pub struct RenderedModule {
    pub path: PathBuf,       // Module file path relative to store root
    pub body: String,        // Nix module content
    pub default_nix: PathBuf, // Parent default.nix for import splicing
    pub secret_path: PathBuf, // .age file path relative to store root
    pub stack: Stack,
}
```

### `StoreEnv` trait

```rust,ignore
pub trait StoreEnv {
    fn validate_host(&self, host: &str) -> Result<()>;
    fn resolve_home_user(&self) -> Result<String>;
}
```

- `LocalEnv` — permissive implementation for standalone use
- `TestEnv` — test implementation (resolves user to `"can"`)

## Key functions

### `render_modules`

```rust,ignore
pub fn render_modules(
    targets: &[TargetSpec],
    generator: Option<&GeneratorSpec>,
) -> Vec<RenderedModule>
```

Renders targets into Nix modules that call `mkSecret` with their source
expressions and delivery targets.

### `render_body`

```rust,ignore
pub fn render_body(target: &TargetSpec, generator: Option<&GeneratorSpec>) -> String
```

Renders one target as a Nix module body.

### `run_plan`

```rust,ignore
pub fn run_plan(args: &CommonSourceArgs, plan: AddPlan) -> Result<()>
```

Executes an `AddPlan`: validates destinations, prepares secret sources,
writes modules, generates or encrypts secrets, stages, and rekeys.

### `camel`

```rust,ignore
pub fn camel(s: &str) -> String
```

Converts kebab-case and snake_case to CamelCase for age names.

Example: `"nix-trusted"` → `"NixTrusted"`, `"copr-token"` → `"CoprToken"`.

### `default_forgejo_age_name`

```rust,ignore
pub fn default_forgejo_age_name(instance: &str, slug: &str) -> String
```

Default agenix secret name for a Forgejo credential:

`("codeberg", "copr-token")` → `"forgejoRunnerCodebergCoprToken"`

### `default_forgejo_ssh_key_age_name`

```rust,ignore
pub fn default_forgejo_ssh_key_age_name(slug: &str) -> String
```

Default agenix secret name for a Forgejo SSH key:

`"aur-ssh-key"` → `"forgejoActionsAurSshKey"`
