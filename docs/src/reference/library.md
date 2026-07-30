# Library API

The `secret_manager` library provides the building blocks used by the CLI.

## Modules

| Module   | Description                                                                                                   |
| -------- | ------------------------------------------------------------------------------------------------------------- |
| `add`    | CLI argument types and plan-building for all secret types                                                     |
| `env`    | `StoreEnv` trait for host validation and user resolution                                                      |
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

Methods:

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

Each variant encodes the source expression, secret path, module path,
and delivery targets.

### `RenderedModule`

The output of rendering a target spec into a Nix module file:

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

Renders a set of targets into Nix modules by calling `mkSecret` with the
appropriate source expressions and delivery targets.

### `render_body`

```rust,ignore
pub fn render_body(target: &TargetSpec, generator: Option<&GeneratorSpec>) -> String
```

Renders a single target into the body of a Nix module.

### `run_plan`

```rust,ignore
pub fn run_plan(args: &CommonSourceArgs, plan: AddPlan) -> Result<()>
```

Executes an `AddPlan`: validates destinations, prepares secret sources,
writes modules, runs generation or encryption, stages, and rekegs.

### `camel`

```rust,ignore
pub fn camel(s: &str) -> String
```

Converts kebab-case and snake_case to CamelCase used for age name derivation.

Example: `"nix-trusted"` → `"NixTrusted"`, `"copr-token"` → `"CoprToken"`.

### `default_forgejo_age_name`

```rust,ignore
pub fn default_forgejo_age_name(instance: &str, slug: &str) -> String
```

Derives the default agenix secret name for a Forgejo credential.

Example: `("codeberg", "copr-token")` → `"forgejoRunnerCodebergCoprToken"`

### `default_forgejo_ssh_key_age_name`

```rust,ignore
pub fn default_forgejo_ssh_key_age_name(slug: &str) -> String
```

Derives the default agenix secret name for a Forgejo SSH key.

Example: `"aur-ssh-key"` → `"forgejoActionsAurSshKey"`
