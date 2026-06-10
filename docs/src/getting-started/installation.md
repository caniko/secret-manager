# Installation

## From source (Nix)

```sh
nix build git+https://codeberg.org/caniko/secret-manager
```

Or add it as a flake input:

```nix
inputs.secret-manager.url = "git+https://codeberg.org/caniko/secret-manager";
```

## From source (Rust)

Requires Rust 2024 edition toolchain.

```sh
git clone https://codeberg.org/caniko/secret-manager.git
cd secret-manager
cargo build --release
```

## Prerequisites

- `agenix` with `agenix edit`, `agenix generate`, and `agenix rekey`
- age identity files at `age/master-*.pub` in the store repository
- (for `push`) `forgejo-cli` or `gh` for Codeberg/GitHub secret API access
