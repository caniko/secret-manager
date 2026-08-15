# Installation

## From source (Nix)

```sh
nix build git+https://github.com/caniko/secret-manager
```

Or add it as a flake input:

```nix
inputs.secret-manager.url = "git+https://github.com/caniko/secret-manager";
```

## From source (Rust)

Requires Rust 2024 edition toolchain.

```sh
git clone https://github.com/caniko/secret-manager.git
cd secret-manager
cargo build --release
```

## Prerequisites

- `agenix` with `agenix edit`, `agenix generate`, and `agenix rekey`
- age identity files at `age/master-*.pub` in the store repository
- (for `push` or `sync`) `fj` or `gh` authentication for Codeberg, Codefloe, or GitHub API access
