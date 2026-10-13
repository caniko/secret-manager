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

Requires Rust 1.88 or newer.

```sh
git clone https://github.com/caniko/secret-manager.git
cd secret-manager
cargo build --release
```

The registry package is `caniko-secret-manager`; installing it provides the
same `secret-manager` executable:

```sh
cargo install caniko-secret-manager --version 0.3.0 --locked
```

## Prerequisites

- `agenix` with `agenix edit`, `agenix generate`, and `agenix rekey`
- age identity files at `age/master-*.pub` in the store repository
- (for `push` or `sync`) `fj` or `gh` authentication for Codeberg, Codefloe, or GitHub API access
