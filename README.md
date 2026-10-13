# secret-manager

<!-- simit:badges:start -->

[![CI](https://img.shields.io/badge/CI-managed+extra-2088ff)](.github/workflows/ci.yaml) [![Nix](https://img.shields.io/badge/Nix-drift-5277c3)](flake.nix) [![docs](https://img.shields.io/badge/docs-enabled-6f42c1)](docs) [![crates.io](https://img.shields.io/badge/crates.io-ready-f46623)](https://crates.io/crates/caniko-secret-manager)

<!-- simit:badges:end -->

Declarative secret management for NixOS — resolve and render age/agenix secrets
from shared Nix declarations, in the same pattern as
[dns-manager](https://github.com/caniko/dns-manager).

The Rust package is `caniko-secret-manager`; its library is `secret_manager`
and its executable is `secret-manager`. Rust 1.88 or newer is required.

```toml
[dependencies]
secret-manager = { package = "caniko-secret-manager", version = "0.3.0" }
```

See the [library guide](docs/src/reference/library.md) for the API and the
[changelog](CHANGELOG.md) for migration details.

## License

MIT. See [LICENSE](LICENSE).
