# secret-manager

Declarative secret management for NixOS — resolve and render age/agenix secrets
from shared Nix declarations.

secret-manager is the engine that generates agenix secret modules, manages
`.age` files in a Nix data repository (a "store"), and pushes decrypted
secrets to Codeberg/Forgejo, Codefloe, and GitHub Actions secret stores.

It was extracted from the [canix](https://github.com/caniko/canix) CLI;
the canix `secret` command family is a thin shim over this library.

## Repository

- **Source**: <https://github.com/caniko/secret-manager>
- **License**: MIT
