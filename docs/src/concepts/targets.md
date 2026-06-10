# Target Stacks

Every secret targets a **stack** that determines where the Nix module is
generated and how the secret is delivered to consumers.

## Home stack

Targets home-manager profiles — per-user or shared. Secrets can be delivered
as environment variables or files on the home filesystem.

| Field     | Purpose                               |
|-----------|---------------------------------------|
| `user`    | Home-manager user profile             |
| `env`     | Shell environment variable names      |
| `file`    | File path within the home profile     |

Generated module path: `home/user/<user>/repositories/<slug>.nix`  
Secret path: `age/secrets/users/<user>/<slug>.age`

## System stack

Targets NixOS hosts. Secrets can be delivered as systemd environment files
or files on the host filesystem.

| Field      | Purpose                               |
|------------|---------------------------------------|
| `host`     | NixOS host name                       |
| `env`      | Environment variable names            |
| `services` | Systemd services receiving the env file |
| `file`     | File path on the host                 |

Generated module path: `root/hosts/<host>/server/<slug>.nix`  
Secret path: `age/secrets/hosts/<host>/<slug>.age`

## Forgejo stack

Targets Forgejo Actions runner credentials. Secrets can be delivered as
runner credentials or source-only (e.g., SSH keys without credential binding).

| Field        | Purpose                             |
|--------------|-------------------------------------|
| `credential` | Credential name in the runner store  |
| `instances`  | Runner instances receiving the credential |

Generated module path: `root/modules/server/forgejo-runner-secrets/<slug>.nix`  
Secret path: `age/secrets/modules/forgejo-runner/<slug>.age`

## Source-only secrets

When a secret has no delivery target (e.g., a shared SSH key stored for
manual use), the engine still generates the `.age` file and optionally
its Nix module, but does not register delivery targets.
