# CLI Reference

```
secret-manager <COMMAND>
```

Declarative secret management for Nix store repositories.

## Commands

### `hm` — Home-manager secrets

Add an agenix secret for a home-manager target.

**Subcommands:**

| Command    | Description                                      |
|------------|--------------------------------------------------|
| `ssh`      | Generate an SSH key and expose as a home-manager file |
| `password` | Generate a passphrase and expose as env vars or a file |
| `text`     | Encrypt text from editor/stdin/--from-file as env vars |
| `file`     | Encrypt a file payload and expose as a home-manager file |

**Options (shared):**

| Flag                     | Description                                       |
|--------------------------|---------------------------------------------------|
| `--name <SLUG>`          | Secret slug                                       |
| `--user <USER>`          | Home-manager user (default: current login user)    |
| `--shared`               | Store under `age/secrets/users/shared/`            |
| `--env <VAR>`            | Environment variable names                         |
| `--file <PATH>`          | File path within the home profile                  |
| `--from-file <PATH>`     | Read plaintext from file                           |
| `--from-age <PATH>`      | Adopt an existing encrypted .age file              |
| `--algorithm <ALGO>`     | SSH key algorithm (`ed25519`, `rsa`)               |
| `--length <N>`           | Passphrase length (32, 48, 64)                    |
| `--no-rekey`             | Skip `agenix rekey -a`                            |
| `--no-stage`             | Skip `git add`                                    |

### `nixos` — NixOS host secrets

Add an agenix secret for a NixOS host target.

**Subcommands:**

| Command    | Description                                      |
|------------|--------------------------------------------------|
| `ssh`      | Generate an SSH key and expose as a NixOS file    |
| `password` | Generate a passphrase for service env vars or a file |
| `text`     | Encrypt text as service env vars                  |
| `file`     | Encrypt a file payload and expose as a NixOS file |

**Options (shared):**

| Flag                     | Description                                       |
|--------------------------|---------------------------------------------------|
| `--name <SLUG>`          | Secret slug                                       |
| `--host <HOST>`          | NixOS host name                                   |
| `--env <VAR>`            | Environment variable names                         |
| `--service <NAME>`       | Systemd service names (required with `--env`)      |
| `--file <PATH>`          | File path on the host                             |
| `--from-file <PATH>`     | Read plaintext from file                          |
| `--from-age <PATH>`      | Adopt an existing encrypted .age file              |
| `--algorithm <ALGO>`     | SSH key algorithm                                  |
| `--length <N>`           | Passphrase length                                 |
| `--no-rekey`             | Skip `agenix rekey -a`                            |
| `--no-stage`             | Skip `git add`                                    |

### `forgejo` — Forgejo Actions secrets

Add an agenix secret for Forgejo Actions or runner credentials.

**Subcommands:**

| Command    | Description                                      |
|------------|--------------------------------------------------|
| `ssh`      | Generate or refresh a Forgejo Actions SSH deploy key |
| `password` | Generate a passphrase as a runner credential       |
| `text`     | Encrypt text as a runner credential               |
| `file`     | Encrypt a file payload as a runner credential      |

**Options (shared):**

| Flag                     | Description                                       |
|--------------------------|---------------------------------------------------|
| `--name <SLUG>`          | Secret slug                                       |
| `--cred <NAME>`          | Runner credential name                             |
| `--instance <INSTANCE>`  | Runner instance (repeatable)                       |
| `--pubkey-var <VAR>`     | Nix variable name for the generated public key     |
| `--rotate`               | Force SSH key rotation                             |
| `--from-file <PATH>`     | Read plaintext from file                          |
| `--from-age <PATH>`      | Adopt an existing encrypted .age file              |
| `--length <N>`           | Passphrase length                                 |
| `--no-rekey`             | Skip `agenix rekey -a`                            |
| `--no-stage`             | Skip `git add`                                    |

### `list` — List secrets

List every `*.age` file tracked in the repository.

```sh
secret-manager list
```

### `push` — Push to CI secret stores

Decrypt an agenix secret and push it to repository Actions secret stores.

```sh
secret-manager push <SECRET.age> \
  --name <SECRET_NAME> \
  --codeberg <OWNER/REPO> \
  --github <OWNER/REPO> \
  --identity <IDENTITY.pub>
```

### `decrypt` — Decrypt to stdout

Decrypt an agenix secret and print plaintext to stdout.

```sh
secret-manager decrypt <SECRET.age> \
  --identity <IDENTITY.pub>
```

### `wg-keygen` — WireGuard keypair

Generate a WireGuard keypair, store the private key as an agenix secret,
print the public key.

```sh
secret-manager wg-keygen <SECRET.age>
```

### `rauthy-env` — Rauthy bootstrap

Bootstrap the Rauthy env-file secret end to end.

```sh
secret-manager rauthy-env [SECRET.age]
```

### `gerrit-cookies` — Gerrit cookies

Encrypt a Gerrit `.gitcookies` payload into an agenix secret.

```sh
secret-manager gerrit-cookies <INPUT_FILE> <SECRET.age>
```

## Global flags

| Flag            | Description |
|-----------------|-------------|
| `-h`, `--help`  | Print help  |
| `-V`, `--version` | Print version |
