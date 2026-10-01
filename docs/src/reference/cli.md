# CLI Reference

```
secret-manager <COMMAND>
```

Declarative secret management for Nix store repositories.

## Commands

### `gpg publish` — Account signing keys

Register an existing armored public key on authenticated forge accounts:

```sh
secret-manager gpg publish nomad.asc --codefloe --github --codeberg
```

| Flag                                 | Description                                                             |
| ------------------------------------ | ----------------------------------------------------------------------- |
| `--codefloe`                         | Register on the Forgejo account at `codefloe.com`                       |
| `--github`                           | Register on the GitHub account at `github.com`                          |
| `--codeberg`                         | Register on the Forgejo account at `codeberg.org`                       |
| `--forgejo HOST`                     | Add another Forgejo destination; repeatable                             |
| `--dry-run`                          | Validate the public key and print destinations without network calls    |
| `--check`                            | Read back registration; fail if any selected account is missing the key |
| `--expected-fingerprint FINGERPRINT` | Require this full fingerprint before contacting a forge                 |

Choose at least one destination. The command accepts exactly one public primary
key in one ASCII-armored block, rejects private-key packets, and inspects it with
GnuPG in an isolated temporary keyring. It does not import into your keyring.
Relative file paths resolve from the working directory; no secret store is needed.

Forgejo destinations reuse `fj` authentication in its existing auth store.
Tokens need `read:user` for listing and `write:user` for registration. GitHub
reuses `gh` authentication; classic/OAuth tokens need `read:gpg_key` and
`write:gpg_key`, respectively.

Retries are idempotent: an existing key is accepted only after matching its full
fingerprint from the API's public-key packets. Every destination is attempted
even if another fails, and incomplete publication exits nonzero. After a failed
POST, a read-back checks whether registration succeeded before reporting failure.

Output reports registration, signing capability, email verification, and
Forgejo's key-ownership verification separately. Uploading a key does not perform
Forgejo's proof-of-possession challenge or verify an account email. Codefloe
account registration uses its Forgejo API, independently of Crow CI credentials.

### `hm` — Home-manager secrets

Add an agenix secret for a home-manager target.

**Subcommands:**

| Command    | Description                                              |
| ---------- | -------------------------------------------------------- |
| `ssh`      | Generate an SSH key and expose as a home-manager file    |
| `password` | Generate a passphrase and expose as env vars or a file   |
| `text`     | Encrypt text from editor/stdin/--from-file as env vars   |
| `file`     | Encrypt a file payload and expose as a home-manager file |

**Options (shared):**

| Flag                 | Description                                     |
| -------------------- | ----------------------------------------------- |
| `--name <SLUG>`      | Secret slug                                     |
| `--user <USER>`      | Home-manager user (default: current login user) |
| `--shared`           | Store under `age/secrets/users/shared/`         |
| `--env <VAR>`        | Environment variable names                      |
| `--file <PATH>`      | File path within the home profile               |
| `--from-file <PATH>` | Read plaintext from file                        |
| `--from-age <PATH>`  | Adopt an existing encrypted .age file           |
| `--algorithm <ALGO>` | SSH key algorithm (`ed25519`, `rsa`)            |
| `--length <N>`       | Passphrase length (32, 48, 64)                  |
| `--no-rekey`         | Skip `agenix rekey -a`                          |
| `--no-stage`         | Skip `git add`                                  |

### `nixos` — NixOS host secrets

Add an agenix secret for a NixOS host target.

**Subcommands:**

| Command    | Description                                          |
| ---------- | ---------------------------------------------------- |
| `ssh`      | Generate an SSH key and expose as a NixOS file       |
| `password` | Generate a passphrase for service env vars or a file |
| `text`     | Encrypt text as service env vars                     |
| `file`     | Encrypt a file payload and expose as a NixOS file    |

**Options (shared):**

| Flag                 | Description                                   |
| -------------------- | --------------------------------------------- |
| `--name <SLUG>`      | Secret slug                                   |
| `--host <HOST>`      | NixOS host name                               |
| `--env <VAR>`        | Environment variable names                    |
| `--service <NAME>`   | Systemd service names (required with `--env`) |
| `--file <PATH>`      | File path on the host                         |
| `--from-file <PATH>` | Read plaintext from file                      |
| `--from-age <PATH>`  | Adopt an existing encrypted .age file         |
| `--algorithm <ALGO>` | SSH key algorithm                             |
| `--length <N>`       | Passphrase length                             |
| `--no-rekey`         | Skip `agenix rekey -a`                        |
| `--no-stage`         | Skip `git add`                                |

### `forgejo` — Forgejo Actions secrets

Add an agenix secret for Forgejo Actions or runner credentials.

**Subcommands:**

| Command        | Description                                                         |
| -------------- | ------------------------------------------------------------------- |
| `ssh`          | Generate or refresh a Forgejo Actions SSH deploy key                |
| `gpg-key-pair` | Generate or adopt an OpenPGP private key and derive public metadata |
| `password`     | Generate a passphrase as a runner credential                        |
| `text`         | Encrypt text as a runner credential                                 |
| `file`         | Encrypt a file payload as a runner credential                       |

**Options (shared):**

| Flag                    | Description                                        |
| ----------------------- | -------------------------------------------------- |
| `--name <SLUG>`         | Secret slug                                        |
| `--cred <NAME>`         | Runner credential name                             |
| `--instance <INSTANCE>` | Runner instance (repeatable)                       |
| `--pubkey-var <VAR>`    | Nix variable name for the generated public key     |
| `--module-dir <DIR>`    | Module-secret directory for `gpg-key-pair` sources |
| `--user-id <UID>`       | OpenPGP user ID for newly generated keys           |
| `--rotate`              | Force SSH key rotation                             |
| `--from-file <PATH>`    | Read plaintext from file                           |
| `--from-age <PATH>`     | Adopt an existing encrypted .age file              |
| `--length <N>`          | Passphrase length                                  |
| `--no-rekey`            | Skip `agenix rekey -a`                             |
| `--no-stage`            | Skip `git add`                                     |

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
  --codefloe <OWNER/REPO> \
  --github <OWNER/REPO> \
  --identity <IDENTITY.pub>
```

### `sync` — Push declared sync targets

Read a collected `services.secretSync` JSON document and push each declared
target to Codeberg/Forgejo, Codefloe, or GitHub Actions scopes. Codeberg/Forgejo
targets support repository, organization, and authenticated-user scopes;
Codefloe and GitHub targets are repository-scoped. Encrypted `secret` targets
are pushed as Actions secrets; plaintext `source` targets are pushed as Actions
variables.

```sh
secret-manager sync --dry-run
secret-manager sync --identity <IDENTITY.pub>
```

By default, `sync` discovers the nearest flake root and evaluates that flake's
`secret-manager.lib.collect` output over `nixosConfigurations`. Use `--dry-run`
to print the planned pushes without decrypting or contacting the forge.

For portable scripts, pass an explicit collected JSON document:

```sh
secret-manager sync --config sync-targets.json --identity <IDENTITY.pub>
```

If `--config` is omitted and stdin is not a terminal, `sync` reads the JSON
document from stdin. Pass `--no-flake` to disable flake auto-detection and
require one of those explicit input paths.

`sync` records the remote Actions secrets and variables it manages in
`<secret-store>/.secret-manager/sync-state.toml` by default. Pass
`--state <PATH>` to use a different state file. Entries that were previously
managed but no longer appear in the collected config are reported as stale.
They are only deleted from their configured forge when `--prune` is passed.

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

| Flag              | Description   |
| ----------------- | ------------- |
| `-h`, `--help`    | Print help    |
| `-V`, `--version` | Print version |
