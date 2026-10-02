# CLI Reference

```
secret-manager <COMMAND>
```

Declarative secret management for Nix store repositories.

## Commands

### `github app` — GitHub-issued App credentials

`enroll` serves a local manifest form and callback on `127.0.0.1`. Open the
printed URL in an authenticated GitHub browser, register the app, then authorize
its **selected-repository** installation. The conversion response is encrypted
before parsing or publication; the CLI never generates an app private key.

```sh
secret-manager github app enroll --config review-app.json \
  --store /path/to/canix --transaction /private/state/review-app \
  --identity age/master_identities/master_nitro3c_identity.pub
```

The transaction's parent directory must already exist. The CLI creates the
transaction directory with mode `0700`; files use `0600`. Keep it outside tracked
source trees. The manifest callback must complete within one hour; the default
listener deadline is 900 seconds (`--timeout-seconds`, maximum 3500). `--port`
chooses a loopback port. Retries reuse the original port and policy/store binding.

The public policy is JSON:

```json
{
  "version": 1,
  "slug": "example-review",
  "owner": "example",
  "repository": "example/project",
  "homepage": "https://github.com/example/project",
  "source": "age/secrets/review-app.age",
  "recipients": ["age1..."],
  "permissions": {"contents": "read", "pull_requests": "write", "checks": "write"},
  "keySecretName": "COMMITPERCLIP_KEY",
  "appIdVariable": "COMMITPERCLIP_APP_ID",
  "appSlugVariable": "COMMITPERCLIP_APP_SLUG"
}
```

Use real public age recipients. The app owner must match the repository owner;
permissions must match the declaration, with only GitHub's automatic
`metadata: read` permitted additionally. The issued slug must match the declared
slug. If GitHub assigns a different slug, retain the encrypted checkpoint and
import a settings-issued key with a corrected policy in a fresh transaction.

For an already registered app or a settings-issued replacement key:

```sh
secret-manager github app import --config review-app.json --store /path/to/canix \
  --transaction /private/state/review-app --app-id 12345 --pem-file /private/key.pem
secret-manager github app installation --config review-app.json \
  --store /path/to/canix --transaction /private/state/review-app
secret-manager github app publish --config review-app.json --store /path/to/canix \
  --transaction /private/state/review-app --identity /private/age-identity
secret-manager github app verify --config review-app.json --store /path/to/canix \
  --transaction /private/state/review-app --identity /private/age-identity
```

`import` requires an operator-owned private PEM file and verifies its JWT against
GitHub `/app`. It retains the original file; remove it through your normal private
credential handling after encrypted adoption. App-key generation/revocation is a
GitHub settings operation; this CLI automates adoption and publication.

`installation` prints the authorization URL. With `--installation-id`, it can
add the declared repository to an existing selected installation using the
operator's authenticated `gh` account. It verifies app/installation ownership and
repository administration before mutation, then verifies token scope afterward.

`publish` verifies the encrypted checkpoint, authenticates the app, checks the
installation, mints an exactly-one-repository token and revokes that verification
token. It writes the encrypted source and adjacent `.app-id` / `.app-slug` public
files, then uses `gh` stdin to set the named repository secret and variables.
Partial publication is retryable using the same transaction. `--replace-key`
permits an explicit verified rotation and retains the previous ciphertext in
`previous.age`. Publication is serialized per source.

The JSON receipt contains IDs, public-key fingerprint, policy/checkpoint/source
hashes, token expiry and successful slot names. It contains no PEM, JWT or token.
Its `actionsSlotQualified` stays `false`: GitHub does not return stored Actions
secret plaintext, so the trusted hosted workflow must prove destination use.
`verify` checks the encrypted source credential, not the installed Actions slot.

If a crash follows manifest exchange, retry `enroll` with the same transaction:
an encrypted response can be recovered. If no ciphertext exists, the consumed
code has an ambiguous outcome; inspect GitHub settings and import an issued key
in a fresh transaction. Never replay that conversion blindly.

`gh` must already be authenticated to `github.com`; age identities use the
existing `--identity` / `SECRET_MANAGER_AGE_IDENTITIES` contract. Canix hardware
identity stubs under `age/master_identities/` should be passed explicitly.
Declaration of `services.secretSync.targets` does not schedule execution.

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
