# CLI Reference

```
secret-manager <COMMAND>
```

Declarative secret management for Nix store repositories.

## Commands

### `github app` — GitHub-issued App credentials

`enroll` serves the manifest form and callback on `127.0.0.1`. Open the
printed URL while signed in to GitHub, register the app, then authorize its
**selected-repository** installation. The CLI encrypts the conversion response
before parsing or publication and never generates an app private key.

```sh
secret-manager github app enroll --config review-app.json \
  --store /path/to/canix --transaction /private/state/review-app \
  --identity age/master_identities/master_nitro3c_identity.pub
```

Create the transaction's parent directory outside tracked source trees. The
CLI creates the transaction directory at mode `0700` and files at `0600`. The
manifest callback must finish within one hour. `--timeout-seconds` sets the
listener deadline (default 900 seconds, maximum 3500); `--port` selects a
loopback port. Retries reuse the original port and policy/store binding.

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
  "permissions": {
    "contents": "read",
    "pull_requests": "write",
    "checks": "write"
  },
  "keySecretName": "COMMITPERCLIP_KEY",
  "appIdVariable": "COMMITPERCLIP_APP_ID",
  "appSlugVariable": "COMMITPERCLIP_APP_SLUG"
}
```

Use real public age recipients. Require matching app and repository owners,
declared permissions (plus only GitHub's automatic `metadata: read`), and an
issued slug matching the declaration. If GitHub assigns another slug, keep the
encrypted checkpoint and import a settings-issued key in a fresh transaction
with a corrected policy.

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

`import` verifies the JWT from an operator-owned private PEM file against
GitHub `/app`. It keeps the original PEM; remove it through your usual private
credential handling after encrypted adoption. Key generation/revocation stays
in GitHub settings; the CLI adopts and publishes keys.

If import saves `issued.age` but stops before recording its digest, retry with
the same transaction, PEM, and age identity. Recovery binds the ciphertext to
the pending transaction and checks the original app identity and key
fingerprint before adoption. Import rejects a recorded digest mismatch or an
unbound checkpoint in a completed transaction.

`installation` prints the authorization URL. With `--installation-id`, it can
add the declared repository to an existing selected installation using your
authenticated `gh` account. It checks app/installation ownership and repository
administration before the change, then verifies token scope.

`publish` verifies the encrypted checkpoint, authenticates the app, checks the
installation, and mints and revokes a verification token scoped to exactly one
repository. Failed revocation blocks publication and a successful verification
receipt. If verification also fails, the diagnostic reports both outcomes.
`publish` writes the encrypted source and adjacent public `.app-id` / `.app-slug`
files, then sets the named repository secret and variables through `gh` stdin.
Retry partial publication with the same transaction. `--replace-key` explicitly
allows verified rotation and keeps the prior ciphertext in `previous.age`.
Publication is serialized per source.

The JSON receipt lists IDs, public-key fingerprint, policy/checkpoint/source
hashes, token expiry, and successful slot names, never PEM, JWT, or token.
`actionsSlotQualified` stays `false`: GitHub withholds stored Actions secret
plaintext, so the trusted hosted workflow must prove destination use.
`verify` checks the encrypted source credential, not the installed Actions slot.

After a post-exchange crash, retry `enroll` with the same transaction to recover
the encrypted manifest response. Without ciphertext, the consumed code's
outcome is ambiguous: inspect GitHub settings and import an issued key in a
fresh transaction. Never replay the conversion blindly.

Authenticate `gh` to `github.com` first. Use the existing `--identity` /
`SECRET_MANAGER_AGE_IDENTITIES` contract; pass Canix hardware identity stubs
under `age/master_identities/` explicitly. Declaring `services.secretSync.targets`
does not schedule execution.

### `github token` — Account tokens through the device flow

Mint a GitHub OAuth token for an account (such as a bot) and save agenix
sources without writing plaintext to the store:

```sh
SECRET_MANAGER_AGE_ENCRYPTOR=$(nix build --no-link --print-out-paths .#agenix-stream-encryptor)/bin/agenix-stream-encryptor \
secret-manager github token --login canikroid \
  --scope repo --scope write:gpg_key --scope admin:public_key \
  --out age/secrets/users/can/canikroid_github_token.age \
  --env-out age/secrets/users/can/canikroid_github_env.age
```

Authorize the printed one-time code at <https://github.com/login/device> while
signed in as `--login`. The command checks that the token authenticates as
that login with every requested scope (`admin:x` implies `write:x`/`read:x`).
It encrypts the bare token to `--out` and `<ENV_NAME>=<token>` to `--env-out`,
then exits. A login or scope mismatch stores nothing.

`gh` runs against a private temporary config directory under `$XDG_RUNTIME_DIR`;
`secret-manager` removes it when the token command returns, keeping the token
out of your `gh` login and keyring. Without `--rotate`, the command refuses
existing sources. Then stage the sources and run `agenix rekey`.

| Flag                  | Description                                                                       |
| --------------------- | --------------------------------------------------------------------------------- |
| `--login LOGIN`       | Account the token must belong to                                                  |
| `--scope SCOPE`       | Requested and required OAuth scope; repeatable                                    |
| `--out PATH`          | Encrypted source for the bare token                                               |
| `--env-out PATH`      | Optional encrypted `ENV_NAME=token` source for EnvironmentFile consumers          |
| `--env-name NAME`     | Variable name for `--env-out` (default `GH_TOKEN`)                                |
| `--rotate`            | Replace existing sources                                                          |
| `--encryptor PATH`    | `lib.mkAgenixStreamEncryptor` executable (default `SECRET_MANAGER_AGE_ENCRYPTOR`) |
| `--timeout-seconds N` | Authorization wait, 30–3600 (default 900)                                         |

### `claude token` — Claude Code subscription tokens

Store a long-lived Claude Code token (`CLAUDE_CODE_OAUTH_TOKEN`) for headless
runners in one step:

```sh
SECRET_MANAGER_AGE_ENCRYPTOR=$(nix build --no-link --print-out-paths .#agenix-stream-encryptor)/bin/agenix-stream-encryptor \
secret-manager claude token --out age/secrets/root/hosts/atlas/paperclip_operations_claude_oauth.age
```

The command runs native `claude setup-token` and waits up to 15 minutes for
browser authorization. Authorization needs only the browser, not a controlling
terminal or token copy/paste. The CLI captures both output channels in private,
bounded, zeroizing memory without printing or saving plaintext. Output must
contain one unique, valid `sk-ant-oat01-` token. Changed, ambiguous, or
malformed output fails closed without storage.
The command encrypts the token under the store's agenix master policy, stages
the source, and distributes it with `agenix rekey`. `--secret NAME` (the
agenix attribute) stages only that secret's rekeyed copies, so unrelated
uncommitted rekeyed changes don't block it. Tokens last one year; renew with
`--rotate`.

The parser ignores native terminal framing outside the token paragraph and
handles color and private display modes without changing token text. It rejects
editing controls inside token data, incomplete sequences, and ambiguous tokens.

Encryption/rekey may still need security-key or pinentry approval. Native
browser-launch or authorization failure never falls back to printing a URL
or token. If rekey fails after encryption, keep the encrypted source and retry
`agenix rekey -a` instead of minting again. Deploy to hosts separately.

| Flag               | Description                                                                       |
| ------------------ | --------------------------------------------------------------------------------- |
| `--out PATH`       | Encrypted source for the token                                                    |
| `--rotate`         | Replace an existing source                                                        |
| `--claude PATH`    | Claude Code executable (default `claude`)                                         |
| `--no-rekey`       | Skip `agenix rekey`; run `agenix rekey -a` before deploying                       |
| `--no-stage`       | Leave staging of the source and rekeyed copies to you                             |
| `--secret NAME`    | Agenix attribute name; stage only its rekeyed copies, ignoring other dirty ones   |
| `--encryptor PATH` | `lib.mkAgenixStreamEncryptor` executable (default `SECRET_MANAGER_AGE_ENCRYPTOR`) |

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

Choose at least one destination. Supply exactly one public primary key in one
ASCII-armored block. The command rejects private-key packets and inspects the
key with GnuPG in an isolated temporary keyring, not yours. Relative paths
resolve from the working directory; no secret store is needed.

Forgejo uses the existing `fj` auth store: tokens need `read:user` to list and
`write:user` to register. GitHub reuses `gh` authentication: classic/OAuth
tokens need `read:gpg_key` to list and `write:gpg_key` to register.

Retries are idempotent: the command accepts an existing key only if its full
fingerprint matches the one derived from the API's public-key packets. It
tries every destination even after a failure and exits nonzero for incomplete
publication. After a failed POST, it reads back registration before reporting
failure.

Output distinguishes registration, signing capability, email verification, and
Forgejo key-ownership verification. Upload does not complete Forgejo's
proof-of-possession challenge or verify account email. Codefloe account
registration uses its Forgejo API, not Crow CI credentials.

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

| Flag                      | Description                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------------------- |
| `--name <SLUG>`           | Secret slug                                                                                              |
| `--user <USER>`           | Home-manager user (default: current login user)                                                          |
| `--shared`                | Store under `age/secrets/users/shared/`                                                                  |
| `--env <VAR>`             | Environment variable names                                                                               |
| `--file <PATH>`           | File path within the home profile                                                                        |
| `--from-file <PATH>`      | Read plaintext from file                                                                                 |
| `--from-age <PATH>`       | Adopt an existing encrypted .age file                                                                    |
| `--algorithm <ALGO>`      | SSH key algorithm (`ed25519`, `rsa`)                                                                     |
| `--length <N>`            | Passphrase length (32, 48, 64)                                                                           |
| `--no-rekey`              | Skip `agenix rekey -a`                                                                                   |
| `--no-stage`              | Skip `git add`                                                                                           |
| `--category <CATEGORY>`   | Use the canonical layout ([`inventory`](#inventory--secret-inventory)) and category-taking name resolver |
| `--expires <DATE\|never>` | Set expiry in `.meta.toml`; every write stamps `rotated_at`                                              |

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

| Flag                      | Description                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------------------- |
| `--name <SLUG>`           | Secret slug                                                                                              |
| `--host <HOST>`           | NixOS host name                                                                                          |
| `--env <VAR>`             | Environment variable names                                                                               |
| `--service <NAME>`        | Systemd service names (required with `--env`)                                                            |
| `--file <PATH>`           | File path on the host                                                                                    |
| `--from-file <PATH>`      | Read plaintext from file                                                                                 |
| `--from-age <PATH>`       | Adopt an existing encrypted .age file                                                                    |
| `--algorithm <ALGO>`      | SSH key algorithm                                                                                        |
| `--length <N>`            | Passphrase length                                                                                        |
| `--no-rekey`              | Skip `agenix rekey -a`                                                                                   |
| `--no-stage`              | Skip `git add`                                                                                           |
| `--category <CATEGORY>`   | Use the canonical layout ([`inventory`](#inventory--secret-inventory)) and category-taking name resolver |
| `--expires <DATE\|never>` | Set expiry in `.meta.toml`; every write stamps `rotated_at`                                              |

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

| Flag                      | Description                                                                                              |
| ------------------------- | -------------------------------------------------------------------------------------------------------- |
| `--name <SLUG>`           | Secret slug                                                                                              |
| `--cred <NAME>`           | Runner credential name                                                                                   |
| `--instance <INSTANCE>`   | Runner instance (repeatable)                                                                             |
| `--pubkey-var <VAR>`      | Nix variable name for the generated public key                                                           |
| `--module-dir <DIR>`      | Module-secret directory for `gpg-key-pair` sources                                                       |
| `--user-id <UID>`         | OpenPGP user ID for newly generated keys                                                                 |
| `--rotate`                | Force SSH key rotation                                                                                   |
| `--from-file <PATH>`      | Read plaintext from file                                                                                 |
| `--from-age <PATH>`       | Adopt an existing encrypted .age file                                                                    |
| `--length <N>`            | Passphrase length                                                                                        |
| `--no-rekey`              | Skip `agenix rekey -a`                                                                                   |
| `--no-stage`              | Skip `git add`                                                                                           |
| `--category <CATEGORY>`   | Use the canonical layout ([`inventory`](#inventory--secret-inventory)) and category-taking name resolver |
| `--expires <DATE\|never>` | Set expiry in `.meta.toml`; every write stamps `rotated_at`                                              |

### `list` — List secrets

List every `*.age` file tracked in the repository.

```sh
secret-manager list
```

### `classify` — Secret metadata

Edit `<name>.meta.toml` without reading or decrypting the source or using a
hardware key. `classify` leaves `rotated_at` unchanged; only a source write
stamps it.

```sh
secret-manager classify age/secrets/home/can/cloud/syndb_cloudflare_pages_token.age \
  --expires never --project syndb
```

| Flag                       | Sidecar field                                                        |
| -------------------------- | -------------------------------------------------------------------- |
| `--expires <DATE\|never>`  | `expiry`: `YYYY-MM-DD` or `never`; absent means unknown              |
| `--kind <KIND>`            | `kind`: `external`, `generated`, `signing`, `generated-with-history` |
| `--custodian <USER>`       | `custodian`; required under `home/shared` and `root/`                |
| `--project <NAME>`         | `project`                                                            |
| `--rotation-method <M>`    | `rotation.method`: `generate`, `replace`, `reissue`, `manual`        |
| `--rotation-command <CMD>` | `rotation.command`                                                   |
| `--note <TEXT>`            | `rotation.note`                                                      |

Without a sidecar, a source's kind defaults by category: `external` for `ai`,
`forge`, `registry`, `oauth` and `cloud`; `generated` for `app` and `system`;
`signing` for `signing` and `ssh`.

### `inventory` — Secret inventory

Print one JSON document for all sources in the canonical layout:

```
age/secrets/home/<user>/<category>/<name>.age
age/secrets/home/shared/<category>/<name>.age
age/secrets/root/hosts/<host>/<category>/<name>.age
age/secrets/root/modules/<category>/<name>.age
```

Categories: `signing`, `ssh`, `ai`, `forge`, `registry`, `oauth`, `cloud`,
`app`, `system`. Inventory reads only paths and sidecars; it omits values,
hashes, and lengths.

```sh
secret-manager inventory --output json
secret-manager inventory --write /var/lib/secret-inventory/inventory.json --mode 640
secret-manager inventory --check
```

Each entry includes `id` (path without `age/secrets/` and `.age`), `tree`,
`scope`, `category`, `project`, `kind`, `custodian`, `expiry` (`{"type":"at",
"date":…}`, `{"type":"never"}` or `{"type":"unknown"}`), `rotatedAt`,
`rotation` and `consumers`. `home/<user>` defaults to that user as custodian
unless overridden in its sidecar. `--consumers FILE` takes a JSON object mapping
IDs to arrays and copies them verbatim. `--write` atomically replaces the file
with `--mode`.

Instead of emitting inventory JSON, `--check` reports and exits nonzero for
sources outside the layout, symlink aliases, orphaned sidecars, repeated names
within a scope, missing custodians under `home/shared` or `root/`, and
unreadable sidecars.

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

Push targets from collected `services.secretSync` JSON. In Actions, encrypted
`secret` targets become secrets and plaintext `source` targets become variables.
Codeberg/Forgejo supports repository, organization, and authenticated-user
scopes; Codefloe supports only repository scope; GitHub supports repository and
environment scopes. Kubernetes accepts only encrypted `secret` targets, each
with a `kubectl` context, namespace, and Secret (see
[Sync Targets](../concepts/sync-targets.md#kubernetes-secrets)).

```sh
secret-manager sync --dry-run
secret-manager sync --identity <IDENTITY.pub>
```

By default, `sync` finds the nearest flake root and evaluates its
`secret-manager.lib.collect` output over `nixosConfigurations`. `--dry-run`
prints planned pushes without decrypting or contacting the forge.

For portable scripts, pass collected JSON explicitly:

```sh
secret-manager sync --config sync-targets.json --identity <IDENTITY.pub>
```

Without `--config`, `sync` reads JSON from non-terminal stdin. `--no-flake`
disables flake auto-detection and requires `--config` or non-terminal stdin.

`sync` tracks managed remote Actions secrets and variables in
`<secret-store>/.secret-manager/sync-state.toml` by default. Override it with
`--state <PATH>`. Sync reports previously managed entries absent from the
collected config as stale and deletes them from their configured forge only
with `--prune`. `--target` narrows pushes, not staleness checks (which use the
full collected config), and cannot be combined with `--prune`. Kubernetes
Secrets apply whole: `--target` includes all targets that write the same
Secret as a selected target.

Sync upgrades version 1 state on read and rewrites it as version 2 after the
next successful sync. Version 1 binaries reject version 2 files, so upgrade
every workstation that syncs.

Three modes help take over live Kubernetes Secrets. They reject non-Kubernetes
targets and are mutually exclusive with each other, `--check`, `--dry-run`,
and `--prune`:

| Flag       | Effect                                                                                                                                                                                                                                                                                                                                                             |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--verify` | Decrypts and reads each live Secret. Prints `equal`, `different`, `missing-live`, or `undeclared-live` per key, plus `foreign-manager <name>` for other managers owning `data`. Exits nonzero unless all declared keys are `equal` and none are undeclared. Applies nothing                                                                                        |
| `--import` | For each `raw` opaque member missing its source, encrypts the live key to the master recipients at the declared path, creating the directory. Never overwrites, needs no hardware key, and prints only key names. Requires `SECRET_MANAGER_AGE_ENCRYPTOR` or an encryptor from the embedding frontend. Unavailable for `render` members or `dockerconfigjson`      |
| `--adopt`  | Re-verifies; refuses unless all keys are `equal` and none are undeclared. Applies under the read `resourceVersion` (changes since read conflict without applying). One JSON patch tests the new `resourceVersion` and removes all other field managers' `data` ownership. As sole data owner, this manager deletes a member's key when the member is later removed |

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

### `guide` — Manual rotation guides

Print manual replacement steps and open provider pages with `xdg-open`.
Without a key, list all guides in the catalogue.

```sh
secret-manager guide --catalogue lib/secrets/Rotations.pkl [KEY] [--no-browser]
```

| Flag                 | Description                                           |
| -------------------- | ----------------------------------------------------- |
| `--catalogue <PATH>` | Pkl file whose module-level `guides` is the catalogue |
| `--no-browser`       | Print the provider pages instead of opening them      |

The command decodes the catalogue with `caniko-secret-manager-schema` and
revalidates it before use: keys must match `^[a-z0-9][a-z0-9._-]*$` and every
URL must start with `https://` because it reaches the opener. Opening is best
effort: missing `xdg-open` never fails the command, and URLs print either way.

A guide's `expiry` controls what it prints: `cadence` (default) prints the
replacement interval; `never` prints `expiry: never expires` for a value
created without an end date; `provider` prints `expiry: provider-reported (<id>)`
when the provider reports expiry. Set `provider` if and only if
`expiry = "provider"`. Leave `cadenceDays`/`warnDays` unset for `never`;
validation rejects other combinations.

## Global flags

| Flag              | Description   |
| ----------------- | ------------- |
| `-h`, `--help`    | Print help    |
| `-V`, `--version` | Print version |
