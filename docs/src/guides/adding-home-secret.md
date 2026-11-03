# Adding a Home-Manager Secret

The `hm` subcommand manages secrets for home-manager profiles. Every secret
targets either a specific user or the shared profile (`--shared`).

## Secret types

| Subcommand | Source                       | Delivery                 |
| ---------- | ---------------------------- | ------------------------ |
| `ssh`      | Generated Ed25519            | `--file` path            |
| `password` | Generated passphrase         | `--env` vars or `--file` |
| `text`     | Plaintext from stdin/file    | `--env` vars or bare     |
| `file`     | Plaintext or existing `.age` | `--file` path            |

## SSH key (file delivery)

```sh
secret-manager hm ssh \
  --name deploy-key \
  --user can \
  --file ~/.ssh/deploy-key \
  --algorithm ed25519
```

## Passphrase (env vars)

```sh
secret-manager hm password \
  --name app-token \
  --user can \
  --env APP_TOKEN \
  --length 48
```

## Text from stdin

```sh
echo "my-secret-value" | secret-manager hm text \
  --env MY_SECRET \
  --user can
```

## Bare source (no env wiring)

Use `--bare` to create only the encrypted source, for consumers that read the
`.age` file directly (for example a `services.secretSync` Kubernetes target)
instead of a home-profile env var. `--name` is required:

```sh
echo "my-secret-value" | secret-manager hm text \
  --bare \
  --name app-token \
  --user can
```

The source is written to `age/secrets/users/<user>/<name>.age`. Re-running the
same command refuses to overwrite an existing source; use `agenix edit` to
replace the value.

## Shared secrets

Use `--shared` to store under `age/secrets/users/shared/` and optionally
register as shared home-manager env vars:

```sh
secret-manager hm text \
  --shared \
  --env DEEPSEEK_API_KEY
```

Pass `--name` explicitly when no env var can provide a default slug.
