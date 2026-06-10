# Adding a Home-Manager Secret

The `hm` subcommand manages secrets for home-manager profiles. Every secret
targets either a specific user or the shared profile (`--shared`).

## Secret types

| Subcommand  | Source             | Delivery               |
|-------------|--------------------|------------------------|
| `ssh`       | Generated Ed25519  | `--file` path          |
| `password`  | Generated passphrase | `--env` vars or `--file` |
| `text`      | Plaintext from stdin/file | `--env` vars      |
| `file`      | Plaintext or existing `.age` | `--file` path   |

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

## Shared secrets

Use `--shared` to store under `age/secrets/users/shared/` and optionally
register as shared home-manager env vars:

```sh
secret-manager hm text \
  --shared \
  --env DEEPSEEK_API_KEY
```

Pass `--name` explicitly when no env var can provide a default slug.
