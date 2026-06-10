# Adding a Forgejo Secret

The `forgejo` subcommand manages secrets for Forgejo Actions runners and
Codeberg/Forgejo CI credential stores.

## Secret types

| Subcommand  | Source               | Delivery                        |
|-------------|----------------------|---------------------------------|
| `ssh`       | Generated Ed25519    | Runner credential or source only |
| `password`  | Generated passphrase | Runner credential               |
| `text`      | Plaintext from stdin/file | Runner credential          |
| `file`      | Plaintext or existing `.age` | Runner credential       |

## SSH deploy key

Generate an Ed25519 key for a Forgejo Actions runner, optionally inject the
public key as a runner credential:

```sh
# Source only (no runner credential)
secret-manager forgejo ssh \
  --name aur-ssh-key \
  --cred AUR_SSH_KEY

# With runner credential injection on instances
secret-manager forgejo ssh \
  --name aur-ssh-key \
  --cred AUR_SSH_KEY \
  --instance codeberg --instance nixTrusted
```

The public key is printed to stdout and embedded as a Nix comment in the
generated module.

## Passphrase credential

```sh
secret-manager forgejo password \
  --name copr-token \
  --cred copr-token \
  --instance codeberg \
  --length 64
```

## Text credential

```sh
echo "my-token" | secret-manager forgejo text \
  --cred COPR_TOKEN \
  --instance codeberg
```

The slug defaults from the `--cred` value (e.g. `COPR_TOKEN` becomes `copr`).

## File credential

```sh
secret-manager forgejo file \
  --name copr-token \
  --cred COPR_TOKEN \
  --instance codeberg \
  --from-file ./token.txt
```

## Key rotation

Pass `--rotate` to force regeneration of an existing SSH key:

```sh
secret-manager forgejo ssh \
  --name aur-ssh-key \
  --cred AUR_SSH_KEY \
  --rotate
```
