# Adding a Forgejo Secret

Use `forgejo` for Forgejo Actions runner secrets and Codeberg/Forgejo CI
credential stores.

## Secret types

| Subcommand     | Source                                   | Delivery                         |
| -------------- | ---------------------------------------- | -------------------------------- |
| `ssh`          | Generated Ed25519                        | Runner credential or source only |
| `gpg-key-pair` | Generated or adopted OpenPGP private key | Source only plus public metadata |
| `password`     | Generated passphrase                     | Runner credential                |
| `text`         | Plaintext from stdin/file                | Runner credential                |
| `file`         | Plaintext or existing `.age`             | Runner credential                |

## SSH deploy key

Generate an Ed25519 key for Forgejo Actions, with optional public-key injection
as a runner credential:

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

The command prints the public key to stdout and embeds it as a Nix comment
in the generated module.

## GPG key pair

Only the armored OpenPGP private key becomes an agenix secret. The command
derives plaintext `.asc` and `.fingerprint` files next to it.

```sh
secret-manager forgejo gpg-key-pair \
  --name modde-apt-repo-gpg-key \
  --cred modde_apt_repo_gpg_key \
  --from-age age/secrets/modules/repos/apt/modde-apt-repo-gpg-key.age
```

Omit `--from-age` and `--from-file` to generate a key. Use `--rotate` to replace
an existing private-key source.

A Nix `mkSecret { generator = "gpg-key-pair"; userId = "Name <email>"; … }`
passes `userId` as `age.secrets.<name>.settings.userId` to the generator. Set it
for signing identities: forges only mark signatures verified if the key UID
includes the committer's verified email.

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

The slug defaults from `--cred`: `COPR_TOKEN` becomes `copr`.

## File credential

```sh
secret-manager forgejo file \
  --name copr-token \
  --cred COPR_TOKEN \
  --instance codeberg \
  --from-file ./token.txt
```

## Key rotation

Use `--rotate` to force regeneration of an existing SSH key:

```sh
secret-manager forgejo ssh \
  --name aur-ssh-key \
  --cred AUR_SSH_KEY \
  --rotate
```
