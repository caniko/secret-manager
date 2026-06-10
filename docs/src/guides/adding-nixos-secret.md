# Adding a NixOS Host Secret

The `nixos` subcommand manages secrets for NixOS hosts. Each secret targets a
specific host via `--host`.

## Secret types

| Subcommand  | Source             | Delivery                     |
|-------------|--------------------|------------------------------|
| `ssh`       | Generated Ed25519  | `--file` path                |
| `password`  | Generated passphrase | `--env` + `--service` or `--file` |
| `text`      | Plaintext from stdin/file | `--env` + `--service`   |
| `file`      | Plaintext or existing `.age` | `--file` path          |

## SSH key

```sh
secret-manager nixos ssh \
  --name service-key \
  --host thething \
  --file /run/secrets/service-key
```

## Passphrase (systemd env file)

```sh
secret-manager nixos password \
  --name vikunja-mailer \
  --host thething \
  --env VIKUNJA_MAILER_PASSWORD \
  --service vikunja \
  --length 48
```

This generates a passphrase and creates a systemd oneshot unit that writes
an environment file consumed by the `vikunja.service` unit.

## Text from stdin

```sh
secret-manager nixos text \
  --host thething \
  --env API_TOKEN \
  --service demo
```

## File from plaintext or existing `.age`

```sh
# Encrypt plaintext from stdin
secret-manager nixos file \
  --name kubeconfig \
  --host thething \
  --file /etc/kubeconfig

# Adopt an existing encrypted .age file
secret-manager nixos file \
  --name kubeconfig \
  --host thething \
  --file /etc/kubeconfig \
  --from-age ./existing-kubeconfig.age
```
