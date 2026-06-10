# Quick Start

All commands operate on a Nix store repository — the directory that owns
`age/secrets/**` and the master identity stubs (`age/master-*.pub`).

## List existing secrets

```sh
cd /path/to/store
secret-manager list
```

## Add a home-manager passphrase secret

```sh
secret-manager hm password --name app-token --env APP_TOKEN --user can
```

This generates a 32-byte passphrase, creates `age/secrets/users/can/app-token.age`,
writes the Nix module at `home/user/can/repositories/app-token.nix`, and splices
it into the `default.nix` imports.

## Decrypt a secret to stdout

```sh
secret-manager decrypt age/secrets/users/can/app-token.age
```

## Push a secret to Codeberg Actions

```sh
secret-manager push age/secrets/users/can/app-token.age \
  --name APP_TOKEN \
  --codeberg caniko/my-repo
```
