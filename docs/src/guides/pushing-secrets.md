# Pushing Secrets to CI

The `push` command decrypts an agenix-encrypted `.age` file and pushes the
plaintext to Codeberg/Forgejo and GitHub Actions secret stores. The
plaintext never touches disk — it lives only in process memory.

```sh
secret-manager push age/secrets/users/can/app-token.age \
  --name APP_TOKEN \
  --codeberg caniko/my-repo \
  --github my-org/other-repo
```

## Decrypt-only

To print a decrypted secret to stdout (for piping into other tools):

```sh
secret-manager decrypt age/secrets/users/can/app-token.age
```

Diagnostics and hardware-key prompts stay on stderr.

## Authentication

- **Codeberg**: the `fj` auth store at
  `${XDG_DATA_HOME:-$HOME/.local/share}/forgejo-cli/keys.json` (set up with
  `fj auth login --host codeberg.org` or `fj auth add-key <user>`).
- **GitHub**: requires `gh` authenticated.

## Identity resolution

Identities are resolved in precedence order:

1. Explicit `--identity` flags (repeatable).
2. The `SECRET_MANAGER_AGE_IDENTITIES` environment variable — a
   colon-separated list of identity paths, mirroring the DNS flow's
   `CANIX_DNS_AGE_IDENTITIES` contract.
3. Master identity stubs discovered from `age/master-*.pub` /
   `age/master_*.pub` in the store root.

Relative paths resolve against the store root.

```sh
secret-manager decrypt secret.age --identity age/my-key.pub
# or, once per shell:
export SECRET_MANAGER_AGE_IDENTITIES=age/master_nitro3c_identity.pub:age/master_nitro3_2_identity.pub
secret-manager sync
```
