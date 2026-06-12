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

By default, the engine discovers master identity stubs from
`age/master-*.pub` in the store root. Pass explicit identities with
`--identity`:

```sh
secret-manager decrypt secret.age --identity age/my-key.pub
```
