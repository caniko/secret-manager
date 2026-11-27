# Sync Targets

`secret-manager` syncs encrypted sources to Kubernetes Secrets or to
Codeberg/Forgejo, Codefloe, and GitHub Actions secrets. Plaintext non-secret
sources go to Actions variables.

Declare targets in the `services.secretSync` Nix module, not with CLI flags.
Only hosts with `enable = true` contribute targets to the JSON document
`secret-manager sync` reads.

The store-local TOML state file (`<secret-store>/.secret-manager/sync-state.toml`)
keeps only non-secret destination metadata. Sync reports previously managed
entries that are now stale and deletes them only with `sync --prune`.

## Declaring sync targets

```nix
{ ... }: {
  imports = [ inputs.secret-manager.nixosModules.default ];

  services.secretSync = {
    enable = true;

    targets = {
      "ci-token" = {
        secret   = "age/secrets/ci-token.age";
        name     = "CI_TOKEN";
        codeberg = ["caniko/my-repo"];
        codefloe = ["caniko/my-repo"];
        github   = ["caniko/my-repo"];
      };

      "publisher-token" = {
        secret = "age/secrets/publisher-token.age";
        name = "CRATES_IO_API_TOKEN";
        githubEnvironments = [{
          repository = "caniko/my-repo";
          environment = "simit-crates-io";
        }];
      };

      "org-token" = {
        secret       = "age/secrets/org-token.age";
        name         = "ORG_TOKEN";
        codebergOrgs = ["caniko"];
      };

      "public-key" = {
        source       = "age/secrets/public-key.asc";
        name         = "PUBLIC_KEY";
        codeberg     = ["caniko/my-repo" "caniko/other-repo"];
        codebergOrgs = ["caniko"];
        codebergUser = true;
      };
    };
  };
}
```

## Target fields

`githubEnvironments` targets GitHub Actions environment secrets (encrypted
sources) or variables (plaintext sources). Enroll the environment and its branch
protection before syncing. Sync checks the environment exists before writing,
passes values to `gh` on stdin, and reads back destination metadata. It never
creates environments or falls back to repository scope.

Encrypted sync requires credential protection before identity resolution or
decryption. If needed, it reexecutes the current frontend in a no-swap user
scope with the original arguments and filtered public configuration on stdin.
The child checks that its effective cgroup disables swap. Without protection,
sync aborts before upload, readback, pruning, or state commit; it holds an
active logind sleep inhibitor through all four. On exit, the handler zeroizes
cached plaintext and temporary copies. GitHub input helpers use bounded,
redacted pipes, scrub credential-debug settings, inherit inhibitors across
exec, and terminate/reap their process group on pipe failure or timeout.
Public variables and read-only planning need no credential inhibitor.

State distinguishes repository from environment copies. Environment names are
case-insensitive: case-only renames do not trigger destructive pruning. Old
repository entries stay stale until an explicit authorized `--prune` after a
successful replacement environment upload. Never reuse this state with older
Secret Manager binaries: they reject environment scope rather than interpreting
it as a repository entry.

| Option               | Type                                | Default          | Description                                  |
| -------------------- | ----------------------------------- | ---------------- | -------------------------------------------- |
| `secret`             | `null or str`                       | `null`           | `.age` path pushed as an Actions secret      |
| `source`             | `null or str`                       | `null`           | plaintext path pushed as an Actions variable |
| `name`               | `str`                               | required         | Actions secret/variable name                 |
| `codeberg`           | `list of str`                       | `[]`             | `owner/repo` Forgejo repository targets      |
| `codefloe`           | `list of str`                       | `[]`             | `owner/repo` Codefloe repository targets     |
| `github`             | `list of str`                       | `[]`             | `owner/repo` GitHub repository targets       |
| `githubEnvironments` | `list of {repository, environment}` | `[]`             | GitHub environment targets                   |
| `kubernetes`         | `list of {context, namespace, ...}` | `[]`             | Kubernetes Secret targets (`secret` only)    |
| `codebergOrgs`       | `list of str`                       | `[]`             | Forgejo organization/account-scope targets   |
| `codebergUser`       | `bool`                              | `false`          | Forgejo authenticated-user account target    |
| `host`               | `str`                               | `"codeberg.org"` | Forge host for `codeberg*` token lookup      |

Set exactly one of `secret` or `source` per target. Codefloe supports only
repository scope; GitHub supports repository and environment scope. Authenticate
Codefloe with `fj -H codefloe.com` and GitHub with `gh auth login`.

## Kubernetes Secrets

`kubernetes` writes the decrypted `secret` with
`kubectl apply --server-side --force-conflicts`. Authenticate `kubectl` for the
named context first; `secret-manager` never reads kubeconfig itself.

```nix
services.secretSync.targets."registry-pull" = {
  secret = "age/secrets/registry-pull.age";
  name = "REGISTRY_PASSWORD";
  kubernetes = [
    {
      context = "nautilus";
      namespace = "syndb";
      secret = "registry-pull";
      format = "dockerconfigjson";
      username = "robot";
      registry = "registry.example"; # default https://index.docker.io/v1/
    }
    {
      context = "nautilus";
      namespace = "syndb";
      secret = "api-token";
      format = "opaque";
      key = "token"; # default: the target `name`
    }
  ];
};
```

| Field          | Applies to         | Description                                                        |
| -------------- | ------------------ | ------------------------------------------------------------------ |
| `context`      | both               | `kubectl --context`; required                                      |
| `namespace`    | both               | RFC 1123 subdomain; required                                       |
| `secret`       | both               | Secret name, RFC 1123 subdomain; required                          |
| `format`       | both               | `opaque` or `dockerconfigjson`; required                           |
| `key`          | `opaque`           | Data key `[-._a-zA-Z0-9]+`; defaults to the target `name`          |
| `registry`     | `dockerconfigjson` | Registry key in `auths`; defaults to `https://index.docker.io/v1/` |
| `username`     | `dockerconfigjson` | Required; must not contain `:`                                     |
| `fieldManager` | both               | Server-side apply manager; defaults to `secret-manager`            |
| `render`       | `opaque`           | `raw` (default) or `sha256-hex`: the value's lowercase hex SHA-256 |
| `allowEmpty`   | `opaque`           | Deliver an empty value instead of refusing it; defaults to `false` |

`opaque` stores the value base64-encoded under `key` with `type: Opaque`.
`dockerconfigjson` stores `{"auths":{"<registry>":{"username","password","auth"}}}`
under `.dockerconfigjson` with `type: kubernetes.io/dockerconfigjson`, using the
decrypted value as the password. Sync rejects invalid names, mixed fields (such
as `registry` on an `opaque` destination), and plaintext `source` values before
decryption or any `kubectl` call.

### Multi-key Secrets

Destinations with the same `context`, `namespace`, and `secret` share one
Secret, even across targets:

```nix
targets.clickhouse-app = {
  secret = "age/secrets/home/can/app/syndb_clickhouse_password.age";
  name = "clickhouse_password";
  kubernetes = [
    { context = "nautilus"; namespace = "syndb"; secret = "syndb-api-secrets"; format = "opaque"; key = "clickhouse_password"; }
    { context = "nautilus"; namespace = "syndb"; secret = "syndb-clickhouse-auth"; format = "opaque"; key = "app_password_sha256"; render = "sha256-hex"; }
  ];
};
```

Members need distinct keys and share a `format` and `fieldManager`.
`dockerconfigjson` requires exactly one member. Sync decrypts all members in
one unlock before a single server-side apply. Failure applies nothing; the
Secret holds exactly the declared keys. `--target` selects the whole Secret
when it selects any member. Once this field manager is the only data owner,
removing a member drops its key on the next apply but keeps the Secret (see
`--adopt` in the [CLI reference](../reference/cli.md)). `--prune` deletes a
Secret only when no members remain declared.

### Leak guarantees

The decrypted value stays in zeroized buffers and the manifest piped to
`kubectl` on stdin:

- `kubectl` never gets values in argv or the environment, or `-v`/`--v` for
  verbose output. Only `get` (for `--verify`, `--import`, and `--adopt`) and the
  `--adopt` apply get `-o json`. Sync parses their stdout, which contains live
  values, in memory into zeroized buffers and reports only stderr.
- `--verify`, `--import` and `--adopt` print key names and states only, never a
  value, hash or length. The ownership handoff patch carries managed field
  names, never values.
- Like other credential helpers, `kubectl` uses bounded private pipes for stdout
  and stderr (1 MiB cap, 90 s deadline, no core dumps, inherited sleep inhibitor,
  process-group cleanup). Neither stream is forwarded to the terminal.
- Failure reports are one line, at most 400 bytes. Before flattening or
  truncating diagnostics (including capture errors), sync replaces every
  occurrence of plaintext and its JSON-escaped and base64 forms with
  `[redacted]`. For `dockerconfigjson` it also redacts `user:password`, the full
  config JSON, and both base64 forms.
- On success the only output is `kubernetes <context>/<namespace>/secret/<name>:
applied`. `--dry-run` and `--check` print the destination and the data key
  names only, and never decrypt.
- Version 2 state keeps one record per Secret with its `members` and destination
  metadata (context, namespace, Secret name, key, registry, username), never values.

Keeping values out of channels that could echo them is the control; redaction
is a backstop. Values shorter than a few characters over-trigger redaction;
use real credentials.

## Relation to mkSecret

- **`mkSecret` delivery** sends decrypted secrets to consumers on the host:
  `home` and `system` env/file targets, or `forgejo` credentials via systemd
  LoadCredential.
- **Sync targets** send decrypted agenix values as Actions secrets, or plaintext
  source files as Actions variables, to external forge repositories,
  organizations, or authenticated-user accounts.

An agenix secret can have local delivery, remote sync targets, both, or neither.

## Collection contract

`lib.collect` gathers every enabled host's targets into this JSON shape:

```json
{
  "hosts": [
    {
      "targets": {
        "ci-token": {
          "secret": "age/secrets/ci-token.age",
          "name": "CI_TOKEN",
          "codeberg": ["caniko/my-repo"],
          "codefloe": ["caniko/my-repo"],
          "github": ["caniko/my-repo"],
          "codebergOrgs": ["caniko"],
          "codebergUser": true,
          "host": "codeberg.org"
        },
        "registry-pull": {
          "secret": "age/secrets/registry-pull.age",
          "name": "REGISTRY_PASSWORD",
          "kubernetes": [
            {
              "context": "nautilus",
              "namespace": "syndb",
              "secret": "registry-pull",
              "format": "dockerconfigjson",
              "username": "robot",
              "registry": "registry.example"
            }
          ]
        },
        "public-key": {
          "source": "age/secrets/public-key.asc",
          "name": "PUBLIC_KEY",
          "codeberg": ["caniko/my-repo"],
          "codefloe": [],
          "github": [],
          "codebergOrgs": ["caniko"],
          "codebergUser": false,
          "host": "codeberg.org"
        }
      }
    }
  ]
}
```

This JSON is the Nix↔Rust contract. `secret-manager` deserializes it as
`SyncDocument`. `secret-manager sync` evaluates the collection automatically
in normal flake-root use; scripts can pass JSON via `--config` or piped stdin.
