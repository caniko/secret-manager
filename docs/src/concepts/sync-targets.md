# Sync Targets

`secret-manager` can push encrypted values to Codeberg/Forgejo, Codefloe, and
GitHub Actions secret stores and to Kubernetes Secrets, and plaintext
non-secret values to Actions variables.

Sync targets are **declared declaratively** via Nix module options — the
`services.secretSync` namespace — rather than passed as ad-hoc CLI flags.
A host must opt in with `enable = true`; its targets are then collected into
a JSON document that `secret-manager sync` reads.

`secret-manager sync` keeps a store-local TOML state file at
`<secret-store>/.secret-manager/sync-state.toml`. The state records only
non-secret destination metadata so later syncs can identify stale entries that
the tool previously managed. Stale entries are reported by default and deleted
only when `sync --prune` is used.

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

`githubEnvironments` selects environment-scoped GitHub Actions secrets (encrypted
sources) or variables (plaintext sources). Enroll the environment and its branch
protection before syncing. Sync verifies the environment exists before writing
and reads back destination metadata afterward; it never creates an environment or
falls back to repository scope. Values are passed to `gh` on stdin.

Encrypted sync acquires credential protection before resolving identities or
decrypting: it reexecutes the current frontend in a no-swap user scope when needed,
replaying the filtered public configuration on stdin with the frontend's original
arguments. The child verifies that swap is disabled in its effective cgroup; an active logind
sleep inhibitor must be held through upload, readback, pruning and state commit.
Missing protection fails before those effects. Cached plaintext and temporary
copies are zeroized when the handler exits. GitHub input helpers use bounded,
redacted pipes, scrub credential-debug settings, inherit active inhibitors across
exec and terminate/reap their process group on pipe or timeout failure. Public
variables and read-only planning do not require a credential inhibitor.

Repository and environment copies have distinct persisted identities. Environment
names are case-insensitive, so a case-only rename does not schedule a destructive
prune. Old repository entries remain stale until an explicit authorized `--prune`
after the replacement environment upload succeeds. Older binaries reject the new
environment scope in persisted state; they cannot reinterpret it as a repository
entry. Never reuse such a state file with an older Secret Manager.

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

Each target must set exactly one of `secret` or `source`.
Codefloe targets are repository-scoped; GitHub supports repository and environment
destinations. Authenticate Codefloe with
`fj -H codefloe.com` and GitHub with `gh auth login`.

## Kubernetes Secrets

`kubernetes` writes a decrypted `secret` value to a Kubernetes Secret with
`kubectl apply --server-side --force-conflicts`. Authenticate `kubectl` for the
named context beforehand; `secret-manager` never reads kubeconfig itself.

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

| Field          | Applies to         | Description                                                     |
| -------------- | ------------------ | --------------------------------------------------------------- |
| `context`      | both               | `kubectl --context`; required                                   |
| `namespace`    | both               | RFC 1123 subdomain; required                                    |
| `secret`       | both               | Secret name, RFC 1123 subdomain; required                       |
| `format`       | both               | `opaque` or `dockerconfigjson`; required                        |
| `key`          | `opaque`           | Data key `[-._a-zA-Z0-9]+`; defaults to the target `name`       |
| `registry`     | `dockerconfigjson` | Registry key in `auths`; defaults to `https://index.docker.io/v1/` |
| `username`     | `dockerconfigjson` | Required; must not contain `:`                                  |
| `fieldManager` | both               | Server-side apply manager; defaults to `secret-manager`         |

`opaque` stores the value base64-encoded under `key` with `type: Opaque`.
`dockerconfigjson` stores `{"auths":{"<registry>":{"username","password","auth"}}}`
under `.dockerconfigjson` with `type: kubernetes.io/dockerconfigjson`, using the
decrypted value as the password. Invalid names, mixed fields (for example
`registry` on an `opaque` destination), plaintext `source` values and a Secret
declared twice are rejected before any decryption or `kubectl` call. Server-side
apply by one field manager owns the whole `data` map, so one Secret has exactly
one declaration. `--prune` deletes a Secret that is no longer declared.

### Leak guarantees

The decrypted value is only ever in zeroized buffers and in the manifest piped to
`kubectl` on stdin. Specifically:

- It is never in `kubectl`'s argv or environment, and `-o`/`--output` and
  `-v`/`--v` are never passed, so `kubectl` has nothing verbose to echo.
- `kubectl`'s stdout and stderr are captured through the same bounded private
  pipes as the other credential helpers (1 MiB cap, 90 s deadline, no core
  dumps, inherited sleep inhibitor, process-group cleanup). Nothing is forwarded
  to the terminal.
- On failure the report is one line of at most 400 bytes. Before it is built,
  every occurrence of the plaintext, its JSON-escaped form, its base64, and for
  `dockerconfigjson` the `user:password` string, its base64 and the whole config
  JSON and its base64 is replaced with `[redacted]`. Errors from the capture
  layer pass through the same redaction.
- On success the only output is `kubernetes <context>/<namespace>/secret/<name>:
  applied`. `--dry-run` and `--check` print the destination and the data key
  names only, and never decrypt.
- The sync state file records destination metadata (context, namespace, Secret
  name, key, registry, username) and never a value.

Redaction is a backstop, not the control: the value is kept out of every channel
that could echo it. A value shorter than a few characters makes redaction
over-eager; use real credentials.

## Relation to mkSecret

Sync targets are **separate** from `mkSecret`'s delivery targets
(`home` env/file, `system` env/file, `forgejo` credential). The two concepts
address different concerns:

- **mkSecret delivery:** how a decrypted secret reaches a consumer **on the host**
  (as an environment variable, file, or systemd LoadCredential).
- **Sync targets:** which external forge repositories, organizations, or
  authenticated-user account scopes receive a decrypted agenix value as an
  Actions secret, or a plaintext source file as an Actions variable.

A single agenix secret can have both local delivery _and_ remote sync targets,
neither, or either.

## Collection contract

The `lib.collect` function gathers all enabled hosts' targets into a JSON
document of the shape:

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

This JSON is the Nix↔Rust contract. The `secret-manager` binary reads it via
the `SyncDocument` deserialization type. In normal flake-root use,
`secret-manager sync` evaluates this collection automatically; `--config` and
piped stdin remain available for scripts that want to provide the JSON
explicitly.
