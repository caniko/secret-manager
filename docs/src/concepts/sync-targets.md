# Sync Targets

`secret-manager` can push decrypted secrets to forge Actions secret stores
(Codeberg/Forgejo, GitHub) so CI workflows can read them as `${{ secrets.<NAME> }}`.

Sync targets are **declared declaratively** via Nix module options — the
`services.secretSync` namespace — rather than passed as ad-hoc CLI flags.
A host must opt in with `enable = true`; its targets are then collected into
a JSON document that `secret-manager sync` reads (coming in Phase 03).

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
      };

      "deploy-key" = {
        secret   = "age/secrets/deploy-key.age";
        name     = "DEPLOY_KEY";
        codeberg = ["caniko/my-repo" "caniko/other-repo"];
        github   = ["caniko/mirror-repo"];
      };
    };
  };
}
```

## Target fields

| Option    | Type           | Default          | Description                                    |
|-----------|----------------|------------------|------------------------------------------------|
| `secret`  | `str`          | required         | `.age` path relative to the store root         |
| `name`    | `str`          | required         | Actions secret name (`${{ secrets.<NAME> }}`) |
| `codeberg`| `list of str`  | `[]`             | `owner/repo` targets on Codeberg/Forgejo       |
| `github`  | `list of str`  | `[]`             | `owner/repo` targets on GitHub                 |
| `host`    | `str`          | `"codeberg.org"` | Forge host for Codeberg/Forgejo token lookup   |

## Relation to mkSecret

Sync targets are **separate** from `mkSecret`'s delivery targets
(`home` env/file, `system` env/file, `forgejo` credential). The two concepts
address different concerns:

- **mkSecret delivery:** how a decrypted secret reaches a consumer **on the host**
  (as an environment variable, file, or systemd LoadCredential).
- **Sync targets:** which external forge repositories receive the plaintext
  as an Actions secret.

A single agenix secret can have both local delivery *and* remote sync targets,
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
          "github": [],
          "host": "codeberg.org"
        }
      }
    }
  ]
}
```

This JSON is the Nix↔Rust contract. The `secret-manager` binary reads it via
the `SyncDocument` deserialization type.
