# Nix Declarations

The engine generates Nix modules that call `mkSecret` to declare each
secret. These modules are consumed by the NixOS/home-manager
configuration that calls `agenix`.

## mkSecret

The core function that declares a single agenix secret:

```nix
canixLib.mkSecret {
  name = "can-app-token";
  stack = "home";
  source = secrets.user "can" "app-token";
  targets.home.env = ["APP_TOKEN"];
}
```

### Parameters

| Parameter   | Description                                    |
| ----------- | ---------------------------------------------- |
| `name`      | agenix secret name (maps to age file identity) |
| `stack`     | `"home"`, `"system"`, or `"forgejo"`           |
| `source`    | Path expression resolving to the `.age` file   |
| `generator` | Optional: `"passphrase"` or `"ssh-key"`        |
| `length`    | Passphrase length (32, 48, or 64)              |
| `algorithm` | SSH key algorithm (`"ed25519"` or `"rsa"`)     |
| `targets`   | Delivery target configuration (stack-specific) |
| `owner`     | File owner (for system file delivery)          |
| `group`     | File group                                     |
| `mode`      | File mode                                      |

### Target shapes

**Home env delivery:**

```nix
targets.home.env = ["APP_TOKEN" "API_KEY"];
```

**Home file delivery:**

```nix
targets.home.file = {
  path = "~/.ssh/deploy-key";
  mode = "600";
};
```

**System env delivery:**

```nix
targets.system.env = {
  vars = ["VIKUNJA_MAILER_PASSWORD"];
  services = ["vikunja"];
};
```

**System file delivery:**

```nix
targets.system.file = {
  path = "/run/secrets/vikunja-mailer";
  owner = "vikunja";
  mode = "0400";
};
```

**Forgejo credential delivery:**

```nix
targets.forgejo.credential = {
  name = "copr-token";
  instances = ["codeberg"];
};
```

## mkSharedSecret

A convenience wrapper that produces a secret declaration for all three stacks
from a single source file. Each stack is optional:

```nix
canixLib.mkSharedSecret {
  source = ./age/secrets/shared-token.age;
  generator = "passphrase";
  length = 48;

  home = {
    targets.home.env = ["SHARED_TOKEN"];
  };

  system = {
    targets.system.env = {
      vars = ["SHARED_TOKEN"];
      services = ["demo"];
    };
  };
}
```

## Source expressions

The `source` parameter resolves the `.age` file path:

```nix
# User-scoped secret
secrets.user "can" "app-token"

# Host-scoped secret
secrets.host "thething" "vikunja-mailer"

# Module-scoped secret
secrets.module "forgejo-runner/copr-token"
```
