# The Store

A "store" is the Nix data repository that owns the agenix secret tree.
secret-manager operates on a store; it does not host secrets itself.

## Store layout

```
<store-root>/
  flake.nix
  age/
    master-identity.pub       # Master identity stubs for decryption
    master-yubikey.pub
    secrets/
      users/
        can/
          app-token.age       # Per-user encrypted secrets
        shared/
          deepseek.age        # Shared profile secrets
      hosts/
        thething/
          vikunja-mailer.age  # Per-host encrypted secrets
      modules/
        forgejo-runner/
          copr-token.age      # Module-scoped secrets
    rekeyed/                  # Rekeyed per-host copies (managed by agenix)
```

## Discovery

The store root is discovered at runtime:

1. `$SECRET_MANAGER_STORE` environment variable, if set
2. Walking up from the current directory to the nearest `flake.nix`

## Master identities

`age/master-*.pub` files are the trust anchors for decryption. They are
typically hardware-key (age plugin) identity stubs — `rage` prompts on the
controlling terminal when decryption is needed.
