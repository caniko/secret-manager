# WireGuard Key Generation

Generate a WireGuard keypair, store the private key as an agenix secret,
and print the public key to stdout:

```sh
secret-manager wg-keygen age/secrets/hosts/myhost/wireguard-private.age
```

Requires `wg` (WireGuard tools) on `PATH`.

## Legacy workflows

### Rauthy env-file bootstrap

The `rauthy-env` command bootstraps a complete Rauthy OIDC provider
environment file:

```sh
secret-manager rauthy-env age/secrets/hosts/thething/rauthy-env.age
```

This generates:
- Encryption keys (via `rauthy generate-enc-key`)
- Cluster secrets (via `rauthy generate-secrets`)
- An Argon2id password hash (interactive prompt)
- A bootstrap API key secret

### Gerrit cookies

Encrypt Gerrit `.gitcookies` into an agenix secret:

```sh
secret-manager gerrit-cookies ~/.gitcookies age/secrets/gerrit-cookies.age
```

Cookie lines are normalized (commas → tabs) before encryption.
