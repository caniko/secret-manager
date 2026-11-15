# caniko-secret-manager-schema

Data types for [secret-manager](https://github.com/caniko/secret-manager)
registries, kept apart from the engine crate.

`accounts::AccountCatalogue` decodes a catalogue of credential services, each
with several accounts and a fleet default, plus per-host and per-user
overrides. `select` resolves the account a user on a host receives: the host
override, else the user override, else the service default. The matching Pkl
classes live in `pkl/SecretRegistry.pkl`.

`rotation::RotationCatalogue` decodes manual rotation guides (title, steps,
provider URLs, storing command, optional cadence). `for_secret` maps a
store-relative secret path to its guide, and `validate` re-checks the key slug
and that every URL is `https://` before the engine hands one to `xdg-open`.
