# caniko-secret-manager-schema

Data types for [secret-manager](https://github.com/caniko/secret-manager)
registries, kept apart from the engine crate.

`accounts::AccountCatalogue` decodes a catalogue of credential services, each
with several accounts and a fleet default, plus per-host and per-user
overrides. `select` resolves the account a user on a host receives: the host
override, else the user override, else the service default. The matching Pkl
classes live in `pkl/SecretRegistry.pkl`.
