# Collect declared sync targets into the raw document the `secret-manager sync`
# binary consumes. This is the Nix↔Rust contract producer: its `builtins.toJSON`
# is exactly the binary's input.
#
# Takes a `syncConfig` attrset like:
#
#   collect { inherit (self) nixosConfigurations; }
#
# and returns `{ hosts = [ { targets = { ... } } ] }`. Only hosts that set
# `services.secretSync.enable = true` are included. Each host's targets are the
# raw option values — already JSON-serializable by construction.
{lib}: syncConfig: let
  nixosConfigurations = syncConfig.nixosConfigurations or {};

  enabledHosts = lib.filter (
    host: host.config.services.secretSync.enable or false
  ) (lib.attrValues nixosConfigurations);

  hostRaw = host: {
    targets = host.config.services.secretSync.targets;
  };
in {
  hosts = map hostRaw enabledHosts;
}
