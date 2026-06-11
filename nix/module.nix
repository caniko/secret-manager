# The `services.secretSync` NixOS / home-manager module.
#
# This module is intentionally thin: it only *declares* sync-target data. All
# logic — decryption, authentication, pushing — lives in the `secret-manager`
# Rust binary, which consumes the data collected from this module (see
# `nix/collect.nix`).
#
# Options are pure data (mkOption only, no config = logic), so this module
# evaluates identically under NixOS and home-manager.
{lib, ...}: let
  targetType = lib.types.submodule {
    options = {
      secret = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Path to the agenix-encrypted `.age` file, relative to the store
          root. This is the same path you would pass to
          `secret-manager push <secret>`.
        '';
        example = "age/secrets/my-token.age";
      };

      source = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Path to a plaintext non-secret file, relative to the store root.
          Plaintext source values are pushed to Forgejo Actions variables,
          not Actions secrets.
        '';
        example = "age/secrets/my-public-key.asc";
      };

      name = lib.mkOption {
        type = lib.types.str;
        description = ''
          Name of the Actions secret or variable to set on each target
          repository. Workflows reference this name at runtime.
        '';
        example = "MY_CI_TOKEN";
      };

      codeberg = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = ''
          Codeberg repositories (in `owner/repo` format) to push this
          secret to. Repeats for multiple repos.
          Auth: `$CODEBERG_TOKEN`, falling back to the forgejo-cli token
          at `~/.local/share/forgejo-cli/<host>/TOKEN`.
        '';
        example = ["caniko/my-repo"];
      };

      host = lib.mkOption {
        type = lib.types.str;
        default = "codeberg.org";
        description = ''
          Forge host for Codeberg/Forgejo token resolution. The token is
          read from `~/.local/share/forgejo-cli/<host>/TOKEN`.
          Only meaningful when `codeberg` is non-empty.
        '';
        example = "codeberg.org";
      };
    };
  };

  checkedTargetType = lib.types.addCheck targetType (
    target: (target.secret != null) != (target.source != null)
  );
in {
  options.services.secretSync = {
    enable = lib.mkEnableOption ''
      declarative secret synchronization to forge Actions secret stores.

      When enabled, the targets declared here are collected into a JSON
      document that `secret-manager sync` reads to push secrets to
      Codeberg/Forgejo repositories without ad-hoc CLI flags.
    '';

    targets = lib.mkOption {
      type = lib.types.attrsOf checkedTargetType;
      default = {};
      description = ''
        Attribute set of sync targets keyed by an arbitrary name meaningful
        to the store operator. Targets with `secret` declare one agenix secret
        that should be pushed as an Actions secret; targets with `source`
        declare one plaintext non-secret file that should be pushed as an
        Actions variable.
      '';
    };
  };
}
