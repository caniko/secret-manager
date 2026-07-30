{
  description = "An example of how to use secret-manager sync targets";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    secret-manager.url = "path:..";
    secret-manager.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    secret-manager,
    ...
  }: {
    nixosConfigurations = {
      host1 = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          secret-manager.nixosModules.default
          ./hosts/host1.nix
        ];
      };
      host2 = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          secret-manager.nixosModules.default
          ./hosts/host2.nix
        ];
      };
    };

    secretSyncTargets = secret-manager.lib.collectModules {
      hosts = [
        {modules = [./hosts/host1.nix];}
        {modules = [./hosts/host2.nix];}
      ];
    };

    # Eval-only check: verify the collected sync targets are valid JSON
    checks = nixpkgs.lib.genAttrs ["x86_64-linux" "aarch64-linux"] (system: let
      lib = nixpkgs.lib;
      catalog = {
        with-sync = {
          source.relative = "age/secrets/with-sync.age";
          env = ["WITH_SYNC_TOKEN"];
          marker = "custom-extra";
          sync = {
            target = "with-sync-target";
            name = "WITH_SYNC_TOKEN";
            codebergUser = true;
          };
        };

        env-only = {
          source.relative = "age/secrets/env-only.age";
          env = ["ENV_ONLY_TOKEN"];
        };

        sync-only = {
          source.relative = "age/secrets/sync-only.age";
          sync = {
            target = "sync-only-target";
            name = "SYNC_ONLY_TOKEN";
            codeberg = ["caniko/example"];
            codefloe = ["caniko/codefloe-example"];
            github = ["caniko/github-example"];
          };
        };
      };

      plain = {
        public-value = {
          source = "age/secrets/public-value.txt";
          value = "not-secret";
          sync = {
            target = "public-value-target";
            name = "PUBLIC_VALUE";
            codeberg = ["caniko/example"];
          };
        };

        unsynced-public.value = "local-only";
      };

      renderedHome = lib.evalModules {
        modules =
          [
            {
              options.renderedSecrets = lib.mkOption {
                type = lib.types.attrsOf lib.types.raw;
                default = {};
              };
            }
          ]
          ++ secret-manager.lib.mkHomeEnvSecretModules {
            inherit catalog;
            mkSecret = args: {
              config.renderedSecrets.${args.name} =
                builtins.removeAttrs args ["extraConfig"]
                // {
                  extra = args.extraConfig "/run/example-secret";
                };
            };
            resolveSource = source: source.relative;
            extraConfig = name: entry: path: {
              inherit name path;
              marker = entry.marker or "default";
            };
          };
      };

      renderedSync = secret-manager.lib.mkSecretSyncTargets {
        inherit catalog plain;
      };
    in {
      collect = let
        legacy = secret-manager.lib.collect {
          inherit (self) nixosConfigurations;
        };
        fast = self.secretSyncTargets;
      in
        assert fast == legacy;
          nixpkgs.legacyPackages.${system}.runCommand "check-collect" {
            json = builtins.toJSON fast;
            passAsFile = ["json"];
          } "cp $jsonPath $out";

      catalog-renderers = let
        homeSecrets = renderedHome.config.renderedSecrets;
      in
        assert builtins.attrNames homeSecrets == ["env-only" "with-sync"];
        assert homeSecrets.with-sync.source == "age/secrets/with-sync.age";
        assert homeSecrets.with-sync.targets.home.env == ["WITH_SYNC_TOKEN"];
        assert homeSecrets.with-sync.extra
        == {
          name = "with-sync";
          path = "/run/example-secret";
          marker = "custom-extra";
        };
        assert renderedSync.with-sync-target.secret == "age/secrets/with-sync.age";
        assert renderedSync.with-sync-target.name == "WITH_SYNC_TOKEN";
        assert renderedSync.sync-only-target.secret == "age/secrets/sync-only.age";
        assert renderedSync.sync-only-target.codefloe == ["caniko/codefloe-example"];
        assert renderedSync.sync-only-target.github == ["caniko/github-example"];
        assert renderedSync.public-value-target.source == "age/secrets/public-value.txt";
        assert !(renderedSync ? env-only);
        assert !(renderedSync ? unsynced-public);
          nixpkgs.legacyPackages.${system}.runCommand "check-catalog-renderers" {} "touch $out";
    });
  };
}
