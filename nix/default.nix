{
  self,
  nixpkgs,
  rs-harbor,
  rust-overlay,
  treefmt-nix,
  git-hooks,
  nix-manager-core,
  plinth,
  ...
}:
nix-manager-core.lib.mkManagerOutputs {
  inherit self nixpkgs rs-harbor rust-overlay treefmt-nix git-hooks;
  crateName = "secret-manager";
  rustEdition = "2024";
  srcDir = ../.;
  extraRuntimePackages = pkgs: [
    pkgs.rage
  ];
  extraOutputs = {
    self,
    lib,
    forAllSystems,
    pkgsFor,
    ...
  }: let
    module = import ./module.nix;
    collectLib = import ./collect.nix {inherit lib;};
    secretLib = import ./lib.nix {inherit lib;};

    rendererCheckFor = pkgs: let
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
          ++ secretLib.mkHomeEnvSecretModules {
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

      renderedSync = secretLib.mkSecretSyncTargets {
        inherit catalog plain;
      };

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
      assert renderedSync.public-value-target.source == "age/secrets/public-value.txt";
      assert !(renderedSync ? env-only);
      assert !(renderedSync ? unsynced-public);
        pkgs.runCommand "secret-manager-catalog-renderers" {} "touch $out";
  in {
    nixosModules = {
      secretSync = module;
      default = module;
    };

    lib = secretLib // collectLib;

    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
      docs = pkgs.stdenv.mkDerivation {
        pname = "secret-manager-docs";
        version = "0.1.0";
        src = ../docs;
        nativeBuildInputs = [pkgs.mdbook];
        phases = ["buildPhase" "installPhase"];
        buildPhase = ''
          mkdir docs
          cp -r --no-preserve=mode "$src"/* docs/
          mdbook build docs
        '';
        installPhase = ''
          cp -r docs/book "$out"
        '';
      };
    in {
      inherit docs;
      site = pkgs.runCommand "secret-manager-site" {} ''
        mkdir -p $out
        cp -rL --no-preserve=mode ${docs}/. $out/
        printf '%s\n' "secret-manager.tartanoglu.com" > $out/.domains
      '';
    });

    apps = forAllSystems (system: {
      deploy-pages = plinth.lib.${system}.mkDeployPagesApp {
        domain = "secret-manager.tartanoglu.com";
      };
    });

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
      toolchain = rs-harbor.lib.mkToolchain {inherit pkgs;};
      cross = rs-harbor.lib.mkCross {inherit pkgs system;};
    in {
      docs = rs-harbor.lib.mkDocsShell {
        inherit pkgs cross;
        inherit (toolchain) craneLib;
        packages = [pkgs.mdbook];
        extraShellHook = ''
          echo "Documentation: mdbook serve docs"
        '';
      };
    });

    checks = forAllSystems (system: {
      catalog-renderers = rendererCheckFor (pkgsFor system);
    });
  };
}
