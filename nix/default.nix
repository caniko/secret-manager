{
  self,
  nixpkgs,
  rs-harbor,
  rust-overlay,
  treefmt-nix,
  git-hooks,
  nix-manager-core,
  nix-pklx,
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
    cargoFor,
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
      runnerFileEnv = secretLib.mkForgejoRunnerFileEnv {
        inherit catalog;
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
      assert renderedSync.sync-only-target.codefloe == ["caniko/codefloe-example"];
      assert renderedSync.sync-only-target.github == ["caniko/github-example"];
      assert renderedSync.public-value-target.source == "age/secrets/public-value.txt";
      assert !(renderedSync ? env-only);
      assert !(renderedSync ? unsynced-public);
      assert runnerFileEnv.instances == {};
        pkgs.runCommand "secret-manager-catalog-renderers" {} "touch $out";

    runnerFileEnvCheckFor = pkgs: let
      rendered = secretLib.mkForgejoRunnerFileEnv {
        catalog = {
          copr-token = {
            source.relative = "age/secrets/modules/repos/coppr/token.age";
            runnerFileEnv = [
              {
                env = "COPR_TOKEN_FILE";
                instances = ["nixTrusted"];
              }
            ];
          };
        };
      };
      instance = rendered.instances.nixTrusted;
    in
      assert rendered.config.age.secrets.forgejo-runner-file-env-nixTrusted-copr-token.rekeyFile
      == "age/secrets/modules/repos/coppr/token.age";
      assert rendered.config.systemd.tmpfiles.settings."10-secret-manager-forgejo-runner-file-env"."/run/secret-manager/forgejo-runner/nixTrusted/copr-token"."C+".argument
      == "/run/agenix/forgejo-runner-file-env-nixTrusted-copr-token";
      assert builtins.elem "-v /run/secret-manager/forgejo-runner/nixTrusted:/run/secret-manager/forgejo-runner/nixTrusted:ro" instance.containerOptions;
      assert builtins.elem "-e COPR_TOKEN_FILE=/run/secret-manager/forgejo-runner/nixTrusted/copr-token" instance.containerOptions;
      assert instance.validVolumes == ["/run/secret-manager/forgejo-runner/nixTrusted"];
        pkgs.runCommand "secret-manager-runner-file-env-renderer" {} "touch $out";
  in {
    nixosModules = {
      secretSync = module;
      default = module;
    };

    lib = secretLib // collectLib;

    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
      pklx = nix-pklx.packages.${system}.pklx;
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
      inherit pklx;
      site = pkgs.runCommand "secret-manager-site" {} ''
        mkdir -p $out
        cp -rL --no-preserve=mode ${docs}/. $out/
        printf '%s\n' "secret-manager.tartanoglu.com" > $out/.domains
      '';
    });

    # Crossbow consumers need the runtime decryptor on the target host. Keep
    # the native package surface above unchanged and publish an explicit
    # build-platform -> aarch64-linux package for target closures.
    crossPackages = forAllSystems (system:
      if system != "x86_64-linux"
      then {}
      else let
        pkgs = pkgsFor system;
        toolchain = rs-harbor.lib.mkToolchain {inherit pkgs; toolchainProfile = "nightly";};
        cross = rs-harbor.lib.mkCross {inherit pkgs system;};
        cargo = cargoFor system;
        targetPkgs = cross.linuxAarch64.pkgsCross;
        packages = rs-harbor.lib.mkCrossPackages {
          inherit pkgs cross;
          inherit (toolchain) craneLib;
          pname = "secret-manager";
          commonArgs = cargo.commonArgs;
          targets = ["aarch64-linux"];
          targetArgs."aarch64-linux" = {
            doCheck = false;
            nativeBuildInputs = [pkgs.makeWrapper];
            postInstall = ''
              if test -x "$out/bin/secret-manager"; then
                wrapProgram "$out/bin/secret-manager" \
                  --prefix PATH : ${pkgs.lib.makeBinPath [targetPkgs.rage]}
              fi
            '';
          };
        };
      in {
        aarch64-linux = {
          # canix's crossPackageFor helper selects this stable runtime name.
          "secret-manager" = packages."secret-manager-aarch64-linux";
        };
      });

    apps = forAllSystems (system: {
      deploy-pages = plinth.lib.${system}.mkDeployPagesApp {
        domain = "secret-manager.tartanoglu.com";
      };
    });

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
      toolchain = rs-harbor.lib.mkToolchain {inherit pkgs; toolchainProfile = "nightly";};
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
      runner-file-env-renderer = runnerFileEnvCheckFor (pkgsFor system);
    });
  };
}
