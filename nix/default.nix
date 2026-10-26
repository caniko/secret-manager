{
  self,
  nixpkgs,
  harbor-rs,
  rust-overlay,
  treefmt-nix,
  git-hooks,
  nix-manager-core,
  nix-pklx,
  plinth,
  ...
}:
nix-manager-core.lib.mkManagerOutputs {
  inherit self nixpkgs harbor-rs rust-overlay treefmt-nix git-hooks;
  crateName = "secret-manager";
  rustEdition = "2024";
  treefmtModule = {pkgs, ...} @ args:
    (import ./treefmt.nix {
      rustfmtPackage =
        (harbor-rs.lib.mkToolchain {
          inherit pkgs;
          toolchainProfile = "nightly";
        }).rustToolchain;
    })
    args;
  srcDir = ../.;
  extraRuntimePackages = pkgs: [
    pkgs.git
    pkgs.rage
    pkgs.gnupg
    pkgs.gh
  ];
  extraDevShellPackages = pkgs: [pkgs.gnupg pkgs.openssl];
  extraOutputs = {
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
            __pkl_class = "SyncTarget";
            target = "sync-only-target";
            name = "SYNC_ONLY_TOKEN";
            codebergOrgs = null;
            codebergUser = null;
            codeberg = ["caniko/example"];
            codefloe = ["caniko/codefloe-example"];
            github = ["caniko/github-example"];
            githubEnvironments = [
              {
                __pkl_class = "GithubEnvironment";
                repository = "caniko/github-example";
                environment = "simit-crates-io";
              }
            ];
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
      assert renderedSync.sync-only-target.githubEnvironments
      == [
        {
          repository = "caniko/github-example";
          environment = "simit-crates-io";
        }
      ];
      assert !(renderedSync.sync-only-target ? __pkl_class);
      assert !(renderedSync.sync-only-target ? codebergOrgs);
      assert !(renderedSync.sync-only-target ? codebergUser);
      assert renderedSync.public-value-target.source == "age/secrets/public-value.txt";
      assert !(renderedSync ? env-only);
      assert !(renderedSync ? unsynced-public);
      assert runnerFileEnv.instances == {};
        pkgs.runCommand "secret-manager-catalog-renderers" {} "touch $out";

    # agenix-rekey hands `settings` to the generator, which owns the UID.
    gpgUserIdCheckFor = pkgs: let
      secret = userId:
        (lib.evalModules {
          modules = [
            {
              options.age.secrets = lib.mkOption {
                type = lib.types.attrsOf lib.types.raw;
                default = {};
              };
              options.assertions = lib.mkOption {
                type = lib.types.listOf lib.types.raw;
                default = [];
              };
            }
            (secretLib.mkSecret ({
                name = "bot-gpg-key";
                stack = "system";
                source = "age/secrets/bot-gpg-key.age";
                generator = "gpg-key-pair";
              }
              // lib.optionalAttrs (userId != null) {inherit userId;}))
          ];
        })
        .config
        .age
        .secrets
        .bot-gpg-key;
    in
      assert (secret "bot <bot@example.test>").settings == {userId = "bot <bot@example.test>";};
      assert !(secret null ? settings);
        pkgs.runCommand "secret-manager-gpg-user-id" {} "touch $out";

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

    generatorChecksFor = pkgs: let
      generators = secretLib.mkGenerators {rotateCommand = "example rotate";};
      script = name: pkgs.writeText name (generators.${name} {inherit pkgs;});
      # The password dependency is a plaintext file and `decrypt` is `cat`.
      minisign = pkgs.writeText "minisign-key-pair" (generators.minisign-key-pair {
        inherit pkgs lib;
        file = "key.age";
        decrypt = "${pkgs.coreutils}/bin/cat";
        deps = [
          {
            name = "password";
            host = "nixos:check";
            file = "password";
          }
        ];
      });
    in {
      generator-minisign = pkgs.runCommand "secret-manager-generator-minisign" {nativeBuildInputs = [pkgs.minisign];} ''
        # Run like agenix does: inside a command substitution, where `set -e`
        # is not in force, so the generator must fail on its own.
        generate() { key=$(${lib.getExe pkgs.bash} ${minisign} </dev/null); }
        for broken in missing empty; do
          rm -f password key.pub
          if [ "$broken" = empty ]; then : > password; fi
          if generate 2>err; then
            echo "minisign-key-pair: succeeded with a $broken password secret" >&2
            exit 1
          fi
          if [ -e key.pub ]; then
            echo "minisign-key-pair: wrote key.pub with a $broken password secret" >&2
            exit 1
          fi
          if [ "$broken" = missing ]; then grep -qF 'run `example rotate` on it first' err; fi
        done
        printf '%s' 'correct-Horse.battery9' > password
        generate
        printf '%s\n' "$key" > key
        grep -q '^untrusted comment: minisign encrypted secret key' key
        echo payload > message
        printf '%s\n' 'correct-Horse.battery9' | minisign -S -s key -m message -x message.minisig
        minisign -V -p key.pub -m message -x message.minisig
        if printf 'wrong\n' | minisign -S -s key -m message -x wrong.minisig; then
          echo 'minisign-key-pair: key signed with the wrong password' >&2
          exit 1
        fi
        touch "$out"
      '';
      generator-alphabet = pkgs.runCommand "secret-manager-generator-alphabet" {} ''
        ${lib.getExe pkgs.python3} ${./tests/passphrase-alphabet.py} \
          ${lib.getExe pkgs.bash} \
          32 ${script "strong-passphrase"} \
          48 ${script "strong-passphrase-48"} \
          64 ${script "strong-passphrase-64"}
        touch "$out"
      '';
    };
  in {
    checks = forAllSystems (system: let
      pkgs = pkgsFor system;
      cargo = cargoFor system;
      testArgs =
        cargo.commonArgs
        // {
          inherit (cargo) cargoArtifacts;
          # The embedded helper scripts need a store-backed interpreter in the
          # sandbox, where /usr/bin/env is unavailable.
          postPatch = ''
            substituteInPlace crates/secret-manager/tests/rotate.rs \
              --replace-fail '#!/usr/bin/env bash' '#!${pkgs.bash}/bin/bash'
            substituteInPlace crates/secret-manager/src/encryption.rs \
              crates/secret-manager/src/rbw.rs \
              crates/secret-manager/tests/rbw_import.rs \
              crates/secret-manager/tests/github_environment_sync.rs \
              --replace-fail '#!/bin/sh' '#!${pkgs.runtimeShell}'
          '';
          # Crane's Cargo filter omits the public signing-key test fixture.
          src = lib.cleanSourceWith {
            src = ../.;
            filter = path: type:
              cargo.craneLib.filterCargoSources path type
              || path == "${toString ../.}/crates/secret-manager/tests/fixtures/gpg-public.asc";
          };
        };
    in
      {
        clippy = cargo.craneLib.cargoClippy (testArgs
          // {
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
        nextest = cargo.craneLib.cargoNextest (testArgs
          // {
            nativeBuildInputs = [pkgs.git pkgs.openssl pkgs.rage pkgs.gnupg];
            partitions = 1;
            partitionType = "count";
          });
        catalog-renderers = rendererCheckFor pkgs;
        runner-file-env-renderer = runnerFileEnvCheckFor pkgs;
        gpg-user-id = gpgUserIdCheckFor pkgs;
      }
      // generatorChecksFor pkgs);
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
        toolchain = harbor-rs.lib.mkToolchain {
          inherit pkgs;
          toolchainProfile = "nightly";
        };
        cross = harbor-rs.lib.mkCross {inherit pkgs system;};
        cargo = cargoFor system;
        targetPkgs = cross.linuxAarch64.pkgsCross;
        packages = harbor-rs.lib.mkCrossPackages {
          inherit pkgs cross;
          inherit (toolchain) craneLib;
          pname = "secret-manager";
          inherit (cargo) commonArgs;
          targets = ["aarch64-linux"];
          targetArgs."aarch64-linux" = {
            doCheck = false;
            nativeBuildInputs = [pkgs.makeWrapper];
            postInstall = ''
              if test -x "$out/bin/secret-manager"; then
                wrapProgram "$out/bin/secret-manager" \
                  --prefix PATH : ${pkgs.lib.makeBinPath [targetPkgs.rage targetPkgs.gnupg targetPkgs.gh]}
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

    apps = forAllSystems (system:
      if system == "x86_64-darwin"
      then {}
      else {
        deploy-pages = plinth.lib.${system}.mkDeployPagesApp {
          domain = "secret-manager.tartanoglu.com";
        };
      });

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
      toolchain = harbor-rs.lib.mkToolchain {
        inherit pkgs;
        toolchainProfile = "nightly";
      };
      cross = harbor-rs.lib.mkCross {inherit pkgs system;};
    in {
      docs = harbor-rs.lib.mkDocsShell {
        inherit pkgs cross;
        inherit (toolchain) craneLib;
        packages = [pkgs.mdbook];
        extraShellHook = ''
          echo "Documentation: mdbook serve docs"
        '';
      };
    });
  };
}
