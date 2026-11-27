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

    # cargo-binstall archives. The crate is Linux-only (libc PDEATHSIG, /proc
    # cgroup swap checks, logind inhibitors) and uses std::os::unix, so the
    # Windows and Darwin targets are not declared at all.
    binstallReleaseFor = system: let
      pkgs = pkgsFor system;
      cargo = cargoFor system;
    in
      harbor-rs.lib.mkBinstallRelease {
        inherit pkgs system;
        pname = "secret-manager";
        version = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package.version;
        # The archive needs the binary only: the test suite wants host tooling
        # (git, rage, gnupg) and the GPG fixture crane's filter drops.
        commonArgs = cargo.commonArgs // {doCheck = false;};
        crates.caniko-secret-manager = {cargoToml = ../crates/secret-manager/Cargo.toml;};
        targets = {x86_64-linux = ["x86_64-linux-musl" "aarch64-linux-musl"];};
        # GCC's aarch64 outline atomics call __aarch64_ldadd4_sync from libgcc,
        # which rustc's static musl link line does not include: vendored libdbus
        # then fails to link. Inline libdbus' word-size atomics instead.
        targetArgs.aarch64-linux-musl = {
          CFLAGS_aarch64_unknown_linux_musl = "-mno-outline-atomics";
        };
      };

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
            kubernetes = [
              {
                __pkl_class = "KubernetesDestination";
                context = "nautilus";
                namespace = "syndb";
                secret = "registry-pull";
                format = "dockerconfigjson";
                key = null;
                registry = null;
                username = "robot";
                fieldManager = null;
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
      assert renderedSync.sync-only-target.kubernetes
      == [
        {
          context = "nautilus";
          namespace = "syndb";
          secret = "registry-pull";
          format = "dockerconfigjson";
          username = "robot";
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
      passphrasePkg = pkgs.callPackage ./passphrase-package.nix {
        passphraseSource = ../crates/secret-manager/src/passphrase.rs;
      };
      script = name: pkgs.writeText name (generators.${name} {inherit pkgs;});
      fakeDecrypt = pkgs.writeShellScript "fake-decrypt" ''
        echo "$@" >> "$DECRYPT_LOG"
        exec ${pkgs.coreutils}/bin/cat "$@"
      '';
      # The password dependency is a plaintext file and `decrypt` is `cat`.
      password = {
        name = "password";
        host = "nixos:check";
        file = "password";
      };
      minisignWith = deps:
        generators.minisign-key-pair {
          inherit pkgs lib deps;
          file = "key.age";
          decrypt = "${pkgs.coreutils}/bin/cat";
        };
      minisignScript = minisignWith [password];
      minisign = pkgs.writeText "minisign-key-pair" minisignScript;
      cifs = pkgs.writeText "cifs-credentials" (generators.cifs-credentials {
        inherit pkgs lib;
        secret.settings.username = "backup";
      });
      bearer = {
        name = "bearer";
        host = "nixos:check";
        file = "bearer";
      };
      detritusWith = deps: settings:
        generators.detritus-tokens {
          inherit pkgs lib deps;
          decrypt = "${fakeDecrypt}";
          secret.settings =
            {
              id = "regicide-prod";
              project = "regicide";
            }
            // settings;
        };
      detritusTokens = settings: pkgs.writeText "detritus-tokens" (detritusWith [bearer] settings);
      # A public half that cannot be written must fail before the private key
      # is emitted.
      unwritable = name:
        pkgs.writeText name (generators.${name} {
          inherit pkgs lib name;
          file = "missing/key.age";
        });
    in
      assert minisignWith {inherit password;} == minisignScript;
      assert detritusWith {inherit bearer;} {} == detritusWith [bearer] {}; {
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
        generator-cifs-credentials = pkgs.runCommand "secret-manager-generator-cifs-credentials" {} ''
          creds=$(${lib.getExe pkgs.bash} ${cifs} </dev/null)
          ${lib.getExe pkgs.python3} - "$creds" <<'PY'
          import string, sys
          lines = sys.argv[1].splitlines()
          assert len(lines) == 2, f"expected 2 lines, got {len(lines)}"
          assert lines[0] == "username=backup", f"unexpected username line: {lines[0]!r}"
          assert lines[1].startswith("password="), f"unexpected password line: {lines[1]!r}"
          pw = lines[1].removeprefix("password=")
          symbols = "@%_+=.,:/?-"
          alphabet = set(string.ascii_letters + string.digits + symbols)
          assert len(pw) == 48, f"expected 48-char password, got {len(pw)}"
          assert set(pw) <= alphabet, "unsafe character in cifs password"
          for cat in (string.ascii_lowercase, string.ascii_uppercase, string.digits, symbols):
              assert set(pw) & set(cat), "missing character class in cifs password"
          PY
          # Failing or empty passphrase generator must fail and emit nothing.
          for replacement in ${pkgs.coreutils}/bin/false ${pkgs.coreutils}/bin/true; do
            broken=$(mktemp)
            sed "s|${lib.getExe passphrasePkg}|$replacement|g" ${cifs} > "$broken"
            if out_bad=$(${lib.getExe pkgs.bash} "$broken" </dev/null 2>/dev/null); then
              echo "cifs-credentials: succeeded when passphrase generator was $replacement" >&2
              exit 1
            fi
            test -z "$out_bad"
            rm -f "$broken"
          done
          touch "$out"
        '';
        generator-detritus-tokens = pkgs.runCommand "secret-manager-generator-detritus-tokens" {nativeBuildInputs = [pkgs.libargon2];} ''
          generate() { tokens=$(${lib.getExe pkgs.bash} "''${1:-${detritusTokens {}}}" </dev/null); }
          export DECRYPT_LOG="$PWD/decrypt.log"
          for broken in missing empty; do
            rm -f bearer
            if [ "$broken" = empty ]; then : > bearer; fi
            if generate 2>err; then
              echo "detritus-tokens: succeeded with a $broken bearer secret" >&2
              exit 1
            fi
            if [ "$broken" = missing ]; then grep -qF 'run `example rotate` on it first' err; fi
          done
          printf '%s' 'correct-Horse.battery9' > bearer
          : > "$DECRYPT_LOG"
          generate
          if [ "$(wc -l < "$DECRYPT_LOG")" != 1 ]; then
            echo "detritus-tokens: expected exactly one decrypt, got:" >&2
            cat "$DECRYPT_LOG" >&2
            exit 1
          fi
          printf '%s\n' "$tokens" > tokens.toml
          grep -qx '\[\[token\]\]' tokens.toml
          grep -qx 'id = "regicide-prod"' tokens.toml
          grep -qx 'project = "regicide"' tokens.toml
          grep -qx 'source_prefix = "regicide/"' tokens.toml
          if grep -q 'correct-Horse' tokens.toml; then
            echo 'detritus-tokens: plaintext bearer leaked into tokens.toml' >&2
            exit 1
          fi
          # Recompute the PHC hash from its own salt: it must verify the bearer
          # and reject another one. The 22-byte salt encodes to 30 unpadded chars.
          hash=$(sed -n 's/^secret = "\(.*\)"$/\1/p' tokens.toml)
          salt=$(printf '%s==' "$(printf '%s' "$hash" | cut -d'$' -f5)" | base64 -d)
          [ "$(printf '%s' 'correct-Horse.battery9' | argon2 "$salt" -id -t 2 -m 16 -p 1 -e)" = "$hash" ]
          [ "$(printf '%s' 'wrong' | argon2 "$salt" -id -t 2 -m 16 -p 1 -e)" != "$hash" ]
          if grep -q '^can_purge' tokens.toml; then exit 1; fi
          generate ${detritusTokens {can_purge = false;}}
          if grep -q '^can_purge' <<< "$tokens"; then exit 1; fi
          generate ${detritusTokens {can_purge = true;}}
          grep -qx 'can_purge = true' <<< "$tokens"
          touch "$out"
        '';
        generator-public-key-write = pkgs.runCommand "secret-manager-generator-public-key-write" {} ''
          for script in ${unwritable "ssh-ed25519-pub"} ${unwritable "gpg-key-pair"}; do
            if key=$(${lib.getExe pkgs.bash} "$script" </dev/null); then
              echo "$script: succeeded without writing its public key" >&2
              exit 1
            fi
            test -z "$key"
          done
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
              crates/secret-manager/tests/guide.rs \
              --replace-fail '#!/bin/sh' '#!${pkgs.runtimeShell}'
          '';
          # Crane's Cargo filter omits the text fixtures the tests read.
          src = lib.cleanSourceWith {
            src = ../.;
            filter = path: type:
              cargo.craneLib.filterCargoSources path type
              || path == "${toString ../.}/crates/secret-manager/tests/fixtures/gpg-public.asc"
              || path == "${toString ../.}/crates/secret-manager/tests/fixtures/rotation-catalogue.pkl"
              || path == "${toString ../.}/pkl/SecretRegistry.pkl";
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
            nativeBuildInputs = [pkgs.git pkgs.openssl pkgs.rage pkgs.gnupg pkgs.minisign pkgs.whois];
            # reqwest loads system roots at client construction, even for localhost HTTP tests.
            SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            partitions = 1;
            partitionType = "count";
          });
        catalog-renderers = rendererCheckFor pkgs;
        runner-file-env-renderer = runnerFileEnvCheckFor pkgs;
        gpg-user-id = gpgUserIdCheckFor pkgs;
      }
      // generatorChecksFor pkgs
      // (binstallReleaseFor system).checks);
    nixosModules = {
      secretSync = module;
      default = module;
    };

    lib = secretLib // collectLib;

    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
      pklx = nix-pklx.packages.${system}.pklx;
      release = binstallReleaseFor system;
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
      secret-manager-passphrase = pkgs.callPackage ./passphrase-package.nix {
        passphraseSource = ../crates/secret-manager/src/passphrase.rs;
      };
    in
      {
        inherit docs;
        inherit pklx;
        inherit secret-manager-passphrase;
        site = pkgs.runCommand "secret-manager-site" {} ''
          mkdir -p $out
          cp -rL --no-preserve=mode ${docs}/. $out/
          printf '%s\n' "secret-manager.tartanoglu.com" > $out/.domains
        '';
      }
      # Only the listed build hosts have a release bundle.
      // lib.optionalAttrs (release.releaseBundle != null) {release-bundle = release.releaseBundle;});

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
