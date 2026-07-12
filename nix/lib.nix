{lib}: let
  secretFileName = name: builtins.replaceStrings ["-"] ["_"] name;

  mkSecret = {
    name,
    stack,
    source,
    generator ? null,
    algorithm ? "ed25519",
    userId ? name,
    length ? 32,
    owner ? null,
    group ? null,
    mode ? null,
    targets ? {},
    extraConfig ? null,
  }: {
    config,
    lib,
    pkgs,
    ...
  }: let
    targetOr = attr: default: let
      value = targets.${attr} or null;
    in
      if value == null
      then default
      else value;

    t = {
      home =
        {
          env = [];
          file = null;
        }
        // targetOr "home" {};
      system =
        {
          env = null;
          file = null;
        }
        // targetOr "system" {};
      forgejo =
        {
          credential = null;
        }
        // targetOr "forgejo" {};
    };

    secretPath = config.age.secrets.${name}.path;

    isSshKey = generator == "ssh-key" || generator == "ssh-ed25519";
    hasEnvTarget = (t.home.env != []) || (t.system.env != null);

    generatorName =
      if generator == null
      then null
      else if generator == "passphrase" || generator == "strong-passphrase"
      then
        if length == 32
        then "strong-passphrase"
        else if length == 48
        then "strong-passphrase-48"
        else if length == 64
        then "strong-passphrase-64"
        else throw "mkSecret ${name}: passphrase length must be 32|48|64"
      else if isSshKey
      then
        if algorithm == "ed25519"
        then "ssh-ed25519-pub"
        else if algorithm == "rsa"
        then "ssh-rsa-pub"
        else throw "mkSecret ${name}: ssh algorithm must be ed25519|rsa"
      else if generator == "gpg-key-pair"
      then "gpg-key-pair"
      else throw "mkSecret ${name}: unknown generator ${generator}";

    core = {
      assertions = [
        {
          assertion = source != null;
          message = "mkSecret ${name}: `source` (rekeyFile) is required";
        }
        {
          assertion = stack == "home" || (t.home.env == [] && t.home.file == null);
          message = "mkSecret ${name}: home targets set on stack=${stack}";
        }
        {
          assertion = stack == "system" || (t.system.env == null && t.system.file == null);
          message = "mkSecret ${name}: system targets set on stack=${stack}";
        }
        {
          assertion = stack == "forgejo" || t.forgejo.credential == null;
          message = "mkSecret ${name}: forgejo target set on stack=${stack}";
        }
        {
          assertion = !(isSshKey && hasEnvTarget);
          message = "mkSecret ${name}: ssh-key cannot be an env var; use a file/credential target";
        }
      ];

      age.secrets.${name} = lib.filterAttrs (_: v: v != null) ({
          name = lib.mkDefault (secretFileName name);
          rekeyFile = source;
          inherit owner group mode;
        }
        // lib.optionalAttrs (generatorName != null) {
          generator.script = generatorName;
        });
    };

    homeConfig = lib.mkMerge [
      (lib.optionalAttrs (t.home.env != []) (let
        replaceXdg = builtins.replaceStrings ["\${XDG_RUNTIME_DIR}"] ["($env.XDG_RUNTIME_DIR)"];
        bashExports = lib.concatMapStringsSep "\n" (v: "    export ${v}=\"$val\"") t.home.env;
        nuPath = replaceXdg secretPath;
        nuExports = lib.concatMapStringsSep "\n" (v: "    $env.${v} = $val") t.home.env;
      in {
        programs.bash.initExtra = ''
            if [ -f "${secretPath}" ]; then
              val=$(cat "${secretPath}")
          ${bashExports}
            fi
        '';

        programs.nushell.envFile.text = ''
            if ($"${nuPath}" | path exists) {
              let val = (open $"${nuPath}" | str trim)
          ${nuExports}
            }
        '';
      }))
      (lib.optionalAttrs (t.home.file != null) {
        age.secrets.${name} = {
          path = t.home.file.path;
          mode = t.home.file.mode or "600";
          symlink = t.home.file.symlink or false;
        };
      })
    ];

    systemConfig = lib.mkMerge [
      (lib.optionalAttrs (t.system.env != null) (let
        e = t.system.env;
        unit = "${name}-envfile";
        envFile = "/run/${unit}/env";
        envMode = e.mode or "0400";
        printfLines =
          lib.concatMapStringsSep "\n"
          (v: ''${pkgs.coreutils}/bin/printf '${v}=%s\n' "$val"'')
          e.vars;
      in {
        systemd.services = lib.mkMerge [
          {
            ${unit} = {
              description = "Render ${name} environment file";
              before = map (s: "${s}.service") e.services;
              wantedBy = map (s: "${s}.service") e.services;
              path = [pkgs.coreutils];

              serviceConfig = {
                Type = "oneshot";
                RemainAfterExit = true;
                RuntimeDirectory = unit;
                RuntimeDirectoryMode = "0700";
              };

              script = ''
                                set -eu
                                umask 077
                                val="$(${pkgs.coreutils}/bin/tr -d '\n' < ${secretPath})"
                                tmp="${envFile}.tmp"
                                {
                ${printfLines}
                                } > "$tmp"
                                ${pkgs.coreutils}/bin/chmod ${envMode} "$tmp"
                                ${lib.optionalString (e.owner or null != null)
                  "${pkgs.coreutils}/bin/chown ${e.owner} \"$tmp\""}
                                ${pkgs.coreutils}/bin/mv "$tmp" "${envFile}"
              '';
            };
          }
          (lib.genAttrs e.services (_: {
            serviceConfig.EnvironmentFile = [envFile];
            after = ["${unit}.service"];
            requires = ["${unit}.service"];
          }))
        ];
      }))
      (lib.optionalAttrs (t.system.file != null) {
        age.secrets.${name} = lib.filterAttrs (_: v: v != null) {
          path = t.system.file.path;
          owner = t.system.file.owner or null;
          group = t.system.file.group or null;
          mode = t.system.file.mode or "0400";
          symlink = t.system.file.symlink or false;
        };
      })
    ];

    forgejoConfig = lib.optionalAttrs (t.forgejo.credential != null) (let
      c = t.forgejo.credential;
      unitName = name: "forgejo-runner-${name}";
    in {
      systemd.services = lib.genAttrs (map unitName c.instances) (_: {
        serviceConfig.LoadCredential = ["${c.name}:${secretPath}"];
      });
    });

    stackConfig =
      if stack == "home"
      then homeConfig
      else if stack == "system"
      then systemConfig
      else if stack == "forgejo"
      then forgejoConfig
      else throw "mkSecret ${name}: unknown stack ${stack}";

    extra =
      if extraConfig == null
      then {}
      else extraConfig secretPath;
  in
    lib.mkMerge [core stackConfig extra];

  mkSharedSecret = {
    source,
    generator ? null,
    algorithm ? "ed25519",
    userId ? null,
    length ? 32,
    home ? null,
    system ? null,
    forgejo ? null,
  }: let
    mkStack = stack: args:
      mkSecret ({
          inherit source generator algorithm length stack;
        }
        // (
          if userId != null
          then {inherit userId;}
          else {}
        )
        // args);

    optionalStack = stack: args:
      if args == null
      then {}
      else {${stack} = mkStack stack args;};
  in
    optionalStack "home" home
    // optionalStack "system" system
    // optionalStack "forgejo" forgejo;

  pubOf = ageSrc:
    (builtins.substring 0 ((builtins.stringLength ageSrc) - 4) ageSrc) + ".pub";

  mkHomeEnvSecretModules = {
    catalog,
    mkSecret,
    resolveSource,
    extraConfig ? (_name: _entry: _path: {}),
  }: let
    envEntries = lib.filterAttrs (_name: entry: (entry.env or []) != []) catalog;
  in
    lib.mapAttrsToList (
      name: entry:
        mkSecret {
          inherit name;
          stack = "home";
          source = resolveSource entry.source;
          targets.home.env = entry.env;
          extraConfig = path: extraConfig name entry path;
        }
    )
    envEntries;

  mkSecretSyncTargets = {
    catalog,
    plain ? {},
    secretSource ? (_name: entry:
      entry.source.relative
      or (throw "secret-manager.lib.mkSecretSyncTargets: encrypted entry is missing source.relative")),
    plainSource ? (_name: entry: entry.source),
  }: let
    syncEntries = lib.filterAttrs (_name: entry: entry ? sync) catalog;
    plainSyncEntries = lib.filterAttrs (_name: entry: entry ? sync) plain;

    renderTarget = sourceAttr: name: entry: {
      name = entry.sync.target or (throw "secret-manager.lib.mkSecretSyncTargets: ${name} is missing sync.target");
      value =
        builtins.removeAttrs entry.sync ["target"]
        // {
          ${sourceAttr} =
            if sourceAttr == "secret"
            then secretSource name entry
            else plainSource name entry;
        };
    };
  in
    lib.mapAttrs' (renderTarget "secret") syncEntries
    // lib.mapAttrs' (renderTarget "source") plainSyncEntries;

  mkForgejoRunnerFileEnv = {
    catalog,
    secretSource ? (_name: entry:
      entry.source.relative
      or (throw "secret-manager.lib.mkForgejoRunnerFileEnv: encrypted entry is missing source.relative")),
    runtimeDir ? "/run/secret-manager/forgejo-runner",
    secretNamePrefix ? "forgejo-runner-file-env",
    owner ? "root",
    group ? "root",
    mode ? "0444",
  }: let
    entries =
      lib.flatten
      (lib.mapAttrsToList (
          id: entry:
            lib.concatMap (
              target:
                map (instance: {
                  inherit id entry target instance;
                  source = secretSource id entry;
                  file = "${runtimeDir}/${instance}/${id}";
                  dir = "${runtimeDir}/${instance}";
                  secretName = "${secretNamePrefix}-${instance}-${id}";
                })
                (target.instances or [])
            )
            (entry.runnerFileEnv or [])
        )
        catalog);

    byInstance =
      lib.groupBy (entry: entry.instance) entries;

    instanceRuntime = instance: instanceEntries: {
      containerOptions =
        ["-v ${runtimeDir}/${instance}:${runtimeDir}/${instance}:ro"]
        ++ map (entry: "-e ${entry.target.env}=${entry.file}") instanceEntries;
      validVolumes = ["${runtimeDir}/${instance}"];
    };
  in {
    config = {
      age.secrets =
        builtins.listToAttrs
        (map (entry:
          lib.nameValuePair entry.secretName {
            rekeyFile = entry.source;
            inherit mode;
          })
        entries);

      systemd.tmpfiles.settings."10-secret-manager-forgejo-runner-file-env" =
        builtins.listToAttrs
        (
          map (instance:
            lib.nameValuePair "${runtimeDir}/${instance}" {
              d = {
                mode = "0755";
                user = owner;
                inherit group;
              };
            })
          (lib.attrNames byInstance)
          ++ map (entry:
            lib.nameValuePair entry.file {
              "C+" = {
                argument = "/run/agenix/${entry.secretName}";
                inherit mode group;
                user = owner;
              };
            })
          entries
        );
    };

    instances = lib.mapAttrs instanceRuntime byInstance;
  };
in {
  inherit mkForgejoRunnerFileEnv mkHomeEnvSecretModules mkSecret mkSecretSyncTargets mkSharedSecret pubOf secretFileName;
}
