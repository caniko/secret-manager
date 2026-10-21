# Public-policy adapter over agenix-rekey's native master encryption backend.
{
  pkgs,
  agenixRekey,
  userFlake,
  nixosConfigurations ? {},
  homeConfigurations ? {},
  darwinConfigurations ? {},
  nodes ? {},
  collectHomeManagerConfigurations ? true,
  agePackage ? (p: p.rage),
}: let
  inherit (pkgs) lib;
  selected = import (agenixRekey + "/nix/select-nodes.nix") {
    inherit lib nodes nixosConfigurations homeConfigurations darwinConfigurations collectHomeManagerConfigurations;
  };
  native = import (agenixRekey + "/nix/lib.nix") {
    inherit pkgs userFlake agePackage;
    nodes = selected;
  };
  command = builtins.match "(.*) encrypt" native.ageMasterEncrypt;
  # builtins.match drops string context; restore it so the wrapper is a
  # runtime dependency instead of a dangling symlink.
  executable = lib.addContextFrom native.ageMasterEncrypt (builtins.head command);
in
  assert lib.assertMsg (command != null) "secret-manager: unsupported agenix-rekey ageMasterEncrypt contract";
    pkgs.runCommand "agenix-stream-encryptor" {
      meta.mainProgram = "agenix-stream-encryptor";
    } ''
      mkdir -p "$out/bin"
      ln -s ${lib.escapeShellArg executable} "$out/bin/agenix-stream-encryptor"
    ''
