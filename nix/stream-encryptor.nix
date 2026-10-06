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
in
  assert lib.assertMsg (command != null) "secret-manager: unsupported agenix-rekey ageMasterEncrypt contract";
    pkgs.runCommand "agenix-stream-encryptor" {
      meta.mainProgram = "agenix-stream-encryptor";
    } ''
      mkdir -p "$out/bin"
      ln -s ${lib.escapeShellArg (builtins.head command)} "$out/bin/agenix-stream-encryptor"
    ''
