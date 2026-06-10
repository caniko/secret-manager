{
  self,
  nixpkgs,
  rs-harbor,
  rust-overlay,
  treefmt-nix,
  git-hooks,
  nix-manager-core,
  ...
}:
nix-manager-core.lib.mkManagerOutputs {
  inherit self nixpkgs rs-harbor rust-overlay treefmt-nix git-hooks;
  crateName = "secret-manager";
  rustEdition = "2024";
  srcDir = ../.;
  extraOutputs = {
    lib,
    forAllSystems,
    pkgsFor,
    ...
  }: {
    lib = import ./lib.nix;

    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
    in {
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
    });
  };
}
