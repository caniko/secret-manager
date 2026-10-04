# Consumer-owned policy passed to mkManagerOutputs and the fleet composer.
{rustfmtPackage}: {pkgs, ...}: {
  projectRootFile = "flake.nix";
  programs.rustfmt = {
    enable = true;
    edition = "2024";
    package = rustfmtPackage;
  };
  programs.alejandra.enable = true;
  programs.taplo.enable = true;
  programs.prettier = {
    enable = true;
    package = pkgs.prettier;
    includes = ["*.md" "*.markdown"];
  };
}
