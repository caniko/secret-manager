{
  description = "An example of how to use secret-manager sync targets";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    secret-manager.url = "path:..";
    secret-manager.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {self, nixpkgs, secret-manager, ...}: {
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

    # Eval-only check: verify the collected sync targets are valid JSON
    checks = nixpkgs.lib.genAttrs ["x86_64-linux" "aarch64-linux"] (system: {
      collect = nixpkgs.legacyPackages.${system}.runCommand "check-collect" {
        json = builtins.toJSON (secret-manager.lib.collect {
          inherit (self) nixosConfigurations;
        });
        passAsFile = ["json"];
      } "cp $jsonPath $out";
    });
  };
}
