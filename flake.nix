{
  description = "Declarative secret management for NixOS — resolve and render age/agenix secrets in Rust";

  inputs = {
    rs-harbor.url = "git+https://github.com/caniko/rs-harbor.git?ref=trunk&rev=77d0a937c760e6ced8b7ec8fc5a214f550abe35e";

    nixpkgs.follows = "rs-harbor/nixpkgs";
    rust-overlay.follows = "rs-harbor/rust-overlay";
    crane.follows = "rs-harbor/crane";
    flake-utils.url = "github:numtide/flake-utils";

    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";

    git-hooks.url = "github:cachix/git-hooks.nix";
    git-hooks.inputs.nixpkgs.follows = "nixpkgs";

    nix-manager-core = {
      url = "git+https://github.com/caniko/nix-manager-core";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rs-harbor.follows = "rs-harbor";
      inputs.rust-overlay.follows = "rust-overlay";
      inputs.crane.follows = "crane";
      inputs.treefmt-nix.follows = "treefmt-nix";
      inputs.git-hooks.follows = "git-hooks";
    };
    nix-pklx = {
      url = "git+https://codeberg.org/caniko/nix-pklx.git";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rs-harbor.follows = "rs-harbor";
      inputs.rust-overlay.follows = "rust-overlay";
      inputs.crane.follows = "crane";
      inputs.plinth.follows = "plinth";
    };
    plinth = {
      url = "git+https://codeberg.org/caniko/plinth.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs: import ./nix inputs;
}
