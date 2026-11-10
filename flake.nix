{
  description = "Declarative secret management for NixOS — resolve and render age/agenix secrets in Rust";

  inputs = {
    harbor-rs.url = "git+https://github.com/caniko/harbor-rs.git?ref=trunk&rev=7f03d58b0e6e748b4817417ff21958e074ec6faf";

    nixpkgs.follows = "harbor-rs/nixpkgs";
    rust-overlay.follows = "harbor-rs/rust-overlay";
    crane.follows = "harbor-rs/crane";
    flake-utils.url = "github:numtide/flake-utils";

    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";

    git-hooks.url = "github:cachix/git-hooks.nix";
    git-hooks.inputs.nixpkgs.follows = "nixpkgs";

    nix-manager-core = {
      url = "git+https://github.com/caniko/nix-manager-core.git?ref=feat/manager-formatter-policy&rev=1e93309793e52347c62e42d85085f53912484f0f";
      inputs.harbor-rs.follows = "harbor-rs";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
      inputs.crane.follows = "crane";
      inputs.treefmt-nix.follows = "treefmt-nix";
      inputs.git-hooks.follows = "git-hooks";
    };
    nix-pklx = {
      url = "git+https://github.com/caniko/nix-pklx.git";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
      inputs.crane.follows = "crane";
      inputs.plinth.follows = "plinth";
    };
    plinth = {
      url = "git+https://github.com/caniko/plinth.git";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs: import ./nix inputs;
}
