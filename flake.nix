{
  description = "Declarative secret management for NixOS — resolve and render age/agenix secrets in Rust";

  inputs = {
    harbor.url = "git+https://github.com/caniko/harbor.git?ref=feat/harbor-monorepo-components&rev=e8b1996580e4ecd51dd402edf4a16d9df88e3a1b";

    nixpkgs.follows = "harbor/nixpkgs";
    rust-overlay.follows = "harbor/rust-overlay";
    crane.follows = "harbor/crane";
    flake-utils.url = "github:numtide/flake-utils";

    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";

    git-hooks.url = "github:cachix/git-hooks.nix";
    # git-hooks evaluates its own package set on Intel macOS.
    git-hooks.inputs.nixpkgs.follows = "harbor/nixpkgs-darwin";

    nix-manager-core = {
      url = "git+https://github.com/caniko/nix-manager-core.git?ref=migrate/harbor-combined-20261012&rev=42b11a63a955e9ab0793bb641daf656747f71dea";
      inputs.harbor.follows = "harbor";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
      inputs.crane.follows = "crane";
      inputs.treefmt-nix.follows = "treefmt-nix";
      inputs.git-hooks.follows = "git-hooks";
    };
    nix-pklx = {
      url = "git+https://github.com/caniko/nix-pklx.git?ref=migrate/harbor-combined-20261012&rev=400f2765a4ebd69e353c79e5fcf2f8d689c91138";
      inputs.harbor.follows = "harbor";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
      inputs.crane.follows = "crane";
    };
    plinth = {
      url = "git+https://github.com/caniko/plinth.git?ref=migrate/harbor-combined-20261012-features&rev=534dfa6dd6217db97b7ccd313501120a3c34d912";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs: import ./nix inputs;
}
