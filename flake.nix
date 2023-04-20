{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    fenix,
    ...
  }: let
    pkgs = import nixpkgs {system = "x86_64-linux";};
    mips-pkgs = import nixpkgs {
      system = "x86_64-linux";
      crossSystem = pkgs.lib.systems.examples.mipsel-linux-gnu;
    };
  in {
    packages.x86_64-linux.default = pkgs.dockerTools.buildLayeredImage {
      name = "mips-cross-builder";
      tag = "latest";
      contents = with pkgs; [
        bashInteractive
        coreutils-full
        cacert
        stdenv.cc
        mips-pkgs.stdenv.cc
        (
          with fenix.packages.x86_64-linux;
            combine [
              stable.rustc
              stable.cargo
              targets.mipsel-unknown-linux-musl.stable.rust-std
            ]
        )
      ];
      extraCommands = "mkdir -m 0777 tmp";
      config = {
        Cmd = ["cargo" "build" "--release"];
        Env = ["CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse"];
        WorkingDir = "/build";
      };
    };
  };
}
