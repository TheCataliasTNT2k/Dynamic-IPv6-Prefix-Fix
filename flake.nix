{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    fenix,
    naersk,
    ...
  }: let
    system = "x86_64-linux";
    target = "mipsel-unknown-linux-musl";
    pkgs = import nixpkgs {inherit system;};
    mips-pkgs = import nixpkgs {
      inherit system;
      crossSystem = pkgs.lib.systems.examples.mipsel-linux-gnu;
    };
  in {
    packages.${system} = let
      toolchain = with fenix.packages.${system};
        combine [
          stable.rustc
          stable.cargo
          targets.${target}.stable.rust-std
        ];
    in {
      default =
        (naersk.lib.${system}.override {
          cargo = toolchain;
          rustc = toolchain;
        })
        .buildPackage {
          src = ./.;
          CARGO_BUILD_TARGET = target;
          CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER = let
            inherit (mips-pkgs.stdenv) cc;
          in "${cc}/bin/${cc.targetPrefix}cc";
        };
      docker = pkgs.dockerTools.buildLayeredImage {
        name = "mips-cross-builder";
        tag = "latest";
        contents = with pkgs; [
          bashInteractive
          coreutils-full
          cacert
          stdenv.cc
          mips-pkgs.stdenv.cc
          toolchain
        ];
        extraCommands = "mkdir -m 0777 tmp";
        config = {
          Cmd = ["cargo" "build" "--release"];
          Env = [
            "CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse"
            "CARGO_BUILD_TARGET=${target}"
          ];
          WorkingDir = "/build";
        };
      };
    };
  };
}
