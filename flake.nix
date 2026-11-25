{
  description = "Open RFC 9458 OHTTP Relay";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.zst";
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";

    # Pin to latest stable Rust toolchain.
    # May require a `nix flake update` when a new stable gets released;
    # alternatively, we may experiment with setting it to the MSRV instead?
    rust-manifest = {
      url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
      flake = false;
    };
  };

  outputs = inputs: {
    packages = builtins.mapAttrs (system: pkgs: {
      default =
        let
          toolchain =
            (inputs.fenix.packages.${system}.fromManifestFile inputs.rust-manifest).minimalToolchain;
        in
        (pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        }).buildRustPackage
          {
            pname = "ocloack";
            version = "0.2.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = with pkgs; [ pkg-config ];
            buildInputs = with pkgs; [ aws-lc ];
          };
    }) inputs.nixpkgs.legacyPackages;

    formatter = builtins.mapAttrs (system: pkgs: pkgs.nixfmt-tree) inputs.nixpkgs.legacyPackages;
  };
}
