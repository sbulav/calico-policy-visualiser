{
  description = "Dev env for calico-policy-visualiser (Vite + React)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        node = pkgs.nodejs_22;
      in
      {
        devShells.default = pkgs.mkShell {
          name = "calico-policy-visualiser";
          buildInputs = [
            node
            pkgs.gnumake
            pkgs.git
          ];

          shellHook = ''
            export NODE_ENV=development
            export BROWSER=none

            echo "[calico-policy-visualiser] devshell ready."
            echo "  make init         # npm install"
            echo "  make dev          # http://localhost:5173"
            echo "  make test         # run tests"
            echo "  make build        # production build -> ./dist"
            echo "  make help         # all targets"
          '';
        };

        apps.dev = {
          type = "app";
          program = "${pkgs.writeShellScript "dev" ''
            set -euo pipefail
            npm install
            npm run dev
          ''}";
        };
      }
    );
}
