{
  description = "pubmirror: guards what a private repository publishes";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f nixpkgs.legacyPackages.${s});
    in
    {
      packages = forAll (pkgs: rec {
        pubmirror = pkgs.buildGoModule {
          pname = "pubmirror";
          version = self.shortRev or self.dirtyShortRev or "dev";
          src = pkgs.lib.cleanSource ./.;
          vendorHash = "sha256-pbA/AlBz3cQYRTMnQ/qBPcinYOKokrBLNhkbRTq54gE=";
          subPackages = [ "cmd/pubmirror" ];
          env.CGO_ENABLED = 0;
          ldflags = [ "-s" "-w" ];
          nativeBuildInputs = [ pkgs.makeWrapper ];
          nativeCheckInputs = [ pkgs.git pkgs.gitleaks ];
          # pubmirror runs git and gitleaks; the wrapper puts the pinned ones first.
          postInstall = ''
            wrapProgram $out/bin/pubmirror --prefix PATH : ${
              pkgs.lib.makeBinPath [ pkgs.git pkgs.gitleaks ]
            }
          '';
          meta = {
            description = "Guards what a private repository publishes";
            license = pkgs.lib.licenses.asl20;
            mainProgram = "pubmirror";
          };
        };
        default = pubmirror;
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.go pkgs.git pkgs.gitleaks ];
        };
      });
    };
}
