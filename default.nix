{ lib
, callPackage
, rustPlatform
}:

rustPlatform.buildRustPackage {
  pname = "mitm-cache";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    filter = path: type:
      (type == "directory" || builtins.any (lib.flip lib.hasSuffix path) [ ".rs" ".toml" ".lock" ])
      && !lib.hasInfix "/target" path;
    src = ./.;
  };

  cargoLock.lockFile = ./Cargo.lock;

  passthru.fetch = callPackage ./fetch.nix { };

  meta = with lib; {
    description = "A MITM caching proxy for use in nixpkgs";
    license = licenses.mit;
    maintainers = with maintainers; [ chayleaf ];
  };
}
