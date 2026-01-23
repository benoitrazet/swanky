{ target }:
with import ./pkgs.nix { };
let
  version = "1.2.5";
  swankyLlvm = import ./llvm.nix;
in
stdenv.mkDerivation {
  name = "musl-sysroot";
  src = fetchurl {
    url = "https://musl.libc.org/releases/musl-${version}.tar.gz";
    hash = "sha256-qaEYu+hNh2TaDqDSizqz+uhHf8fkCF2QECuFlvx8deQ=";
  };
  configurePhase = ''
    export CC="${swankyLlvm.clang-unwrapped}/bin/clang"
    export CFLAGS="--target=${target}"
    ./configure "--prefix=$out" "--target=${target}"
  '';
  buildPhase = "true";
  installPhase = ''
    mkdir -p "$out"
    echo "${version}" > "$out/version.txt"
    make install-headers
  '';
}
