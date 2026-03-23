{}:
let sources = import ./npins;
in
(import sources.nixpkgs)
{
  overlays = [ (import sources.rust-overlay) ];
}
