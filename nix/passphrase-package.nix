# Standalone passphrase generator for agenix-rekey (nix/generators.nix).
# Built from one std-only Rust file with plain rustc so it changes only when
# passphrase.rs does, not with every CLI or Cargo.lock change.
{
  runCommand,
  rustc,
  stdenv,
  passphraseSource ? ../crates/secret-manager/src/passphrase.rs,
}:
runCommand "secret-manager-passphrase" {
  nativeBuildInputs = [rustc stdenv.cc];
  meta.mainProgram = "secret-manager-passphrase";
} ''
  cp ${./passphrase-main.rs} main.rs
  cp ${passphraseSource} passphrase.rs
  rustc --edition 2024 -C opt-level=2 --test passphrase.rs -o passphrase-test
  ./passphrase-test
  mkdir -p "$out/bin"
  rustc --edition 2024 -C opt-level=2 main.rs -o "$out/bin/secret-manager-passphrase"
''
