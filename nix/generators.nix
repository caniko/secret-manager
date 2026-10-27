# agenix-rekey generators for the names `mkSecret` emits (`strong-passphrase*`,
# `ssh-*-pub`, `gpg-key-pair`) plus `minisign-key-pair`. Register the result as
# `age.generators` on every agenix module (NixOS and Home Manager) that
# evaluates secrets declaring `generator.script = "<name>"`.
#
# Each value is an agenix-rekey generator function. agenix-rekey calls it with
# `{ name, secret, lib, pkgs, file, deps, decrypt, ... }` and runs the returned
# script with bash to produce the secret plaintext on stdout. The script may
# write adjacent files (the ssh generators drop a `.pub` next to the `.age`).
# agenix-rekey runs each script as `( script ) || die`, where `set -e` is
# ignored, so the key generators fail explicitly on every step before they
# emit the private key.
#
# `rotateCommand` is the consumer's command for regenerating one secret; it
# only appears in diagnostics.
{rotateCommand ? "secret-manager rotate"}: let
  # Single-line password, no trailing newline, uniform over an
  # env-file/shell-safe alphabet, guaranteed >=1 each of lower/upper/digit/
  # symbol. The symbol set deliberately excludes every character that is
  # special to a systemd `KEY=value` EnvironmentFile or a bash/nushell
  # `export VAR="$val"` (no `$ " ' \` backtick `#`, no whitespace), so the same
  # value is safe in every delivery target.
  mkStrongPassphrase = len: {pkgs, ...}: ''
    lower='abcdefghijklmnopqrstuvwxyz'
    upper='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    digit='0123456789'
    # GNU tr treats a middle hyphen as a range, unlike the intended alphabet.
    symbol='@%_+=.,:/?-'
    alphabet="$lower$upper$digit$symbol"
    len=${toString len}
    while :; do
      pw=""
      # head -c bounds the read so the upstream closes cleanly (no SIGPIPE,
      # safe under agenix-rekey's global `set -euo pipefail`). tr rejection-
      # samples uniformly from the alphabet.
      while [ "''${#pw}" -lt "$len" ]; do
        chunk=$(LC_ALL=C ${pkgs.coreutils}/bin/head -c 256 /dev/urandom \
          | LC_ALL=C ${pkgs.coreutils}/bin/tr -dc "$alphabet")
        pw="$pw$chunk"
      done
      pw="''${pw:0:$len}"
      case "$pw" in *[a-z]*) ;; *) continue ;; esac
      case "$pw" in *[A-Z]*) ;; *) continue ;; esac
      case "$pw" in *[0-9]*) ;; *) continue ;; esac
      # `-` last in the bracket so it is a literal, not a range.
      case "$pw" in *[@%_+=.,:/?-]*) ;; *) continue ;; esac
      break
    done
    ${pkgs.coreutils}/bin/printf '%s' "$pw"
  '';

  # ed25519 (or rsa-4096) private key to stdout (becomes the `.age` plaintext),
  # public key written to `<secret>.pub` adjacent to the encrypted file so it
  # can be read by `canix` and referenced by other modules. Wrapped in a
  # subshell so the cleanup `trap` is scoped to this generator when several run
  # in one `agenix generate`.
  mkSshKey = algo: {
    pkgs,
    lib,
    name,
    file,
    ...
  }: ''
    (
      tmp=$(${pkgs.coreutils}/bin/mktemp -d) || exit 1
      trap '${pkgs.coreutils}/bin/rm -rf "$tmp"' EXIT
      ${pkgs.openssh}/bin/ssh-keygen -q -t ${algo} ${lib.optionalString (algo == "rsa") "-b 4096"} \
        -N "" -C ${lib.escapeShellArg name} -f "$tmp/key" || exit 1
      ${pkgs.coreutils}/bin/install -m 0644 "$tmp/key.pub" \
        ${lib.escapeShellArg (lib.removeSuffix ".age" file + ".pub")} || exit 1
      ${pkgs.coreutils}/bin/cat "$tmp/key"
    )
  '';

  # `settings.userId` sets the full UID ("Name <email>"); forges verify a
  # signature only when the UID carries the committer email.
  mkGpgKeyPair = {
    pkgs,
    lib,
    name,
    file,
    secret ? {},
    ...
  }: ''
    (
      tmp=$(${pkgs.coreutils}/bin/mktemp -d) || exit 1
      trap '${pkgs.coreutils}/bin/rm -rf "$tmp"' EXIT
      export GNUPGHOME="$tmp/gnupg"
      ${pkgs.coreutils}/bin/mkdir -m 700 "$GNUPGHOME" || exit 1
      ${pkgs.gnupg}/bin/gpg --batch --pinentry-mode loopback --passphrase "" \
        --quick-generate-key ${lib.escapeShellArg (secret.settings.userId or "${name} <${name}@secrets.invalid>")} \
        rsa4096 sign 0 || exit 1
      fingerprint=$(${pkgs.gnupg}/bin/gpg --batch --with-colons --list-secret-keys \
        | ${pkgs.gawk}/bin/awk -F: '$1 == "fpr" { print $10; exit }')
      test -n "$fingerprint" || exit 1
      public=${lib.escapeShellArg (lib.removeSuffix ".age" file + ".asc")}
      fingerprint_file=${lib.escapeShellArg (lib.removeSuffix ".age" file + ".fingerprint")}
      ${pkgs.gnupg}/bin/gpg --batch --armor --export "$fingerprint" > "$public" || exit 1
      ${pkgs.coreutils}/bin/printf '%s\n' "$fingerprint" > "$fingerprint_file" || exit 1
      ${pkgs.coreutils}/bin/chmod 0644 "$public" "$fingerprint_file" || exit 1
      ${pkgs.gnupg}/bin/gpg --batch --pinentry-mode loopback --passphrase "" \
        --armor --export-secret-keys "$fingerprint"
    )
  '';

  # minisign secret key encrypted with the password secret it depends on
  # (`generator.dependencies = [ <password secret> ]`, exactly one). The
  # `.age` plaintext is the encrypted key file; the public key is written to
  # `<secret>.pub` next to it. Release CI signs with the pair as
  # MINISIGN_SECRET_KEY + MINISIGN_PASSWORD. The password only crosses a pipe.
  # `agenix generate <key path>` does not generate the dependency: rotate the
  # password first.
  mkMinisignKeyPair = {
    pkgs,
    lib,
    file,
    deps,
    decrypt,
    ...
  }: let
    # agenix-rekey passes `deps` in the shape `dependencies` was declared in.
    depList =
      if builtins.isAttrs deps
      then builtins.attrValues deps
      else deps;
  in
    assert lib.assertMsg (builtins.length depList == 1)
    "minisign-key-pair: depend on exactly one password secret"; ''
      (
        tmp=$(${pkgs.coreutils}/bin/mktemp -d)
        trap '${pkgs.coreutils}/bin/rm -rf "$tmp"' EXIT
        dep=${lib.escapeShellArg (lib.head depList).file}
        if [ ! -s "$dep" ]; then
          echo "minisign-key-pair: password secret $dep is missing; run \`"${lib.escapeShellArg rotateCommand}"\` on it first" >&2
          exit 1
        fi
        password=$(${decrypt} "$dep") || exit 1
        if [ -z "$password" ]; then
          echo "minisign-key-pair: password secret $dep decrypted to nothing" >&2
          exit 1
        fi
        ${pkgs.coreutils}/bin/printf '%s\n%s\n' "$password" "$password" \
          | ${pkgs.minisign}/bin/minisign -G -p "$tmp/key.pub" -s "$tmp/key" >/dev/null || exit 1
        ${pkgs.coreutils}/bin/install -m 0644 "$tmp/key.pub" \
          ${lib.escapeShellArg (lib.removeSuffix ".age" file + ".pub")} || exit 1
        ${pkgs.coreutils}/bin/cat "$tmp/key" || exit 1
      )
    '';
in {
  strong-passphrase = mkStrongPassphrase 32;
  strong-passphrase-48 = mkStrongPassphrase 48;
  strong-passphrase-64 = mkStrongPassphrase 64;
  ssh-ed25519-pub = mkSshKey "ed25519";
  ssh-rsa-pub = mkSshKey "rsa";
  gpg-key-pair = mkGpgKeyPair;
  minisign-key-pair = mkMinisignKeyPair;
}
