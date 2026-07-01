#!/usr/bin/env bash
set -euo pipefail

repo_url="${BASTION_REPO_URL:-https://codeberg.org/melokki/bastion.git}"
branch="${BASTION_BRANCH:-main}"
install_root="${BASTION_INSTALL_ROOT:-${CARGO_INSTALL_ROOT:-$HOME/.cargo}}"
package_name="bastion"
binary_name="bastion"
bin_dir="$install_root/bin"

say() {
  printf 'bastion-install: %s\n' "$*"
}

fail() {
  printf 'bastion-install: error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

require_command cargo
require_command git

say "installing $binary_name from $repo_url ($branch)"

cargo install \
  --git "$repo_url" \
  --branch "$branch" \
  --locked \
  --bin "$binary_name" \
  --root "$install_root" \
  "$package_name"

if [ ! -x "$bin_dir/$binary_name" ]; then
  fail "expected installed binary at $bin_dir/$binary_name"
fi

say "installed $binary_name to $bin_dir/$binary_name"

case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *)
    say "add this to your shell profile if $binary_name is not found:"
    say "export PATH=\"$bin_dir:\$PATH\""
    ;;
esac
