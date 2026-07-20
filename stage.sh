#!/usr/bin/env sh
# Build the DB Studio sidecar and stage it into dist/ for local core-routed
# loading (the core resolves sidecar:<name> from <home>/sidecars/<name>/dist/<bin>).
# Idempotent: rebuild, then atomically replace dist/<bin> with a real file copy
# (no symlink — A17). No publishing. Usage: ./stage.sh [debug|release]
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

# GUI/background shells often lack cargo on PATH — add rustup's bin.
command -v cargo >/dev/null 2>&1 || PATH="$HOME/.cargo/bin:$PATH"
export PATH

bin=soksak-sidecar-db-studio
profile="${1:-debug}"
case "$profile" in
  release) cargo build --release; src="target/release/$bin" ;;
  debug)   cargo build;           src="target/debug/$bin" ;;
  *) echo "usage: $0 [debug|release]" >&2; exit 2 ;;
esac

mkdir -p dist
tmp="dist/.$bin.stage.$$"
cp "$src" "$tmp"
mv -f "$tmp" "dist/$bin"   # atomic within the same filesystem
echo "staged: $here/dist/$bin ($profile)"
