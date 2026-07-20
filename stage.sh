#!/usr/bin/env bash
# Build the sidecar and stage it into <dist>/ for local core-routed loading, or cross-build for a
# release target (the 5-platform CI matrix calls `./stage.sh dist <triple>`). No native engine —
# a service sidecar is a plain cargo build. Usage: stage.sh [<dist-dir>] [<target-triple>]
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

dist="${1:-dist}"
target="${2:-}"
name="soksak-sidecar-db-studio"

ext=""
case "$target" in *windows*) ext=".exe" ;; esac

if [ -n "$target" ]; then
  cargo build --release --target "$target" --bin "$name"
  reldir="$target/release"
else
  cargo build --release --bin "$name"
  reldir="release"
fi

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
src="$TARGET_DIR/$reldir/$name$ext"
[ -f "$src" ] || { echo "release binary not found at $src" >&2; exit 1; }

mkdir -p "$dist"
tmp="$dist/.$name.tmp.$$"
cp "$src" "$tmp"
chmod +x "$tmp"
mv -f "$tmp" "$dist/$name$ext"
echo "staged: $dist/$name$ext"
