#!/bin/bash
# Dry-run helper: lay out a throwaway "installed Runtime" the way the installer
# does, so demo.sh can be tried without a real installation.
#
#   installed-layout.sh <runtime-binary> <new-folder>
#
# It writes <new-folder>/bin/elastos (a copy of the binary) and, under
# <new-folder>/data, components.json, installation/release.json and
# installation/release-head.json whose SHA-256 values match those copies.
# The records are unsigned and name version 0.0.0-dry-run: they stand in for a
# release only as far as the hash chain goes.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    printf 'usage: installed-layout.sh <runtime-binary> <new-folder>\n' >&2
    exit 2
fi
source_binary=$1
root=$2
lane=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
repository=$(cd -- "$lane/../.." && pwd -P)

case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) platform=aarch64-darwin ;;
    Darwin-x86_64) platform=x86_64-darwin ;;
    Linux-x86_64) platform=x86_64-linux ;;
    Linux-aarch64) platform=aarch64-linux ;;
    *) printf 'installed-layout.sh: no release platform for this machine\n' >&2; exit 1 ;;
esac
digest() {
    shasum -a 256 "$1" | cut -d ' ' -f 1
}

mkdir "$root"
mkdir "$root/bin" "$root/data" "$root/data/installation"
cp "$source_binary" "$root/bin/elastos"
chmod 755 "$root/bin/elastos"
cp "$repository/components.json" "$root/data/components.json"
commit=$(git -C "$repository" rev-parse --verify HEAD)
printf '{"payload":{"version":"0.0.0-dry-run","source":{"commit":"%s"},"platforms":{"%s":{"binary":{"sha256":"%s"},"components":{"sha256":"%s"}}}}}\n' \
    "$commit" "$platform" "$(digest "$root/bin/elastos")" "$(digest "$root/data/components.json")" \
    >"$root/data/installation/release.json"
printf '{"payload":{"version":"0.0.0-dry-run","release_sha256":"%s"}}\n' \
    "$(digest "$root/data/installation/release.json")" \
    >"$root/data/installation/release-head.json"
printf 'binary: %s\ndata: %s\n' "$root/bin/elastos" "$root/data"
