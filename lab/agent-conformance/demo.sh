#!/bin/bash
# The owner's one command for A14: run the suite on the installed Runtime and
# keep a receipt that binds the run, the reviews, the staged bundles and the
# installed Runtime. Nothing under the install paths is written: the installed
# binary is launched where it is, in throwaway Homes that run.sh creates.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    printf 'usage: demo.sh <reviews.json>\n' >&2
    exit 2
fi
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
repository=$(cd -- "$lane/../.." && pwd -P)

case "$(uname -s)" in
    Darwin) default_data="$HOME/Library/Application Support/elastos" ;;
    *) default_data="${XDG_DATA_HOME:-$HOME/.local/share}/elastos" ;;
esac
binary=${AGENT_CONFORMANCE_INSTALLED_BINARY:-$HOME/.local/bin/elastos}
data=${AGENT_CONFORMANCE_INSTALLED_DATA:-$default_data}
reviews=$1
receipts=${ELASTOS_DEMO_RECEIPTS:-$HOME/elastos-demo-receipts}

missing=0
if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
    printf 'missing: the installed Runtime binary: %s\n' "$binary" >&2
    missing=1
fi
if [ ! -d "$data" ]; then
    printf 'missing: the installed Runtime data folder: %s\n' "$data" >&2
    missing=1
fi
if [ ! -f "$reviews" ]; then
    printf 'missing: the reviews file: %s\n' "$reviews" >&2
    missing=1
fi
if [ "$missing" -ne 0 ]; then
    exit 1
fi

# The suite and the report need absolute paths; run.sh changes directory.
absolute() {
    printf '%s/%s\n' "$(cd -- "$(dirname -- "$1")" && pwd -P)" "$(basename -- "$1")"
}
binary=$(absolute "$binary")
reviews=$(absolute "$reviews")
data=$(cd -- "$data" && pwd -P)

dirty=$(git -C "$repository" status --porcelain=v1 --untracked-files=all)
if [ -n "$dirty" ]; then
    printf 'refused: the tree is not clean, so the reviews cannot bind to it:\n%s\n' "$dirty" >&2
    printf 'keep the reviews file outside the repository.\n' >&2
    exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/elastos-demo.XXXXXX")
output="$work/demo-output.log"
suite=0
AGENT_CONFORMANCE_REVIEWS="$reviews" \
AGENT_CONFORMANCE_INSTALLED_BINARY="$binary" \
AGENT_CONFORMANCE_INSTALLED_DATA="$data" \
AGENT_CONFORMANCE_RUNTIME_BINARY="$binary" \
    "$lane/run.sh" 2>&1 | tee "$output" || suite=$?

receipt=$(sed -n 's/^versions receipt: //p' "$output" | tail -n 1)
if [ -z "$receipt" ]; then
    printf 'demo: FAIL; run.sh wrote no receipt (exit %s); its output: %s\n' "$suite" "$output" >&2
    exit 1
fi
case "$receipt" in
    /*) ;;
    *) receipt="$lane/$receipt" ;;
esac

printf '\nA14 rows of %s:\n' "$receipt"
rows=0
"$lane/target/host/debug/report" --a14 "$receipt" || rows=$?

mkdir -p "$receipts"
kept="$receipts/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$kept"
cp -R "$(dirname -- "$receipt")/." "$kept/"
cp "$output" "$kept/demo-output.log"
printf 'receipt folder: %s\n' "$kept"

if [ "$suite" -ne 0 ]; then
    printf 'demo: FAIL; the suite did not pass (run.sh exit %s)\n' "$suite" >&2
    exit 1
fi
if [ "$rows" -ne 0 ]; then
    printf 'demo: FAIL; not every A14 row passes\n' >&2
    exit 1
fi
printf 'demo: PASS; every A14 row passes\n'
