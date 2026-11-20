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

# Where a folder that may not exist yet will really be: the nearest folder that
# does exist, with its links resolved, then the part still to be made. Fails
# when that cannot be told: a file or a dangling link in the way, or a `..` in
# the part still to be made.
resolved() {
    local path=$1 rest=""
    case "$path" in
        /*) ;;
        *) path="$PWD/$path" ;;
    esac
    while [ ! -d "$path" ]; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            return 1
        fi
        rest="/$(basename -- "$path")$rest"
        path=$(dirname -- "$path")
    done
    case "$rest/" in
        */../* | */./*) return 1 ;;
    esac
    printf '%s%s\n' "$(cd -- "$path" && pwd -P)" "$rest"
}

# This command writes in two places: the receipts folder and a temporary
# folder. Neither may be inside the installed Runtime. Prints where the folder
# will really be, or says why it is refused.
binary_folder=$(dirname -- "$binary")
outside_install() {
    local label=$1 real inside
    if ! real=$(resolved "$2"); then
        printf 'refused: cannot tell where the %s would be: %s\n' "$label" "$2" >&2
        return 1
    fi
    case "$real/" in
        "$data"/*) inside="the installed data folder" ;;
        "$binary_folder"/*) inside="the folder holding the installed binary" ;;
        *)
            printf '%s\n' "$real"
            return 0
            ;;
    esac
    printf 'refused: the %s is inside %s: %s\n' "$label" "$inside" "$real" >&2
    printf 'this command writes nothing under the install paths; set ELASTOS_DEMO_RECEIPTS (or TMPDIR) to a folder outside them.\n' >&2
    return 1
}
# Both are settled here, before anything runs.
receipts=$(outside_install "receipts folder" "$receipts")
temporary=$(outside_install "temporary folder" "${TMPDIR:-/tmp}")

dirty=$(git -C "$repository" status --porcelain=v1 --untracked-files=all)
if [ -n "$dirty" ]; then
    printf 'refused: the tree is not clean, so the reviews cannot bind to it:\n%s\n' "$dirty" >&2
    printf 'keep the reviews file outside the repository.\n' >&2
    exit 1
fi

work=$(mktemp -d "$temporary/elastos-demo.XXXXXX")
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

# The rows are the ones run.sh printed with the reporter copy it verified and
# keeps outside every path the suite was given. This command runs no reporter
# of its own: the build path it could reach is one the suite can write.
rows=$(sed -n 's/^A14 rows result: //p' "$output" | tail -n 1)
if [ -z "$rows" ]; then
    printf 'demo: FAIL; run.sh printed no A14 rows (exit %s); its output: %s\n' "$suite" "$output" >&2
    exit 1
fi

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
if [ "$rows" != PASS ]; then
    printf 'demo: FAIL; not every A14 row passes\n' >&2
    exit 1
fi
printf 'demo: PASS; every A14 row passes\n'
