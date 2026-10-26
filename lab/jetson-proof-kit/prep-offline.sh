#!/bin/bash
# Prepare an offline C0 (and C9) bundle on a machine that has git and cargo.
# Copy dest/src onto the Jetson under ~/flint-elastos-test/src, then run:
#   JPK_OFFLINE=1 ./run-on-jetson.sh
# The board build then uses cargo --offline against the vendored crates.
# This script is the prep half. It is not the board runner.

set -eu

kit=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd -P)
JPK_KIT=$kit
# shellcheck source=lib.sh
. "$kit/lib.sh"

jpk_prep_stop() {
    local reason="$1"
    printf '%s\n' "$reason" >&2
    exit 2
}

jpk_prep_materialize() {
    local dest="$1"
    local ref="$2"
    local sha="$3"
    local remote head
    remote=$(jpk_git_remote)
    mkdir -p -- "$dest"
    if [ ! -d "$dest/.git" ]; then
        git init --quiet "$dest"
        git -C "$dest" remote add origin "$remote"
    fi
    if [ -n "$sha" ]; then
        git -C "$dest" fetch --quiet --depth 1 origin "$sha"
        git -C "$dest" checkout --quiet --detach "$sha"
    else
        git -C "$dest" fetch --quiet --depth 1 origin "$ref"
        git -C "$dest" checkout --quiet --detach FETCH_HEAD
    fi
    head=$(git -C "$dest" rev-parse HEAD)
    if [ -n "$sha" ] && [ "$head" != "$sha" ]; then
        jpk_prep_stop "REFUSED $ref HEAD is $head, pin is $sha"
    fi
    printf '%s\n' "$head" >"$dest/.jpk-pin"
    printf '%s\n' "$head"
}

jpk_prep_vendor_c0() {
    local crate="$1"
    mkdir -p -- "$crate/.cargo"
    if ! command -v cargo >/dev/null 2>&1; then
        jpk_prep_stop "REFUSED cargo is absent"
    fi
    (
        CDPATH= cd -- "$crate"
        cargo vendor --locked --versioned-dirs vendor
    )
    cat >"$crate/.cargo/config.toml" <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF
}

main() {
    local dest c0_dest c9_dest c0_head c9_head
    jpk_require_unprivileged || jpk_prep_stop "unprivileged guard refused the start"
    jpk_require_kit_omits_host_surfaces "$kit" || jpk_prep_stop "host surface guard refused the start"
    dest=${1:-$PWD/offline-bundle}
    mkdir -p -- "$dest/tmp" "$dest/src"
    export TMPDIR="$dest/tmp"
    if [ "${JPK_DRY_RUN:-0}" = 1 ]; then
        printf 'dry run: would vendor C0 at %s into %s and write cargo --offline config\n' \
            "$(jpk_c0_pin)" "$dest"
        exit 0
    fi
    if ! command -v git >/dev/null 2>&1; then
        jpk_prep_stop "REFUSED git is absent"
    fi
    c0_dest="$dest/src/fail-closed-linux"
    c9_dest="$dest/src/linux-confine"
    c0_head=$(jpk_prep_materialize "$c0_dest" "$(jpk_c0_ref)" "$(jpk_c0_pin)")
    c9_head=$(jpk_prep_materialize "$c9_dest" "$JPK_C9_BRANCH" "$JPK_C9_SHA")
    jpk_prep_vendor_c0 "$c0_dest/lab/fail-closed-linux"
    printf 'offline bundle at %s\n' "$dest"
    printf 'C0 %s\n' "$c0_head"
    printf 'C9 %s\n' "$c9_head"
    printf 'copy %s/src to ~/flint-elastos-test/src, then JPK_OFFLINE=1 ./run-on-jetson.sh\n' "$dest"
}

if [ "${JPK_SOURCE_ONLY:-0}" != 1 ]; then
    main "$@"
fi
