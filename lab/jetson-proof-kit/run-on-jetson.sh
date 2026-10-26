#!/bin/bash
# One operator script for the Jetson Orin Nano. Run as an unprivileged user
# from ~/flint-elastos-test after this folder has been copied there.
# Fetches draft PRs #307 and #296 into this folder, builds with four jobs,
# and writes evidence.txt. A Landlock ABI below 5 is a guard refusal.

set -eu

kit=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=lib.sh
. "$kit/lib.sh"

root=$(jpk_allowed_root)
evidence="${JPK_EVIDENCE:-$root/evidence.txt}"
work="$root/work"
src="$root/src"

jpk_seed_evidence() {
    if [ ! -f "$evidence" ]; then
        cp -- "$kit/evidence.txt" "$evidence"
    fi
}

jpk_stop() {
    local reason="$1"
    printf '%s\n' "$reason" >&2
    exit 2
}

jpk_prepare() {
    jpk_require_path "$kit" || jpk_stop "kit folder is outside $(jpk_allowed_root)"
    jpk_require_path "$PWD" || jpk_stop "current directory is outside $(jpk_allowed_root)"
    jpk_require_memory || jpk_stop "memory guard refused the start"
    mkdir -p -- "$root" "$work" "$src"
    jpk_require_path "$work"
    jpk_require_path "$src"
    jpk_require_path "$evidence"
    jpk_seed_evidence
    if [ "${JPK_DRY_RUN:-0}" = 1 ]; then
        printf 'dry run: guards accepted\n'
        exit 0
    fi
}

jpk_record_host() {
    local probe_out abi
    jpk_require_memory || jpk_stop "memory guard refused the host probe"
    jpk_set_row "$evidence" host.uname_r PASS "$(uname -r)"
    jpk_set_row "$evidence" host.uname_m PASS "$(uname -m)"
    probe_out=$(python3 -I "$kit/probe_landlock.py")
    printf '%s\n' "$probe_out"
    abi=$(printf '%s\n' "$probe_out" | awk '/^landlock_abi / { print $2; exit }')
    if [ -z "$abi" ]; then
        jpk_set_row "$evidence" host.landlock_abi REFUSED "probe printed no landlock_abi line"
        return 2
    fi
    case "$abi" in
        absent | disabled | error)
            jpk_set_row "$evidence" host.landlock_abi REFUSED "landlock_abi $abi"
            ;;
        *)
            jpk_set_row "$evidence" host.landlock_abi PASS "$abi"
            ;;
    esac
    printf '%s\n' "$abi"
}

jpk_fetch() {
    local dest="$1"
    local branch="$2"
    local sha="$3"
    local remote head
    jpk_require_path "$dest" || return 2
    jpk_require_memory || return 2
    remote=$(jpk_git_remote)
    if [ -d "$dest/.git" ]; then
        git -C "$dest" fetch --depth 1 origin "$branch"
        git -C "$dest" checkout --detach "$sha"
    else
        jpk_with_memory_guard git clone --depth 1 --branch "$branch" "$remote" "$dest"
    fi
    head=$(git -C "$dest" rev-parse HEAD)
    if [ "$head" != "$sha" ]; then
        printf 'REFUSED %s HEAD is %s, pin is %s\n' "$branch" "$head" "$sha" >&2
        return 2
    fi
}

jpk_run_c0() {
    local dest="$src/fail-closed-linux"
    local crate="$dest/lab/fail-closed-linux"
    local bin storage exe out rc
    if ! jpk_fetch "$dest" "$JPK_C0_BRANCH" "$JPK_C0_SHA"; then
        jpk_set_row "$evidence" C0.build REFUSED "fetch of $JPK_C0_BRANCH failed"
        jpk_set_row "$evidence" C0.guard NOT RUN "C0.build was refused"
        return 0
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        jpk_set_row "$evidence" C0.build REFUSED "cargo is absent"
        jpk_set_row "$evidence" C0.guard NOT RUN "C0.build was refused"
        return 0
    fi
    export CARGO_HOME="$root/cargo-home"
    export CARGO_TARGET_DIR="$root/target/c0"
    export CARGO_BUILD_BUILD_DIR="$root/target/c0-build"
    export CARGO_BUILD_JOBS="$JPK_BUILD_JOBS"
    export CARGO_INCREMENTAL=0
    mkdir -p -- "$CARGO_HOME" "$CARGO_TARGET_DIR" "$CARGO_BUILD_BUILD_DIR"
    jpk_require_path "$CARGO_HOME"
    jpk_require_path "$CARGO_TARGET_DIR"
    if ! jpk_with_memory_guard cargo build --locked --manifest-path "$crate/Cargo.toml" --bin fcl-launch -j "$JPK_BUILD_JOBS"; then
        jpk_set_row "$evidence" C0.build REFUSED "cargo build -j $JPK_BUILD_JOBS failed"
        jpk_set_row "$evidence" C0.guard NOT RUN "C0.build was refused"
        return 0
    fi
    jpk_set_row "$evidence" C0.build PASS "fcl-launch at $JPK_C0_SHA"
    bin="$CARGO_TARGET_DIR/debug/fcl-launch"
    storage="$work/c0-storage"
    exe="$work/c0-provider"
    mkdir -p -- "$storage"
    : >"$exe"
    chmod +x "$exe"
    set +e
    out=$("$bin" --provider did-provider --storage-root "$storage" -- "$exe" 2>&1)
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        jpk_set_row "$evidence" C0.guard PASS "$out"
    else
        jpk_set_row "$evidence" C0.guard REFUSED "$out"
    fi
}

jpk_run_c9() {
    local dest="$src/linux-confine"
    local helper="$dest/lab/linux-confine/helper"
    local setup="$work/lc-setup"
    local probe="$work/lc-probe"
    local out rc
    if ! jpk_fetch "$dest" "$JPK_C9_BRANCH" "$JPK_C9_SHA"; then
        jpk_set_row "$evidence" C9.build REFUSED "fetch of $JPK_C9_BRANCH failed"
        jpk_set_row "$evidence" C9.launcher NOT RUN "C9.build was refused"
        return 0
    fi
    if ! command -v gcc >/dev/null 2>&1; then
        jpk_set_row "$evidence" C9.build REFUSED "gcc is absent"
        jpk_set_row "$evidence" C9.launcher NOT RUN "C9.build was refused"
        return 0
    fi
    if ! jpk_with_memory_guard gcc -O2 -Wall -Wextra -Werror -o "$setup" "$helper/setup.c"; then
        jpk_set_row "$evidence" C9.build REFUSED "gcc -j $JPK_BUILD_JOBS failed for lc-setup"
        jpk_set_row "$evidence" C9.launcher NOT RUN "C9.build was refused"
        return 0
    fi
    if ! jpk_with_memory_guard gcc -static -nostdlib -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -O2 -Wall -Wextra -Werror -o "$probe" "$helper/probe.c"; then
        jpk_set_row "$evidence" C9.build REFUSED "gcc failed for lc-probe"
        jpk_set_row "$evidence" C9.launcher NOT RUN "C9.build was refused"
        return 0
    fi
    jpk_set_row "$evidence" C9.build PASS "lc-setup at $JPK_C9_SHA"
    # Production launcher. ABI below 5 refuses before a policy is read.
    set +e
    out=$("$setup" 2>&1)
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        jpk_set_row "$evidence" C9.launcher PASS "$out"
    else
        jpk_set_row "$evidence" C9.launcher REFUSED "$out"
    fi
}

main() {
    jpk_prepare
    jpk_record_host >/dev/null
    jpk_run_c0
    jpk_run_c9
    printf 'wrote %s\n' "$evidence"
}

if [ "${JPK_SOURCE_ONLY:-0}" != 1 ]; then
    main "$@"
fi
