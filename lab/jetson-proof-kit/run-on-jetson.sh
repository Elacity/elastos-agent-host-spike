#!/bin/bash
# One operator script for the Jetson Orin Nano. Run as an unprivileged user
# from ~/flint-elastos-test after this folder has been copied there.
# Records kernel, Landlock ABI and rights, seccomp, namespaces, and CapBnd,
# then prints a launch/refuse table for did, wallet, and model under both
# floor options. Fetches the C0 guard (PR ref selectable) and the C9
# launcher, builds with four jobs, and writes evidence.txt.

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

jpk_fact() {
    local key="$1"
    local facts="$2"
    printf '%s\n' "$facts" | awk -v key="$key" '
        $1 == key {
            $1 = ""
            sub(/^ /, "")
            print
            exit
        }
    '
}

jpk_record_host() {
    local facts abi
    jpk_require_memory || jpk_stop "memory guard refused the host probe"
    facts=$(python3 -I "$kit/probe_host.py")
    printf '%s\n' "$facts"

    jpk_set_row "$evidence" host.uname_r PASS "$(jpk_fact uname_r "$facts")"
    jpk_set_row "$evidence" host.uname_m PASS "$(jpk_fact uname_m "$facts")"

    abi=$(jpk_fact landlock_abi "$facts")
    if [ -z "$abi" ]; then
        jpk_set_row "$evidence" host.landlock_abi REFUSED "probe printed no landlock_abi line"
    else
        case "$abi" in
            absent | disabled | error)
                jpk_set_row "$evidence" host.landlock_abi REFUSED "landlock_abi $abi"
                ;;
            *)
                jpk_set_row "$evidence" host.landlock_abi PASS "$abi"
                ;;
        esac
    fi

    jpk_set_row "$evidence" host.right.truncate PASS "$(jpk_fact right.truncate "$facts")"
    jpk_set_row "$evidence" host.right.ioctl_dev PASS "$(jpk_fact right.ioctl_dev "$facts")"
    jpk_set_row "$evidence" host.right.net_bind_tcp PASS "$(jpk_fact right.net_bind_tcp "$facts")"
    jpk_set_row "$evidence" host.right.net_connect_tcp PASS "$(jpk_fact right.net_connect_tcp "$facts")"
    jpk_set_row "$evidence" host.right.scope_signal PASS "$(jpk_fact right.scope_signal "$facts")"
    jpk_set_row "$evidence" host.right.scope_abstract_unix PASS "$(jpk_fact right.scope_abstract_unix "$facts")"
    jpk_set_row "$evidence" host.seccomp PASS "$(jpk_fact seccomp "$facts")"
    jpk_set_row "$evidence" host.seccomp_arch PASS "$(jpk_fact seccomp_arch "$facts") $(jpk_fact seccomp_arch_id "$facts")"
    jpk_set_row "$evidence" host.userns PASS "$(jpk_fact userns "$facts")"
    jpk_set_row "$evidence" host.pidns PASS "$(jpk_fact pidns "$facts")"
    jpk_set_row "$evidence" host.mntns PASS "$(jpk_fact mntns "$facts")"
    jpk_set_row "$evidence" host.sysctl.max_user_namespaces PASS "$(jpk_fact sysctl.user.max_user_namespaces "$facts")"
    jpk_set_row "$evidence" host.sysctl.max_pid_namespaces PASS "$(jpk_fact sysctl.user.max_pid_namespaces "$facts")"
    jpk_set_row "$evidence" host.sysctl.max_mnt_namespaces PASS "$(jpk_fact sysctl.user.max_mnt_namespaces "$facts")"
    jpk_set_row "$evidence" host.sysctl.unprivileged_userns_clone PASS "$(jpk_fact sysctl.kernel.unprivileged_userns_clone "$facts")"
    jpk_set_row "$evidence" host.cap_bnd PASS "$(jpk_fact cap_bnd "$facts")"

    printf 'provider\tfloor\tdecision\treason\n'
    jpk_record_decisions "$facts"
}

jpk_record_decisions() {
    local facts="$1"
    local provider floor decision reason status
    while IFS="$(printf '\t')" read -r provider floor decision reason; do
        [ -n "$provider" ] || continue
        if [ "$decision" = LAUNCH ]; then
            status=PASS
        else
            status=REFUSED
        fi
        jpk_set_row "$evidence" "decision.${provider}.${floor}" "$status" "$reason"
        printf '%s\t%s\t%s\t%s\n' "$provider" "$floor" "$decision" "$reason"
    done <<EOF
$(printf '%s\n' "$facts" | python3 -I "$kit/decide.py")
EOF
}

jpk_run_c0() {
    local dest="$src/fail-closed-linux"
    local crate="$dest/lab/fail-closed-linux"
    local ref pin head bin storage exe out rc
    ref=$(jpk_c0_ref)
    pin=$(jpk_c0_pin)
    if ! head=$(jpk_fetch "$dest" "$ref" "$pin"); then
        jpk_set_row "$evidence" C0.source REFUSED "fetch of $ref failed"
        jpk_set_row "$evidence" C0.build REFUSED "fetch of $ref failed"
        jpk_set_row "$evidence" C0.guard NOT RUN "C0.build was refused"
        return 0
    fi
    jpk_set_row "$evidence" C0.source PASS "$ref at $head"
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
    jpk_set_row "$evidence" C0.build PASS "fcl-launch at $head"
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
    local head out rc
    if ! head=$(jpk_fetch "$dest" "$JPK_C9_BRANCH" "$JPK_C9_SHA"); then
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
    jpk_set_row "$evidence" C9.build PASS "lc-setup at $head"
    # Production launcher. The fetched guard applies its own floor.
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
    jpk_record_host
    jpk_run_c0
    jpk_run_c9
    printf 'wrote %s\n' "$evidence"
}

if [ "${JPK_SOURCE_ONLY:-0}" != 1 ]; then
    main "$@"
fi
