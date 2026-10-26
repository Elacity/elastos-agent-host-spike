#!/bin/bash
# One operator script for the Jetson Orin Nano. Run as an unprivileged user
# from ~/flint-elastos-test after this folder has been copied there.
# Refuses uid 0 and a SUDO_* environment. TMPDIR, CARGO_HOME, and every git
# checkout stay under that folder. Online mode fetches C0/C9; offline mode
# (JPK_OFFLINE=1 after prep-offline.sh) builds with cargo --offline.

set -eu

kit=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd -P)
JPK_KIT=$kit
# shellcheck source=lib.sh
. "$kit/lib.sh"

root=$(jpk_allowed_root)
evidence="${JPK_EVIDENCE:-$root/evidence.txt}"
work="$root/work"
src=$(jpk_src_root)

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
    jpk_require_unprivileged || jpk_stop "unprivileged guard refused the start"
    jpk_require_kit_omits_host_surfaces "$kit" || jpk_stop "host surface guard refused the start"
    jpk_require_path "$kit" || jpk_stop "kit folder is outside $(jpk_allowed_root)"
    jpk_require_path "$PWD" || jpk_stop "current directory is outside $(jpk_allowed_root)"
    jpk_require_memory || jpk_stop "memory guard refused the start"
    mkdir -p -- "$root" "$work" "$src"
    jpk_require_path "$work"
    jpk_require_path "$src"
    jpk_apply_contained_env || jpk_stop "contained env refused the start"
    jpk_require_path "$TMPDIR"
    jpk_require_path "$CARGO_HOME"
    jpk_require_path "$evidence"
    jpk_seed_evidence
    if [ "${JPK_DRY_RUN:-0}" = 1 ]; then
        printf 'dry run: guards accepted TMPDIR=%s CARGO_HOME=%s\n' "$TMPDIR" "$CARGO_HOME"
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

    jpk_record_availability host.right.truncate "$(jpk_fact right.truncate "$facts")"
    jpk_record_availability host.right.ioctl_dev "$(jpk_fact right.ioctl_dev "$facts")"
    jpk_record_availability host.right.net_bind_tcp "$(jpk_fact right.net_bind_tcp "$facts")"
    jpk_record_availability host.right.net_connect_tcp "$(jpk_fact right.net_connect_tcp "$facts")"
    jpk_record_availability host.right.scope_signal "$(jpk_fact right.scope_signal "$facts")"
    jpk_record_availability host.right.scope_abstract_unix "$(jpk_fact right.scope_abstract_unix "$facts")"
    jpk_record_availability host.seccomp "$(jpk_fact seccomp "$facts")"
    jpk_set_row "$evidence" host.seccomp_arch PASS "$(jpk_fact seccomp_arch "$facts") $(jpk_fact seccomp_arch_id "$facts")"
    jpk_record_availability host.userns "$(jpk_fact userns "$facts")"
    jpk_record_availability host.pidns "$(jpk_fact pidns "$facts")"
    jpk_record_availability host.mntns "$(jpk_fact mntns "$facts")"
    jpk_set_row "$evidence" host.sysctl.max_user_namespaces PASS "$(jpk_fact sysctl.user.max_user_namespaces "$facts")"
    jpk_set_row "$evidence" host.sysctl.max_pid_namespaces PASS "$(jpk_fact sysctl.user.max_pid_namespaces "$facts")"
    jpk_set_row "$evidence" host.sysctl.max_mnt_namespaces PASS "$(jpk_fact sysctl.user.max_mnt_namespaces "$facts")"
    jpk_set_row "$evidence" host.sysctl.unprivileged_userns_clone PASS "$(jpk_fact sysctl.kernel.unprivileged_userns_clone "$facts")"
    jpk_set_row "$evidence" host.cap_bnd PASS "$(jpk_fact cap_bnd "$facts")"

    printf 'oracle (copies fail_closed_linux at %s; not fcl-launch)\n' "$JPK_C0_PER_RIGHT_SHA"
    printf 'provider\tfloor\tdecision\treason\n'
    jpk_record_decisions "$facts"
}

jpk_record_availability() {
    local id="$1"
    local value="$2"
    jpk_set_row "$evidence" "$id" "$(jpk_availability_status "$value")" "$value"
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
$(printf '%s\n' "$facts" | python3 -I "$kit/decide.py" --pin "$(jpk_c0_pin)")
EOF
}

jpk_run_c0() {
    local dest="$src/fail-closed-linux"
    local crate="$dest/lab/fail-closed-linux"
    local ref pin head bin standin out rc
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
    if ! jpk_with_memory_guard cargo build --locked $(jpk_cargo_offline_args) --manifest-path "$crate/Cargo.toml" --bin fcl-launch -j "$JPK_BUILD_JOBS"; then
        jpk_set_row "$evidence" C0.build REFUSED "cargo build -j $JPK_BUILD_JOBS failed"
        jpk_set_row "$evidence" C0.guard NOT RUN "C0.build was refused"
        return 0
    fi
    jpk_set_row "$evidence" C0.build PASS "fcl-launch at $head"
    bin="$CARGO_TARGET_DIR/debug/fcl-launch"
    if ! standin=$(jpk_c0_standin "$CARGO_TARGET_DIR"); then
        jpk_set_row "$evidence" C0.guard NOT RUN "no static stand-in"
        jpk_set_row "$evidence" C0.guard.did NOT RUN "no static stand-in"
        jpk_set_row "$evidence" C0.guard.wallet NOT RUN "no static stand-in"
        jpk_set_row "$evidence" C0.guard.model NOT RUN "no static stand-in"
        return 0
    fi
    printf 'fcl-launch (real guard at %s)\n' "$head"
    printf 'provider\tfloor\tdecision\treason\n'
    jpk_run_c0_provider "$bin" "$standin" did
    jpk_run_c0_provider "$bin" "$standin" wallet
    jpk_run_c0_provider "$bin" "$standin" model
    jpk_summarize_c0_guard
}

jpk_c0_standin() {
    local target_dir="$1"
    local found dest
    found=$(find "$target_dir" -name fcl-probe -type f -perm -111 2>/dev/null | head -n 1)
    if [ -n "$found" ]; then
        printf '%s\n' "$found"
        return 0
    fi
    dest="$work/c0-standin"
    jpk_require_path "$dest" || return 2
    if command -v rustc >/dev/null 2>&1; then
        if jpk_with_memory_guard rustc --edition 2021 -C opt-level=1 -C panic=abort \
            -C target-feature=+crt-static -o "$dest" "$kit/standin.rs"; then
            printf '%s\n' "$dest"
            return 0
        fi
    fi
    return 1
}

jpk_run_c0_provider() {
    local bin="$1"
    local standin="$2"
    local name="$3"
    local storage outside out rc status
    storage="$work/c0-storage-$name"
    outside="$work/c0-outside-$name"
    mkdir -p -- "$storage" "$outside"
    : >"$outside/file"
    jpk_require_path "$storage"
    jpk_require_path "$standin"
    set +e
    out=$("$bin" --provider "${name}-provider" --storage-root "$storage" -- \
        "$standin" "${name}-provider" "$storage" "$outside/file" "$outside" </dev/null 2>&1)
    rc=$?
    set -e
    status=$(jpk_classify_c0_launch "$rc" "$out")
    jpk_set_row "$evidence" "C0.guard.$name" "$status" "$out"
    if [ "$status" = PASS ]; then
        printf '%s\t%s\t%s\t%s\n' "$name" "fcl-launch" LAUNCH "$out"
    elif [ "$status" = REFUSED ]; then
        printf '%s\t%s\t%s\t%s\n' "$name" "fcl-launch" REFUSE "$out"
    else
        printf '%s\t%s\t%s\t%s\n' "$name" "fcl-launch" "$status" "$out"
    fi
}

jpk_summarize_c0_guard() {
    local did wallet model
    did=$(awk -F '\t' '$1 == "C0.guard.did" { print $2; exit }' "$evidence")
    wallet=$(awk -F '\t' '$1 == "C0.guard.wallet" { print $2; exit }' "$evidence")
    model=$(awk -F '\t' '$1 == "C0.guard.model" { print $2; exit }' "$evidence")
    case "$did $wallet $model" in
        "PASS PASS PASS")
            jpk_set_row "$evidence" C0.guard PASS "did wallet model launched"
            ;;
        *"REFUSED"*)
            jpk_set_row "$evidence" C0.guard REFUSED "did=$did wallet=$wallet model=$model"
            ;;
        *)
            jpk_set_row "$evidence" C0.guard NOT RUN "did=$did wallet=$wallet model=$model"
            ;;
    esac
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
