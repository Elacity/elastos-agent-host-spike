#!/bin/bash
# Tests for the path guard and the memory guard. Jetson rows stay NOT RUN.
set -eu

kit=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=../lib.sh
. "$kit/lib.sh"

pass=0
fail=0

assert_eq() {
    local name="$1"
    local got="$2"
    local want="$3"
    if [ "$got" = "$want" ]; then
        printf 'PASS %s\n' "$name"
        pass=$((pass + 1))
    else
        printf 'FAIL %s: got %s want %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

assert_status() {
    local name="$1"
    local got="$2"
    local want="$3"
    if [ "$got" -eq "$want" ]; then
        printf 'PASS %s\n' "$name"
        pass=$((pass + 1))
    else
        printf 'FAIL %s: status %s want %s\n' "$name" "$got" "$want"
        fail=$((fail + 1))
    fi
}

assert_contains() {
    local name="$1"
    local haystack="$2"
    local needle="$3"
    case "$haystack" in
        *"$needle"*)
            printf 'PASS %s\n' "$name"
            pass=$((pass + 1))
            ;;
        *)
            printf 'FAIL %s: missing %s in %s\n' "$name" "$needle" "$haystack"
            fail=$((fail + 1))
            ;;
    esac
}

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
export HOME="$scratch/home"
mkdir -p -- "$HOME/$JPK_ROOT_NAME/inside" "$scratch/outside"

root=$(jpk_allowed_root)
assert_eq allowed_root "$root" "$HOME/$JPK_ROOT_NAME"

assert_eq default_c0_ref "$(jpk_c0_ref)" "$JPK_C0_DEFAULT_BRANCH"
assert_eq default_c0_pin "$(jpk_c0_pin)" "$JPK_C0_DEFAULT_SHA"
JPK_C0_PR=307
assert_eq pr_c0_ref "$(jpk_c0_ref)" "pull/307/head"
assert_eq pr_c0_pin_empty "$(jpk_c0_pin)" ""
JPK_C0_SHA=abc
assert_eq pr_c0_pin_explicit "$(jpk_c0_pin)" "abc"
unset JPK_C0_PR JPK_C0_SHA
JPK_C0_REF=cursor/updated-guard
assert_eq ref_c0_ref "$(jpk_c0_ref)" "cursor/updated-guard"
assert_eq ref_c0_pin_empty "$(jpk_c0_pin)" ""
unset JPK_C0_REF

if jpk_path_inside "$root" "$root/inside"; then
    inside_rc=0
else
    inside_rc=$?
fi
assert_status path_inside_folder "$inside_rc" 0

if jpk_path_inside "$root" "$scratch/outside"; then
    outside_rc=0
else
    outside_rc=$?
fi
assert_status planted_path_outside_folder "$outside_rc" 1

# Prefix twin: flint-elastos-test-evil is not the folder.
mkdir -p -- "$HOME/${JPK_ROOT_NAME}-evil"
if jpk_path_inside "$root" "$HOME/${JPK_ROOT_NAME}-evil"; then
    twin_rc=0
else
    twin_rc=$?
fi
assert_status prefix_twin_is_outside "$twin_rc" 1

set +e
outside_msg=$(jpk_require_path "$scratch/outside" 2>&1)
outside_req=$?
set -e
assert_status require_outside_path "$outside_req" 2
assert_contains require_outside_reason "$outside_msg" "REFUSED path is outside"

low="$scratch/meminfo-low"
high="$scratch/meminfo-high"
printf 'MemTotal:        7773952 kB\nMemAvailable:     500000 kB\n' >"$low"
printf 'MemTotal:        7773952 kB\nMemAvailable:    2000000 kB\n' >"$high"

JPK_MEMINFO="$high"
high_kb=$(jpk_mem_available_kb)
assert_eq mem_available_high "$high_kb" 2000000
set +e
jpk_require_memory >/dev/null
high_rc=$?
set -e
assert_status memory_above_floor "$high_rc" 0

JPK_MEMINFO="$low"
low_kb=$(jpk_mem_available_kb)
assert_eq mem_available_low "$low_kb" 500000
set +e
low_msg=$(jpk_require_memory 2>&1)
low_rc=$?
set -e
assert_status memory_below_floor_is_refused "$low_rc" 2
assert_contains memory_below_floor_reason "$low_msg" "REFUSED available memory below 1 GiB"

missing="$scratch/meminfo-missing"
printf 'MemTotal:        7773952 kB\n' >"$missing"
JPK_MEMINFO="$missing"
set +e
miss_msg=$(jpk_require_memory 2>&1)
miss_rc=$?
set -e
assert_status memory_line_missing_is_refused "$miss_rc" 2
assert_contains memory_line_missing_reason "$miss_msg" "REFUSED MemAvailable is missing"

# Full script: planted path outside the folder.
script_out="$scratch/script-outside.txt"
set +e
(CDPATH= cd -- "$scratch/outside" && JPK_DRY_RUN=1 JPK_EVIDENCE="$scratch/outside/evidence.txt" "$kit/run-on-jetson.sh") \
    >"$script_out" 2>&1
script_rc=$?
set -e
assert_status script_refuses_outside_cwd "$script_rc" 2
assert_contains script_outside_reason "$(cat "$script_out")" "REFUSED path is outside"

# Full script: missing memory check surface (low MemAvailable after a valid path).
mkdir -p -- "$root"
cp -- "$kit/lib.sh" "$kit/probe_landlock.py" "$kit/probe_host.py" "$kit/decide.py" "$kit/evidence.txt" "$root/"
cp -- "$kit/run-on-jetson.sh" "$root/run-on-jetson.sh"
chmod +x "$root/run-on-jetson.sh"
set +e
(CDPATH= cd -- "$root" && JPK_DRY_RUN=1 JPK_MEMINFO="$low" JPK_EVIDENCE="$root/evidence.txt" "$root/run-on-jetson.sh") \
    >"$scratch/script-low-mem.txt" 2>&1
low_script_rc=$?
set -e
assert_status script_refuses_low_memory "$low_script_rc" 2
assert_contains script_low_memory_reason "$(cat "$scratch/script-low-mem.txt")" "REFUSED available memory below 1 GiB"

# Committed Jetson rows stay NOT RUN.
while IFS= read -r line; do
    case "$line" in
        '' | \#*) continue ;;
    esac
    id=$(printf '%s\n' "$line" | awk -F '\t' '{ print $1 }')
    status=$(printf '%s\n' "$line" | awk -F '\t' '{ print $2 }')
    assert_eq "committed_$id" "$status" "NOT RUN"
done <"$kit/evidence.txt"

# The operator script never names the host surfaces it must leave alone.
if grep -E '(^|[[:space:]])(sudo|apt|pm2|PM2)([[:space:]]|$)' "$kit/run-on-jetson.sh" "$kit/lib.sh" "$kit/probe_host.py" "$kit/decide.py"; then
    printf 'FAIL scripts_name_host_surfaces\n'
    fail=$((fail + 1))
else
    printf 'PASS scripts_leave_host_surfaces_unnamed\n'
    pass=$((pass + 1))
fi
if grep -E '4200' "$kit/run-on-jetson.sh" "$kit/lib.sh" "$kit/probe_host.py" "$kit/decide.py"; then
    printf 'FAIL scripts_name_port_4200\n'
    fail=$((fail + 1))
else
    printf 'PASS scripts_leave_port_unnamed\n'
    pass=$((pass + 1))
fi

printf 'summary %s passed %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
