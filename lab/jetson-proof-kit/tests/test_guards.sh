#!/bin/bash
# Tests for the path guard and the memory guard. Jetson rows stay NOT RUN.
set -eu

kit=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
JPK_KIT=$kit
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
assert_eq default_c0_pin_is_per_right "$JPK_C0_DEFAULT_SHA" "2c70a0d845f9acc15144a2afec889370612cca66"
assert_eq default_c0_pin_not_old_floor "$JPK_C0_DEFAULT_SHA" "$JPK_C0_PER_RIGHT_SHA"
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

assert_eq availability_available "$(jpk_availability_status "available")" PASS
assert_eq availability_absent "$(jpk_availability_status "absent EINVAL")" ABSENT
assert_eq availability_unavailable "$(jpk_availability_status "unavailable ENOSPC")" REFUSED
assert_eq availability_empty "$(jpk_availability_status "")" REFUSED

assert_eq classify_started "$(jpk_classify_c0_launch 0 "started did-provider pid=9")" PASS
assert_eq classify_refusal "$(jpk_classify_c0_launch 71 "fail-closed-linux refused to start did-provider: layer landlock, step abi_floor: this kernel's Landlock ABI 1 cannot deny truncate (needs ABI 3); ioctl_dev (needs ABI 5); the provider was not started")" REFUSED
assert_eq classify_enoexec "$(jpk_classify_c0_launch 71 "step execve: Exec format error (os error 8)")" "NOT RUN"
assert_eq classify_os_error_8 "$(jpk_classify_c0_launch 71 "fail-closed-linux refused to start did-provider: layer exec, step execve: Exec format error (os error 8); the provider was not started")" "NOT RUN"

# The operator script launches a real stand-in for each provider.
if grep -F ': >"$exe"' "$kit/run-on-jetson.sh"; then
    printf 'FAIL script_uses_empty_provider\n'
    fail=$((fail + 1))
else
    printf 'PASS script_has_no_empty_provider\n'
    pass=$((pass + 1))
fi
script=$(cat "$kit/run-on-jetson.sh")
assert_contains script_launches_did "$script" 'jpk_run_c0_provider "$bin" "$standin" did'
assert_contains script_launches_wallet "$script" 'jpk_run_c0_provider "$bin" "$standin" wallet'
assert_contains script_launches_model "$script" 'jpk_run_c0_provider "$bin" "$standin" model'
assert_contains script_provider_name_suffix "$script" '"${name}-provider"'

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
if grep -E '(^|[[:space:]])(sudo|apt|pm2|PM2)([[:space:]]|$)' "$kit/run-on-jetson.sh" "$kit/lib.sh" "$kit/prep-offline.sh" "$kit/probe_host.py" "$kit/decide.py" "$kit/standin.rs"; then
    printf 'FAIL scripts_name_host_surfaces\n'
    fail=$((fail + 1))
else
    printf 'PASS scripts_leave_host_surfaces_unnamed\n'
    pass=$((pass + 1))
fi
if grep -E '4200' "$kit/run-on-jetson.sh" "$kit/lib.sh" "$kit/prep-offline.sh" "$kit/probe_host.py" "$kit/decide.py" "$kit/standin.rs"; then
    printf 'FAIL scripts_name_port_4200\n'
    fail=$((fail + 1))
else
    printf 'PASS scripts_leave_port_unnamed\n'
    pass=$((pass + 1))
fi
if grep -F 'pc2.net' "$kit/run-on-jetson.sh" "$kit/lib.sh" "$kit/prep-offline.sh" "$kit/probe_host.py" "$kit/decide.py" "$kit/standin.rs"; then
    printf 'FAIL scripts_name_pc2_net\n'
    fail=$((fail + 1))
else
    printf 'PASS scripts_leave_pc2_unnamed\n'
    pass=$((pass + 1))
fi

# uid 0 and an elevated environment are refused.
set +e
uid0_msg=$(
    jpk_current_uid() { printf '0\n'; }
    jpk_require_unprivileged 2>&1
)
uid0_rc=$?
set -e
assert_status uid0_is_refused "$uid0_rc" 2
assert_contains uid0_reason "$uid0_msg" "uid 0"
set +e
sudo_msg=$(
    SUDO_USER=someone
    jpk_require_unprivileged 2>&1
)
sudo_rc=$?
set -e
assert_status sudo_env_is_refused "$sudo_rc" 2
assert_contains sudo_env_reason "$sudo_msg" "SUDO_USER"
set +e
jpk_require_unprivileged >/dev/null
plain_uid_rc=$?
set -e
assert_status current_uid_is_allowed "$plain_uid_rc" 0

# TMPDIR and CARGO_HOME stay under the allowed folder.
jpk_apply_contained_env
assert_eq tmpdir_is_inside_root "$TMPDIR" "$root/tmp"
assert_eq cargo_home_is_inside_root "$CARGO_HOME" "$root/cargo-home"
assert_eq src_root_is_inside "$(jpk_src_root)" "$root/src"
set +e
jpk_path_inside "$root" "$TMPDIR"
tmpdir_inside_rc=$?
jpk_path_inside "$root" "$CARGO_HOME"
cargo_inside_rc=$?
set -e
assert_status tmpdir_path_inside "$tmpdir_inside_rc" 0
assert_status cargo_home_path_inside "$cargo_inside_rc" 0

# Offline path: cargo --offline, no git fetch, pin file is enough.
# Fetch cases run only while offline mode is really on, so a planted
# online-only function cannot start a network fetch from this test.
JPK_OFFLINE=1
assert_eq offline_cargo_flag "$(jpk_cargo_offline_args)" --offline
if jpk_offline_mode; then
    mkdir -p -- "$root/src/fail-closed-linux/lab/fail-closed-linux"
    printf '%s\n' "$JPK_C0_DEFAULT_SHA" >"$root/src/fail-closed-linux/.jpk-pin"
    JPK_MEMINFO="$high"
    set +e
    offline_head=$(jpk_fetch "$root/src/fail-closed-linux" "$JPK_C0_DEFAULT_BRANCH" "$JPK_C0_DEFAULT_SHA" 2>&1)
    offline_ok=$?
    set -e
    assert_status offline_fetch_uses_bundle "$offline_ok" 0
    assert_eq offline_fetch_uses_pin "$offline_head" "$JPK_C0_DEFAULT_SHA"
    printf 'deadbeef\n' >"$root/src/fail-closed-linux/.jpk-pin"
    set +e
    mismatch_msg=$(jpk_fetch "$root/src/fail-closed-linux" "$JPK_C0_DEFAULT_BRANCH" "$JPK_C0_DEFAULT_SHA" 2>&1)
    mismatch_rc=$?
    set -e
    assert_status offline_fetch_pin_mismatch "$mismatch_rc" 2
    assert_contains offline_fetch_pin_mismatch_reason "$mismatch_msg" "pin is"
    mkdir -p -- "$root/src"
    set +e
    missing_msg=$(jpk_fetch "$root/src/missing-c0" "$JPK_C0_DEFAULT_BRANCH" "$JPK_C0_DEFAULT_SHA" 2>&1)
    missing_rc=$?
    set -e
    assert_status offline_fetch_missing_is_refused "$missing_rc" 2
    assert_contains offline_fetch_missing_reason "$missing_msg" "REFUSED offline source missing"
fi
unset JPK_OFFLINE
assert_eq online_cargo_flag "$(jpk_cargo_offline_args)" ""

# Prep script vendors crates and documents the offline board command.
prep=$(cat "$kit/prep-offline.sh")
assert_contains prep_runs_cargo_vendor "$prep" "cargo vendor"
assert_contains prep_writes_vendor_config "$prep" "replace-with = \"vendored-sources\""
assert_contains prep_writes_pin_file "$prep" ".jpk-pin"
assert_contains prep_documents_offline_flag "$prep" "JPK_OFFLINE=1"
set +e
prep_dry=$(JPK_DRY_RUN=1 "$kit/prep-offline.sh" "$scratch/bundle" 2>&1)
prep_dry_rc=$?
set -e
assert_status prep_dry_run "$prep_dry_rc" 0
assert_contains prep_dry_run_names_vendor "$prep_dry" "vendor"
assert_contains run_script_offline_cargo "$(cat "$kit/run-on-jetson.sh")" '$(jpk_cargo_offline_args)'

# Host-surface detector sees the assembled tokens and ignores clean text.
if jpk_command_touches_host_surface "https://pc2.net/x"; then
    pc2_rc=0
else
    pc2_rc=1
fi
assert_status host_surface_detects_pc2 "$pc2_rc" 0
if jpk_command_touches_host_surface "please sudo -i"; then
    sudo_touch_rc=0
else
    sudo_touch_rc=1
fi
assert_status host_surface_detects_sudo "$sudo_touch_rc" 0
if jpk_command_touches_host_surface "listen :4200"; then
    port_rc=0
else
    port_rc=1
fi
assert_status host_surface_detects_port "$port_rc" 0
if jpk_command_touches_host_surface "apt install"; then
    apt_rc=0
else
    apt_rc=1
fi
assert_status host_surface_detects_apt "$apt_rc" 0
if jpk_command_touches_host_surface "pm2 start"; then
    pm2_rc=0
else
    pm2_rc=1
fi
assert_status host_surface_detects_pm2 "$pm2_rc" 0
if jpk_command_touches_host_surface "echo hello"; then
    clean_rc=0
else
    clean_rc=1
fi
assert_status host_surface_allows_clean "$clean_rc" 1
set +e
jpk_require_kit_omits_host_surfaces "$kit" >/dev/null
kit_omit_rc=$?
set -e
assert_status kit_omits_host_surfaces "$kit_omit_rc" 0

# Full script: elevated env is refused before any work.
cp -- "$kit/prep-offline.sh" "$root/prep-offline.sh"
chmod +x "$root/run-on-jetson.sh" "$root/prep-offline.sh"
set +e
(CDPATH= cd -- "$root" && SUDO_USER=someone JPK_DRY_RUN=1 JPK_MEMINFO="$high" JPK_EVIDENCE="$root/evidence.txt" "$root/run-on-jetson.sh") \
    >"$scratch/script-sudo.txt" 2>&1
sudo_script_rc=$?
set -e
assert_status script_refuses_sudo_env "$sudo_script_rc" 2
assert_contains script_sudo_reason "$(cat "$scratch/script-sudo.txt")" "SUDO_USER"

# Full script dry-run prints contained TMPDIR and CARGO_HOME.
set +e
(CDPATH= cd -- "$root" && JPK_DRY_RUN=1 JPK_MEMINFO="$high" JPK_EVIDENCE="$root/evidence.txt" "$root/run-on-jetson.sh") \
    >"$scratch/script-dry.txt" 2>&1
dry_script_rc=$?
set -e
assert_status script_dry_run_ok "$dry_script_rc" 0
assert_contains script_dry_run_tmpdir "$(cat "$scratch/script-dry.txt")" "TMPDIR=$root/tmp"
assert_contains script_dry_run_cargo "$(cat "$scratch/script-dry.txt")" "CARGO_HOME=$root/cargo-home"

# Memory stop kills the child, not only the parent.
pg_mem="$scratch/meminfo-pg"
printf 'MemTotal:        7773952 kB\nMemAvailable:    2000000 kB\n' >"$pg_mem"
JPK_MEMINFO="$pg_mem"
JPK_MEM_POLL_S=0.2
child_pid_file="$scratch/pg-child.pid"
rm -f "$child_pid_file"
set +e
jpk_with_memory_guard bash -c '
    trap "" HUP
    sleep 120 &
    printf "%s\n" "$!" >"$1"
    wait
' _ "$child_pid_file" &
guard_bg=$!
set -e
i=0
while [ ! -s "$child_pid_file" ] && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
done
child=$(cat "$child_pid_file" 2>/dev/null || true)
if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
    printf 'PASS memory_kill_child_started\n'
    pass=$((pass + 1))
else
    printf 'FAIL memory_kill_child_started\n'
    fail=$((fail + 1))
    child=""
fi
printf 'MemTotal:        7773952 kB\nMemAvailable:     500000 kB\n' >"$pg_mem"
set +e
wait "$guard_bg"
guard_rc=$?
set -e
assert_status memory_kill_returns_refused "$guard_rc" 2
if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
    printf 'FAIL memory_kill_stops_child\n'
    fail=$((fail + 1))
    kill -KILL "$child" 2>/dev/null || true
else
    printf 'PASS memory_kill_stops_child\n'
    pass=$((pass + 1))
fi
unset JPK_MEM_POLL_S

printf 'summary %s passed %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
