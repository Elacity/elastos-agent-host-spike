#!/bin/bash
# Cargo supplies both the inventory and results; report owns table grading.
set -eu
features=()
case "${1:-}" in
    "") ;;
    --agent-host) features=(--features agent-host); shift ;;
    *) printf 'usage: run.sh [--agent-host]\n' >&2; exit 2 ;;
esac
if [ "$#" -ne 0 ]; then
    printf 'usage: run.sh [--agent-host]\n' >&2
    exit 2
fi
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
cd "$lane/../.."
if [ -L "$lane/target" ]; then
    printf 'test | PASS/FAIL/BLOCKED (id)/SKIPPED (reason)\ncargo | FAIL\n'
    printf 'lane target must be a directory without symlinks\n' >&2
    exit 1
fi
mkdir -p "$lane/target"
run_dir=$(mktemp -d "$lane/target/run-table.XXXXXX")
# The installed-path row's launch evidence is one record this script writes.
# The file is run-private with mode 0600, outside the TMPDIR the suite
# inherits, and its path never enters the environment of the suite: the report
# is given it on its command line only, after the suite. No test process is
# given it, and no library function writes one.
record_dir=$(mktemp -d "$lane/target/launch-record.XXXXXX")
launch_record=$(mktemp "$record_dir/launches.XXXXXX")
chmod 600 "$launch_record"
# An ambient value would otherwise reach every test process.
unset AGENT_CONFORMANCE_LAUNCH_RECORD
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$lane/target/host"
export CARGO_BUILD_BUILD_DIR="$lane/target/host-build"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
export TMPDIR="$run_dir"
manifest="$lane/Cargo.toml"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# The path the report compares: through symlinks, then with a physical parent.
canonical_path() {
    local path=$1 link dir
    case "$path" in
        /*) ;;
        *) path=$PWD/$path ;;
    esac
    while [ -L "$path" ]; do
        link=$(readlink "$path")
        case "$link" in
            /*) path=$link ;;
            *) path=$(dirname "$path")/$link ;;
        esac
    done
    dir=$(cd -- "$(dirname -- "$path")" && pwd -P)
    printf '%s/%s\n' "$dir" "$(basename -- "$path")"
}

# Run one command with a time limit, without `timeout`, which macOS lacks.
launch_limited() {
    local limit=$1 child watcher status=0
    shift
    "$@" &
    child=$!
    ( sleep "$limit"; kill -9 "$child" 2>/dev/null ) >/dev/null 2>&1 &
    watcher=$!
    wait "$child" || status=$?
    kill -9 "$watcher" 2>/dev/null || true
    wait "$watcher" 2>/dev/null || true
    return "$status"
}

# A review binds to the tested commit only on a clean tree. The tree is checked
# here, after the suite below, and again when the report is written; a dirty
# answer at any check leaves review_binding FAIL.
tree_dirty=0
check_tree() {
    if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
        tree_dirty=1
    fi
}
check_tree
# Prepare this checkout's report before collecting evidence, including failed suites.
if ! cargo build --locked --manifest-path "$manifest" --bin report >"$run_dir/report-build" 2>&1; then
    printf 'versions receipt failure: report build failed; retained output: %s\n' "$run_dir" >&2
    exit 1
fi
report_bin="$CARGO_TARGET_DIR/debug/report"
"$report_bin" --check-earlier-runs

# Hash the installed binary, launch it once, and hash it again. A record is
# written only when the launch answered and both hashes equal the installed
# record's binary hash.
launch_note="none; no installed Runtime was named"
first=none
second=none
expected=none
installed_binary=${AGENT_CONFORMANCE_INSTALLED_BINARY:-}
installed_data=${AGENT_CONFORMANCE_INSTALLED_DATA:-}
if [ -n "$installed_binary" ] && [ -n "$installed_data" ]; then
    launch_note="none; the installed binary does not match its installed record"
    if expected=$("$report_bin" --installed-binary-hash "$installed_binary" "$installed_data" 2>/dev/null); then
        launch_note="none; the installed binary could not be hashed"
        if first=$(sha256_of "$installed_binary"); then
            home=$(mktemp -d "$run_dir/launch-home.XXXXXX")
            launch_note="none; the installed binary did not answer with a version"
            if answer=$(launch_limited 30 env HOME="$home" TMPDIR="$home" "$installed_binary" --version 2>&1); then
                answer=$(printf '%s\n' "$answer" | sed -n '1p' | tr -d '\r')
                case "$answer" in
                    *[0-9].[0-9]*)
                        second=$(sha256_of "$installed_binary")
                        launch_note="none; the installed binary changed between the two hashes"
                        if [ "$first" != "$expected" ]; then
                            launch_note="none; the first hash matches no installed record"
                        elif [ "$second" = "$first" ]; then
                            printf 'path=%s sha256=%s answer=%s\n' \
                                "$(canonical_path "$installed_binary")" "$first" "$answer" >"$launch_record"
                            launch_note="one record for the installed path"
                        fi
                        ;;
                esac
            fi
        fi
    else
        expected=none
    fi
    printf 'installed launch: expected hash %s, first hash %s, second hash %s\n' \
        "$expected" "$first" "$second"
    printf 'launch record: %s\n' "$launch_note"
fi
: >"$run_dir/results"
status=0
if cargo test --locked --manifest-path "$manifest" ${features[@]+"${features[@]}"} -- --list >"$run_dir/list" 2>"$run_dir/build"; then
    cargo test --locked --no-fail-fast --manifest-path "$manifest" ${features[@]+"${features[@]}"} -- --format pretty --color never --show-output >"$run_dir/results" 2>>"$run_dir/build" || status=$?
else
    status=$?
fi
check_tree
sed -n '/^version identity:/p; /^given Runtime changed:/p; /^operator census:/p; /^cleanup census:/p; /^probe refusal effect:/p; /^parallel process isolation:/p; /^instance overlap:/p; /^cancel settlement:/p; /^kill settlement:/p; /^absent-policy settlement:/p; /^fixture controller:/p; /^fixture read:/p; /^session grant/p; /^host key read:/p; /^agent-host /p; /^FAILURE /p; /^SKIPPED /p' "$run_dir/results"
mode=$(stat -c %a "$launch_record" 2>/dev/null || stat -f %Lp "$launch_record")
printf 'launch record file: %s (%s record(s), mode %s)\n' "$launch_record" "$(awk 'END {print NR}' "$launch_record")" "$mode"
printf 'launch record contents: %s\n' "$(cat "$launch_record")"
printf 'process_isolation rows: process isolation, not capsule isolation; diagnostic results only\n'
printf 'instance rows: two_instances_overlap_with_separate_grants and instance_grant_does_not_authorise_sibling each run one shared journey; process isolation, not A3 (A3 needs resident instances in one Runtime); lab half of A6 and A9\n'
if AGENT_CONFORMANCE_TREE_DIRTY_DURING_RUN="$tree_dirty" "$report_bin" "$run_dir/list" "$run_dir/results" "$status" "$run_dir/VERSIONS.json" "$launch_record"; then
    rm -- "$run_dir/list" "$run_dir/results" "$run_dir/build" "$run_dir/report-build"
else
    printf 'retained Cargo output: %s\n' "$run_dir" >&2
    exit 1
fi
