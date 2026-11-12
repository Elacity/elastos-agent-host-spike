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
# The suite gets this run folder as TMPDIR. The installed-path record is made
# only after the suite has exited, in a new private folder outside the lane and
# outside every path the suite was given. The report is given the record's path
# on its command line after the suite; no test process is given it. The folder
# is removed once the report has read it, and the record it held stays in the
# receipt output.
base_tmp=${TMPDIR:-/tmp}
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
# The watcher runs in its own process group so that stopping it also stops the
# sleep it started: a leftover sleep would outlive this command.
launch_limited() {
    local limit=$1 child watcher status=0
    shift
    "$@" &
    child=$!
    set -m
    ( sleep "$limit"; kill -9 "$child" 2>/dev/null ) >/dev/null 2>&1 &
    watcher=$!
    set +m
    wait "$child" || status=$?
    kill -9 -- -"$watcher" 2>/dev/null || true
    wait "$watcher" 2>/dev/null || true
    return "$status"
}

# Run one suite command as its own process group, and remember the group. A
# member still alive after the command exits is a process the suite started and
# left behind; no record is made then.
suite_groups=()
suite_group() {
    local status=0 child
    set -m
    "$@" &
    child=$!
    wait "$child" || status=$?
    set +m
    suite_groups+=("$child")
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

# The suite runs first. Nothing is recorded while it runs.
: >"$run_dir/results"
status=0
if suite_group cargo test --locked --manifest-path "$manifest" ${features[@]+"${features[@]}"} -- --list >"$run_dir/list" 2>"$run_dir/build"; then
    suite_group cargo test --locked --no-fail-fast --manifest-path "$manifest" ${features[@]+"${features[@]}"} -- --format pretty --color never --show-output >"$run_dir/results" 2>>"$run_dir/build" || status=$?
else
    status=$?
fi
check_tree
# A process the suite left behind could still write or launch, so the record is
# refused while one lives. The check covers the process groups the suite
# commands were started in; a process that leaves its group is not seen.
lingering=0
for group in ${suite_groups[@]+"${suite_groups[@]}"}; do
    if kill -0 -- -"$group" 2>/dev/null; then
        lingering=1
        printf 'suite process still alive: process group %s\n' "$group" >&2
    fi
done

# Only now, with the suite finished, make a new private folder outside every
# path the suite was given, hash the installed binary, launch it once, and hash
# it again. A record is written atomically, and only when the launch answered
# and both hashes equal the installed record's binary hash. Any failure leaves
# no file anywhere and the report is named no record.
launch_note="none; no installed Runtime was named"
launch_record=
record_dir=
first=none
second=none
expected=none
installed_binary=${AGENT_CONFORMANCE_INSTALLED_BINARY:-}
installed_data=${AGENT_CONFORMANCE_INSTALLED_DATA:-}
if [ "$lingering" -ne 0 ]; then
    launch_note="none; a process started for the suite is still alive"
elif [ -n "$installed_binary" ] && [ -n "$installed_data" ]; then
    launch_note="none; the installed binary does not match its installed record"
    if record_dir=$(mktemp -d "$base_tmp/a14-launch-record.XXXXXX" 2>/dev/null); then
        case "$record_dir" in
            "$lane"|"$lane"/*|"$run_dir"|"$run_dir"/*)
                rm -rf -- "$record_dir" 2>/dev/null || true
                record_dir=
                launch_note="none; the record folder would sit under a path the suite was given"
                ;;
        esac
    else
        record_dir=
        launch_note="none; no private record folder could be made"
    fi
    if [ -n "$record_dir" ]; then
        if expected=$("$report_bin" --installed-binary-hash "$installed_binary" "$installed_data" 2>/dev/null); then
            launch_note="none; the installed binary could not be hashed"
            if first=$(sha256_of "$installed_binary"); then
                home=$(mktemp -d "$record_dir/home.XXXXXX")
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
                                if staged=$(mktemp "$record_dir/launches.XXXXXX" 2>/dev/null) &&
                                    printf 'path=%s sha256=%s answer=%s\n' \
                                        "$(canonical_path "$installed_binary")" "$first" "$answer" >"$staged" &&
                                    chmod 600 "$staged" &&
                                    mv -- "$staged" "$record_dir/launches"; then
                                    launch_record="$record_dir/launches"
                                    launch_note="one record for the installed path"
                                else
                                    launch_note="none; the record could not be written"
                                fi
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
    fi
fi
printf 'launch record: %s\n' "$launch_note"
sed -n '/^version identity:/p; /^given Runtime changed:/p; /^operator census:/p; /^cleanup census:/p; /^probe refusal effect:/p; /^parallel process isolation:/p; /^instance overlap:/p; /^cancel settlement:/p; /^kill settlement:/p; /^absent-policy settlement:/p; /^fixture controller:/p; /^fixture read:/p; /^session grant/p; /^host key read:/p; /^agent-host /p; /^FAILURE /p; /^SKIPPED /p' "$run_dir/results"
if [ -n "$launch_record" ]; then
    mode=$(stat -c %a "$launch_record" 2>/dev/null || stat -f %Lp "$launch_record")
    printf 'launch record file: %s (%s record(s), mode %s)\n' "$launch_record" "$(awk 'END {print NR}' "$launch_record")" "$mode"
    printf 'launch record contents: %s\n' "$(cat "$launch_record")"
else
    printf 'launch record file: none (0 record(s), mode -)\n'
    printf 'launch record contents: \n'
fi
printf 'process_isolation rows: process isolation, not capsule isolation; diagnostic results only\n'
printf 'instance rows: two_instances_overlap_with_separate_grants and instance_grant_does_not_authorise_sibling each run one shared journey; process isolation, not A3 (A3 needs resident instances in one Runtime); lab half of A6 and A9\n'
set -- "$run_dir/list" "$run_dir/results" "$status" "$run_dir/VERSIONS.json"
if [ -n "$launch_record" ]; then
    set -- "$@" "$launch_record"
fi
report_failed=
if AGENT_CONFORMANCE_TREE_DIRTY_DURING_RUN="$tree_dirty" "$report_bin" "$@"; then
    rm -- "$run_dir/list" "$run_dir/results" "$run_dir/build" "$run_dir/report-build"
else
    printf 'retained Cargo output: %s\n' "$run_dir" >&2
    report_failed=1
fi
# The report has read the record; the receipt output above keeps a copy.
if [ -n "$record_dir" ]; then
    rm -rf -- "$record_dir" 2>/dev/null || true
fi
if [ -n "$report_failed" ]; then
    exit 1
fi
