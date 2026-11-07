#!/bin/sh
# Run fail-closed-linux suites, or the ABI-1 refusal probe, inside the guest.
# Label comes from /etc/fcl-guest.env. Never native. Never Jetson.
set -eu

EVIDENCE=/evidence
if [ ! -w "$EVIDENCE" ]; then
    EVIDENCE=/tmp/evidence
    mkdir -p "$EVIDENCE"
fi
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export TMPDIR=/tmp
export HOME=/tmp
export RUST_BACKTRACE=1
export RUST_TEST_THREADS=1

. /etc/fcl-guest.env
LABEL="${FCL_GUEST_LABEL}"
NONCE="${FCL_GUEST_NONCE:-missing-nonce}"
SRC="${FCL_GUEST_SRC}"
MODE="${FCL_GUEST_MODE:-full}"
BINS="$SRC/guest-bins"
SUMMARY="$EVIDENCE/summary.txt"
RESULTS="$EVIDENCE/guest-results.txt"

: > "$RESULTS"
echo "LABEL=$LABEL" | tee "$SUMMARY"
echo "native=0" | tee -a "$SUMMARY"
echo "jetson=0" | tee -a "$SUMMARY"
echo "emulated_cpu=1" | tee -a "$SUMMARY"
echo "nonce=$NONCE" | tee -a "$SUMMARY" | tee -a "$RESULTS"
echo "src=$SRC" | tee -a "$SUMMARY"
echo "mode=$MODE" | tee -a "$SUMMARY"
echo "uid=$(id -u) gid=$(id -g)" | tee -a "$SUMMARY"
uname -a | tee -a "$SUMMARY"

run_suite() {
    name=$1
    expected=$2
    bin="$BINS/$name"
    log="$EVIDENCE/${name}.txt"
    echo "=== suite $name expected=$expected ===" | tee -a "$SUMMARY"
    if [ ! -x "$bin" ]; then
        echo "MISSING $bin" | tee -a "$SUMMARY"
        echo "FAIL" > "$EVIDENCE/${name}.status"
        echo "127" > "$EVIDENCE/${name}.exit"
        echo "suite=$name status=MISSING" >> "$RESULTS"
        echo "FCL_MARK nonce=$NONCE suite=$name exit=127 passed=0 failed=0 ignored=0 status=MISSING"
        return 1
    fi
    set +e
    "$bin" --test-threads=1 --nocapture > "$log" 2>&1
    rc=$?
    set -e
    echo "$rc" > "$EVIDENCE/${name}.exit"
    grep -E '^test |^test result:' "$log" | tee -a "$SUMMARY" || true
    passed=$(grep -E '^test result:' "$log" | awk '{print $4}' | tail -1)
    failed=$(grep -E '^test result:' "$log" | awk '{print $6}' | tail -1)
    ignored=$(grep -E '^test result:' "$log" | awk '{print $8}' | tail -1)
    passed=${passed:-0}
    failed=${failed:-0}
    ignored=${ignored:-0}
    status=FAIL
    if [ "$rc" -eq 0 ] && [ "$failed" = "0" ] && [ "$passed" = "$expected" ]; then
        status=PASS
    elif [ "$passed" != "$expected" ]; then
        status=SHORT
    fi
    echo "$status" > "$EVIDENCE/${name}.status"
    echo "suite=$name exit=$rc passed=$passed failed=$failed ignored=$ignored status=$status" | tee -a "$RESULTS"
    echo "FCL_MARK nonce=$NONCE suite=$name exit=$rc passed=$passed failed=$failed ignored=$ignored status=$status"
    [ "$status" = "PASS" ]
}

run_abi1() {
    launch="$BINS/fcl-launch"
    dummy="$BINS/dummy"
    echo "=== ABI-1 refusal probe ===" | tee -a "$SUMMARY"
    if [ ! -x "$launch" ]; then
        echo "MISSING $launch" | tee -a "$SUMMARY"
        echo "FAIL" > "$EVIDENCE/abi1.status"
        return 1
    fi
    ok=1
    for provider in did-provider wallet-provider model-provider; do
        store="/tmp/abi1-$provider"
        mkdir -p "$store"
        log="$EVIDENCE/abi1-$provider.txt"
        set +e
        "$launch" --provider "$provider" --storage-root "$store" -- "$dummy" > "$log" 2>&1
        rc=$?
        set -e
        echo "provider=$provider exit=$rc" | tee -a "$SUMMARY"
        cat "$log" | tee -a "$SUMMARY"
        if [ "$rc" != "71" ]; then
            echo "ABI1 $provider did not exit 71" | tee -a "$SUMMARY"
            ok=0
        fi
        if ! grep -q "truncate" "$log"; then
            echo "ABI1 $provider did not name truncate" | tee -a "$SUMMARY"
            ok=0
        fi
        if ! grep -q "ioctl_dev" "$log"; then
            echo "ABI1 $provider did not name ioctl_dev" | tee -a "$SUMMARY"
            ok=0
        fi
    done
    if [ "$ok" = "1" ]; then
        echo "PASS" > "$EVIDENCE/abi1.status"
        echo "suite=abi1 status=PASS" >> "$RESULTS"
        echo "FCL_MARK nonce=$NONCE suite=abi1 exit=0 passed=3 failed=0 ignored=0 status=PASS"
        return 0
    fi
    echo "FAIL" > "$EVIDENCE/abi1.status"
    echo "suite=abi1 status=FAIL" >> "$RESULTS"
    echo "FCL_MARK nonce=$NONCE suite=abi1 exit=1 passed=0 failed=1 ignored=0 status=FAIL"
    return 1
}

overall=0
if [ "$MODE" = "abi1" ]; then
    run_abi1 || overall=1
else
    run_suite lib 9 || overall=1
    run_suite simulated 22 || overall=1
    run_suite real_kernel 31 || overall=1
fi
echo "overall=$overall" | tee -a "$SUMMARY" | tee -a "$RESULTS"
exit "$overall"
