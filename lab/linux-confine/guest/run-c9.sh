#!/bin/sh
# Run every C9 linux-confine suite inside the aarch64 guest.
# Label: aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)
# Never native aarch64. Never Jetson.
set -eu

LABEL='aarch64 guest kernel 6.18 under qemu-system TCG (emulated CPU)'
EVIDENCE=/evidence
if [ ! -w "$EVIDENCE" ]; then
    EVIDENCE=/tmp/evidence
    mkdir -p "$EVIDENCE"
fi
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export TMPDIR=/tmp
export HOME=/tmp
export RUST_BACKTRACE=1

# Host writes the worktree path. The nonce is root-only and is not here.
if [ -f /etc/lc-guest.env ]; then
    # shellcheck disable=SC1091
    . /etc/lc-guest.env
fi
unset LC_GUEST_NONCE 2>/dev/null || true
REPO="${LC_GUEST_REPO:-/workspace}"
DEPS="$REPO/target-build/aarch64-unknown-linux-gnu/debug/deps"
BINS="$REPO/lab/linux-confine/guest-bins"
OUT="$REPO/target-build/aarch64-unknown-linux-gnu/debug/build"
HELPER_DIR="${LC_GUEST_HELPER_DIR:-}"
if [ -z "$HELPER_DIR" ]; then
    HELPER_DIR=$(ls -d "$OUT"/linux-confine-*/out 2>/dev/null | head -1)
fi
PLANTS="$REPO/lab/linux-confine/guest-plants"
SUMMARY="$EVIDENCE/summary.txt"
RESULTS="$EVIDENCE/guest-results.txt"

pick_bin() {
    name=$1
    if [ -x "$BINS/$name" ]; then
        echo "$BINS/$name"
        return
    fi
    ls "$DEPS"/${name}-* 2>/dev/null | grep -v '\.d$' | head -1
}

confine_bin=$(pick_bin confine)
providers_bin=$(pick_bin providers)
elf_bin=$(pick_bin elf)
aarch64_bin=$(pick_bin aarch64)

: > "$RESULTS"
echo "LABEL=$LABEL" | tee "$SUMMARY"
echo "native=0" | tee -a "$SUMMARY"
echo "jetson=0" | tee -a "$SUMMARY"
echo "repo=$REPO" | tee -a "$SUMMARY"
echo "uid=$(id -u) gid=$(id -g)" | tee -a "$SUMMARY"
echo "confine_bin=$confine_bin" | tee -a "$SUMMARY"
echo "providers_bin=$providers_bin" | tee -a "$SUMMARY"
echo "elf_bin=$elf_bin" | tee -a "$SUMMARY"
echo "aarch64_bin=$aarch64_bin" | tee -a "$SUMMARY"
echo "helper_dir=$HELPER_DIR" | tee -a "$SUMMARY"

if [ ! -x "$HELPER_DIR/lc-setup" ]; then
    echo "HELPERS MISSING path=$HELPER_DIR (baked host path hidden?)" | tee -a "$SUMMARY" | tee -a "$RESULTS"
    echo "FAIL" > "$EVIDENCE/helpers.status"
    echo "1" > "$EVIDENCE/helpers.exit"
    echo "guest_exit=1" >> "$EVIDENCE/guest-exit.txt"
    exit 1
fi
for name in did-provider wallet-provider model-provider; do
    if [ ! -x "$REPO/capsules/$name/target/debug/$name" ]; then
        echo "PROVIDER MISSING $REPO/capsules/$name/target/debug/$name" | tee -a "$SUMMARY"
        exit 1
    fi
done

counts_from_log() {
    log=$1
    # Last rust harness summary in this log.
    line=$(grep -E '^test result:' "$log" | tail -1 || true)
    if [ -z "$line" ]; then
        echo "0 0 0"
        return
    fi
    echo "$line" | awk '{
        p=0; f=0; i=0;
        for (n=1; n<=NF; n++) {
            if ($n=="passed;") p=$(n-1);
            if ($n=="failed;") f=$(n-1);
            if ($n=="ignored;") i=$(n-1);
        }
        print p, f, i
    }'
}

mark() {
    suite=$1
    rc=$2
    passed=$3
    failed=$4
    ignored=$5
    status=$6
    echo "suite=$suite exit=$rc passed=$passed failed=$failed ignored=$ignored status=$status" >> "$RESULTS"
}

run_suite() {
    name=$1
    bin=$2
    want_passed=$3
    want_failed=$4
    want_ignored=$5
    extra=${6:-}
    log="$EVIDENCE/${name}.txt"
    echo "======== suite $name ========" | tee -a "$SUMMARY"
    if [ ! -x "$bin" ]; then
        echo "$name MISSING $bin" | tee -a "$SUMMARY"
        echo "MISSING" > "$EVIDENCE/${name}.status"
        echo "1" > "$EVIDENCE/${name}.exit"
        mark "$name" 1 0 0 0 MISSING
        return 1
    fi
    set +e
    # shellcheck disable=SC2086
    "$bin" --test-threads=1 --nocapture $extra > "$log" 2>&1
    rc=$?
    set -e
    echo "$rc" > "$EVIDENCE/${name}.exit"
    set -- $(counts_from_log "$log")
    passed=$1
    failed=$2
    ignored=$3
    grep -E '^test |^test result:' "$log" | tee -a "$SUMMARY" || true
    status=PASS
    if [ "$rc" -ne 0 ]; then
        status=FAIL
    fi
    if [ "$passed" -lt "$want_passed" ] || [ "$failed" -ne "$want_failed" ] || [ "$ignored" -lt "$want_ignored" ]; then
        echo "$name SHORT counts passed=$passed failed=$failed ignored=$ignored want $want_passed/$want_failed/$want_ignored" | tee -a "$SUMMARY"
        status=SHORT
        if [ "$rc" -eq 0 ]; then
            rc=1
        fi
    fi
    if [ "$status" = "PASS" ]; then
        echo "$name PASS" | tee -a "$SUMMARY"
        echo "PASS" > "$EVIDENCE/${name}.status"
    else
        echo "$name $status exit=$rc" | tee -a "$SUMMARY"
        echo "$status" > "$EVIDENCE/${name}.status"
        tail -80 "$log" | tee -a "$SUMMARY"
    fi
    mark "$name" "$rc" "$passed" "$failed" "$ignored" "$status"
    if [ "$status" != "PASS" ]; then
        return 1
    fi
    return 0
}

fail=0
run_suite elf "$elf_bin" 6 0 0 || fail=1
run_suite aarch64 "$aarch64_bin" 2 0 1 || fail=1
# Do not pass --ignored: qemu-user Landlock ENOSYS is a host-kernel row.
run_suite confine "$confine_bin" 25 0 0 || fail=1
run_suite providers "$providers_bin" 4 0 0 || fail=1

echo "======== falsify.py-equivalent plants ========" | tee -a "$SUMMARY"
swap_helper() {
    plant=$1
    if [ -z "$HELPER_DIR" ] || [ ! -d "$HELPER_DIR" ]; then
        echo "no standing helper dir" | tee -a "$SUMMARY"
        return 1
    fi
    if [ ! -f "$plant" ]; then
        echo "missing plant $plant" | tee -a "$SUMMARY"
        return 1
    fi
    cp -a "$HELPER_DIR/lc-setup" "$HELPER_DIR/lc-setup.standing"
    cp -a "$plant" "$HELPER_DIR/lc-setup"
    chmod 755 "$HELPER_DIR/lc-setup"
    return 0
}

restore_helper() {
    if [ -f "$HELPER_DIR/lc-setup.standing" ]; then
        mv -f "$HELPER_DIR/lc-setup.standing" "$HELPER_DIR/lc-setup"
        chmod 755 "$HELPER_DIR/lc-setup"
    fi
}

run_plant() {
    id=$1
    testname=$2
    caught=$3
    bin=$4
    helper_plant=${5:-}
    log="$EVIDENCE/${id}.txt"
    echo "----- $id -----" | tee -a "$SUMMARY"
    if [ ! -x "$bin" ]; then
        echo "$id NOT RUN: missing $bin" | tee -a "$SUMMARY"
        echo "NOT_RUN" > "$EVIDENCE/${id}.status"
        echo "plant=$id status=NOT_RUN" >> "$RESULTS"
        return 0
    fi
    if [ -n "$helper_plant" ]; then
        if ! swap_helper "$helper_plant"; then
            echo "$id NOT RUN: helper swap failed" | tee -a "$SUMMARY"
            echo "NOT_RUN" > "$EVIDENCE/${id}.status"
            echo "plant=$id status=NOT_RUN" >> "$RESULTS"
            return 0
        fi
    fi
    set +e
    "$bin" --test-threads=1 --nocapture --exact "$testname" > "$log" 2>&1
    rc=$?
    set -e
    if [ -n "$helper_plant" ]; then
        restore_helper
    fi
    if [ "$rc" -ne 0 ] && grep -q "$caught" "$log"; then
        echo "$id CAUGHT" | tee -a "$SUMMARY"
        echo "CAUGHT" > "$EVIDENCE/${id}.status"
        echo "plant=$id status=CAUGHT" >> "$RESULTS"
    elif [ "$rc" -eq 0 ]; then
        echo "$id SURVIVED (test passed under the plant)" | tee -a "$SUMMARY"
        echo "SURVIVED" > "$EVIDENCE/${id}.status"
        echo "plant=$id status=SURVIVED" >> "$RESULTS"
        tail -40 "$log" | tee -a "$SUMMARY"
        fail=1
    else
        echo "$id NOT RUN or unexpected fail (no '$caught')" | tee -a "$SUMMARY"
        echo "UNEXPECTED" > "$EVIDENCE/${id}.status"
        echo "plant=$id status=UNEXPECTED" >> "$RESULTS"
        tail -40 "$log" | tee -a "$SUMMARY"
        fail=1
    fi
}

# C-helper plants against the standing test binaries.
run_plant F-LC-CAPBND confined_process_cap_bnd_is_zero \
    "capability bounding set did not drop" \
    "$providers_bin" "$PLANTS/F-LC-CAPBND/lc-setup"
run_plant F-LC-BLOCK production_launcher_rejects_block_switches \
    "the production launcher accepted a block switch" \
    "$confine_bin" "$PLANTS/F-LC-BLOCK/lc-setup"
run_plant F-LC-STORAGE did_profile_permits_its_operations_and_refuses_the_rest \
    "storage root rights drifted" \
    "$confine_bin" "$PLANTS/F-LC-STORAGE/lc-setup"
run_plant F-LC-PROVIDER-SOCKET provider_filter_refuses_socket \
    "provider filter socket denial did not hold" \
    "$confine_bin" "$PLANTS/F-LC-PROVIDER-SOCKET/lc-setup"

# Rust-level plants: prebuilt test binaries (plus a C helper where needed).
socket_bin="$PLANTS/F-LC-SOCKET/confine"
any_bin="$PLANTS/F-LC-ANY-ERRNO/confine"
run_plant F-LC-SOCKET did_profile_permits_its_operations_and_refuses_the_rest \
    "socket denial did not hold" \
    "$socket_bin"
run_plant F-LC-ANY-ERRNO provider_filter_refuses_clone_process \
    "not any failure" \
    "$any_bin" "$PLANTS/F-LC-ANY-ERRNO/lc-setup"

# Official review plants. Skip-netns needs a guest NIC besides lo.
run_plant F-LC-SKIP-NETNS did_profile_permits_its_operations_and_refuses_the_rest \
    "netns=host" \
    "$confine_bin" "$PLANTS/F-LC-SKIP-NETNS/lc-setup"
run_plant F-LC-DROP-SECCOMP did_profile_permits_its_operations_and_refuses_the_rest \
    "op=socket result=ok" \
    "$confine_bin" "$PLANTS/F-LC-DROP-SECCOMP/lc-setup"
run_plant F-LC-WIDE-ROOT did_profile_permits_its_operations_and_refuses_the_rest \
    "op=outside-read result=ok" \
    "$confine_bin" "$PLANTS/F-LC-WIDE-ROOT/lc-setup"

echo "F-LC-WRONG-ARCH-CC NOT RUN in guest (host cargo check / TARGET_CC=cc)" | tee -a "$SUMMARY"
echo "F-LC-QEMU-USER-LANDLOCK NOT RUN in guest (qemu-user host-kernel row)" | tee -a "$SUMMARY"
echo "NOT_RUN" > "$EVIDENCE/F-LC-WRONG-ARCH-CC.status"
echo "NOT_RUN" > "$EVIDENCE/F-LC-QEMU-USER-LANDLOCK.status"
echo "plant=F-LC-WRONG-ARCH-CC status=NOT_RUN" >> "$RESULTS"
echo "plant=F-LC-QEMU-USER-LANDLOCK status=NOT_RUN" >> "$RESULTS"

echo "======== end $LABEL ========" | tee -a "$SUMMARY"
echo "guest_fail=$fail" >> "$RESULTS"
# Non-zero if a standing suite failed, was missing, or was short, or a plant survived.
for s in elf aarch64 confine providers; do
    st=$(cat "$EVIDENCE/${s}.status" 2>/dev/null || echo FAIL)
    if [ "$st" != "PASS" ]; then
        fail=1
    fi
done
exit "$fail"
