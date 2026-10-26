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

DEPS=/workspace/target-build/aarch64-unknown-linux-gnu/debug/deps
BINS=/workspace/lab/linux-confine/guest-bins
OUT=/workspace/target-build/aarch64-unknown-linux-gnu/debug/build
HELPER_DIR=$(ls -d "$OUT"/linux-confine-*/out 2>/dev/null | head -1)
PLANTS=/workspace/lab/linux-confine/guest-plants
SUMMARY="$EVIDENCE/summary.txt"

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

echo "LABEL=$LABEL" | tee "$SUMMARY"
echo "native=0" | tee -a "$SUMMARY"
echo "jetson=0" | tee -a "$SUMMARY"
echo "uid=$(id -u) gid=$(id -g)" | tee -a "$SUMMARY"
echo "confine_bin=$confine_bin" | tee -a "$SUMMARY"
echo "providers_bin=$providers_bin" | tee -a "$SUMMARY"
echo "elf_bin=$elf_bin" | tee -a "$SUMMARY"
echo "aarch64_bin=$aarch64_bin" | tee -a "$SUMMARY"
echo "helper_dir=$HELPER_DIR" | tee -a "$SUMMARY"

run_suite() {
    name=$1
    bin=$2
    extra=${3:-}
    log="$EVIDENCE/${name}.log"
    echo "======== suite $name ========" | tee -a "$SUMMARY"
    if [ ! -x "$bin" ]; then
        echo "$name MISSING $bin" | tee -a "$SUMMARY"
        echo "MISSING" > "$EVIDENCE/${name}.status"
        return 1
    fi
    set +e
    # shellcheck disable=SC2086
    "$bin" --test-threads=1 --nocapture $extra > "$log" 2>&1
    rc=$?
    set -e
    echo "$rc" > "$EVIDENCE/${name}.exit"
    # Rust harness summary lines.
    grep -E '^test |^test result:' "$log" | tee -a "$SUMMARY" || true
    if [ "$rc" -eq 0 ]; then
        echo "$name PASS" | tee -a "$SUMMARY"
        echo "PASS" > "$EVIDENCE/${name}.status"
    else
        echo "$name FAIL exit=$rc" | tee -a "$SUMMARY"
        echo "FAIL" > "$EVIDENCE/${name}.status"
        tail -80 "$log" | tee -a "$SUMMARY"
    fi
    return 0
}

run_suite elf "$elf_bin"
run_suite aarch64 "$aarch64_bin"
# Do not pass --ignored: qemu-user Landlock ENOSYS is a host-kernel row.
run_suite confine "$confine_bin"
run_suite providers "$providers_bin"

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
    log="$EVIDENCE/${id}.log"
    echo "----- $id -----" | tee -a "$SUMMARY"
    if [ ! -x "$bin" ]; then
        echo "$id NOT RUN: missing $bin" | tee -a "$SUMMARY"
        echo "NOT_RUN" > "$EVIDENCE/${id}.status"
        return 0
    fi
    if [ -n "$helper_plant" ]; then
        if ! swap_helper "$helper_plant"; then
            echo "$id NOT RUN: helper swap failed" | tee -a "$SUMMARY"
            echo "NOT_RUN" > "$EVIDENCE/${id}.status"
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
    elif [ "$rc" -eq 0 ]; then
        echo "$id SURVIVED (test passed under the plant)" | tee -a "$SUMMARY"
        echo "SURVIVED" > "$EVIDENCE/${id}.status"
        tail -40 "$log" | tee -a "$SUMMARY"
    else
        echo "$id NOT RUN or unexpected fail (no '$caught')" | tee -a "$SUMMARY"
        echo "UNEXPECTED" > "$EVIDENCE/${id}.status"
        tail -40 "$log" | tee -a "$SUMMARY"
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

echo "F-LC-WRONG-ARCH-CC NOT RUN in guest (host cargo check / TARGET_CC=cc)" | tee -a "$SUMMARY"
echo "F-LC-QEMU-USER-LANDLOCK NOT RUN in guest (qemu-user host-kernel row)" | tee -a "$SUMMARY"
echo "NOT_RUN" > "$EVIDENCE/F-LC-WRONG-ARCH-CC.status"
echo "NOT_RUN" > "$EVIDENCE/F-LC-QEMU-USER-LANDLOCK.status"

echo "======== end $LABEL ========" | tee -a "$SUMMARY"
# Non-zero only if a standing suite failed.
fail=0
for s in elf aarch64 confine providers; do
    st=$(cat "$EVIDENCE/${s}.status" 2>/dev/null || echo FAIL)
    if [ "$st" != "PASS" ]; then
        fail=1
    fi
done
exit "$fail"
