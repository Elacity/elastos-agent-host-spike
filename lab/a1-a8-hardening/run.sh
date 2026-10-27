#!/bin/bash
# Run every row once against this checkout and print one result per row.
set -eu
if [ "$#" -ne 0 ]; then
    printf 'usage: run.sh\n' >&2
    exit 2
fi
lane=$(cd -- "$(dirname -- "$0")" && pwd -P)
cd "$lane/../.."
mkdir -p "$lane/target"
out="$lane/target/run.txt"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$lane/target/host"
export CARGO_BUILD_BUILD_DIR="$lane/target/host-build"
export RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
status=0
cargo test --locked --no-fail-fast --manifest-path "$lane/Cargo.toml" -- --nocapture >"$out" 2>&1 || status=$?
grep -E '^(a1|a8) ' "$out" || true

result() {
    local line authorship
    line=$(grep -E "^test $1 \.\.\. " "$out" | head -n 1 || true)
    if [ "$1" = "agent_host_host_key_read_is_refused" ]; then
        authorship=$(grep -E "^a8 authorship: needs runtime: " "$out" | head -n 1 || true)
        if [ -n "$authorship" ]; then
            if [[ "$line" == *" ... FAILED" ]]; then
                printf 'NEEDS RUNTIME (%s)' "${authorship#a8 authorship: needs runtime: }"
                return
            fi
            if [[ "$line" == *" ... ok" ]]; then
                printf 'FAIL (cargo ok while Runtime-ask fields are missing)'
                return
            fi
        fi
    fi
    case "$line" in
        *" ... ok") printf 'PASS' ;;
        *" ... FAILED") printf 'FAIL' ;;
        *" ... ignored, blocked: "*) printf 'BLOCKED (%s)' "${line#*ignored, blocked: }" ;;
        *" ... ignored, needs runtime: "*) printf 'NEEDS RUNTIME (%s)' "${line#*ignored, needs runtime: }" ;;
        "") printf 'NOT RUN' ;;
        *) printf 'UNKNOWN (%s)' "$line" ;;
    esac
}

a1=$(result wasi_import_is_refused_at_admission)
a8=$(result agent_host_host_key_read_is_refused)
wasm=$(result shipped_wasm_bus_prints_internal_sentence)
bytes=$(result shipped_agent_host_bytes_read_host_key)
printf '\nrow | test | result\n'
printf 'A1 | wasi_import_is_refused_at_admission | %s\n' "$a1"
printf 'A8 | agent_host_host_key_read_is_refused | %s\n' "$a8"
printf 'A8 | shipped_wasm_bus_prints_internal_sentence | %s\n' "$wasm"
printf 'A8 | shipped_agent_host_bytes_read_host_key | %s\n' "$bytes"
if [ "$a1" = PASS ] && [[ "$a8" == NEEDS\ RUNTIME* ]] && [[ "$wasm" == NEEDS\ RUNTIME* ]] && [[ "$bytes" == BLOCKED* ]]; then
    status=0
fi
printf 'cargo exit %s; full output: %s\n' "$status" "${out#"$PWD"/}"
exit "$status"
