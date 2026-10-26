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
        if [ -n "$authorship" ] && [[ "$line" == *" ... ok" ]]; then
            printf 'NEEDS RUNTIME (%s)' "${authorship#a8 authorship: needs runtime: }"
            return
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

printf '\nrow | test | result\n'
printf 'A1 | wasi_import_is_refused_at_admission | %s\n' "$(result wasi_import_is_refused_at_admission)"
printf 'A8 | agent_host_host_key_read_is_refused | %s\n' "$(result agent_host_host_key_read_is_refused)"
printf 'A8 | shipped_wasm_bus_prints_internal_sentence | %s\n' "$(result shipped_wasm_bus_prints_internal_sentence)"
printf 'A8 | shipped_agent_host_bytes_read_host_key | %s\n' "$(result shipped_agent_host_bytes_read_host_key)"
printf 'cargo exit %s; full output: %s\n' "$status" "${out#"$PWD"/}"
exit "$status"
