#!/usr/bin/env bash
# The archive viewer: the core's fmt, clippy (host and wasm32), tests and
# falsifiers; the render-only page's tests, its falsifiers and its Chromium
# smoke; then, with --runtime, the built component in the Runtime's
# ComponentProvider with its admission check, the F35 grant stop and the F36
# fuel gate (the host-test crate), and their falsifiers.
#
# Usage: verify.sh [--runtime | --guest-only]
#
# --runtime     also build the component and run the host-test crate and its
#               runtime falsifiers (this Mac; needs wasm32 and the repository
#               component builder).
# --guest-only  the guest checks only, for a machine without the component
#               build.
# no argument   guest checks only. The lane gate runs this script with no
#               argument, so it selects the full check through GATE_LIST.
#
# A run that leaves a part out (no --runtime, or no browser for the smoke)
# does not end "OK": its last line names what did not run. With
# ELASTOS_EXAMPLE_GATE_STRICT=1 it stops with an error instead.
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VIEWER_DIR}/../.." && pwd)"
WIT="${REPO_ROOT}/elastos/wit/elastos-bus-v1.wit"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

# A part of this gate that could not run is never reported as "OK". Each such
# part is noted here and named in the last line. With
# ELASTOS_EXAMPLE_GATE_STRICT=1, which receipts use, a part that cannot run
# stops the gate with an error instead.
NOT_RUN=()
not_run() { # <what did not run> <why>
    if [[ "${ELASTOS_EXAMPLE_GATE_STRICT:-0}" == "1" ]]; then
        echo "archive-viewer: $1 did not run ($2), and ELASTOS_EXAMPLE_GATE_STRICT=1 requires every part" >&2
        exit 1
    fi
    echo "archive-viewer: $1 skipped: $2"
    NOT_RUN+=("$1")
}
finish() { # <the line for a complete run>
    if [[ ${#NOT_RUN[@]} -eq 0 ]]; then
        echo "$1: OK"
    else
        local list; list="$(printf '%s; ' "${NOT_RUN[@]}")"
        echo "$1: INCOMPLETE, the parts that ran passed; not run: ${list%; }"
    fi
}


host_log=""
runtime_log=""

snapshot_cleanup() {
    # A signal handler writes the keep marker before it exits. Only the main
    # shell removes the snapshot, so an EXIT trap that Bash runs in a subshell
    # (BASH_SUBSHELL > 0) keeps it. BASH_SUBSHELL exists in Bash 3.2 and 5;
    # the handler leaves a marker file instead of a variable, because a
    # subshell's variable would not reach this trap.
    if [[ "${BASH_SUBSHELL:-1}" -eq 0 && ! -e "${VIEWER_DIR}/.verify-snapshot-keep" ]]; then
        rm -rf "${VIEWER_DIR}/.verify-snapshot"
    fi
    rm -f "$host_log" "$runtime_log"
}

install_snapshot_traps() {
    trap snapshot_cleanup EXIT
    trap 'touch "${VIEWER_DIR}/.verify-snapshot-keep"; exit 143' TERM
    trap 'touch "${VIEWER_DIR}/.verify-snapshot-keep"; exit 130' INT
    trap 'touch "${VIEWER_DIR}/.verify-snapshot-keep"; exit 129' HUP
}

RUNTIME=0
GATE=0
case "${GATE_LIST:-}" in
    # run-lane.sh exports the gate commands (the substring is `gates-photo`),
    # and older forms may carry the name; either way this is the lane gate.
    *gates-photo* | *photo-gates*) GATE=1 ;;
esac
if [[ $# -eq 0 ]]; then
    # The lane gate runs verify.sh with no argument, so it selects the full
    # check; every other no-argument run is guest-only.
    [[ $GATE -eq 1 ]] && RUNTIME=1
else
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --runtime) RUNTIME=1 ;;
            --guest-only) RUNTIME=0 ;;
            *)
                echo "usage: $0 [--runtime | --guest-only]" >&2
                exit 2
                ;;
        esac
        shift
    done
fi
# Fail closed: the lane gate must never certify a guest-only run.
if [[ $GATE -eq 1 && $RUNTIME -ne 1 ]]; then
    echo "verify.sh: the lane gate requires the runtime step; drop --guest-only" >&2
    exit 1
fi

python3 -I "${VIEWER_DIR}/falsify_restore_test.py"
python3 -I "${VIEWER_DIR}/falsify_restore_test.py" --falsify
python3 -I - "$VIEWER_DIR" <<'PY'
import shutil
import sys

sys.path.insert(0, sys.argv[1])
from falsify import HERE, SNAPSHOT_FILES, restore_interrupted_plants

restore_interrupted_plants()
snapshot = HERE / ".verify-snapshot"
for name in SNAPSHOT_FILES:
    saved = snapshot / name
    saved.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HERE / name, saved)
(snapshot / "INCOMPLETE").write_text("verification in progress\n")
PY
rm -f "${VIEWER_DIR}/.verify-snapshot-keep"
install_snapshot_traps

python3 -I "${REPO_ROOT}/examples/capsule-kit/scripts/check-manifest.py" \
    "${VIEWER_DIR}/capsule.json" "${WIT}" archive-viewer

cargo fmt --manifest-path "${VIEWER_DIR}/Cargo.toml" --all -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" --all-targets -- -D warnings
# The Bus v1 component glue: the same crate built for the guest's target.
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" \
    --target wasm32-unknown-unknown -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/Cargo.toml"

# Every rule: break it, see its test fail, restore it.
python3 -I "${VIEWER_DIR}/falsify_groups_test.py"
python3 -I "${VIEWER_DIR}/falsify_groups_test.py" --falsify
python3 -I "${VIEWER_DIR}/falsify.py"

# Surface: the render-only page against a fake fetch, then its page
# falsifiers (F37 to F39, the shipped renderer's drift from its kit owner and
# the rest), then the real page in real Chromium, framed in Home's sandbox
# against the kit's stand-in server. A machine without Playwright's Chromium
# skips the smoke with a clear line; the page tests and the falsifiers still
# run.
node --test "${VIEWER_DIR}/surface/reader.test.mjs"
python3 -I "${VIEWER_DIR}/falsify-surface.py"
export PLAYWRIGHT_DIR="${REPO_ROOT}/elastos/tools/browser-playwright-engine"
# One Playwright for the check below and for the smoke: the shared fixture
# takes this variable first, so both ask the same copy.
export ELASTOS_PLAYWRIGHT_MODULE="${PLAYWRIGHT_DIR}/node_modules/playwright"
if node -e "const {chromium}=require(process.env.ELASTOS_PLAYWRIGHT_MODULE); process.exit(require('node:fs').existsSync(chromium.executablePath()) ? 0 : 1)" >/dev/null 2>&1; then
    node "${VIEWER_DIR}/surface/reader-browser-smoke.mjs"
else
    not_run "the browser smoke" "no Playwright Chromium at ${PLAYWRIGHT_DIR}"
fi

if [[ $RUNTIME -eq 1 ]]; then
    host_log="$(mktemp)"
    runtime_log="$(mktemp)"

    # Component: built with the repository builder.
    "${VIEWER_DIR}/build.sh"
    test -f "${VIEWER_DIR}/archive-viewer.component.wasm"

    # Host: the component inside the Runtime's ComponentProvider, its import
    # admission and the fuel gate.
    cargo fmt --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --check
    cargo clippy --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" --all-targets -- -D warnings
    cargo test --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --nocapture \
        2>&1 | tee "$host_log"

    # The component falsifiers: each rebuilds the component and runs the host test.
    python3 -I "${VIEWER_DIR}/falsify.py" --runtime 2>&1 | tee "$runtime_log"

    # The lane gate certifies the runtime step only when it actually ran:
    # the host suite passed and the component falsifiers caught F3, F35, F36
    # and F43.
    if [[ $GATE -eq 1 ]]; then
        grep -q '^test result: ok\. [1-9][0-9]* passed; 0 failed;' "$host_log"
        grep -q '^caught: F3 ' "$runtime_log"
        grep -q '^caught: F35 ' "$runtime_log"
        grep -q '^caught: F36 ' "$runtime_log"
        grep -q '^caught: F43 ' "$runtime_log"
    fi
else
    not_run "the runtime path (the component, the host test and F3/F35/F36/F43)" "--runtime was not given"
fi

finish "archive-viewer verification"
