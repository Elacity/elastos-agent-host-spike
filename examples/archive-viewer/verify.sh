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
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VIEWER_DIR}/../.." && pwd)"
WIT="${REPO_ROOT}/elastos/wit/elastos-bus-v1.wit"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

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

python3 -I "${REPO_ROOT}/examples/capsule-kit/scripts/check-manifest.py" \
    "${VIEWER_DIR}/capsule.json" "${WIT}" archive-viewer

cargo fmt --manifest-path "${VIEWER_DIR}/Cargo.toml" --all -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" --all-targets -- -D warnings
# The Bus v1 component glue: the same crate built for the guest's target.
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" \
    --target wasm32-unknown-unknown -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/Cargo.toml"

# Every rule: break it, see its test fail, restore it.
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
if node -e "const {chromium}=require(process.env.PLAYWRIGHT_DIR+'/node_modules/playwright'); process.exit(require('node:fs').existsSync(chromium.executablePath()) ? 0 : 1)" >/dev/null 2>&1; then
    node "${VIEWER_DIR}/surface/reader-browser-smoke.mjs"
else
    echo "archive-viewer: Chromium smoke skipped: no Playwright Chromium at ${PLAYWRIGHT_DIR}"
fi

if [[ $RUNTIME -eq 1 ]]; then
    host_log="$(mktemp)"
    runtime_log="$(mktemp)"
    trap 'rm -f "$host_log" "$runtime_log"' EXIT

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
    echo "archive-viewer: guest checks only; pass --runtime for the component, host test and F3/F35/F36/F43"
fi

echo "archive-viewer verification: OK"
