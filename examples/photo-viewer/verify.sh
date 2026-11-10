#!/usr/bin/env bash
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VIEWER_DIR}/../.." && pwd)"
MANIFEST="${VIEWER_DIR}/capsule.json"
WIT="${REPO_ROOT}/elastos/wit/elastos-bus-v1.wit"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

# A part of this gate that could not run is never reported as "OK". Each such
# part is noted here and named in the last line. With
# ELASTOS_EXAMPLE_GATE_STRICT=1, which receipts use, a part that cannot run
# stops the gate with an error instead.
NOT_RUN=()
not_run() { # <what did not run> <why>
    if [[ "${ELASTOS_EXAMPLE_GATE_STRICT:-0}" == "1" ]]; then
        echo "photo-viewer: $1 did not run ($2), and ELASTOS_EXAMPLE_GATE_STRICT=1 requires every part" >&2
        exit 1
    fi
    echo "photo-viewer: $1 skipped: $2"
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

python3 -I "${REPO_ROOT}/examples/capsule-kit/scripts/check-manifest.py" "${MANIFEST}" "${WIT}" photo-viewer

# Restore the gate falsifier before Bash reads the branch it changes.
python3 -I "${VIEWER_DIR}/verify_gate_test.py"
python3 -I "${VIEWER_DIR}/verify_gate_test.py" --falsify

python3 -I "${VIEWER_DIR}/repro/pins_test.py"
python3 -I "${VIEWER_DIR}/repro/pins_test.py" --falsify

python3 -I "${VIEWER_DIR}/repro/recorded_hash_test.py"
python3 -I "${VIEWER_DIR}/repro/recorded_hash_test.py" --falsify

GATE=0
case "${GATE_LIST:-}" in
    *gates-photo* | *photo-gates*) GATE=1 ;;
esac
# A standalone run owns the kit checks; the lane gate owns them when the kit changes.
if [[ $GATE -eq 0 ]]; then
    bash "${VIEWER_DIR}/../capsule-kit/guest/verify.sh"
else
    echo "photo-viewer: lane gate leaves kit guest checks to the kit verify"
fi

# Guest: logic and refusals against a fake Runtime.
cargo fmt --manifest-path "${VIEWER_DIR}/Cargo.toml" -- --check
cargo test --locked --manifest-path "${VIEWER_DIR}/Cargo.toml"
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" --all-targets -- -D warnings

# Component: built with the repository builder.
"${REPO_ROOT}/scripts/build-component-capsule.sh" "${VIEWER_DIR}"
test -f "${VIEWER_DIR}/photo-viewer.component.wasm"

# Host: the component inside the Runtime's ComponentProvider.
cargo fmt --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" --all-targets -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --nocapture

# This test code stands in for the Runtime's launch by CID, which does not exist yet.
python3 -I "${VIEWER_DIR}/falsify-ph6-stand-in.py"

# Surface: the render-only page against a fake fetch, each of its rules broken
# in turn, then the page in real Chromium where Playwright's Chromium is
# already installed. This gate does not install a browser; without one the
# smoke is skipped with a clear line, the page tests above it still run, and
# the gate's last line says the smoke did not run.
node --test "${VIEWER_DIR}/surface/photos.test.mjs"
python3 -I "${VIEWER_DIR}/falsify-surface.py"
export PLAYWRIGHT_DIR="${REPO_ROOT}/elastos/tools/browser-playwright-engine"
if node -e "const {chromium}=require(process.env.PLAYWRIGHT_DIR+'/node_modules/playwright'); process.exit(require('node:fs').existsSync(chromium.executablePath()) ? 0 : 1)" >/dev/null 2>&1; then
    node "${VIEWER_DIR}/surface/photos-browser-smoke.mjs"
else
    not_run "the browser smoke" "no Playwright Chromium at ${PLAYWRIGHT_DIR}"
fi

# Every refusal: break it, see its test fail, restore it.
# The runner itself: a case is caught only when every named test fails.
python3 -I "${VIEWER_DIR}/../capsule-kit/falsify/test_falsify_kit.py"
python3 -I "${VIEWER_DIR}/falsify.py" --runtime

finish "photo-viewer capsule verification"
