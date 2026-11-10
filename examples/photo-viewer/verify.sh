#!/usr/bin/env bash
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VIEWER_DIR}/../.." && pwd)"
MANIFEST="${VIEWER_DIR}/capsule.json"
WIT="${REPO_ROOT}/elastos/wit/elastos-bus-v1.wit"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

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
# smoke is skipped with a clear line and the page tests above it still run.
node --test "${VIEWER_DIR}/surface/photos.test.mjs"
python3 -I "${VIEWER_DIR}/falsify-surface.py"
export PLAYWRIGHT_DIR="${REPO_ROOT}/elastos/tools/browser-playwright-engine"
if node -e "const {chromium}=require(process.env.PLAYWRIGHT_DIR+'/node_modules/playwright'); process.exit(require('node:fs').existsSync(chromium.executablePath()) ? 0 : 1)" >/dev/null 2>&1; then
    node "${VIEWER_DIR}/surface/photos-browser-smoke.mjs"
else
    echo "photo-viewer: Chromium smoke skipped: no Playwright Chromium at ${PLAYWRIGHT_DIR}"
fi

# Every refusal: break it, see its test fail, restore it.
# The runner itself: a case is caught only when every named test fails.
python3 -I "${VIEWER_DIR}/../capsule-kit/falsify/test_falsify_kit.py"
python3 -I "${VIEWER_DIR}/falsify.py" --runtime

echo "photo-viewer capsule verification: OK"
