#!/usr/bin/env bash
set -euo pipefail

VIEWER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${VIEWER_DIR}/../.." && pwd)"
MANIFEST="${VIEWER_DIR}/capsule.json"
WIT="${REPO_ROOT}/elastos/wit/elastos-bus-v1.wit"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"

python3 -I "${REPO_ROOT}/examples/capsule-kit/scripts/check-manifest.py" "${MANIFEST}" "${WIT}" docs-viewer

# The capsule kit's guest crate this guest is built on: its own tests and falsifiers.
bash "${VIEWER_DIR}/../capsule-kit/guest/verify.sh"

# Guest and model: logic and refusals against a fake Runtime.
cargo fmt --manifest-path "${VIEWER_DIR}/Cargo.toml" --all -- --check
cargo test --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" --workspace
cargo clippy --locked --manifest-path "${VIEWER_DIR}/Cargo.toml" --workspace --all-targets -- -D warnings

# Component: built with the repository builder.
"${REPO_ROOT}/scripts/build-component-capsule.sh" "${VIEWER_DIR}"
test -f "${VIEWER_DIR}/docs-viewer.component.wasm"

# Host: the component inside the Runtime's ComponentProvider.
cargo fmt --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" --all-targets -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/host-test/Cargo.toml" -- --nocapture

# Bundle: both capsules packed, named by CID, claimed and admitted under a policy.
cargo fmt --manifest-path "${VIEWER_DIR}/bundle-test/Cargo.toml" -- --check
cargo clippy --locked --manifest-path "${VIEWER_DIR}/bundle-test/Cargo.toml" --all-targets -- -D warnings
cargo test --locked --manifest-path "${VIEWER_DIR}/bundle-test/Cargo.toml" -- --nocapture

# Surface: the render-only page, against a fake fetch, then in real Chromium
# framed in Home's sandbox against a stand-in server (Playwright's Chromium).
# Playwright and its browser live outside this checkout (node_modules is
# ignored); when the runner has neither, install them so the smoke runs
# instead of failing to load a module.
export PLAYWRIGHT_DIR="${REPO_ROOT}/elastos/tools/browser-playwright-engine"
if ! node -e "require(process.env.PLAYWRIGHT_DIR + '/node_modules/playwright')" >/dev/null 2>&1; then
    (cd "${PLAYWRIGHT_DIR}" && npm ci --no-audit --no-fund)
fi
if ! node -e "const {chromium}=require(process.env.PLAYWRIGHT_DIR+'/node_modules/playwright'); process.exit(require('node:fs').existsSync(chromium.executablePath()) ? 0 : 1)" >/dev/null 2>&1; then
    (cd "${PLAYWRIGHT_DIR}" && npx playwright install chromium)
fi
node --test "${VIEWER_DIR}/surface/reader.test.mjs"
node "${VIEWER_DIR}/surface/reader-browser-smoke.mjs"

# Bus v2: the resident reader in the Bus v2 proof's stub host, with the
# proof's own test helpers and busy guest. Each part is built from its own
# folder, so rustup picks its toolchain (Rust 1.95.0). The guests are deleted
# first and checked after, so a stale or missing guest is never tested.
build_guest() { # <folder> <package> <file>
    (
        cd "$1"
        rm -f "target/wasm32-unknown-unknown/release/$3.wasm"
        cargo build --locked --release --target wasm32-unknown-unknown -p "$2"
        if [ ! -f "target/wasm32-unknown-unknown/release/$3.wasm" ]; then
            echo "verify: FAILED: the build did not produce $1/target/wasm32-unknown-unknown/release/$3.wasm" >&2
            exit 1
        fi
    )
}
build_guest "${REPO_ROOT}/examples/bus2-proof" bus2-busy-guest bus2_busy_guest
build_guest "${VIEWER_DIR}/bus2" docs-bus2-guest docs_bus2_guest
(
    cd "${VIEWER_DIR}/bus2"
    cargo fmt --all -- --check
    cargo clippy --locked -p docs-bus2-host-test --all-targets -- -D warnings
    cargo clippy --locked --release --target wasm32-unknown-unknown -p docs-bus2-guest -- -D warnings
    cargo test --locked -p docs-bus2-host-test -- --nocapture
)

# Every refusal and every page rule: break it, see its test fail, restore it.
# The runner itself: a case is caught only when every named test fails.
python3 -I "${VIEWER_DIR}/../capsule-kit/falsify/test_falsify_kit.py"
python3 -I "${VIEWER_DIR}/falsify.py" --runtime
python3 -I "${VIEWER_DIR}/falsify-surface.py"

echo "docs-viewer capsule verification: OK"
