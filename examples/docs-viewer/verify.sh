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
        echo "docs-viewer: $1 did not run ($2), and ELASTOS_EXAMPLE_GATE_STRICT=1 requires every part" >&2
        exit 1
    fi
    echo "docs-viewer: $1 skipped: $2"
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


python3 -I "${REPO_ROOT}/examples/capsule-kit/scripts/check-manifest.py" "${MANIFEST}" "${WIT}" docs-viewer

# Check and restore the gate falsifier before Bash reads the branch below.
python3 -I "${VIEWER_DIR}/verify_gate_test.py"
python3 -I "${VIEWER_DIR}/verify_gate_test.py" --falsify

# Restore both pattern plants before Bash reads the bus2 directory change.
python3 -I "${VIEWER_DIR}/patterns_test.py"
python3 -I "${VIEWER_DIR}/patterns_test.py" --falsify

# Restore each report plant before the Cargo checks.
python3 -I "${VIEWER_DIR}/client_owner_report_test.py"
python3 -I "${VIEWER_DIR}/client_owner_report_test.py" --falsify

GATE=0
case "${GATE_LIST:-}" in
    # run-lane.sh exports the gate commands (the substring is `gates-photo`),
    # and older forms may carry the name; either way this is the lane gate.
    *gates-photo* | *photo-gates*) GATE=1 ;;
esac

# A standalone run owns the kit checks; the lane gate runs them when the kit changes.
if [[ $GATE -eq 0 ]]; then
    bash "${VIEWER_DIR}/../capsule-kit/guest/verify.sh"
else
    echo "docs-viewer: lane gate leaves kit guest checks to the kit verify"
fi

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
# This gate installs nothing: no npm packages and no browser. Where
# Playwright's Chromium is not already installed for the repository's browser
# engine, the smoke is skipped with a clear line, as the photo and archive
# gates do; the page tests still run, and the gate's last line says the smoke
# did not run.
export PLAYWRIGHT_DIR="${REPO_ROOT}/elastos/tools/browser-playwright-engine"
has_chromium() {
    node -e "const {chromium}=require(process.env.PLAYWRIGHT_DIR+'/node_modules/playwright'); process.exit(require('node:fs').existsSync(chromium.executablePath()) ? 0 : 1)" >/dev/null 2>&1
}
node --test "${VIEWER_DIR}/surface/reader.test.mjs"
if has_chromium; then
    node "${VIEWER_DIR}/surface/reader-browser-smoke.mjs"
else
    not_run "the browser smoke" "no Playwright Chromium at ${PLAYWRIGHT_DIR}"
fi

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

finish "docs-viewer capsule verification"
