#!/usr/bin/env bash
# The fast source checks: CI source-gate and the local pre-push gate both run
# this file, so a failure shows locally before it shows in CI.
#   test-source-gate.sh           runs every section
#   test-source-gate.sh SECTION   runs one section (CI names one per step):
#                                 product-data, prepush, product-ui, release,
#                                 redteam
set -euo pipefail
cd "$(dirname "$0")/.."

product_data() {
  node scripts/check-product-data.mjs
}

prepush() {
  python3 scripts/ci-local-prepush-test.py
}

redteam() {
  # Every plant's anchor must appear exactly once in its committed target file.
  # This test builds nothing and needs no rustc or wasm32 target, so CI and the
  # local pre-push both run it. A skip is not a pass: unittest exits 0 on an
  # all-skipped run, so the exact run is checked below.
  # The full receipt probe builds three copies and takes 8-11 minutes; it stays
  # a local command, not part of this gate. It needs rustc 1.91.0, the lab
  # lane's own pin, which is older than this repository's. The probe runs
  # rustc from the lane's folder, where rustup picks 1.91.0 by itself; RUSTC
  # names that compiler outright, so that a rustc first on PATH that is not
  # rustup's cannot stand in for it (a wrong version skips the tests, and an
  # all-skipped run exits 0):
  #   RUSTC="$(rustup which --toolchain 1.91.0 rustc)" \
  #     python3 -I -m unittest discover -s lab/redteam/py \
  #     -p test_wasm_capsule_receipt.py -v
  local output status=0
  output="$(python3 -I -m unittest discover -s lab/redteam/py \
    -p test_wasm_capsule_receipt.py \
    -k test_every_plant_anchor_appears_exactly_once -v 2>&1)" || status=$?
  printf '%s\n' "$output"
  (( status == 0 )) || return "$status"
  if [[ "$output" != *"Ran 1 test"* || "$output" == *"skipped"* ]]; then
    echo "redteam: the anchor test did not run; a skip is not a pass" >&2
    return 1
  fi
}

product_ui() {
  node --version
  node scripts/check-chat-ui-artifacts.mjs check
  node scripts/home-shell-regression-smoke.mjs
  node scripts/home-shell-bridge-smoke.mjs
  node scripts/home-shell-recovery-smoke.mjs
  node scripts/home-agent-shell-smoke.mjs
  node scripts/people-discovery-smoke.mjs
  node scripts/home-clipboard-source-gate.mjs
  node --test scripts/home-clipboard-source-gate.test.mjs
  node scripts/public-copy-entropy-check.mjs
  node scripts/library-product-behavior-smoke.mjs
}

release() {
  node --test scripts/ci-model-package.test.mjs scripts/ci-installed-home-failure.test.mjs
  python3 scripts/ci-release-policy-test.py
  python3 scripts/ci-download-cache-test.py
  python3 scripts/components-release-integrity-check.py --self-test
  python3 scripts/publish-platform-artifacts-test.py
  python3 scripts/fixture-git-env-test.py
  python3 scripts/release-platform-input-test.py
  python3 scripts/prepare-release-platform-test.py
  python3 scripts/media-tools-build-test.py
  python3 scripts/verify-linux-arm64-package-test.py
  python3 scripts/verify-linux-engine-test.py
  python3 scripts/update-hop-compare-test.py
  python3 .github/scripts/release-mac-capacity-test.py
}

case "${1:-all}" in
  product-data) product_data ;;
  prepush) prepush ;;
  product-ui) product_ui ;;
  release) release ;;
  redteam) redteam ;;
  all) product_data; prepush; product_ui; release; redteam ;;
  *) echo "usage: $0 [product-data|prepush|product-ui|release|redteam]" >&2; exit 2 ;;
esac
