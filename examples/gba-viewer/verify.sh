#!/usr/bin/env bash
# The gba-viewer example's gate (AP4 slice 1a): the by-CID mapping, the staging
# script, the rows that drive both, and this gate's own falsifier.
set -euo pipefail

VIEWER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

python3 -I "${VIEWER_DIR}/rows_test.py"
python3 -I "${VIEWER_DIR}/verify_gate_test.py"
python3 -I "${VIEWER_DIR}/verify_gate_test.py" --falsify

echo "gba-viewer: rows green, gate falsifier caught"
