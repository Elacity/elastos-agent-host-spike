#!/usr/bin/env bash
set -euo pipefail

VIEWER_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

python3 -I "${VIEWER_DIR}/verify_empty_test.py"
python3 -I "${VIEWER_DIR}/verify_empty_test.py" --falsify

cd -- "$VIEWER_DIR"
refused="$(find . -mindepth 1 \
    ! \( -type f \( -path './.gitignore' -o -path './verify.sh' \
        -o -path './verify_empty_test.py' \) \) -print -quit)"
if [[ -n "$refused" ]]; then
    printf 'gba-viewer has no viewer yet; refusing %s\n' "${refused#./}" >&2
    exit 1
fi
printf 'gba-viewer: no viewer sources\n'
