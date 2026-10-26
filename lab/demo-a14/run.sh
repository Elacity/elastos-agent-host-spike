#!/usr/bin/env bash
# Run the installed A14 demo. RUNBOOK.md explains the output.
set -euo pipefail
exec python3 -I "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/demo.py" run "$@"
