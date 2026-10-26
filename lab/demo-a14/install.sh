#!/usr/bin/env bash
# Install the A14 demo. RUNBOOK.md explains each step.
set -euo pipefail
exec python3 -I "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/demo.py" install "$@"
