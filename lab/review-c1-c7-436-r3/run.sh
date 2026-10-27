#!/usr/bin/env bash
# Replay this review's plants against the #436 fence. Does not edit #436 files.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
export C17_RUNBOOK_DIR="$root/lab/c1-c7-mac-runbook"
export C17_REPO_ROOT="$root"
exec python3 -I "$root/lab/review-c1-c7-436-r3/plants.py"
