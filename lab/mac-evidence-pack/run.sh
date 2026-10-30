#!/bin/sh
# Direct pack entry (tests and --dry-run). Morning use is morning.sh.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -I "$here/pack.py" "$@"
