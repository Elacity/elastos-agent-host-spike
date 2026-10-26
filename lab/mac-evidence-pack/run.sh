#!/bin/sh
# Morning entry. Writes one work dir under $HOME/mac-evidence-pack/.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 -I "$here/pack.py" "$@"
