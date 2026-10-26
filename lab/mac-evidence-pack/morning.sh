#!/bin/sh
# Exact morning command. Run from any directory.
# Creates $HOME/mac-evidence-pack/pack-clone or refuses if that path already
# holds something this pack did not create. Never git-checkouts an existing
# spike clone.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -f "$here/pack.py" ]; then
  echo "REFUSED: pack.py is missing next to morning.sh" >&2
  exit 2
fi
exec python3 -I "$here/pack.py" --bootstrap "$@"
