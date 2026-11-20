#!/bin/bash
# B0 measurement plant: apply one macOS root-read form to one provider profile,
# run that provider's whole confine suite, then restore the profile and prove it.
#
# Usage: root-read-b0-plant.sh <did|wallet|model> <data|metadata|none>
#
# The plant replaces the profile's one root-read line with another operation, or
# deletes it for `none`. It refuses when the profile does not hold exactly one
# copy of the line it expects. `mktemp` holds the backup; the EXIT trap restores
# the profile with `cp -p` before it deletes anything, so an interrupted run
# cannot leave a planted profile behind. `cmp` proves the bytes and
# `git diff --quiet` proves the tree. `touch` then gives the restored file a new
# mtime, because the wallet suite embeds its profile with include_str! and a
# preserved older mtime would keep the planted copy inside the next test binary.
set -u
root=$(cd "$(dirname "$0")/../.." && pwd) || exit 2
cd "$root" || exit 2

provider=${1:-}
mode=${2:-''}
case $provider in
did)
  file=capsules/did-provider/confine.sb
  old='(allow file-read* (literal "/"))'
  manifest=capsules/did-provider/Cargo.toml
  ;;
wallet)
  file=capsules/wallet-provider/confine.sb
  old='(allow file-read* (literal "/"))'
  manifest=capsules/wallet-provider/Cargo.toml
  ;;
model)
  file=capsules/model-provider/confine.sb
  old='(allow file-read-data (literal "/"))'
  manifest=capsules/model-provider/Cargo.toml
  ;;
*)
  echo "usage: $0 <did|wallet|model> <data|metadata|none>" >&2
  exit 2
  ;;
esac
case $mode in
data) new='(allow file-read-data (literal "/"))' ;;
metadata) new='(allow file-read-metadata (literal "/"))' ;;
none) new='' ;;
*)
  echo "usage: $0 <did|wallet|model> <data|metadata|none>" >&2
  exit 2
  ;;
esac

held=$(grep -cxF "$old" "$file") || exit 2
if [ "$held" -ne 1 ]; then
  echo "$file must hold one $old; found $held" >&2
  exit 3
fi

backup=
scratch=
child=
status=0
cleanup() {
  rc=$?
  if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then
    kill -TERM "$child" 2>/dev/null
    wait "$child" 2>/dev/null
  fi
  if [ -n "$backup" ] && [ -f "$backup" ]; then
    cp -p "$backup" "$file" || { echo "restore $file failed" >&2; rc=97; }
    touch "$file" 2>/dev/null || rc=97
    cmp "$backup" "$file" || { echo "restore $file differs from its backup" >&2; rc=97; }
    rm -f "$backup"
  fi
  rm -f "$scratch"
  if ! git diff --quiet; then
    echo "worktree changed after restore" >&2
    rc=98
  fi
  if [ "$rc" -eq 0 ] && [ "$status" -ne 0 ]; then rc=$status; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

backup=$(mktemp) || exit 2
scratch=$(mktemp) || exit 2
cp -p "$file" "$backup" || exit 2
if [ -z "$new" ]; then
  awk -v o="$old" '$0==o{next} {print}' "$file" > "$scratch" || exit 2
else
  awk -v o="$old" -v n="$new" '$0==o{$0=n} {print}' "$file" > "$scratch" || exit 2
fi
cat "$scratch" > "$file" || exit 2

cargo test --locked --manifest-path "$manifest" --test confine --no-fail-fast -- --nocapture &
child=$!
wait "$child"
status=$?
child=
echo "plant $provider $mode suite exit=$status"
exit "$status"
