#!/bin/bash
# B0 measurement plant: apply one macOS root-read form to one provider profile,
# run that provider's named macOS tests, then restore the profile and prove it.
#
# Usage: root-read-b0-plant.sh <did|wallet|model> <data|metadata|none>
#
# The plant replaces the profile's one root-read line with another operation, or
# deletes it for `none`. It refuses when the profile does not hold exactly one
# copy of the line it expects. `mktemp` holds the backup; `cp -p` restores it;
# `cmp` proves the bytes and `git diff --quiet` proves the tree.
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
  tests=(confined_provider_serves_did_operations_under_its_root outside_write_denied outside_read_denied)
  ;;
wallet)
  file=capsules/wallet-provider/confine.sb
  old='(allow file-read* (literal "/"))'
  manifest=capsules/wallet-provider/Cargo.toml
  tests=(confined_provider_serves_wallet_operations_under_its_root confined_outside_write_is_denied confined_outside_read_is_denied)
  ;;
model)
  file=capsules/model-provider/confine.sb
  old='(allow file-read-data (literal "/"))'
  manifest=capsules/model-provider/Cargo.toml
  tests=(model_provider_ops_under_profile model_outside_write_denied model_outside_read_denied)
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

backup=$(mktemp) || exit 2
scratch=$(mktemp) || exit 2
trap 'rm -f "$backup" "$scratch"' EXIT
cp -p "$file" "$backup" || exit 2
if [ -z "$new" ]; then
  awk -v o="$old" '$0==o{next} {print}' "$file" > "$scratch" || exit 2
else
  awk -v o="$old" -v n="$new" '$0==o{$0=n} {print}' "$file" > "$scratch" || exit 2
fi
cat "$scratch" > "$file" || exit 2

status=0
for test in "${tests[@]}"; do
  cargo test --locked --manifest-path "$manifest" --test confine "$test" -- --exact --nocapture
  rc=$?
  echo "plant $provider $mode test $test exit=$rc"
  [ "$rc" -eq 0 ] || status=1
done

cp -p "$backup" "$file"
cmp "$backup" "$file" || status=97
git diff --quiet || status=98
exit "$status"
