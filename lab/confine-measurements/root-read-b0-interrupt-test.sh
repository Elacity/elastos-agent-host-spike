#!/bin/bash
# Proves the plant restores the profile when it is interrupted after the plant.
# Starts the wallet `data` plant, waits until the profile differs from HEAD,
# sends SIGTERM, then checks the profile and the tree are restored.
set -u
root=$(cd "$(dirname "$0")/../.." && pwd) || exit 2
cd "$root" || exit 2
file=capsules/wallet-provider/confine.sb
backup=$(mktemp) || exit 2
trap 'rm -f "$backup"' EXIT
cp -p "$file" "$backup" || exit 2
./lab/confine-measurements/root-read-b0-plant.sh wallet data &
pid=$!
deadline=$((SECONDS + 120))
until ! cmp -s "$file" "$backup"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "plant exited before it planted the profile" >&2
    wait "$pid" 2>/dev/null
    exit 3
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "profile was not planted before the deadline" >&2
    kill -TERM "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    exit 4
  fi
  sleep 0.05
done
echo "profile planted; sending SIGTERM to the plant"
kill -TERM "$pid"
wait "$pid"
rc=$?
cmp "$backup" "$file" || { echo "profile differs after interruption" >&2; exit 5; }
git diff --quiet -- "$file" || { echo "profile changed after interruption" >&2; exit 6; }
echo "interrupted plant exit=$rc; profile restored and tree clean"
exit 0
