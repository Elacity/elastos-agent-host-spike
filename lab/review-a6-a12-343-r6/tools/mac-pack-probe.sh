#!/bin/sh
# Read-only probe of the author's Mac pack cleanup. Does not run rm.
set -eu
SUBJECT=${1:-/tmp/pr343-r6}
RUN="$SUBJECT/lab/a6-a12-evidence-fix/run.sh"
MAC="$SUBJECT/lab/a6-a12-evidence-fix/mac-pack.sh"
printf 'mac-pack probe at %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"
printf 'uname=%s\n' "$(uname -s)"
for f in "$RUN" "$MAC"; do
  if [ ! -f "$f" ]; then
    printf 'MISSING %s\n' "$f"
    continue
  fi
  printf '\n== %s ==\n' "$f"
  grep -n 'rm -rf' "$f" || true
  grep -n 'PACK_TMP\|PACK=' "$f" || true
  if grep -q 'rm -rf "\$PACK_TMP"' "$f" || grep -q 'rm -rf "\$PACK"' "$f"; then
    printf 'quoted rm -rf of pack var: OK\n'
  else
    printf 'quoted pack rm not found\n'
  fi
done
if [ "$(uname -s)" = Darwin ]; then
  printf 'Mac owner journeys would run here; this host is Linux.\n'
else
  printf 'Mac owner journeys: NOT RUN (need macOS)\n'
fi
