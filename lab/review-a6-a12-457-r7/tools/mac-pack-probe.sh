#!/bin/sh
# Read-only probe of Mac pack commands. Never rm -rf a host path.
set -eu
SUBJECT=${1:-/tmp/pr457-r7}
printf 'uname %s\n' "$(uname -s)"
printf 'subject HEAD %s\n' "$(git -C "$SUBJECT" rev-parse HEAD)"
if [ "$(uname -s)" = Darwin ]; then
  printf 'Mac owner journeys would run here; this r7 host is Linux\n'
else
  printf 'Mac owner A6/A12 journeys: NOT RUN (need macOS)\n'
fi
# Confirm run.sh quotes the isolated pack only.
if grep -n 'rm -rf "\$PACK_TMP"' "$SUBJECT/lab/a6-a12-evidence-fix/run.sh" \
  "$SUBJECT/lab/a6-a12-evidence-fix/mac-pack.sh"; then
  printf 'mac-pack cleanup quotes PACK_TMP only\n'
else
  printf 'WARNING: isolated rm -rf "$PACK_TMP" not found\n'
fi
if grep -n 'rm -rf /tmp' "$SUBJECT/lab/a6-a12-evidence-fix/run.sh" \
  "$SUBJECT/lab/a6-a12-evidence-fix/mac-pack.sh"; then
  printf 'WARNING: host /tmp rm found\n'
else
  printf 'no host /tmp rm in pack scripts\n'
fi
