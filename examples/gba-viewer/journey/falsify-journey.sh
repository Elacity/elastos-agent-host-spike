#!/bin/bash
# The journey's planted faults: each run of run-journey.sh with one fault planted must fail, at the check named
# here, with the named refusal or page message in THAT check's own detail. A needle must appear in the first
# "FAILED:" line itself (journey-browser prints the detail on that line); a build, stage or plant error before
# that line, or a missing earlier pass, makes the row unexpected.
# Usage: falsify-journey.sh <checkout> <work folder (new, empty)>
# Each row: plant|expected FAILED: line|one or more strings its detail must carry|an ok: line that must precede it.
set -u
WT="$1"; WORK="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -e "$WORK" ] && { echo "the work folder must be new: $WORK"; exit 2; }
mkdir -p "$WORK" || exit 2
missed=0
has() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }
while IFS='|' read -r plant expect needle2 needle3 needle4 ok_before; do
  log="$WORK/$plant.log"
  JOURNEY_PLANT="$plant" bash "$HERE/run-journey.sh" "$WT" "$WORK/$plant" > "$log" 2>&1
  code=$?
  failed_at=$(grep -n -m1 '^FAILED: ' "$log" | cut -d: -f1)
  failed_line=$( [ -n "$failed_at" ] && sed -n "${failed_at}p" "$log" )
  # The FAILED line's own detail: everything after the exact check name. Empty means another check failed first.
  detail=""
  case "${failed_line:-}" in
    "$expect ("*) detail="${failed_line#"$expect"}" ;;
  esac
  prior=$( [ -n "$failed_at" ] && sed -n "1,$((failed_at - 1))p" "$log" )
  ok=1
  [ "$code" != 0 ] || ok=0
  grep -q "JOURNEY FAILED" "$log" || ok=0
  { [ -n "$failed_at" ] && [ -n "$detail" ]; } || ok=0
  for needle in "$needle2" "$needle3" "$needle4"; do
    [ -z "$needle" ] || has "$detail" "$needle" || ok=0
  done
  if [ -n "$prior" ] && printf '%s\n' "$prior" | grep -Eq 'NOT AS EXPECTED|did not build|was not staged|did not apply|exit=[1-9]'; then
    ok=0
  fi
  if [ -n "$ok_before" ]; then
    grep -n -Fx -- "$ok_before" "$log" | cut -d: -f1 \
      | awk -v f="$failed_at" '$1 + 0 < f + 0' | grep -q . || ok=0
  fi
  if [ "$ok" = 1 ]; then
    echo "RED: $plant -> $expect"
  else
    echo "NOT AS EXPECTED: $plant (exit $code)"; grep -E "^(ok|FAILED):" "$log" | head -10; missed=1
  fi
done <<'ROWS'
wrong-content-cid|FAILED: Home opens the game by its CID|bundle_cid_mismatch|"non_2xx":true|"token_field":"none"|
token-dropped|FAILED: the page boots the game (#status hidden and empty, #power-led on)|Open GBA from Home or Library.|||ok: Home opens the game by its CID
rom-record-mismatch|FAILED: the page boots the game (#status hidden and empty, #power-led on)|gba_launch_rom_hash_mismatch|||ok: Home opens the game by its CID
content-byte-flipped|FAILED: Home opens the game by its CID|bundle_cid_mismatch|"non_2xx":true|"token_field":"none"|
ROWS
[ "$missed" = 0 ] && echo "all 4 journey plants red where expected" || echo "SOME JOURNEY PLANTS NOT AS EXPECTED"
exit $missed
