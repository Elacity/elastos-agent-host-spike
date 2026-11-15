#!/bin/bash
# The journey's planted faults: each run of run-journey.sh with one fault planted must fail, at the check named
# here, with the named refusal or page message in its detail. A plant that leaves the journey passing, or fails it
# elsewhere, is reported.
# Usage: falsify-journey.sh <checkout> <work folder (new, empty)>
# Each row: plant|expected FAILED: line|one or more strings its failure detail must carry.
set -u
WT="$1"; WORK="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -e "$WORK" ] && { echo "the work folder must be new: $WORK"; exit 2; }
mkdir -p "$WORK" || exit 2
missed=0
while IFS='|' read -r plant expect needle2 needle3 needle4; do
  JOURNEY_PLANT="$plant" bash "$HERE/run-journey.sh" "$WT" "$WORK/$plant" > "$WORK/$plant.log" 2>&1
  code=$?
  if [ "$code" != 0 ] && grep -q "JOURNEY FAILED" "$WORK/$plant.log" && grep -qF "$expect" "$WORK/$plant.log" \
    && { [ -z "$needle2" ] || grep -qF "$needle2" "$WORK/$plant.log"; } \
    && { [ -z "$needle3" ] || grep -qF "$needle3" "$WORK/$plant.log"; } \
    && { [ -z "$needle4" ] || grep -qF "$needle4" "$WORK/$plant.log"; }; then
    echo "RED: $plant -> $expect"
  else
    echo "NOT AS EXPECTED: $plant (exit $code)"; grep -E "^(ok|FAILED):" "$WORK/$plant.log" | head -10; missed=1
  fi
done <<'ROWS'
wrong-content-cid|FAILED: Home opens the game by its CID|bundle_cid_mismatch|"non_2xx":true|"token_field":"none"
token-dropped|FAILED: the page boots the game (#status hidden and empty, #power-led on)|Open GBA from Home or Library.
rom-record-mismatch|FAILED: the page boots the game (#status hidden and empty, #power-led on)|gba_launch_rom_hash_mismatch
content-byte-flipped|FAILED: Home opens the game by its CID|bundle_cid_mismatch|"non_2xx":true|"token_field":"none"
ROWS
[ "$missed" = 0 ] && echo "all 4 journey plants red where expected" || echo "SOME JOURNEY PLANTS NOT AS EXPECTED"
exit $missed
