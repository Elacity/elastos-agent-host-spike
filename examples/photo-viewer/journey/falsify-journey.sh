#!/bin/bash
# The journey's planted faults: each run of run-journey.sh with one fault planted must fail, at the check named
# here. A plant that leaves the journey passing, or fails it elsewhere, is reported.
# Usage: falsify-journey.sh <checkout> <work folder (new, empty)> <photo core .wasm, built at its reference hash>
set -u
WT="$1"; WORK="$2"; CORE_WASM="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -e "$WORK" ] && { echo "the work folder must be new: $WORK"; exit 2; }
mkdir -p "$WORK" || exit 2
missed=0
for row in \
  "token-dropped|FAILED: the three pictures are shown" \
  "page-pins-another-core|FAILED: Home opens the set by its CID" \
  "set-changed|FAILED: Home opens the set by its CID" \
  "old-routes|FAILED: the three pictures are shown"; do
  plant=${row%%|*}; expect=${row#*|}
  JOURNEY_PLANT="$plant" bash "$HERE/run-journey.sh" "$WT" "$WORK/$plant" "$CORE_WASM" > "$WORK/$plant.log" 2>&1
  code=$?
  if [ "$code" != 0 ] && grep -q "JOURNEY FAILED" "$WORK/$plant.log" && grep -qF "$expect" "$WORK/$plant.log"; then
    echo "RED: $plant -> $expect"
  else
    echo "NOT AS EXPECTED: $plant (exit $code)"; grep -E "^(ok|FAILED):" "$WORK/$plant.log" | head -10; missed=1
  fi
done
[ "$missed" = 0 ] && echo "all 4 journey plants red where expected" || echo "SOME JOURNEY PLANTS NOT AS EXPECTED"
exit $missed
