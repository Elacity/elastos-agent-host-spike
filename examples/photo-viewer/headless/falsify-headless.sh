#!/bin/bash
# The headless receipt's planted faults, each red at its own named assertion and not at a build error:
#   changed-byte-not-refused  the copy's byte is left alone, so run-headless.sh must fail naming the refusal of the
#                             changed-byte start;
#   altered-cid               one CID changed in a copy of a good receipt, so compare-hashes.py must fail naming it;
#   missing-field             one required field removed from a copy, so compare-hashes.py must name it.
# The plants change no file in the checkout: the first is an environment variable, the other two work on copies
# under the work folder.
# Usage: falsify-headless.sh <checkout> <work folder (new, empty)> <photo core .wasm, at its reference hash>
set -u
WT="$1"; WORK="$2"; CORE_WASM="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -e "$WORK" ] && { echo "the work folder must be new: $WORK"; exit 2; }
mkdir -p "$WORK" || exit 2
WORK=$(cd "$WORK" && pwd)
missed=0
red() { echo "RED: $1 -> $2"; }
not_red() { echo "NOT AS EXPECTED: $1"; missed=1; }

# A good receipt first: the plants are red only against a receipt that is otherwise green.
bash "$HERE/run-headless.sh" "$WT" "$WORK/good" "$CORE_WASM" > "$WORK/good.log" 2>&1
code=$?
if [ "$code" = 0 ] && grep -q "HEADLESS PASSED" "$WORK/good.log" && [ -s "$WORK/good/results.json" ]; then
  echo "GREEN BASELINE: the receipt"
else
  echo "NOT AS EXPECTED: the baseline receipt (exit $code)"; tail -20 "$WORK/good.log"; exit 1
fi

HEADLESS_PLANT=changed-byte-not-refused bash "$HERE/run-headless.sh" "$WT" "$WORK/plant" "$CORE_WASM" > "$WORK/plant.log" 2>&1
code=$?
expect="NOT AS EXPECTED (the changed-byte start is refused (bundle_cid_mismatch))"
if [ "$code" != 0 ] && grep -q "HEADLESS FAILED" "$WORK/plant.log" && grep -qF "$expect" "$WORK/plant.log"; then
  red "changed-byte-not-refused" "$expect"
else
  not_red "changed-byte-not-refused (exit $code)"; grep -E "^(AS|NOT AS) EXPECTED" "$WORK/plant.log"
fi

python3 -I - "$WORK/good/results.json" "$WORK/altered.json" <<'PYEOF'
import json, sys
receipt = json.load(open(sys.argv[1]))
# a well-formed CID that differs in its last character, so the plant is red at the comparison, not the form check
cid = receipt["content_cid"]
receipt["content_cid"] = cid[:-1] + ("a" if cid[-1] != "a" else "b")
json.dump(receipt, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PYEOF
python3 -I "$HERE/compare-hashes.py" "$WORK/altered.json" "$WORK/good/results.json" > "$WORK/altered.log" 2>&1
code=$?
if [ "$code" != 0 ] && grep -q "MISMATCH content_cid" "$WORK/altered.log"; then
  red "altered-cid" "MISMATCH content_cid"
else
  not_red "altered-cid (exit $code)"; cat "$WORK/altered.log"
fi

python3 -I - "$WORK/good/results.json" "$WORK/missing.json" <<'PYEOF'
import json, sys
receipt = json.load(open(sys.argv[1]))
del receipt["component_sha256"]
json.dump(receipt, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PYEOF
python3 -I "$HERE/compare-hashes.py" "$WORK/missing.json" "$WORK/good/results.json" > "$WORK/missing.log" 2>&1
code=$?
if [ "$code" != 0 ] && grep -q "MISMATCH missing field: component_sha256" "$WORK/missing.log"; then
  red "missing-field" "MISMATCH missing field: component_sha256"
else
  not_red "missing-field (exit $code)"; cat "$WORK/missing.log"
fi

python3 -I - "$WORK/good/results.json" "$WORK/badref.json" <<'PYEOF'
import json, sys
receipt = json.load(open(sys.argv[1]))
receipt["changed_start_status"] = 200
receipt["changed_start_refusal"] = ""
json.dump(receipt, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PYEOF
python3 -I "$HERE/compare-hashes.py" "$WORK/good/results.json" "$WORK/badref.json" > "$WORK/badref.log" 2>&1
code=$?
if [ "$code" != 0 ] && grep -q "MISMATCH INVALID reference: changed_start_status 200 is not 400" "$WORK/badref.log"; then
  red "reference-not-refused" "MISMATCH INVALID reference: changed_start_status 200 is not 400"
else
  not_red "reference-not-refused (exit $code)"; cat "$WORK/badref.log"
fi

[ "$missed" = 0 ] && echo "all 4 headless plants red where expected" || echo "SOME HEADLESS PLANTS NOT AS EXPECTED"
exit $missed
