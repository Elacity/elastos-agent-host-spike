#!/bin/bash
# The headless receipt's planted faults, each red at its own named assertion and not at a build error:
#   changed-byte-not-refused  the copy's byte is left alone, so run-headless.sh must fail naming the refusal of the
#                             changed-byte start;
#   altered-cid               one CID changed in a copy of a good receipt, so compare-hashes.py must fail naming it;
#   missing-field             one required field removed from a copy, so compare-hashes.py must name it;
#   given-signature-other-cid a signature file for a different CID in the fourth-argument folder, so run-headless.sh
#                             must stop naming that bundle's signature and make no key.
#   given-signature-bytes-other-cid  the set's signature file keeps this run's CID but carries the signature bytes the
#                             same publisher made for another CID, so staging must refuse it and the run stop naming
#                             the set bundle.
# The plants change no file in the checkout: some are environment variables and the others work on copies under
# the work folder.
# Usage: falsify-headless.sh <checkout> <work folder (new, empty)> <photo core .wasm, at its reference hash>
set -u
WT="$1"; WORK="$2"; CORE_WASM="$3"
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -e "$WORK" ] && { echo "the work folder must be new: $WORK"; exit 2; }
# Refuse a work folder inside the checkout BEFORE anything is made, comparing real paths, as run-headless.sh does.
real_path() { python3 -I -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"; }
case "$(real_path "$WORK")/" in "$(real_path "$WT")"/*) echo "the work folder must be outside the checkout: $WORK"; exit 2 ;; esac
mkdir -p "$(dirname "$WORK")" && mkdir -m 700 "$WORK" || { echo "the work folder could not be made new: $WORK"; exit 2; }  # atomic: never adopt an existing folder
WORK=$(cd -P "$WORK" && pwd -P)
WORK_ID=$(python3 -I -c 'import os, sys; s = os.stat(sys.argv[1], follow_symlinks=False); print("%d:%d" % (s.st_dev, s.st_ino))' "$WORK") || exit 2
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

# A signature file made for a different CID, carried in the fourth-argument folder: the run must stop by name and
# make no key. The baseline run saved its four signature files (signatures/), so they are the good folder here.
cp -R "$WORK/good/signatures" "$WORK/given-sigs"
python3 -I - "$WORK/given-sigs/core.sig.json" <<'PYEOF'
import json, sys
path = sys.argv[1]
sig = json.load(open(path))
cid = sig["cid"]
sig["cid"] = cid[:-1] + ("a" if cid[-1] != "a" else "b")
json.dump(sig, open(path, "w"))
PYEOF
bash "$HERE/run-headless.sh" "$WT" "$WORK/given-plant" "$CORE_WASM" "$WORK/given-sigs" > "$WORK/given-plant.log" 2>&1
code=$?
expect="NOT AS EXPECTED (the given core signature signs this run's core CID)"
if [ "$code" != 0 ] && grep -qF "$expect" "$WORK/given-plant.log" \
   && grep -qF "this run makes no key" "$WORK/given-plant.log" \
   && ! grep -qF "three publishers for this run only" "$WORK/given-plant.log"; then
  red "given-signature-other-cid" "$expect, on the carried-signature branch that makes no key"
else
  not_red "given-signature-other-cid (exit $code)"; tail -5 "$WORK/given-plant.log"
fi

# The set's signature file names this run's set CID, but its signature bytes are the ones the same publisher made for
# the changed copy's CID: only the Runtime's check of the bytes at staging can refuse it.
cp -R "$WORK/good/signatures" "$WORK/bytes-sigs"
python3 -I - "$WORK/bytes-sigs/set.sig.json" "$WORK/bytes-sigs/changed.sig.json" <<'PYEOF'
import json, sys
path, other = sys.argv[1:3]
sig = json.load(open(path))
sig["signature"] = json.load(open(other))["signature"]
json.dump(sig, open(path, "w"))
PYEOF
bash "$HERE/run-headless.sh" "$WT" "$WORK/bytes-plant" "$CORE_WASM" "$WORK/bytes-sigs" > "$WORK/bytes-plant.log" 2>&1
code=$?
expect="NOT AS EXPECTED (the set bundle stages with its signature)"
if [ "$code" != 0 ] && grep -qF "$expect" "$WORK/bytes-plant.log" && grep -qF "this run makes no key" "$WORK/bytes-plant.log"; then
  red "given-signature-bytes-other-cid" "$expect, on the carried-signature branch that makes no key"
else
  not_red "given-signature-bytes-other-cid (exit $code)"; tail -5 "$WORK/bytes-plant.log"
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

HEADLESS_PLANT=home-swapped bash "$HERE/run-headless.sh" "$WT" "$WORK/swapped" "$CORE_WASM" > "$WORK/swapped.log" 2>&1
code=$?
expect="home is not the folder this run made; nothing removed there"
if [ "$code" != 0 ] && grep -q "HEADLESS FAILED (cleanup)" "$WORK/swapped.log" && grep -qF "$expect" "$WORK/swapped.log" \
   && [ -d "$WORK/swapped/home" ] && [ -d "$WORK/swapped/home.moved" ]; then
  red "home-swapped" "$expect"
else
  not_red "home-swapped (exit $code)"; tail -5 "$WORK/swapped.log"
fi
# the plant's moved Home still holds its throwaway device key: removed through this falsifier's own work folder
# (opened as itself, identity checked) by secure_rm.py, never by following a path
# Each folder is bound to the identity the run recorded (plant-ids); a missing or different folder is a failure.
if read -r S_ID M_ID D_ID < "$WORK/swapped/plant-ids" 2>/dev/null && [ -n "$D_ID" ]; then
  python3 -I "$HERE/secure_rm.py" "$WORK/swapped" "$S_ID" --tree home.moved --expect "$M_ID" --tree home --expect "$D_ID" \
    || { echo "NOT AS EXPECTED: the plant's moved Home was not removed"; missed=1; }
else
  echo "NOT AS EXPECTED: the plant recorded no folder identities; its moved Home may remain under $WORK/swapped"; missed=1
fi

[ "$missed" = 0 ] && echo "all 7 headless plants red where expected" || echo "SOME HEADLESS PLANTS NOT AS EXPECTED"
exit $missed
