#!/bin/bash
# The photo viewer's journey, end to end, through the real Runtime and gateway: a photo set named by its CID is
# opened from Home by a signed-in person, and its pictures are shown by the photo viewer's page in Chromium; a set
# whose bytes no longer match its CID, and a CID never staged, are each refused by name.
#
# What runs: the built `elastos` binary as the gateway (it holds the host lock) and as Home's Runtime (`serve`,
# a subordinate of the gateway, writing its coordinates where Home's open reads them, as the Runtime Home starts
# for itself does), on one throwaway data folder; Home installed from this checkout's `capsules/home`; three
# bundles, each signed by a publisher of its own made for this run only: the photo core (the reference artifact,
# checked against its recorded hash), the photo viewer's page (pinning the core) and a photo set of three pictures
# under `images/` (pinning the page). The browser step is `journey-browser.mjs`.
#
# Usage: run-journey.sh <checkout> <work folder (new, empty)> <photo core .wasm, built at its reference hash>
# JOURNEY_PLANT=<name> plants one fault, for falsify-journey.sh only: token-dropped, page-pins-another-core,
# set-changed, old-routes.
# Needs: the binary and the storage provider built in the checkout (elastos/target/debug/elastos and
# localhost-provider; `serve` refuses to start without the latter); node; Playwright with Chromium
# (ELASTOS_PLAYWRIGHT_MODULE, or the checkout's elastos/tools/browser-playwright-engine).
set -u
PLANT="${JOURNEY_PLANT:-}"
RUSTC_VERSION=$(rustc --version 2>/dev/null)
NODE=$(command -v node)
# Playwright's browsers are found in the real HOME's cache, looked up before HOME is pointed elsewhere.
case "$(uname)" in Darwin) BROWSERS="$HOME/Library/Caches/ms-playwright" ;; *) BROWSERS="$HOME/.cache/ms-playwright" ;; esac
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$BROWSERS}"
WT=$(cd "$1" && pwd); WORK="$2"; CORE_WASM="$3"
BIN="$WT/elastos/target/debug/elastos"
PV="$WT/examples/photo-viewer"
HERE="$PV/journey"
STORAGE="$WT/elastos/target/debug/localhost-provider"
[ -x "$BIN" ] || { echo "no binary at $BIN"; exit 3; }
[ -x "$STORAGE" ] || { echo "no storage provider at $STORAGE (cargo build -p localhost-provider)"; exit 3; }
[ -e "$WORK" ] && { echo "the work folder must be new: $WORK"; exit 2; }
mkdir -p "$WORK/home" "$WORK/evidence" || exit 2
WORK=$(cd "$WORK" && pwd)
export HOME="$WORK/home"
unset XDG_DATA_HOME
case "$(uname)" in
  Darwin) DATA="$HOME/Library/Application Support/elastos" ;;
  *) DATA="$HOME/.local/share/elastos" ;;
esac
mkdir -p "$DATA"
chmod 700 "$HOME" "$DATA"  # owner-only, as an install makes them; Home refuses a person's root under a looser parent
step() { echo; echo "=== $*"; }
failed=0
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; }
trap cleanup EXIT
as_expected() { echo "AS EXPECTED ($1)"; }
not_expected() { echo "NOT AS EXPECTED ($1)"; failed=1; }
cid_of() { "$BIN" stage-bundle "$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["cid"])'; }
sign() { # <cid> <key name> <signature file>
  printf %s "$1" | "$BIN" sign-payload --domain elastos.capsule.bundle.v1 --key "$WORK/$2.key" | python3 -I -c '
import json, sys
signed = json.load(sys.stdin)
json.dump({"schema": "elastos.capsule.bundle-signature/v1", "cid": sys.argv[1],
           "signer_did": signed["signer_did"], "signature": signed["signature"]}, open(sys.argv[2], "w"))' "$1" "$3"; }
pub_of() { python3 -I - "$1" <<'PYEOF'
import json, sys
did = json.load(open(sys.argv[1]))["signer_did"]
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n = 0
for ch in did[len("did:key:z"):]:
    n = n * 58 + alphabet.index(ch)
raw = n.to_bytes(34, "big")
assert raw[:2] == b"\xed\x01", raw[:2]
print(raw[2:].hex())
PYEOF
}
free_port() { python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
manifest() { # <out> <python expression over m (the source manifest, or {})> [source manifest]
  python3 -I - "$@" <<'PYEOF'
import json, sys
out, expr = sys.argv[1], sys.argv[2]
m = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else {}
exec(expr)
json.dump(m, open(out, "w"), indent=2)
PYEOF
}

step "machine, head, binary, tools"
uname -sm; echo "$RUSTC_VERSION"; echo "node $("$NODE" --version)"
git -C "$WT" rev-parse HEAD
git -C "$WT" status --porcelain | wc -l | sed 's/^ *//; s/^/changed paths: /'
ls -l "$BIN" | awk '{print $5, $6, $7, $8}'

step "1. the photo core is the reference artifact"
REF=$(grep -E '^photo-viewer ' "$WT/examples/capsule-kit/repro/recorded-hashes.txt" | awk '{print $2}')
GOT=$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$CORE_WASM")
echo "recorded: $REF"; echo "this one: $GOT"
[ -n "$REF" ] && [ "$REF" = "$GOT" ] && as_expected "the core's bytes are the recorded ones" || { not_expected "the core is not the reference artifact"; exit 1; }

step "2. Home and the storage provider installed in the throwaway data folder, from this checkout"
# As `elastos setup` lays them out: Home's capsule under capsules/, the storage provider under bin/, each listed
# in components.json (the provider with this checkout's own entry and the checksum of the binary built here).
mkdir -p "$DATA/capsules" "$DATA/bin" && cp -R "$WT/capsules/home" "$DATA/capsules/home" && cp "$STORAGE" "$DATA/bin/localhost-provider"
python3 -I - "$DATA/components.json" "$WT/components.json" "$DATA/bin/localhost-provider" <<'PYEOF'
import hashlib, json, platform, sys
out, source, binary = sys.argv[1:4]
plat = {"Darwin": "darwin", "Linux": "linux"}[platform.system()] + "-" + {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}[platform.machine()]
storage = json.load(open(source))["external"]["localhost-provider"]
storage["platforms"] = {plat: dict(storage["platforms"][plat], checksum="sha256:" + hashlib.sha256(open(binary, "rb").read()).hexdigest())}
json.dump({"external": {"home": {"install_path": "capsules/home", "platforms": {}}, "localhost-provider": storage},
           "capsules": {}, "profiles": {}}, open(out, "w"), indent=2)
print("platform", plat)
PYEOF
ls "$DATA/capsules/home" "$DATA/bin"

step "3. three publishers, a key each for this run only; the core, the page and two photo sets"
for who in of-core of-page of-set; do python3 -I -c 'import os; print(os.urandom(32).hex())' > "$WORK/$who.key"; chmod 600 "$WORK/$who.key"; done
mkdir -p "$WORK/core" "$WORK/page" "$WORK/set/images" "$WORK/changed/images" "$WORK/never/images"
cp "$PV/capsule.json" "$WORK/core/capsule.json"; cp "$CORE_WASM" "$WORK/core/photo-viewer.component.wasm"
CORE=$(cid_of "$WORK/core"); sign "$CORE" of-core "$WORK/core.sig.json"
cp -R "$PV/surface/browser" "$WORK/page/browser"
PINNED_CORE="$CORE"
[ "$PLANT" = page-pins-another-core ] && { PINNED_CORE=$(cid_of "$PV/surface"); echo "PLANT: the page pins another CID as its core"; }
[ "$PLANT" = old-routes ] && { sed -i.bak -e 's#/launch/output/playlist.json#/playlist#' -e 's#/launch/content/#/item/#' "$WORK/page/browser/photos.js" && rm "$WORK/page/browser/photos.js.bak"; echo "PLANT: the page reads the routes it read before D2b"; }
manifest "$WORK/page/capsule.json" "m['requires'] = [{'name': 'photo-viewer', 'kind': 'capsule', 'cid': '$PINNED_CORE'}]" "$PV/surface/capsule.json"
PAGE=$(cid_of "$WORK/page"); sign "$PAGE" of-page "$WORK/page.sig.json"
PICS="$PV/host-test/fixtures/stand-in-photo-set/images"
for folder in set changed never; do cp "$PICS/01.png" "$PICS/02.jpg" "$PICS/03.webp" "$WORK/$folder/images/"; done
for folder in set changed never; do
  manifest "$WORK/$folder/capsule.json" "m.update({'schema': 'elastos.capsule/v1', 'name': 'photos-$folder', 'version': '0.1.0', 'role': 'content', 'type': 'data', 'entrypoint': 'images/01.png', 'requires': [{'name': 'image-viewer', 'kind': 'capsule', 'cid': '$PAGE'}]})"
done
SET=$(cid_of "$WORK/set"); sign "$SET" of-set "$WORK/set.sig.json"
CHANGED=$(cid_of "$WORK/changed"); sign "$CHANGED" of-set "$WORK/changed.sig.json"
NEVER=$(cid_of "$WORK/never")
K_CORE=$(pub_of "$WORK/core.sig.json"); K_PAGE=$(pub_of "$WORK/page.sig.json"); K_SET=$(pub_of "$WORK/set.sig.json")
printf 'dev_mode = true\ntrusted_keys = ["%s", "%s", "%s"]\n' "$K_SET" "$K_PAGE" "$K_CORE" > "$DATA/config.toml"
for b in core page set changed; do
  "$BIN" stage-bundle "$WORK/$b" --signature "$WORK/$b.sig.json" > /dev/null 2>> "$WORK/stage.err"; echo "staged $b, exit=$?"
done
echo "core:    $CORE"; echo "page:    $PAGE"; echo "set:     $SET"; echo "changed: $CHANGED"; echo "never staged: $NEVER"
[ "$K_CORE" != "$K_PAGE" ] && [ "$K_PAGE" != "$K_SET" ] && [ "$K_CORE" != "$K_SET" ] && as_expected "three different publishers" || not_expected "the publishers are not three"
[ -d "$DATA/capsules/by-cid/$NEVER" ] && not_expected "the CID never staged is in the store" || as_expected "the CID never staged is not in the store"
# One byte of one picture changed where the second set is kept: its CID no longer names its bytes.
SLOT=$(find "$DATA/capsules/by-cid/$CHANGED" -name 02.jpg | head -1)
chmod u+w "$SLOT"  # the store keeps a staged slot read-only; this run changes it on purpose
python3 -I - "$SLOT" <<'PYEOF'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
data[len(data) // 2] ^= 0x01
open(path, "wb").write(bytes(data))
PYEOF
echo "changed one byte of $(basename "$SLOT") in the second set's slot"
if [ "$PLANT" = set-changed ]; then
  GOOD=$(find "$DATA/capsules/by-cid/$SET" -name 01.png | head -1); chmod u+w "$GOOD"
  python3 -I -c 'import sys; p = sys.argv[1]; d = bytearray(open(p, "rb").read()); d[-1] ^= 1; open(p, "wb").write(bytes(d))' "$GOOD"
  echo "PLANT: one byte of the good set's 01.png changed too"
fi

step "4. the gateway, and Home's Runtime under it"
GW_PORT=$(free_port); RT_PORT=$(free_port)
"$BIN" gateway --addr "127.0.0.1:$GW_PORT" > "$WORK/gateway.log" 2>&1 & pids+=($!)
for i in $(seq 1 60); do curl -fsS "http://127.0.0.1:$GW_PORT/healthz" > /dev/null 2>&1 && break; sleep 1; done
curl -fsS "http://127.0.0.1:$GW_PORT/healthz" > /dev/null 2>&1 && as_expected "the gateway answers on $GW_PORT" || { not_expected "the gateway did not start"; tail -20 "$WORK/gateway.log"; exit 1; }
ELASTOS_ALLOW_SUBORDINATE_RUNTIME_HOST=1 ELASTOS_RUNTIME_COORDS_FILE="$DATA/home-runtime-coords.json" \
  "$BIN" serve --addr "127.0.0.1:$RT_PORT" > "$WORK/runtime.log" 2>&1 & pids+=($!)
for i in $(seq 1 60); do [ -s "$DATA/home-runtime-coords.json" ] && curl -fsS "http://127.0.0.1:$RT_PORT/api/health" > /dev/null 2>&1 && break; sleep 1; done
[ -s "$DATA/home-runtime-coords.json" ] && as_expected "Home's Runtime answers on $RT_PORT and wrote its coordinates where Home's open reads them" || { not_expected "Home's Runtime did not start"; tail -20 "$WORK/runtime.log"; exit 1; }

step "5. in Chromium: sign in to Home, open the set by its CID, the pictures shown; the two refusals"
JOURNEY_PLANT="$PLANT" BASE="http://localhost:$GW_PORT" SET_CID="$SET" CHANGED_CID="$CHANGED" NEVER_CID="$NEVER" EVIDENCE="$WORK/evidence" \
  PLAYWRIGHT_FALLBACK="$WT/elastos/tools/browser-playwright-engine/node_modules/playwright" \
  "$NODE" "$HERE/journey-browser.mjs"
code=$?; echo "exit=$code"
[ "$code" = 0 ] && as_expected "the browser journey" || not_expected "the browser journey"

step "result"
[ "$failed" = 0 ] && echo "JOURNEY PASSED" || echo "JOURNEY FAILED"
exit $failed
