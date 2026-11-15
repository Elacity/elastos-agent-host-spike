#!/bin/bash
# The GBA viewer's journey, end to end, through the real Runtime and gateway: the
# product page and the product ROM, each named by its CID, are opened from Home by
# a signed-in person; the page boots the real game the core recorded, and its
# frames advance. A wrong content CID, a page loaded without its token, a core
# whose record differs from the ROM's bytes by one hex digit, and ROM bytes changed
# in the store are each refused or shown by name.
#
# What runs: the built `elastos` binary as the gateway (it holds the host lock) and
# as Home's Runtime (`serve`, a subordinate of the gateway, writing its coordinates
# where Home's open reads them), on one throwaway data folder; Home installed from
# this checkout's `capsules/home`; the GBA core built from a throwaway copy of
# `examples/gba-viewer/core` under the work folder with the repo's
# `scripts/build-component-capsule.sh`; three bundles, each signed by a publisher of its own
# made for this run only: the core, the product page (`capsules/gba-emulator/browser`,
# pinning the core) and the product ROM (`capsules/gba-ucity/ucity.gba`, pinning the
# page). The page assets and the ROM are staged byte-for-byte by
# `examples/gba-viewer/prepare_bundles.py`, which derives both manifests. The browser
# step is `journey-browser.mjs`.
#
# Usage: run-journey.sh <checkout> <work folder (new, empty)>
# JOURNEY_PLANT=<name> plants one fault, for falsify-journey.sh only:
# wrong-content-cid, token-dropped, rom-record-mismatch, content-byte-flipped.
# Needs: `elastos` and `localhost-provider` built in the checkout (in
# ${CARGO_TARGET_DIR:-elastos/target}/debug); the wasm32-unknown-unknown target; node;
# Playwright with Chromium (ELASTOS_PLAYWRIGHT_MODULE, or the checkout's
# elastos/tools/browser-playwright-engine).
set -u
PLANT="${JOURNEY_PLANT:-}"
RUSTC_VERSION=$(rustc --version 2>/dev/null)
NODE=$(command -v node)
# Playwright's browsers are found in the real HOME's cache, looked up before HOME is pointed elsewhere.
case "$(uname)" in Darwin) BROWSERS="$HOME/Library/Caches/ms-playwright" ;; *) BROWSERS="$HOME/.cache/ms-playwright" ;; esac
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$BROWSERS}"
WT=$(cd "$1" && pwd); WORK="$2"
TARGET_DIR="${CARGO_TARGET_DIR:-$WT/elastos/target}"
case "$TARGET_DIR" in /*) ;; *) TARGET_DIR="$(cd "$TARGET_DIR" && pwd)" ;; esac
export CARGO_TARGET_DIR="$TARGET_DIR"
BIN="$TARGET_DIR/debug/elastos"
STORAGE="$TARGET_DIR/debug/localhost-provider"
GV="$WT/examples/gba-viewer"
HERE="$GV/journey"
CORE_ART_NAME="gba-viewer-core.component.wasm"
[ -x "$BIN" ] || { echo "no binary at $BIN"; exit 3; }
[ -x "$STORAGE" ] || { echo "no storage provider at $STORAGE (cargo build -p localhost-provider)"; exit 3; }
[ -e "$WORK" ] && { echo "the work folder must be new: $WORK"; exit 2; }
mkdir -p "$WORK/home" "$WORK/evidence" || exit 2
WORK=$(cd "$WORK" && pwd)
# The throwaway HOME must not hide the real toolchain: cargo and rustup keep their own homes here, looked up
# before HOME is pointed elsewhere (the wasm32 target lives under the real rustup home).
REAL_HOME="$HOME"
export CARGO_HOME="${CARGO_HOME:-$REAL_HOME/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$REAL_HOME/.rustup}"
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

step "machine, head, binary, tools"
uname -sm; echo "$RUSTC_VERSION"; echo "node $("$NODE" --version)"
git -C "$WT" rev-parse HEAD
git -C "$WT" status --porcelain | wc -l | sed 's/^ *//; s/^/changed paths: /'
ls -l "$BIN" | awk '{print $5, $6, $7, $8}'

step "1. the GBA core, built from a throwaway copy in the work folder"
# The build writes its component beside the source, so the source is always a copy under $WORK: the checkout
# keeps no build output. The copy's capsule-kit path dependency points at this checkout's kit.
CORE_TREE="$WORK/core"
mkdir -p "$CORE_TREE/examples/gba-viewer"
cp -R "$GV/core" "$CORE_TREE/examples/gba-viewer/core"
rm -f "$CORE_TREE/examples/gba-viewer/core/$CORE_ART_NAME"
ln -s "$WT/examples/capsule-kit" "$CORE_TREE/examples/capsule-kit"
CORE_SRC="$CORE_TREE/examples/gba-viewer/core"
if [ "$PLANT" = rom-record-mismatch ]; then
  # The plant lives only in this copy: the checkout's core source is read, never changed.
  python3 -I - "$CORE_SRC/src/lib.rs" <<'PYEOF' || { not_expected "the plant did not apply"; exit 1; }
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
anchor = "    let sha256 = digest.sha256;"
plant = """    // PLANT: the record's sha256 differs from the Runtime's digest by one hex digit.
    let mut digits: Vec<char> = digest.sha256.chars().collect();
    digits[0] = if digits[0] == '0' { '1' } else { '0' };
    let sha256: String = digits.into_iter().collect();"""
if text.count(anchor) != 1:
    raise SystemExit("the plant's anchor is not once in the core source")
path.write_text(text.replace(anchor, plant))
print("PLANT: the core copies the Runtime's digest and alters one hex digit")
PYEOF
  CORE_TARGET="$TARGET_DIR/plant-core"
  BUILD_LABEL="the planted core"
else
  CORE_TARGET="$TARGET_DIR/core"
  BUILD_LABEL="the core"
fi
CARGO_TARGET_DIR="$CORE_TARGET" nice -n 10 bash "$WT/scripts/build-component-capsule.sh" "$CORE_SRC" \
  || { not_expected "$BUILD_LABEL did not build"; exit 1; }
CORE_ART="$CORE_SRC/$CORE_ART_NAME"
[ -f "$CORE_ART" ] && as_expected "the core's component exists at $CORE_ART" || { not_expected "the core did not build"; exit 1; }
echo "core sha256: $(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$CORE_ART")"

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

step "3. three publishers, a key each for this run only; the core, the product page and the product ROM by CID"
for who in of-core of-page of-content; do python3 -I -c 'import os; print(os.urandom(32).hex())' > "$WORK/$who.key"; chmod 600 "$WORK/$who.key"; done
mkdir -p "$WORK/core-bundle" "$WORK/wrong"
cp "$CORE_SRC/capsule.json" "$WORK/core-bundle/capsule.json"
cp "$CORE_ART" "$WORK/core-bundle/$CORE_ART_NAME"
CORE=$(cid_of "$WORK/core-bundle"); sign "$CORE" of-core "$WORK/bundles-core.sig.json"
# The page's CID is the CID of its manifest AND its assets, so the page folder is staged once with a placeholder
# valid-form content pin to learn it; the content manifest is then derived from the real page CID and staged again.
python3 -I "$GV/prepare_bundles.py" --out "$WORK/bundles" --core-cid "$CORE" \
  --core-name gba-viewer-core --page-cid "$CORE" || { not_expected "the page was not staged"; exit 1; }
PAGE=$(cid_of "$WORK/bundles/page"); sign "$PAGE" of-page "$WORK/bundles-page.sig.json"
python3 -I "$GV/prepare_bundles.py" --out "$WORK/bundles" --core-cid "$CORE" \
  --core-name gba-viewer-core --page-cid "$PAGE" || { not_expected "the content was not staged"; exit 1; }
STAGED_PAGE=$(cid_of "$WORK/bundles/page"); CONTENT=$(cid_of "$WORK/bundles/content")
sign "$CONTENT" of-content "$WORK/bundles-content.sig.json"
echo "core:    $CORE"; echo "page:    $PAGE"; echo "content: $CONTENT ($(wc -c < "$WORK/bundles/content/ucity.gba" | sed 's/^ *//') bytes)"
[ "$STAGED_PAGE" = "$PAGE" ] && as_expected "the staged page keeps the CID derived for it" || not_expected "the staged page has another CID"
mkdir -p "$DATA/capsules/by-cid"
K_CORE=$(pub_of "$WORK/bundles-core.sig.json"); K_PAGE=$(pub_of "$WORK/bundles-page.sig.json"); K_CONTENT=$(pub_of "$WORK/bundles-content.sig.json")
printf 'dev_mode = true\ntrusted_keys = ["%s", "%s", "%s"]\n' "$K_CORE" "$K_PAGE" "$K_CONTENT" > "$DATA/config.toml"
# The core is staged from the bundle source this run built (never from the copy prepare_bundles made), so a planted
# core is the one staged. The page and the content come from prepare_bundles' output.
"$BIN" stage-bundle "$WORK/core-bundle" --signature "$WORK/bundles-core.sig.json" > /dev/null 2>> "$WORK/stage.err"; echo "staged core, exit=$?"
for b in page content; do
  "$BIN" stage-bundle "$WORK/bundles/$b" --signature "$WORK/bundles-$b.sig.json" > /dev/null 2>> "$WORK/stage.err"; echo "staged $b, exit=$?"
done
[ "$K_CORE" != "$K_PAGE" ] && [ "$K_PAGE" != "$K_CONTENT" ] && [ "$K_CORE" != "$K_CONTENT" ] && as_expected "three different publishers" || not_expected "the publishers are not three"

ASK_CID="$CONTENT"
if [ "$PLANT" = wrong-content-cid ]; then
  # A valid CID the store never staged, given the page's files in its slot: the slot no longer recomputes to it.
  cp "$WORK/bundles/content/ucity.gba" "$WORK/wrong/ucity.gba"
  python3 -I - "$WORK/bundles/content/capsule.json" "$WORK/wrong/capsule.json" <<'PYEOF'
import json, sys
manifest = json.load(open(sys.argv[1]))
manifest["name"] = "gba-ucity-never-staged"
json.dump(manifest, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PYEOF
  ASK_CID=$(cid_of "$WORK/wrong")
  cp -R "$DATA/capsules/by-cid/$PAGE" "$DATA/capsules/by-cid/$ASK_CID"
  echo "PLANT: the store's slot for $ASK_CID holds the page's files"
fi
if [ "$PLANT" = content-byte-flipped ]; then
  # One byte of the ROM changed where it is kept: its CID no longer names its bytes.
  SLOT=$(find "$DATA/capsules/by-cid/$CONTENT" -name ucity.gba | head -1)
  chmod u+w "$SLOT"  # the store keeps a staged slot read-only; this run changes it on purpose
  python3 -I - "$SLOT" <<'PYEOF'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
data[len(data) // 2] ^= 0x01
open(path, "wb").write(bytes(data))
PYEOF
  echo "PLANT: one byte of $(basename "$SLOT") in the content's slot changed"
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

step "5. in Chromium: sign in to Home, open the game by its CID, the real ROM boots and frames advance"
JOURNEY_PLANT="$PLANT" BASE="http://localhost:$GW_PORT" CONTENT_CID="$ASK_CID" PAGE_CID="$PAGE" EVIDENCE="$WORK/evidence" \
  PLAYWRIGHT_FALLBACK="$WT/elastos/tools/browser-playwright-engine/node_modules/playwright" \
  "$NODE" "$HERE/journey-browser.mjs"
code=$?; echo "exit=$code"
[ "$code" = 0 ] && as_expected "the browser journey" || not_expected "the browser journey"

step "result"
[ "$failed" = 0 ] && echo "JOURNEY PASSED" || echo "JOURNEY FAILED"
exit $failed
