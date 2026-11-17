#!/bin/bash
# A headless receipt that the photo viewer's signed bundle starts by its CID on this machine, and that a bundle whose
# bytes no longer match its CID is refused by name. No browser and no node: the same signed bundles the browser
# journey stages (`journey/run-journey.sh`) are started through the Runtime's own open route, `POST /api/launch/open`
# on `elastos serve` — the route the journey's gateway calls for the person's open. The person's passkey session is
# not available without a browser, so the open carries the Runtime's local device authority, the same authority
# `elastos home` uses for local tools: a launch token signed by this Home's own device key (`identity/device.key`,
# derived as `elastos-identity` derives it) for the device principal, with a `local:` session and a `grant:local:`
# grant. The token is written to this run's own folder, serves the run's two opens, and is removed; it is never
# printed or recorded. When the run ends, on success or failure, the throwaway Home (its device key and the Runtime's
# attach secret) is removed too, through the work folder opened as itself; if it is no longer the folder this run
# made, nothing is removed there and the run fails (secure_cleanup).
#
# The bundle signatures are either made here or carried here. Without the fourth argument the run makes three
# publisher keys for itself, signs the core, the page, the set and the changed copy, and saves the four signature
# files in <work>/signatures/ for the other machines; the private keys are made only in this run's folder, are
# never copied there, and are removed with the other credentials when the run ends. With the fourth argument, a
# folder holding those four files from an earlier run, no key is made:
# the four files are copied, each must name exactly the CID this run computed for its bundle (the run stops naming
# the file that does not), and their signer keys become this run's trusted keys. So every machine runs ONE signed
# bundle, not four bundles with the same content.
#
# Writes results.json in the run's folder: the host triple, the content, page and core CIDs, the component's
# sha256, the Runtime binary's sha256, the open's answer status and page, the changed-byte refusal name, and for
# the core, the page and the set the signer's public key and the sha256 of its signature file.
# Exit 0 only when the good start answered 200 and the changed-byte start was refused as expected.
#
# Usage: run-headless.sh <checkout> <work folder (new, empty)> <photo core .wasm, at its reference hash> [signature folder]
# Needs: the built binary and storage provider in the checkout's target (CARGO_TARGET_DIR, or elastos/target),
# python3 and curl. HEADLESS_PLANT=changed-byte-not-refused or home-swapped plants one fault, for falsify-headless.sh only.
set -u
umask 077  # every file this run makes (keys, tokens, receipts) is owner-only
PLANT="${HEADLESS_PLANT:-}"
WT=$(cd "$1" && pwd); WORK="$2"; CORE_WASM="$3"; SIGN_SRC="${4:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${CARGO_TARGET_DIR:-}"
[ -n "$TARGET" ] || TARGET="$WT/elastos/target"
TARGET=$(cd "$TARGET" 2>/dev/null && pwd) || { echo "no target folder at ${CARGO_TARGET_DIR:-$WT/elastos/target} (cargo build -p elastos-server --bin elastos; cargo build -p localhost-provider)"; exit 3; }
BIN="$TARGET/debug/elastos"
PV="$WT/examples/photo-viewer"
STORAGE="$TARGET/debug/localhost-provider"
[ -x "$BIN" ] || { echo "no binary at $BIN"; exit 3; }
[ -x "$STORAGE" ] || { echo "no storage provider at $STORAGE (cargo build -p localhost-provider)"; exit 3; }
[ -f "$CORE_WASM" ] || { echo "no photo core at $CORE_WASM"; exit 3; }
[ -z "$SIGN_SRC" ] || [ -d "$SIGN_SRC" ] || { echo "no signature folder at $SIGN_SRC"; exit 3; }
[ -e "$WORK" ] && { echo "the work folder must be new: $WORK"; exit 2; }
# Refuse a work folder inside the checkout BEFORE anything is made, comparing real paths (symlinks resolved).
real_path() { python3 -I -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"; }
case "$(real_path "$WORK")/" in "$(real_path "$WT")"/*) echo "the work folder must be outside the checkout: $WORK"; exit 2 ;; esac
# Cleanup is armed BEFORE the work folder is made, so every later exit runs it.
pids=()
WORK_ID=""; HOME_ID=""
dir_id() { python3 -I -c 'import os, sys; s = os.stat(sys.argv[1], follow_symlinks=False); print("%d:%d" % (s.st_dev, s.st_ino))' "$1"; }
# Removes the credential files and the throwaway Home (device key; attach secret while serve ran) through
# secure_rm.py: the work folder is opened without following a symlink and must be the folder this run made (device and
# inode recorded when it was made); the Home is opened from it, its identity checked on the open descriptor, and
# emptied through that descriptor. If a check fails, nothing is removed there and the run fails, naming what may remain.
secure_cleanup() { # <credentials | all>: "all" also removes the Home, once its processes are gone
  [ -n "$WORK_ID" ] || return 0
  if [ "$1" = all ] && [ -n "$HOME_ID" ]; then
    python3 -I "$HERE/secure_rm.py" "$WORK" "$WORK_ID" --credentials --tree home --expect "$HOME_ID"
  else
    python3 -I "$HERE/secure_rm.py" "$WORK" "$WORK_ID" --credentials
  fi
}
secrets_rm() { secure_cleanup credentials || { failed=1; return 1; }; }
cleanup() {
  for p in ${pids[@]+"${pids[@]}"}; do kill "$p" 2>/dev/null; done; wait 2>/dev/null
  # falsify-headless.sh only: put another folder where the Home was, so cleanup must refuse rather than remove it
  # (it writes the folders' identities, not secrets, to plant-ids so the falsifier can remove the moved Home checked)
  [ "$PLANT" = home-swapped ] && [ -n "$HOME_ID" ] && mv "$WORK/home" "$WORK/home.moved" && mkdir "$WORK/home" \
    && echo "$WORK_ID $HOME_ID $(dir_id "$WORK/home")" > "$WORK/plant-ids" && echo "PLANT: the Home was swapped before cleanup"
  secure_cleanup all || { echo "HEADLESS FAILED (cleanup)"; exit 1; }
}
trap cleanup EXIT
# Made atomically: plain mkdir fails if anything (a folder or a symlink) is already at that name, so the run never
# adopts a folder it did not make.
mkdir -p "$(dirname "$WORK")" && mkdir -m 700 "$WORK" || { echo "the work folder could not be made new: $WORK"; exit 2; }
mkdir "$WORK/home" "$WORK/out" || exit 2
WORK=$(cd -P "$WORK" && pwd -P) || exit 2  # the real path from here on
chmod 700 "$WORK" || exit 2
WORK_ID=$(dir_id "$WORK") && HOME_ID=$(dir_id "$WORK/home") || exit 2
HOME_REAL="$WORK/home"
export HOME="$HOME_REAL"
unset XDG_DATA_HOME
case "$(uname)" in
  Darwin) DATA="$HOME/Library/Application Support/elastos" ;;
  *) DATA="$HOME/.local/share/elastos" ;;
esac
mkdir -p "$DATA"
chmod 700 "$HOME" "$DATA"  # owner-only, as an install makes them; Home refuses a person's root under a looser parent
step() { echo; echo "=== $*"; }
failed=0
as_expected() { echo "AS EXPECTED ($1)"; }
not_expected() { echo "NOT AS EXPECTED ($1)"; failed=1; }
cid_of() { "$BIN" stage-bundle "$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["cid"])'; }
sign() { # <cid> <key name> <signature file>
  printf %s "$1" | "$BIN" sign-payload --domain elastos.capsule.bundle.v1 --key "$WORK/$2.key" | python3 -I -c '
import json, sys
signed = json.load(sys.stdin)
json.dump({"schema": "elastos.capsule.bundle-signature/v1", "cid": sys.argv[1],
           "signer_did": signed["signer_did"], "signature": signed["signature"]}, open(sys.argv[2], "w"))' "$1" "$3"; }
sig_cid() { # <signature file>: the CID it names, or empty
  python3 -I - "$1" <<'PYEOF'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("cid", ""))
except (OSError, ValueError):
    print("")
PYEOF
}
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
sha_of() { python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }

step "machine, binary, core artifact"
HOST=$(uname -sm); echo "host: $HOST"
echo "binary: $BIN"; echo "sha256: $(sha_of "$BIN")"
REF=$(grep -E '^photo-viewer ' "$WT/examples/capsule-kit/repro/recorded-hashes.txt" | awk '{print $2}')
COMPONENT=$(sha_of "$CORE_WASM")
echo "recorded core: $REF"; echo "this core:     $COMPONENT"
[ -n "$REF" ] && [ "$REF" = "$COMPONENT" ] && as_expected "the core's bytes are the recorded ones" || { not_expected "the core is not the reference artifact"; exit 1; }

step "Home and the storage provider installed in the throwaway data folder, from this checkout"
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

step "the core, the page and two photo sets"
mkdir -p "$WORK/core" "$WORK/page" "$WORK/set/images" "$WORK/changed/images"
cp "$PV/capsule.json" "$WORK/core/capsule.json"; cp "$CORE_WASM" "$WORK/core/photo-viewer.component.wasm"
CORE=$(cid_of "$WORK/core")
cp -R "$PV/surface/browser" "$WORK/page/browser"
manifest "$WORK/page/capsule.json" "m['requires'] = [{'name': 'photo-viewer', 'kind': 'capsule', 'cid': '$CORE'}]" "$PV/surface/capsule.json"
PAGE=$(cid_of "$WORK/page")
PICS="$PV/host-test/fixtures/stand-in-photo-set/images"
for folder in set changed; do cp "$PICS/01.png" "$PICS/02.jpg" "$PICS/03.webp" "$WORK/$folder/images/"; done
for folder in set changed; do
  manifest "$WORK/$folder/capsule.json" "m.update({'schema': 'elastos.capsule/v1', 'name': 'photos-$folder', 'version': '0.1.0', 'role': 'content', 'type': 'data', 'entrypoint': 'images/01.png', 'requires': [{'name': 'image-viewer', 'kind': 'capsule', 'cid': '$PAGE'}]})"
done
SET=$(cid_of "$WORK/set")
CHANGED=$(cid_of "$WORK/changed")
echo "core:    $CORE"; echo "page:    $PAGE"; echo "set:     $SET"; echo "changed: $CHANGED"
if [ -n "$SIGN_SRC" ]; then
  step "the signatures made once and carried here: this run makes no key"
  for b in core page set changed; do
    [ -f "$SIGN_SRC/$b.sig.json" ] || { echo "the signature folder has no $b.sig.json: $SIGN_SRC"; exit 3; }
    cp "$SIGN_SRC/$b.sig.json" "$WORK/$b.sig.json" || exit 3
    case "$b" in
      core) want="$CORE" ;; page) want="$PAGE" ;; set) want="$SET" ;; changed) want="$CHANGED" ;;
    esac
    got=$(sig_cid "$WORK/$b.sig.json")
    [ "$got" = "$want" ] || { echo "the given $b signature names ${got:-nothing}, not this run's $b CID $want"; not_expected "the given $b signature signs this run's $b CID"; exit 1; }
    echo "the given $b signature names $got"
  done
else
  step "three publishers for this run only; the four signatures, for the other machines"
  for who in of-core of-page of-set; do python3 -I -c 'import os; print(os.urandom(32).hex())' > "$WORK/$who.key"; chmod 600 "$WORK/$who.key"; done
  sign "$CORE" of-core "$WORK/core.sig.json"
  sign "$PAGE" of-page "$WORK/page.sig.json"
  sign "$SET" of-set "$WORK/set.sig.json"
  sign "$CHANGED" of-set "$WORK/changed.sig.json"
  mkdir -p "$WORK/signatures"
  for b in core page set changed; do cp "$WORK/$b.sig.json" "$WORK/signatures/$b.sig.json"; done
  echo "the four signatures are saved in $WORK/signatures; the private keys are made only in $WORK, are never copied there, and are removed when the run ends"
fi
K_CORE=$(pub_of "$WORK/core.sig.json"); K_PAGE=$(pub_of "$WORK/page.sig.json"); K_SET=$(pub_of "$WORK/set.sig.json")
printf 'dev_mode = true\ntrusted_keys = ["%s", "%s", "%s"]\n' "$K_SET" "$K_PAGE" "$K_CORE" > "$DATA/config.toml"
for b in core page set changed; do
  "$BIN" stage-bundle "$WORK/$b" --signature "$WORK/$b.sig.json" > /dev/null 2>> "$WORK/stage.err"; code=$?
  echo "staged $b, exit=$code"
  # A signature whose bytes do not verify for this CID is refused by the Runtime at staging; stop there by name.
  [ "$code" = 0 ] || { tail -3 "$WORK/stage.err"; not_expected "the $b bundle stages with its signature"; exit 1; }
done
# One byte of one picture changed in the COPY of the set, where it is kept: its CID no longer names its bytes. The
# source folder `$WORK/set` is never touched. PLANT=changed-byte-not-refused skips this, for the falsifier only.
SLOT=$(find "$DATA/capsules/by-cid/$CHANGED" -name 02.jpg | head -1)
if [ "$PLANT" = changed-byte-not-refused ]; then
  echo "PLANT: the copy's byte is left alone"
else
  chmod u+w "$SLOT"  # the store keeps a staged slot read-only; this run changes it on purpose
  python3 -I - "$SLOT" <<'PYEOF'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
data[len(data) // 2] ^= 0x01
open(path, "wb").write(bytes(data))
PYEOF
  echo "changed one byte of $(basename "$SLOT") in the copy's slot"
fi

step "this Home's device identity, and the Runtime-local launch token"
DID=$("$BIN" identity show | awk -F': +' '/^DID:/ {print $2}')
[ -n "$DID" ] || { not_expected "the Home has no device identity"; exit 1; }
python3 -I - "$WORK" "$DATA" "$DID" <<'PYEOF'
import hashlib, json, os, secrets, sys, time
work, data, did = sys.argv[1], sys.argv[2], sys.argv[3]
secret = open(os.path.join(data, "identity", "device.key"), "rb").read()
if len(secret) != 32:
    sys.exit("device.key is not 32 bytes")
# elastos-identity's derive_did: the Ed25519 signing key is SHA-256("elastos-did-v1" || device secret).
key = hashlib.sha256(b"elastos-did-v1" + secret).hexdigest()
path = os.path.join(work, "did-signing.key")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, key.encode()); os.close(fd)
now = int(time.time())
payload = {
    "schema": "elastos.home.launch-token/v4",
    "launch_id": "launch:" + secrets.token_hex(16),
    "launch_context": {"schema": "elastos.runtime.browser-launch/v1",
                       "selected_resource": "home", "executable_actor": "home",
                       "authority_actor": "home"},
    "iat": now, "exp": now + 600,
    "principal_id": "device:" + did,
    "session_id": "local:" + secrets.token_hex(16),
    "grant_id": "grant:local:" + secrets.token_hex(16),
    "non_delegatable": True,
}
with open(os.path.join(work, "token-payload.json"), "w") as out:
    out.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
PYEOF
[ -s "$WORK/token-payload.json" ] || { not_expected "the launch token payload was not made"; exit 1; }
"$BIN" sign-payload --domain elastos.home.launch.v4 --key "$WORK/did-signing.key" < "$WORK/token-payload.json" > "$WORK/signed.json" || { not_expected "the launch token was not signed"; exit 1; }
python3 -I - "$WORK" "$DID" <<'PYEOF'
import base64, json, os, sys
work, did = sys.argv[1], sys.argv[2]
signed = json.load(open(os.path.join(work, "signed.json")))
if signed["signer_did"] != did:
    sys.exit("signer DID is not this Home's device DID")
payload = json.load(open(os.path.join(work, "token-payload.json")))
envelope = {"payload": payload, "signature": signed["signature"], "signer_did": did}
token = base64.urlsafe_b64encode(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()).rstrip(b"=").decode()
fd = os.open(os.path.join(work, "home-token"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, token.encode()); os.close(fd)
print("launch token minted for the device principal")
PYEOF
[ -s "$WORK/home-token" ] || { not_expected "the launch token was not assembled"; exit 1; }

step "the gateway, and Home's Runtime under it"
GW_PORT=$(free_port); RT_PORT=$(free_port)
"$BIN" gateway --addr "127.0.0.1:$GW_PORT" > "$WORK/gateway.log" 2>&1 & pids+=($!)
for i in $(seq 1 60); do curl -fsS "http://127.0.0.1:$GW_PORT/healthz" > /dev/null 2>&1 && break; sleep 1; done
curl -fsS "http://127.0.0.1:$GW_PORT/healthz" > /dev/null 2>&1 && as_expected "the gateway answers" || { not_expected "the gateway did not start"; tail -20 "$WORK/gateway.log"; exit 1; }
ELASTOS_ALLOW_SUBORDINATE_RUNTIME_HOST=1 ELASTOS_RUNTIME_COORDS_FILE="$DATA/home-runtime-coords.json" \
  "$BIN" serve --addr "127.0.0.1:$RT_PORT" > "$WORK/runtime.log" 2>&1 & pids+=($!)
for i in $(seq 1 60); do [ -s "$DATA/home-runtime-coords.json" ] && curl -fsS "http://127.0.0.1:$RT_PORT/api/health" > /dev/null 2>&1 && break; sleep 1; done
[ -s "$DATA/home-runtime-coords.json" ] && as_expected "Home's Runtime answers and published its coordinates" || { not_expected "Home's Runtime did not start"; tail -20 "$WORK/runtime.log"; exit 1; }
for p in "${pids[@]}"; do kill -0 "$p" 2>/dev/null || { not_expected "a process this run started has exited (pid $p): the port may answer for another program"; exit 1; }; done
RT="http://127.0.0.1:$RT_PORT"

step "the open by CID, and the changed-byte refusal"
# The shell attach token and the launch token go into a curl config file (0600) so neither appears in a process
# list; the credential files are removed right after the opens (secrets_rm) and again by the EXIT trap on any exit.
python3 -I - "$DATA/home-runtime-coords.json" "$WORK/attach-body.json" <<'PYEOF'
import json, os, sys
coords = json.load(open(sys.argv[1]))
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, json.dumps({"secret": coords["attach_secret"], "scope": "shell"}).encode()); os.close(fd)
PYEOF
ATTACH=$(curl -fsS -X POST -H 'content-type: application/json' --data-binary "@$WORK/attach-body.json" -o "$WORK/attach.json" -w '%{http_code}' "$RT/api/auth/attach")
rm -f "$WORK/attach-body.json"
[ "$ATTACH" = 200 ] && [ -s "$WORK/attach.json" ] && as_expected "the Runtime issued a shell attach token" || { not_expected "the Runtime issued no shell attach token"; exit 1; }
python3 -I - "$WORK/home-token" "$WORK/attach.json" "$WORK/open.cfg" <<'PYEOF'
import json, os, sys
token = open(sys.argv[1]).read().strip()
attach = json.load(open(sys.argv[2]))["token"]
lines = ['header = "x-elastos-home-token: %s"' % token,
         'header = "Authorization: Bearer %s"' % attach,
         'header = "content-type: application/json"']
fd = os.open(sys.argv[3], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, "\n".join(lines).encode()); os.close(fd)
PYEOF
GOOD_STATUS=$(curl -sS -o "$WORK/good.json" -w '%{http_code}' -X POST --config "$WORK/open.cfg" --data "{\"cid\": \"$SET\"}" "$RT/api/launch/open")
echo "the open answered $GOOD_STATUS"
CHANGED_STATUS=$(curl -sS -o "$WORK/changed.json" -w '%{http_code}' -X POST --config "$WORK/open.cfg" --data "{\"cid\": \"$CHANGED\"}" "$RT/api/launch/open")
echo "the changed-byte open answered $CHANGED_STATUS"
secrets_rm
PAGE_NAME=$(python3 -I - "$WORK/good.json" <<'PYEOF'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("page", ""))
except (OSError, ValueError):
    print("")
PYEOF
)
REFUSAL=$(python3 -I - "$WORK/changed.json" <<'PYEOF'
import json, sys
try:
    text = open(sys.argv[1]).read().strip()
except OSError:
    text = ""
print(text.split(":", 1)[0].strip() if text else "")
PYEOF
)
echo "good start page: ${PAGE_NAME:-none}"; echo "changed start refusal: ${REFUSAL:-none}"
[ "$GOOD_STATUS" = 200 ] && [ -n "$PAGE_NAME" ] && as_expected "the set starts by its CID" || not_expected "the set starts by its CID"
[ "$CHANGED_STATUS" = 400 ] && [ "$REFUSAL" = bundle_cid_mismatch ] && as_expected "the changed-byte start is refused (bundle_cid_mismatch)" || not_expected "the changed-byte start is refused (bundle_cid_mismatch)"

step "results"
python3 -I - "$WORK/results.json" "$HOST" "$SET" "$PAGE" "$CORE" "$COMPONENT" "$(sha_of "$BIN")" \
  "$GOOD_STATUS" "$PAGE_NAME" "$CHANGED_STATUS" "$REFUSAL" \
  "$K_CORE" "$(sha_of "$WORK/core.sig.json")" "$K_PAGE" "$(sha_of "$WORK/page.sig.json")" \
  "$K_SET" "$(sha_of "$WORK/set.sig.json")" <<'PYEOF'
import json, sys
(out, host, content, page, core, component, binary, status, page_name, changed_status, refusal,
 core_key, core_sig, page_key, page_sig, set_key, set_sig) = sys.argv[1:18]
receipt = {
    "schema": "elastos.photo-viewer.headless-receipt/v1",
    "host_triple": host,
    "content_cid": content,
    "page_cid": page,
    "core_cid": core,
    "component_sha256": component,
    "runtime_binary_sha256": binary,
    "core_signer_key": core_key,
    "core_signature_sha256": core_sig,
    "page_signer_key": page_key,
    "page_signature_sha256": page_sig,
    "set_signer_key": set_key,
    "set_signature_sha256": set_sig,
    "start_status": int(status),
    "start_page": page_name,
    "changed_start_status": int(changed_status),
    "changed_start_refusal": refusal,
    "checks": {"good_start_started": int(status) == 200 and bool(page_name),
               "changed_byte_refused": int(changed_status) == 400 and refusal == "bundle_cid_mismatch"},
}
json.dump(receipt, open(out, "w"), indent=2, sort_keys=True)
print("wrote", out)
PYEOF
[ "$failed" = 0 ] && echo "HEADLESS PASSED" || echo "HEADLESS FAILED"
exit $failed
