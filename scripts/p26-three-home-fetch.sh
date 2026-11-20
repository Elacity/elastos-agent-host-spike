#!/usr/bin/env bash
set -euo pipefail
umask 077
# Disposable test Homes never join the Community network a release pins.
export ELASTOS_COLLABORATION_STARTUP_MODE=isolated

# P2-6 slice 5: three isolated Homes on one machine. Two hold the same CID,
# the third fetches it with min_distinct_holders 2 and keeps its signed
# receipt set. Every saved file is checked outside the runtime process by the
# #[ignore]d server test `saved_lab_distinct_holder_run_verifies`.
#
# Hosts are changeable through three variables; this script orchestrates one
# machine only:
#   P26_HOLDER_A_HOST  bind host for holder-a   (default 127.0.0.1)
#   P26_HOLDER_B_HOST  bind host for holder-b   (default 127.0.0.1)
#   P26_REQUESTER_HOST bind host for requester  (default 127.0.0.1)
# Ports are chosen free on each host. A remote host requires that host to
# run its own copy of this script and a real trusted-source bootstrap; this
# script does not do that.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${P26_TARGET_DIR:-${ROOT}/target-build}"
EVIDENCE_DIR="${P26_EVIDENCE_DIR:-${HOME}/Sparks/office/evidence/m3-p26-s4}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${EVIDENCE_DIR}/run-${STAMP}"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/elastos-p26-XXXXXX")"

HOLDER_A_HOST="${P26_HOLDER_A_HOST:-127.0.0.1}"
HOLDER_B_HOST="${P26_HOLDER_B_HOST:-127.0.0.1}"
REQUESTER_HOST="${P26_REQUESTER_HOST:-127.0.0.1}"

SKIP_BUILD=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1; shift ;;
        --help|-h)
            sed -n '2,18p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

ELASTOS_BIN="${TARGET_DIR}/debug/elastos"
LOCALHOST_PROVIDER="${TARGET_DIR}/debug/localhost-provider"
IPFS_PROVIDER="${TARGET_DIR}/release/ipfs-provider"

declare -A HOME_DIR XDG_DIR DATA_DIR LOG_PATH COORDS_PATH API_URL ATTACH_SECRET TOKEN PID NODE_DID PEER_CAP CONTENT_CAP

cleanup() {
    local status=$?
    for name in holder-a holder-b requester; do
        local pid="${PID[$name]:-}"
        if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
            kill "${pid}" 2>/dev/null || true
            wait "${pid}" 2>/dev/null || true
        fi
        # The ipfs provider owns an offline Kubo daemon per Home.
        local coords="${DATA_DIR[$name]:-}/ipfs-coords.json"
        if [[ -n "${DATA_DIR[$name]:-}" && -f "${coords}" ]]; then
            local kubo_pid
            kubo_pid="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("kubo_pid",0))' "${coords}" 2>/dev/null || echo 0)"
            if [[ "${kubo_pid}" =~ ^[0-9]+$ ]] && [[ "${kubo_pid}" != "0" ]] && kill -0 "${kubo_pid}" 2>/dev/null; then
                kill "${kubo_pid}" 2>/dev/null || true
            fi
        fi
    done
    if [[ -n "${TEST_ROOT:-}" && -d "${TEST_ROOT}" ]]; then
        rm -rf "${TEST_ROOT}"
    fi
    exit "${status}"
}
trap cleanup EXIT

fail() {
    echo "[p26] FAIL: $*" >&2
    for name in holder-a holder-b requester; do
        local path="${LOG_PATH[$name]:-}"
        if [[ -n "${path}" && -f "${path}" ]]; then
            echo "--- ${name} log (last 40 lines) ---" >&2
            tail -n 40 "${path}" >&2 || true
        fi
    done
    exit 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

sha256_text() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    else
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    fi
}

free_port() {
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

platform_key() {
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64) echo "darwin-arm64" ;;
        Darwin-x86_64) echo "darwin-amd64" ;;
        Linux-x86_64) echo "linux-amd64" ;;
        Linux-aarch64) echo "linux-arm64" ;;
        *) echo "unsupported" ;;
    esac
}

json_post() {
    local url="$1" auth="$2" cap="$3" body="$4"
    local -a headers=(-H "Content-Type: application/json")
    [[ -n "${auth}" ]] && headers+=(-H "Authorization: Bearer ${auth}")
    [[ -n "${cap}" ]] && headers+=(-H "X-Capability-Token: ${cap}")
    curl -sS -X POST "${url}" "${headers[@]}" -d "${body}"
}

wait_for_file() {
    local path="$1"
    for _ in $(seq 1 120); do
        [[ -f "${path}" ]] && return 0
        sleep 0.25
    done
    return 1
}

wait_for_health() {
    local api="$1"
    for _ in $(seq 1 120); do
        if [[ "$(curl -s -o /dev/null -w '%{http_code}' "${api}/api/health" || true)" == "200" ]]; then
            return 0
        fi
        sleep 0.25
    done
    return 1
}

stage_home() {
    local name="$1" host="$2"
    local platform checksum_localhost checksum_ipfs
    platform="$(platform_key)"
    [[ "${platform}" != "unsupported" ]] || fail "unsupported platform $(uname -s)-$(uname -m)"
    checksum_localhost="sha256:$(sha256_of "${LOCALHOST_PROVIDER}")"
    checksum_ipfs="sha256:$(sha256_of "${IPFS_PROVIDER}")"

    HOME_DIR[$name]="${TEST_ROOT}/${name}"
    XDG_DIR[$name]="${HOME_DIR[$name]}/xdg-data"
    # dirs::data_dir() follows HOME on macOS and XDG_DATA_HOME on Linux.
    if [[ "$(uname -s)" == "Darwin" ]]; then
        DATA_DIR[$name]="${HOME_DIR[$name]}/Library/Application Support/elastos"
    else
        DATA_DIR[$name]="${XDG_DIR[$name]}/elastos"
    fi
    LOG_PATH[$name]="${TEST_ROOT}/${name}.log"
    COORDS_PATH[$name]="${DATA_DIR[$name]}/runtime-coords.json"
    mkdir -p "${DATA_DIR[$name]}/bin"
    # Holder Homes run as publisher/seed runtimes: their Carrier fetch admission
    # accepts any peer (is_trusted_source_runtime). An ordinary Home serves only
    # content its people published; a headless lab has no passkey contact flow.
    if [[ "${name}" != "requester" ]]; then
        mkdir -p "${DATA_DIR[$name]}/ElastOS/SystemServices/Publisher/artifacts"
    fi
    cp "${LOCALHOST_PROVIDER}" "${DATA_DIR[$name]}/bin/localhost-provider"
    cp "${IPFS_PROVIDER}" "${DATA_DIR[$name]}/bin/ipfs-provider"
    python3 - "${DATA_DIR[$name]}" "${platform}" "${checksum_localhost}" "${checksum_ipfs}" <<'PY'
import json, sys
data_dir, platform, localhost, ipfs = sys.argv[1:5]
providers = (
    ("localhost-provider", localhost, "localhost://*",
     "Host localhost provider binary for runtime storage access"),
    ("ipfs-provider", ipfs, "elastos://ipfs/*",
     "Host IPFS bridge binary for local content"),
)
manifest = {
    "schema": "elastos.components/v1",
    "external": {
        name: {
            "install_path": f"bin/{name}",
            "description": description,
            "provider_runtime": {
                "role": "provider",
                "substrate": "native",
                "runtime_abi": "elastos.provider-stdio/v1",
                "execution": "native-provider",
                "provides": provides,
            },
            "platforms": {
                platform: {"install_path": f"bin/{name}", "checksum": checksum}
            },
        }
        for name, checksum, provides, description in providers
    },
    "capsules": {},
    "profiles": {},
}
with open(f"{data_dir}/components.json", "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
PY
    printf '{"allow":["elastos://peer/*","elastos://content/publish","elastos://content/ensure","elastos://content/fetch"]}\n' \
        >"${HOME_DIR[$name]}/policy.json"

    local port
    port="$(free_port)"
    HOME="${HOME_DIR[$name]}" \
    XDG_DATA_HOME="${XDG_DIR[$name]}" \
    ELASTOS_DATA_DIR="${DATA_DIR[$name]}" \
    ELASTOS_POLICY_FILE="${HOME_DIR[$name]}/policy.json" \
    "${ELASTOS_BIN}" serve --addr "${host}:${port}" >"${LOG_PATH[$name]}" 2>&1 &
    PID["$name"]=$!

    wait_for_file "${COORDS_PATH[$name]}" || fail "runtime-coords.json missing for ${name}"
    API_URL[$name]=""
    for _ in $(seq 1 120); do
        API_URL[$name]="$(jq -r '.api_url // empty' "${COORDS_PATH[$name]}" 2>/dev/null || true)"
        ATTACH_SECRET[$name]="$(jq -r '.attach_secret // empty' "${COORDS_PATH[$name]}" 2>/dev/null || true)"
        [[ -n "${API_URL[$name]}" && -n "${ATTACH_SECRET[$name]}" ]] && break
        sleep 0.25
    done
    [[ -n "${API_URL[$name]}" && -n "${ATTACH_SECRET[$name]}" ]] \
        || fail "runtime-coords.json is incomplete for ${name}"
    wait_for_health "${API_URL[$name]}" || fail "health never ready for ${name}"
}

attach_runtime() {
    local name="$1"
    TOKEN[$name]="$(json_post "${API_URL[$name]}/api/auth/attach" "" "" \
        "$(jq -nc --arg secret "${ATTACH_SECRET[$name]}" '{secret:$secret,scope:"shell"}')" \
        | jq -r '.token')"
    [[ -n "${TOKEN[$name]}" && "${TOKEN[$name]}" != "null" ]] || fail "attach failed for ${name}"
}

# Print the granted token for one resource; the Home's shell grants its own
# pending request. A Home keeps one peer token and one content token.
grant_capability() {
    local name="$1" resource="$2" action="$3"
    local request_id token
    request_id="$(json_post "${API_URL[$name]}/api/capability/request" "${TOKEN[$name]}" "" \
        "$(jq -nc --arg resource "${resource}" --arg action "${action}" \
            '{resource:$resource,action:$action,reason:"P2-6 three-Home lab"}')" \
        | jq -r '.request_id // empty')"
    [[ -n "${request_id}" ]] || fail "capability request failed for ${name}: ${resource}"
    token="$(json_post "${API_URL[$name]}/api/capability/grant" "${TOKEN[$name]}" "" \
        "$(jq -nc --arg id "${request_id}" '{request_id:$id,duration:"session",rationale:"P2-6 three-Home lab shell grant"}')" \
        | jq -r '.token // empty')"
    [[ -n "${token}" ]] || fail "capability grant failed for ${name}: ${resource}"
    echo "${token}"
}

peer_post() {
    local name="$1" op="$2" body="$3"
    json_post "${API_URL[$name]}/api/provider/peer/${op}" "${TOKEN[$name]}" "${PEER_CAP[$name]}" "${body}"
}

content_post() {
    local name="$1" op="$2" body="$3"
    json_post "${API_URL[$name]}/api/provider/content/${op}" "${TOKEN[$name]}" "${CONTENT_CAP[$name]}" "${body}"
}

get_ticket() {
    local name="$1"
    peer_post "${name}" "get_ticket" '{}' | jq -r '.data.ticket // empty'
}

get_node_id() {
    local name="$1"
    peer_post "${name}" "get_node_id" '{}' | jq -r '.data.node_id // empty'
}

connect_peer() {
    local name="$1" ticket="$2"
    peer_post "${name}" "connect" "$(jq -nc --arg ticket "${ticket}" '{ticket:$ticket}')" \
        | jq -e '.status == "ok"' >/dev/null || fail "${name} could not connect a peer"
}

wait_for_peers() {
    local name="$1" min_count="$2" count=""
    for _ in $(seq 1 120); do
        count="$(peer_post "${name}" "list_peers" '{}' | jq -r '.data.peers | length' 2>/dev/null || echo 0)"
        if [[ "${count}" =~ ^[0-9]+$ ]] && (( count >= min_count )); then
            return 0
        fi
        sleep 0.25
    done
    fail "${name} peer count stayed below ${min_count}"
}

join_availability_topic() {
    local name="$1" cid="$2"
    local topic
    topic="__elastos_content/v1/$(sha256_text "${cid}")"
    peer_post "${name}" "gossip_join" "$(jq -nc --arg topic "${topic}" '{topic:$topic,mode:"direct"}')" \
        | jq -e '.status == "ok" or .code == "already_joined"' >/dev/null \
        || fail "${name} could not join the availability topic"
    echo "${topic}"
}

# Count distinct announcements for one CID in the requester's topic buffer.
announcements_seen() {
    local topic="$1" attempt="$2"
    peer_post requester "gossip_recv" \
        "$(jq -nc --arg topic "${topic}" --arg consumer "p26-poll-${attempt}" '{topic:$topic,limit:50,consumer_id:$consumer}')" \
        | jq -r '
            [ .data.messages[]?
              | .content
              | fromjson?
              | .payload.node_did
              | select(. != null) ] | unique | length'
}

wait_for_announcements() {
    local topic="$1" expected="$2" seen=0
    for attempt in $(seq 1 120); do
        seen="$(announcements_seen "${topic}" "${attempt}" 2>/dev/null || echo 0)"
        if [[ "${seen}" =~ ^[0-9]+$ ]] && (( seen >= expected )); then
            return 0
        fi
        sleep 0.25
    done
    fail "requester saw ${seen} announcement(s) for ${topic}; ${expected} expected"
}

sanitize_and_scan() {
    python3 - "${RUN_DIR}" <<'PY'
import json, os, re, sys

run_dir = sys.argv[1]
secret_key = re.compile(r"(?i)^(token|secret|ticket|authorization|password|passphrase|attach_secret)$")
bearer = re.compile(r"(?i)bearer\s+\S+")
base32_ticket = re.compile(r"[a-z2-7]{120,}")

secret_fragment = re.compile(
    r'(?i)"(token|secret|ticket|authorization|password|passphrase)"\s*:\s*"[^"]*"'
)

def mask_string(text):
    text = bearer.sub("Bearer <masked>", text)
    text = secret_fragment.sub('"<masked-key>": "<masked>"', text)
    return base32_ticket.sub("<masked>", text)

def walk(value):
    if isinstance(value, dict):
        return {
            key: "<masked>" if secret_key.match(str(key)) else walk(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [walk(item) for item in value]
    if isinstance(value, str):
        return mask_string(value)
    return value

for name in sorted(os.listdir(run_dir)):
    path = os.path.join(run_dir, name)
    if not os.path.isfile(path) or name == "RUN.md":
        continue
    text = open(path, "r", encoding="utf-8", errors="replace").read()
    try:
        masked = json.dumps(walk(json.loads(text)), indent=2, sort_keys=True) + "\n"
    except json.JSONDecodeError:
        masked = "\n".join(mask_string(line) for line in text.splitlines()) + "\n"
    if masked != text:
        open(path, "w", encoding="utf-8").write(masked)
PY
    local hits
    hits="$(grep -rEn '"token"|"ticket"|attach_secret|Bearer |[a-z2-7]{120,}' "${RUN_DIR}" \
        --include='*.json' --include='*.log' --include='*.txt' --include='*.md' || true)"
    if [[ -n "${hits}" ]]; then
        fail "saved run still holds token or ticket shapes: ${hits}"
    fi
}

mkdir -p "${RUN_DIR}"

if [[ "${SKIP_BUILD}" -eq 0 ]]; then
    echo "[p26] build elastos binary and provider binaries"
    cargo build --locked --target-dir "${TARGET_DIR}" \
        --manifest-path "${ROOT}/elastos/Cargo.toml" -p elastos-server -p localhost-provider \
        >"${RUN_DIR}/build-runtime.log" 2>&1 || fail "runtime build failed; see build-runtime.log"
    cargo build --locked --release --target-dir "${TARGET_DIR}" \
        --manifest-path "${ROOT}/capsules/ipfs-provider/Cargo.toml" \
        >"${RUN_DIR}/build-ipfs.log" 2>&1 || fail "ipfs-provider build failed; see build-ipfs.log"
fi
for binary in "${ELASTOS_BIN}" "${LOCALHOST_PROVIDER}" "${IPFS_PROVIDER}"; do
    [[ -x "${binary}" ]] || fail "missing built binary ${binary}"
done

BIN_SHA256="$(sha256_of "${ELASTOS_BIN}")"
HEAD_COMMIT="$(git -C "${ROOT}" rev-parse HEAD)"
BRANCH="$(git -C "${ROOT}" rev-parse --abbrev-ref HEAD)"

echo "[p26] run folder: ${RUN_DIR}"
echo "[p26] start three isolated Homes"
stage_home holder-a "${HOLDER_A_HOST}"
stage_home holder-b "${HOLDER_B_HOST}"
stage_home requester "${REQUESTER_HOST}"

for name in holder-a holder-b requester; do
    attach_runtime "${name}"
    # Every peer operation maps to Action::Message in provider_operation_action.
    PEER_CAP[$name]="$(grant_capability "${name}" "elastos://peer/*" message)"
    NODE_DID[$name]="$(get_node_id "${name}")"
    [[ -n "${NODE_DID[$name]}" ]] || fail "${name} has no node DID"
done
# Content tokens: holders write, the requester reads its fetch answer.
CONTENT_CAP[holder-a]="$(grant_capability holder-a "elastos://content/*" write)"
CONTENT_CAP[holder-b]="$(grant_capability holder-b "elastos://content/*" write)"
CONTENT_CAP[requester]="$(grant_capability requester "elastos://content/fetch" read)"

if [[ "${NODE_DID[holder-a]}" == "${NODE_DID[holder-b]}" || "${NODE_DID[holder-a]}" == "${NODE_DID[requester]}" || "${NODE_DID[holder-b]}" == "${NODE_DID[requester]}" ]]; then
    fail "node DIDs are not three distinct keys"
fi

echo "[p26] cross-connect the three Homes"
TICKET_A="$(get_ticket holder-a)"
TICKET_B="$(get_ticket holder-b)"
TICKET_R="$(get_ticket requester)"
[[ -n "${TICKET_A}" && -n "${TICKET_B}" && -n "${TICKET_R}" ]] || fail "a Home has no connect ticket"
connect_peer requester "${TICKET_A}"
connect_peer requester "${TICKET_B}"
connect_peer holder-a "${TICKET_R}"
connect_peer holder-b "${TICKET_R}"
wait_for_peers requester 2
wait_for_peers holder-a 1
wait_for_peers holder-b 1

echo "[p26] make one 256 KiB file"
SOURCE_FILE="${RUN_DIR}/source.bin"
python3 - "${SOURCE_FILE}" <<'PY'
import os, sys
with open(sys.argv[1], "wb") as handle:
    handle.write(os.urandom(256 * 1024))
PY
SOURCE_SHA256="$(sha256_of "${SOURCE_FILE}")"
SOURCE_BYTES="$(wc -c <"${SOURCE_FILE}" | tr -d ' ')"

publish_file() {
    local name="$1" prefix="$2" cid
    local body
    body="$(python3 - "${SOURCE_FILE}" <<'PY'
import base64, json, sys
data = base64.b64encode(open(sys.argv[1], "rb").read()).decode("ascii")
print(json.dumps({"kind": "file", "filename": "p26-content.bin", "data": data, "pin": True}))
PY
)"
    content_post "${name}" "publish" "${body}" >"${RUN_DIR}/${prefix}-publish.json"
    cid="$(jq -r '.data.cid // empty' "${RUN_DIR}/${prefix}-publish.json")"
    [[ -n "${cid}" ]] || fail "${name} publish returned no CID"
    jq '.data.receipt' "${RUN_DIR}/${prefix}-publish.json" >"${RUN_DIR}/${prefix}-receipt.json"
    echo "${cid}"
}

echo "[p26] holder-a and holder-b add the same bytes"
CID_A="$(publish_file holder-a holder-a)"
CID_B="$(publish_file holder-b holder-b)"
[[ "${CID_A}" == "${CID_B}" ]] || fail "holders added different CIDs: ${CID_A} ${CID_B}"
CID="${CID_A}"
for holder in holder-a holder-b; do
    jq -e --arg cid "${CID}" '.payload.cid == $cid' "${RUN_DIR}/${holder}-receipt.json" >/dev/null \
        || fail "${holder} receipt does not name ${CID}"
done

echo "[p26] requester local-only lookup must miss"
content_post requester "fetch" "$(jq -nc --arg cid "${CID}" '{cid:$cid,local_only:true}')" \
    >"${RUN_DIR}/local-only-miss.json"
jq -e '.status == "error"' "${RUN_DIR}/local-only-miss.json" >/dev/null \
    || fail "requester already held ${CID} locally"

echo "[p26] requester joins the CID topic; holders re-announce"
TOPIC="$(join_availability_topic requester "${CID}")"
content_post holder-a "ensure" "$(jq -nc --arg cid "${CID}" '{cid:$cid}')" >/dev/null
content_post holder-b "ensure" "$(jq -nc --arg cid "${CID}" '{cid:$cid}')" >/dev/null
wait_for_announcements "${TOPIC}" 2

echo "[p26] requester fetches ${CID} with min_distinct_holders 2"
content_post requester "fetch" "$(jq -nc --arg cid "${CID}" '{cid:$cid,min_distinct_holders:2}')" \
    >"${RUN_DIR}/fetch.json"
jq -e '.status == "ok"' "${RUN_DIR}/fetch.json" >/dev/null \
    || fail "distinct-holder fetch failed: $(jq -c '{code,message}' "${RUN_DIR}/fetch.json")"
jq -e '.data.availability | (.distinct_holders == 2 and .required_distinct_holders == 2 and (.receipts | length) == 2)' \
    "${RUN_DIR}/fetch.json" >/dev/null || fail "fetch answer does not name two distinct holders"
FETCH_SHA256="$(jq -r '.data.data' "${RUN_DIR}/fetch.json" | python3 -c 'import base64,hashlib,sys;print(hashlib.sha256(base64.b64decode(sys.stdin.read())).hexdigest())')"
[[ "${FETCH_SHA256}" == "${SOURCE_SHA256}" ]] || fail "fetched bytes differ from the source file"

echo "[p26] refusal run: stop holder-b, publish a fresh CID on holder-a only"
kill "${PID[holder-b]}" 2>/dev/null || true
wait "${PID[holder-b]}" 2>/dev/null || true
unset 'PID[holder-b]'
if [[ -f "${DATA_DIR[holder-b]}/ipfs-coords.json" ]]; then
    kubo_pid="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("kubo_pid",0))' "${DATA_DIR[holder-b]}/ipfs-coords.json" 2>/dev/null || echo 0)"
    if [[ "${kubo_pid}" =~ ^[0-9]+$ ]] && [[ "${kubo_pid}" != "0" ]] && kill -0 "${kubo_pid}" 2>/dev/null; then
        kill "${kubo_pid}" 2>/dev/null || true
    fi
fi

python3 - "${RUN_DIR}/refusal-source.bin" <<'PY'
import os, sys
with open(sys.argv[1], "wb") as handle:
    handle.write(os.urandom(256 * 1024))
PY
SOURCE_FILE="${RUN_DIR}/refusal-source.bin"
CID_2="$(publish_file holder-a holder-a-refusal)"
[[ "${CID_2}" != "${CID}" ]] || fail "refusal run reused the first CID"
TOPIC_2="$(join_availability_topic requester "${CID_2}")"
content_post holder-a "ensure" "$(jq -nc --arg cid "${CID_2}" '{cid:$cid}')" >/dev/null
wait_for_announcements "${TOPIC_2}" 1
content_post requester "fetch" "$(jq -nc --arg cid "${CID_2}" '{cid:$cid,min_distinct_holders:2}')" \
    >"${RUN_DIR}/refusal.json"
jq -e '.status == "error" and .code == "carrier_fetch_distinct_holders"' "${RUN_DIR}/refusal.json" >/dev/null \
    || fail "refusal answer did not use the distinct-holders code: $(jq -c '{status,code}' "${RUN_DIR}/refusal.json")"
jq -e '.data | (.distinct_holders == 1 and .required_distinct_holders == 2 and (.receipts | length) == 1 and (.receipt_set.signature | length) > 0)' \
    "${RUN_DIR}/refusal.json" >/dev/null || fail "refusal answer lost its receipt or signed set"

echo "[p26] write the run record"
python3 - "${RUN_DIR}" "${CID}" "${CID_2}" "${SOURCE_SHA256}" "${SOURCE_BYTES}" \
    "${NODE_DID[holder-a]}" "${NODE_DID[holder-b]}" "${NODE_DID[requester]}" <<'PY'
import json, sys
(run_dir, cid, cid2, source_sha256, source_bytes,
 holder_a_did, holder_b_did, requester_did) = sys.argv[1:9]
meta = {
    "cid": cid,
    "refusal_cid": cid2,
    "source_sha256": source_sha256,
    "source_bytes": int(source_bytes),
    "holder-a_did": holder_a_did,
    "holder-b_did": holder_b_did,
    "requester_did": requester_did,
    "min_distinct_holders": 2,
}
with open(f"{run_dir}/meta.json", "w", encoding="utf-8") as handle:
    json.dump(meta, handle, indent=2, sort_keys=True)
PY

echo "[p26] verify the saved run outside the runtime process"
(
    cd "${ROOT}/elastos"
    ELASTOS_P26_RUN_DIR="${RUN_DIR}" RUST_TEST_THREADS=2 nice -n 10 \
        cargo test --locked -p elastos-server --lib --target-dir "${TARGET_DIR}" \
        content::tests::saved_lab_distinct_holder_run_verifies -- --ignored --exact --nocapture
) >"${RUN_DIR}/verify.txt" 2>&1 || fail "saved-run verification failed; see verify.txt"
grep -q '^test content::tests::saved_lab_distinct_holder_run_verifies .* ok$' "${RUN_DIR}/verify.txt" \
    || fail "saved-run verification did not run the test; see verify.txt"

cp "${LOG_PATH[holder-a]}" "${RUN_DIR}/holder-a.log"
cp "${LOG_PATH[holder-b]}" "${RUN_DIR}/holder-b.log"
cp "${LOG_PATH[requester]}" "${RUN_DIR}/requester.log"

sanitize_and_scan

cat >"${RUN_DIR}/RUN.md" <<EOF
# P2-6 slice 5: three Homes fetch one CID from two holders

- Head commit: ${HEAD_COMMIT} (branch ${BRANCH}, working tree changes included)
- elastos binary: ${ELASTOS_BIN}, sha256 ${BIN_SHA256}
- Host: $(uname -srm)
- Homes: holder-a=${HOLDER_A_HOST}, holder-b=${HOLDER_B_HOST}, requester=${REQUESTER_HOST}
- Node DIDs: holder-a ${NODE_DID[holder-a]}; holder-b ${NODE_DID[holder-b]}; requester ${NODE_DID[requester]}
- CID: ${CID}; refusal CID: ${CID_2}
- Source file: ${SOURCE_BYTES} bytes, sha256 ${SOURCE_SHA256}
- Capabilities: holders \`elastos://content/*\` write (publish and ensure); requester \`elastos://content/fetch\` read; peer operations \`elastos://peer/*\` message, which is the action every peer operation requires. Each was requested and granted by the Home's own shell session (\`/api/capability/request\` then \`/api/capability/grant\`), and \`enforce_capability\` in the provider proxy checks the token before the provider runs.
- Commands: \`bash scripts/p26-three-home-fetch.sh\` (build, three Homes, publish, fetch, verify, refusal). Hosts are set by P26_HOLDER_A_HOST, P26_HOLDER_B_HOST, P26_REQUESTER_HOST.
- Verification: \`ELASTOS_P26_RUN_DIR=<this folder> cargo test --locked -p elastos-server --lib --target-dir target-build content::tests::saved_lab_distinct_holder_run_verifies -- --ignored --exact --nocapture\`; output is verify.txt.
- Saved answers: fetch.json (success), refusal.json (distinct-holders refusal), holder-a-receipt.json, holder-b-receipt.json (each holder's signed availability receipt), local-only-miss.json, meta.json, sanitized runtime logs.

## What this run shows

Three isolated Homes with three distinct node keys ran on one machine. holder-a and holder-b each added the same 256 KiB random file, announced availability the product's normal way, and the requester fetched the CID through the normal content fetch with min_distinct_holders 2, so the fetch went only through the existing availability fallback into carrier-availability fetch and the Carrier provider invocation, with the requester's existing CID check on the returned bytes. The saved fetch answer names two distinct verified holder DIDs, carries one receipt per holder answer, and carries a receipt set signed by the requester's node key; the fetched bytes hash to the source file's SHA-256. In the refusal run holder-b was stopped and a fresh CID held only by holder-a was refused with carrier_fetch_distinct_holders, one verified receipt and the requester-signed set.

The holder Homes run as publisher/seed runtimes (an empty Publisher artifacts directory), so their Carrier fetch admission accepts any peer. An ordinary Home serves only CIDs its people published, and then only to accepted contacts; a headless lab cannot pass a passkey contact handshake, so this run exercises the seed branch of that admission and not the contact branch.

## What this run does not show

The three Homes are on one machine, so this does not show cross-machine behaviour, network partitions, or independent failure domains. Every receipt is the requester's own statement written after its CID check: the set is requester-signed and self-attested, and no holder countersigns a fetch receipt. The fetch is a whole-object read only; bounded and ranged reads are not in the distinct-holder mode. Availability announcements are signed by each holder and were verified here against the holder DIDs in the same server test.
EOF

echo "[p26] OK"
echo "  cid:        ${CID}"
echo "  distinct:   2 (holder-a ${NODE_DID[holder-a]}, holder-b ${NODE_DID[holder-b]})"
echo "  requester:  ${NODE_DID[requester]}"
echo "  run folder: ${RUN_DIR}"
