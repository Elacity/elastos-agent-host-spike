#!/usr/bin/env bash
# A15-R installed journey.
#
# The owner route is POST /api/apps/system/agents/launch. The runner enables
# agents, creates two, activates them, takes a fresh passkey step-up for
# operation agent.start, and posts that route. The route mints a one-use
# launch grant and asks the managed Home Runtime POST /api/capsules.
#
# That runtime exists only after the gateway owns the Home and the owner
# calls POST /api/apps/home/runtime/ensure. The runner starts `elastos gateway`
# and does not start an operator `elastos serve` on the same data directory.
set -u
OUT="${1:-}"
if [[ -z "$OUT" || "$OUT" == "-h" || "$OUT" == "--help" ]]; then
  echo "usage: $0 <output-folder>" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Users/sash/code/target-a15r}"
export CARGO_BUILD_BUILD_DIR="${CARGO_BUILD_BUILD_DIR:-/Users/sash/code/target-a15r-build}"
mkdir -p "$OUT"
HOME_ROOT="$OUT/installed-home"
DATA="$HOME_ROOT/Library/Application Support/elastos"
PID_FILE="$OUT/serve.pid"
LOG="$OUT/serve.log"
STATUS=1

cleanup() {
  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "${pid}" ]]; then
      kill -- "-${pid}" 2>/dev/null || kill "${pid}" 2>/dev/null || true
    fi
  fi
  if [[ -n "${DATA:-}" && -f "$DATA/home-runtime-coords.json" ]]; then
    local child
    child="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("pid",""))' "$DATA/home-runtime-coords.json" 2>/dev/null || true)"
    if [[ -n "${child}" ]]; then
      kill "${child}" 2>/dev/null || true
    fi
  fi
  if [[ -n "${DATA:-}" && -e "$DATA/.a15r-publisher.key" ]]; then
    rm -f "$DATA/.a15r-publisher.key"
  fi
}
trap cleanup EXIT

fail() {
  local name="$1"
  shift
  echo "a15r-installed-journey: $*" >&2
  if [[ ! -f "$OUT/receipt.json" ]]; then
    FAILED="$name" REASON="$*" OUT_DIR="$OUT" python3 - <<'PY'
import json, os
from pathlib import Path
names = [
    "release_signed", "signing_key_deleted", "installed_identity_recorded",
    "gateway_started", "owner_passkey_created", "home_runtime_ensured", "runtime_started",
    "u3_agents_enabled", "u3_owner_field_refused", "u3_agent_created",
    "u3_unknown_id_refused", "u3_guest_refused", "u3_agent_activated",
    "u3_agent_started", "u4_second_agent_created", "u4_both_running",
    "u4_distinct_roots", "u4_no_cross_read", "journal_in_agent_root",
    "plan_card_captured", "one_pending_record", "approve_without_step_up_refused",
    "step_up_approve", "one_authorised_write", "owner_document_unchanged",
    "one_result_and_receipt", "signed_start_audit", "signed_completion_audit",
    "card_removed", "replay_zero", "restart_zero",
]
failed = os.environ["FAILED"]
reason = os.environ["REASON"]
assertions = []
seen = False
for name in names:
    if name == failed:
        assertions.append({"name": name, "status": "fail", "detail": reason})
        seen = True
    elif not seen:
        assertions.append({"name": name, "status": "not reached", "detail": ""})
    else:
        assertions.append({"name": name, "status": "not reached", "detail": ""})
Path(os.environ["OUT_DIR"], "receipt.json").write_text(json.dumps({
    "route": "POST /api/apps/system/agents/launch",
    "step_up_operation": "agent.start",
    "assertions": assertions,
    "stopped": reason,
}, indent=2) + "\n")
PY
  fi
  exit 1
}

if [[ -e "$HOME_ROOT" ]]; then
  fail release_signed "installed home already exists at $HOME_ROOT; this runner does not reuse or delete it"
fi

echo "building prototype-agents runtime"
(
  cd "$ROOT/elastos"
  cargo build --locked -p elastos-server --features prototype-agents --release --bin elastos
) >"$OUT/cargo-elastos.log" 2>&1 || fail release_signed "elastos release build failed; see $OUT/cargo-elastos.log"
(
  cd "$ROOT/elastos"
  cargo build --locked -p localhost-provider --release --bin localhost-provider
) >"$OUT/cargo-provider.log" 2>&1 || fail release_signed "localhost-provider build failed; see $OUT/cargo-provider.log"
echo "building did-provider and shell"
(
  cd "$ROOT"
  cargo build --locked --manifest-path capsules/did-provider/Cargo.toml --release --bin did-provider
) >"$OUT/cargo-did.log" 2>&1 || fail release_signed "did-provider build failed; see $OUT/cargo-did.log"
(
  cd "$ROOT/elastos"
  cargo build --locked -p shell --release --bin shell
) >"$OUT/cargo-shell.log" 2>&1 || fail release_signed "shell build failed; see $OUT/cargo-shell.log"
"$ROOT/scripts/build-component-capsule.sh" "$ROOT/examples/agent-host" \
  >"$OUT/cargo-agent-host.log" 2>&1 || fail release_signed "agent-host component build failed; see $OUT/cargo-agent-host.log"

RUNTIME="$CARGO_TARGET_DIR/release/elastos"
PROVIDER="$CARGO_TARGET_DIR/release/localhost-provider"
DID="$CARGO_TARGET_DIR/release/did-provider"
SHELL_BIN="$CARGO_TARGET_DIR/release/shell"
WASM="$ROOT/examples/agent-host/agent-host.component.wasm"
[[ -f "$RUNTIME" && -f "$PROVIDER" && -f "$DID" && -f "$SHELL_BIN" && -f "$WASM" ]] || fail release_signed "built artifacts are missing"

python3 "$ROOT/scripts/a15r-installed-journey.py" \
  --home "$HOME_ROOT" \
  --data "$DATA" \
  --runtime "$RUNTIME" \
  --provider "$PROVIDER" \
  --did "$DID" \
  --shell "$SHELL_BIN" \
  --wasm "$WASM" \
  --manifest "$ROOT/examples/agent-host/capsule.json" \
  --out "$OUT/install.json" || fail release_signed "disposable release staging failed"
[[ ! -e "$DATA/.a15r-publisher.key" ]] || fail signing_key_deleted "disposable signing key still exists"

for name in home system inbox home-gui; do
  mkdir -p "$DATA/capsules/$name"
  cp -R "$ROOT/capsules/$name/." "$DATA/capsules/$name/"
done

GW_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
BIN="$DATA/bin/elastos"

set -m
(
  cd "$HOME_ROOT"
  exec env \
    -u XDG_DATA_HOME -u XDG_CONFIG_HOME -u XDG_STATE_HOME -u XDG_CACHE_HOME \
    HOME="$HOME_ROOT" \
    ELASTOS_QUIET_RUNTIME_NOTICES=1 \
    "$BIN" gateway --addr "127.0.0.1:${GW_PORT}"
) >>"$LOG" 2>&1 &
echo $! >"$PID_FILE"
set +m

python3 - "127.0.0.1" "$GW_PORT" <<'PY' || fail gateway_started "gateway did not accept connections"
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
for _ in range(90):
    try:
        with socket.create_connection((host, port), 2):
            raise SystemExit(0)
    except OSError:
        time.sleep(1)
raise SystemExit(1)
PY

SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')"
export A15R_OUT="$OUT"
export A15R_ROOT="$ROOT"
export A15R_HOME="$HOME_ROOT"
export A15R_DATA="$DATA"
export A15R_GATEWAY="http://localhost:${GW_PORT}"
export A15R_GATEWAY_ADDR="127.0.0.1:${GW_PORT}"
export A15R_SERVE_BIN="$BIN"
export A15R_PID_FILE="$PID_FILE"
export A15R_LOG="$LOG"
export A15R_SOURCE_COMMIT="$SOURCE_COMMIT"
export A15R_SOURCE_TREE="$SOURCE_TREE"

if [[ ! -d "$OUT/tool/node_modules/playwright" ]]; then
  mkdir -p "$OUT/tool"
  if ! (cd "$OUT/tool" && npm init -y >/dev/null && npm install --silent playwright); then
    echo "playwright install failed; passkey screenshots will be skipped" >&2
  else
    PLAYWRIGHT_BROWSERS_PATH="$OUT/tool/browsers" \
      "$OUT/tool/node_modules/.bin/playwright" install chromium \
      >"$OUT/playwright-install.log" 2>&1 || echo "chromium download failed" >&2
  fi
fi
export PLAYWRIGHT_BROWSERS_PATH="$OUT/tool/browsers"

node "$ROOT/scripts/a15r-installed-journey.mjs"
STATUS=$?
exit "$STATUS"
