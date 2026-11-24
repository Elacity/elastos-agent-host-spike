#!/usr/bin/env bash
# Full mode needs the agents-in-gateway change. It is not proof of anything
# until that change is in the gateway. Full mode refuses to run until it
# detects that route.
# `--only u3-create` is the create proof. It does not start a guest.
# This installed journey runs on Mac only. The Home data directory is
# Library/Application Support/elastos.
# Carrier is not disabled. config.toml sets carrier_bind_addr to 127.0.0.1:0,
# a free loopback port, so Carrier does not bind UDP 4433.
set -u
# macOS tar must not add AppleDouble files beside the committed page bytes.
export COPYFILE_DISABLE=1
ONLY=""
if [[ "${1:-}" == "--only" ]]; then
  if [[ $# -lt 3 || "$2" != "u3-create" ]]; then
    echo "usage: $0 [--only u3-create] <output-folder>" >&2
    exit 2
  fi
  ONLY="$2"
  shift 2
fi
OUT="${1:-}"
if [[ -z "$OUT" || "$OUT" == "-h" || "$OUT" == "--help" ]]; then
  echo "usage: $0 [--only u3-create] <output-folder>" >&2
  exit 2
fi
export A15R_ONLY="$ONLY"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
export CARGO_BUILD_BUILD_DIR="${CARGO_BUILD_BUILD_DIR:-$ROOT/target-build}"
mkdir -p "$OUT"
# An old receipt is removed before this run can keep it or skip writing one.
rm -f "$OUT/receipt.json"
SCRATCH="${A15R_SCRATCH:-$ROOT/target/a15r-homes}"
export A15R_SCRATCH="$SCRATCH"
HOME_ROOT="$SCRATCH/$(basename "$OUT")"
# Mac only. On Darwin the runtime data dir is ~/Library/Application Support.
DATA="$HOME_ROOT/Library/Application Support/elastos"
PID_FILE="$OUT/serve.pid"
LOG="$OUT/serve.log"
STATUS=1

node_proof() {
  node "$ROOT/scripts/a15r-installed-journey.mjs" "$@"
}

cleanup() {
  A15R_OUT="$OUT" A15R_HOME="$HOME_ROOT" A15R_SCRATCH="$SCRATCH" A15R_DATA="$DATA" \
    node_proof --stop-home || echo "a15r-installed-journey: stop failed" >&2
  A15R_OUT="$OUT" node_proof --scrub-evidence || echo "a15r-installed-journey: scrub failed" >&2
  if [[ -d "$HOME_ROOT" ]]; then
    A15R_HOME="$HOME_ROOT" A15R_SCRATCH="$SCRATCH" \
      node_proof --remove-throwaway || echo "a15r-installed-journey: throwaway remove failed" >&2
  fi
}
trap cleanup EXIT

fail() {
  local name="$1"
  shift
  echo "a15r-installed-journey: $*" >&2
  if [[ ! -f "$OUT/receipt.json" ]]; then
    A15R_OUT="$OUT" \
      A15R_SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)" \
      A15R_SOURCE_TREE="$(git -C "$ROOT" rev-parse 'HEAD^{tree}')" \
      A15R_ONLY="$ONLY" \
      FAILED="$name" REASON="$*" \
      node_proof --shell-fail || true
  fi
  exit 1
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  fail release_signed "This installed journey runs on Mac only. The Home data directory is Library/Application Support/elastos."
fi

if [[ -z "$ONLY" ]]; then
  echo "Full mode needs the agents-in-gateway change. It is not proof of anything until that change is in the gateway."
  if ! node_proof --agents-in-gateway; then
    fail release_signed "full mode refuses to run: the agents-in-gateway route is not in this tree"
  fi
fi

GIT_BEFORE="$(git -C "$ROOT" status --porcelain)"
export A15R_GIT_BEFORE="$GIT_BEFORE"
if [[ -n "$GIT_BEFORE" ]]; then
  fail release_signed "git status --porcelain is not empty before the build"
fi

if [[ -e "$HOME_ROOT" ]]; then
  fail release_signed "installed home already exists at $HOME_ROOT; this runner does not reuse or delete it"
fi
mkdir -p "$SCRATCH"
mkdir -p "$HOME_ROOT"
printf '%s\n' "$HOME_ROOT" > "$HOME_ROOT/.a15r-throwaway"

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
  git -C "$ROOT" archive --format=tar "HEAD:capsules/$name" | tar -x -C "$DATA/capsules/$name" \
    || fail installed_identity_recorded "could not copy the committed $name page folder"
done
# Free loopback port. The well-known UDP 4433 is not used.
# The gateway's managed serve is a second process with its own Home, so it
# gets the same line. Otherwise that process would bind 0.0.0.0:4433.
printf '%s\n' 'carrier_bind_addr = "127.0.0.1:0"' > "$DATA/config.toml"
for label in home identity chat; do
  child="$DATA/managed-runtimes/$label/home/Library/Application Support/elastos"
  mkdir -p "$child"
  printf '%s\n' 'carrier_bind_addr = "127.0.0.1:0"' > "$child/config.toml"
done

GW_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
BIN="$DATA/bin/elastos"

set -m
(
  cd "$HOME_ROOT"
  exec env -i \
    ${PATH:+PATH="$PATH"} \
    ${TMPDIR:+TMPDIR="$TMPDIR"} \
    ${LANG:+LANG="$LANG"} \
    ${LC_ALL:+LC_ALL="$LC_ALL"} \
    ${LC_CTYPE:+LC_CTYPE="$LC_CTYPE"} \
    ${USER:+USER="$USER"} \
    ${LOGNAME:+LOGNAME="$LOGNAME"} \
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

PLAYWRIGHT_SETUP="$(A15R_ROOT="$ROOT" A15R_SCRATCH="$SCRATCH" node_proof --prepare-playwright)" \
  || fail owner_passkey_created "pinned playwright is not available"
A15R_PLAYWRIGHT_DIR="$(printf '%s\n' "$PLAYWRIGHT_SETUP" | sed -n '1p')"
PLAYWRIGHT_BROWSERS_PATH="$(printf '%s\n' "$PLAYWRIGHT_SETUP" | sed -n '2p')"
export A15R_PLAYWRIGHT_DIR PLAYWRIGHT_BROWSERS_PATH
export A15R_PLAYWRIGHT_SOURCE="$(printf '%s\n' "$PLAYWRIGHT_SETUP" | sed -n '3p')"
export A15R_PLAYWRIGHT_VERSION="$(printf '%s\n' "$PLAYWRIGHT_SETUP" | sed -n '4p')"
if [[ -n "$ONLY" ]]; then
  echo "mode: $ONLY"
fi

node_proof
STATUS=$?
GIT_AFTER="$(git -C "$ROOT" status --porcelain)"
if [[ -n "$GIT_AFTER" ]]; then
  echo "a15r-installed-journey: git status --porcelain is not empty at the end" >&2
  STATUS=1
fi
exit "$STATUS"
