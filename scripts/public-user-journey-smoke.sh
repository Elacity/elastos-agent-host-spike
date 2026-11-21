#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

bash "$SCRIPT_DIR/public-root-site-smoke.sh"
bash "$SCRIPT_DIR/system-camofox-smoke.sh"
bash "$SCRIPT_DIR/home-camofox-smoke.sh"
if [[ -z "${ELASTOS_CLI_LAUNCH_TOKEN:-}" ]]; then
  ELASTOS_CLI_LAUNCH_TOKEN="$("${ELASTOS_CLI_BIN:-elastos}" home --cli-launch-token)"
  [[ -n "$ELASTOS_CLI_LAUNCH_TOKEN" ]] || { echo "Home CLI returned no launch grant" >&2; exit 1; }
  export ELASTOS_CLI_LAUNCH_TOKEN
fi
bash "$SCRIPT_DIR/chat-room-runtime-activity-smoke.sh"
bash "$SCRIPT_DIR/chat-room-session-reuse-camofox-smoke.sh"
bash "$SCRIPT_DIR/chat-room-guest-identity-camofox-smoke.sh"
bash "$SCRIPT_DIR/chat-room-gateway-camofox-smoke.sh"
