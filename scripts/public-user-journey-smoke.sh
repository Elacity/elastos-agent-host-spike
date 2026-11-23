#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

bash "$SCRIPT_DIR/public-root-site-smoke.sh"
bash "$SCRIPT_DIR/system-camofox-smoke.sh"
bash "$SCRIPT_DIR/home-camofox-smoke.sh"
if [[ -z "${ELASTOS_CLI_LAUNCH_TOKEN:-}" ]]; then
  echo "Home CLI launch grant is passkey-gated; set ELASTOS_CLI_LAUNCH_TOKEN" >&2
  exit 1
fi
bash "$SCRIPT_DIR/chat-room-runtime-activity-smoke.sh"
bash "$SCRIPT_DIR/chat-room-session-reuse-camofox-smoke.sh"
bash "$SCRIPT_DIR/chat-room-guest-identity-camofox-smoke.sh"
bash "$SCRIPT_DIR/chat-room-gateway-camofox-smoke.sh"
