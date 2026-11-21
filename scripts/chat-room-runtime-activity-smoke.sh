#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${ELASTOS_BASE_URL:-http://127.0.0.1:8090}"
CLI_LAUNCH_TOKEN="${ELASTOS_CLI_LAUNCH_TOKEN:?set ELASTOS_CLI_LAUNCH_TOKEN to a home-cli grant}"
# The named Home is running before this activity check starts.

launch_json=$(
  curl -fsS \
    -H "x-elastos-home-token: ${CLI_LAUNCH_TOKEN}" \
    -X POST \
    -H 'content-type: application/json' \
    "${BASE_URL}/api/apps/home/launch" \
    -d '{"target":"chat-room"}'
)

sleep 1

system_launch_json=$(
  curl -fsS \
    -H "x-elastos-home-token: ${CLI_LAUNCH_TOKEN}" \
    -X POST \
    -H 'content-type: application/json' \
    "${BASE_URL}/api/apps/home/launch" \
    -d '{"target":"system"}'
)
system_token=$(node -e 'const launch = JSON.parse(process.argv[1]); const url = new URL(launch.route, "https://example.invalid"); process.stdout.write(new URLSearchParams(url.hash.slice(1)).get("home_token") || "");' "$system_launch_json")
summary_json=$(curl -fsS -H "x-elastos-home-token: ${system_token}" "${BASE_URL}/api/apps/system/summary")

node - <<'NODE' "$launch_json" "$summary_json"
const launch = JSON.parse(process.argv[2]);
const summary = JSON.parse(process.argv[3]);

function fail(message, details) {
  console.error(`FAIL chat-room-runtime-activity-smoke: ${message}`);
  if (details) {
    console.error(JSON.stringify(details, null, 2));
  }
  process.exit(1);
}

if (launch.target !== "chat-room") {
  fail("unexpected launch target", launch);
}
if (launch.launch_status !== "launched") {
  fail("chat-room was not runtime-launched", launch);
}
if (typeof launch.capsule_id !== "string" || launch.capsule_id.trim() === "") {
  fail("chat-room launch did not return a capsule id", launch);
}
if (!String(launch.route || "").startsWith("/apps/chat-room/?home_token=")) {
  fail("chat-room launch route is not Home-scoped", launch);
}

const runtime = summary.runtime || {};
if (runtime.running !== true) {
  fail("system summary does not report a running local runtime", summary);
}

const events = summary.runtime_log?.events || [];
if (!events.some((event) => event.kind === "capsule_launch" && String(event.summary || "").includes("chat-room"))) {
  fail("system runtime activity did not record the chat-room launch", summary);
}

console.log("PASS chat-room-runtime-activity-smoke");
NODE
