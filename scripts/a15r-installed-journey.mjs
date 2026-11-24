#!/usr/bin/env node
// Owner journey against the installed Home started by a15r-installed-journey.sh.
// Route: POST /api/apps/system/agents/launch after enable, create, activate,
// and passkey step-up operation agent.start.

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const out = process.env.A15R_OUT;
const root = process.env.A15R_ROOT;
const home = process.env.A15R_HOME;
const data = process.env.A15R_DATA;
const gateway = process.env.A15R_GATEWAY;
const gatewayAddr = process.env.A15R_GATEWAY_ADDR;
const serveBin = process.env.A15R_SERVE_BIN;
const pidFile = process.env.A15R_PID_FILE;
const logPath = process.env.A15R_LOG;
const pageOrigin = gateway;
const unknownId = "agent:v2:" + "f".repeat(32);
const noSuchAgent = "the caller owns no agent with that id";
const adminRequired = "admin passkey required";
const freshPasskey = "fresh passkey is required to approve an agent plan";
const names = [
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
];

const marks = new Map();
const started = Date.now();
const timings = {};
const notes = [];
const screenshots = [];
let browser;
let adminPage;
let stopped = "";
const state = {
  homeToken: "",
  guestToken: "",
  systemToken: "",
  guestSystemToken: "",
  inboxToken: "",
  agentA: "",
  agentB: "",
  rootA: "",
  rootB: "",
  launchA: null,
  launchB: null,
  grants: [],
  card: null,
  requestId: "",
  approveBody: null,
};

function clip(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > 900 ? text.slice(0, 900) + "…" : text;
}

function mark(name, status, detail = "") {
  marks.set(name, { name, status, detail: clip(detail) });
}

function pass(name, detail = "") {
  mark(name, "pass", detail);
}

function halt(name, detail = "") {
  mark(name, "fail", detail);
  const error = new Error(name);
  error.detail = detail;
  throw error;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function call(method, urlPath, token, body) {
  // Home launch and step-up are the Home document. A System or Inbox token
  // is a capsule grant and is admitted only from the opaque origin.
  const capsule = urlPath.startsWith("/api/apps/system/") || urlPath.startsWith("/api/apps/inbox/");
  const headers = capsule
    ? { origin: "null" }
    : {
        origin: pageOrigin,
        "sec-fetch-site": "same-origin",
        referer: pageOrigin + "/home/",
      };
  if (token) headers["x-elastos-home-token"] = token;
  let payload;
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const response = await fetch(pageOrigin + urlPath, { method, headers, body: payload });
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* plain refusal text */ }
  return { status: response.status, text, json };
}

function tokenFromRoute(route) {
  const hash = String(route || "").split("#")[1] || "";
  return new URLSearchParams(hash).get("home_token") || "";
}

async function launchApp(homeToken, target) {
  const reply = await call("POST", "/api/apps/home/launch", homeToken, { target });
  const token = tokenFromRoute(reply.json && reply.json.route);
  return { reply, token };
}

function loadPlaywright() {
  const candidates = [
    path.join(out, "tool/node_modules/playwright/index.js"),
    path.join(root, "elastos/tools/browser-playwright-engine/node_modules/playwright/index.js"),
  ];
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    return createRequire(candidate)(candidate);
  }
  return null;
}

async function addAuthenticator(context, page) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

async function shot(page, name) {
  const dir = path.join(out, "screenshots");
  fs.mkdirSync(dir, { recursive: true });
  for (const [label, width, height] of [["desktop", 1280, 800], ["phone", 390, 844]]) {
    const file = path.join(dir, `${name}-${label}.png`);
    try {
      await page.setViewportSize({ width, height });
      await page.screenshot({ path: file });
      screenshots.push({ name: `${name}-${label}`, status: "taken", path: file });
    } catch (error) {
      screenshots.push({ name: `${name}-${label}`, status: "skipped", detail: clip(String(error)) });
    }
  }
  await page.setViewportSize({ width: 1280, height: 800 }).catch(() => {});
}

async function enroll(page, displayName, guest) {
  await page.goto(pageOrigin + "/home/", { waitUntil: "domcontentloaded", timeout: 30000 });
  if (guest) {
    await page.locator("#home-unlock-create").waitFor({ state: "visible", timeout: 30000 });
    await page.locator("#home-unlock-create").click();
  }
  const field = page.locator("#home-unlock-name");
  await field.waitFor({ state: "visible", timeout: 30000 });
  await field.fill(displayName);
  const registered = page.waitForResponse((response) => (
    response.request().method() === "POST"
    && response.url().endsWith("/api/auth/passkey/register/complete")
  ), { timeout: 60000 });
  registered.catch(() => {});
  await page.locator("#home-unlock-primary").click();
  const completion = await registered;
  const text = await completion.text();
  if (!completion.ok()) {
    const status = await page.locator("#home-unlock-status").textContent().catch(() => "");
    throw new Error(`register ${completion.status()} ${text.slice(0, 240)} ${status}`);
  }
  return JSON.parse(text);
}

async function assertCredential(options) {
  return adminPage.evaluate(async (options) => {
    const decode = (value) => {
      const text = String(value).replace(/-/g, "+").replace(/_/g, "/");
      const padded = text + "=".repeat((4 - (text.length % 4)) % 4);
      const binary = atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
      return bytes.buffer;
    };
    const encode = (buffer) => {
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    };
    const publicKey = { ...(options.publicKey || {}) };
    publicKey.challenge = decode(publicKey.challenge);
    publicKey.allowCredentials = (publicKey.allowCredentials || []).map((credential) => ({
      ...credential,
      id: decode(credential.id),
    }));
    const credential = await navigator.credentials.get({ publicKey });
    if (!credential) throw new Error("assertion was cancelled");
    return {
      id: credential.id,
      rawId: encode(credential.rawId),
      type: credential.type,
      response: {
        clientDataJson: encode(credential.response.clientDataJSON),
        authenticatorData: encode(credential.response.authenticatorData),
        signature: encode(credential.response.signature),
        userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null,
      },
    };
  }, options);
}

async function stepUp(appToken, operation, request) {
  const begun = await call("POST", "/api/auth/passkey-step-up/begin", state.homeToken, {
    schema: "elastos.auth.passkey-step-up.begin.request/v1",
    app_token: appToken,
    operation,
    request,
  });
  if (begun.status !== 200) {
    throw new Error(`step-up begin ${begun.status} ${begun.text.slice(0, 300)}`);
  }
  const assertion = await assertCredential(begun.json.options);
  const done = await call("POST", "/api/auth/passkey-step-up/complete", state.homeToken, {
    schema: "elastos.auth.passkey-step-up.complete.request/v1",
    ceremony_id: begun.json.ceremony_id,
    response: assertion,
  });
  if (done.status !== 200 || !done.json?.step_up_token) {
    throw new Error(`step-up complete ${done.status} ${done.text.slice(0, 300)}`);
  }
  return done.json.step_up_token;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function agentRows() {
  const file = path.join(data, "ElastOS/System/Auth/agent-records.json");
  if (!fs.existsSync(file)) return [];
  const body = readJson(file);
  return (body.agents || []).map((agent) => ({
    id: agent.record?.principal_id || "",
    root: agent.record?.localhost_root || "",
    owner: agent.record?.owner || "",
    active: agent.active === true,
  }));
}

function rootSuffix(root) {
  return String(root || "").replace(/^localhost:\/\//, "");
}

function inspectRecords() {
  const dir = path.join(data, "inspect-actions");
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((name) => name.endsWith(".json")).map((name) => (
    readJson(path.join(dir, name))
  ));
}

function auditEvents() {
  const file = path.join(data, "ElastOS/System/Auth/auth-state.json");
  if (!fs.existsSync(file)) return [];
  const body = readJson(file);
  return Array.isArray(body.audit) ? body.audit : [];
}

function signedCount(eventType) {
  return auditEvents().filter((event) => (
    event.event_type === eventType
    && typeof event.signature === "string"
    && event.signature.length > 0
  )).length;
}

function interestingFiles() {
  const found = [];
  const walk = (dir) => {
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name === "provider-copies") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        const rel = path.relative(data, full);
        if (rel.includes("Documents") || entry.name === "journal" || entry.name === "note.txt") {
          try {
            const bytes = fs.readFileSync(full);
            const hash = crypto.createHash("sha256").update(bytes).digest("hex");
            found.push({
              path: rel,
              sha256: hash,
              size: bytes.length,
              plaintext: bytes.equals(Buffer.from("three lines")),
            });
          } catch { /* a live file can be replaced while the receipt is taken */ }
        }
      }
    }
  };
  walk(data);
  return found.sort((left, right) => left.path.localeCompare(right.path));
}

function ownerFiles(files) {
  return files.filter((file) => file.path.includes("/Users/") && !file.path.includes("UsersAI"));
}

async function shellToken() {
  const coords = readJson(path.join(data, "home-runtime-coords.json"));
  const response = await fetch(String(coords.api_url).replace(/\/$/, "") + "/api/auth/attach", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ secret: coords.attach_secret, scope: "shell" }),
  });
  const body = await response.json();
  if (!response.ok || !body.token) throw new Error("runtime attach failed");
  return { token: body.token, api: String(coords.api_url).replace(/\/$/, "") };
}

async function capsules() {
  const attached = await shellToken();
  const response = await fetch(attached.api + "/api/capsules", {
    headers: { authorization: "Bearer " + attached.token },
  });
  const text = await response.text();
  return { status: response.status, text, json: JSON.parse(text) };
}

function liveSessions(list, launches) {
  const rows = list.json?.capsules || [];
  return launches.filter((launch) => rows.some((row) => (
    row.session_id === launch.session_id
    && (row.status === "starting" || row.status === "running")
  )));
}

async function inbox() {
  const reply = await call("GET", "/api/apps/inbox/summary", state.inboxToken);
  if (reply.status === 401 || reply.status === 403) {
    const launched = await launchApp(state.homeToken, "inbox");
    if (launched.token) state.inboxToken = launched.token;
    return call("GET", "/api/apps/inbox/summary", state.inboxToken);
  }
  return reply;
}

function entries(summary) {
  return summary.json?.notifications?.entries || [];
}

function resourceOf(body) {
  const text = String(body || "");
  const matched = text.match(/access to ([^.]*)\./);
  return matched ? matched[1] : text;
}

async function approveGrants(deadlineMs) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    const summary = await inbox();
    let acted = false;
    for (const entry of entries(summary)) {
      const action = entry.action_ref?.action_id || "";
      if (!action.startsWith("capability-approve-request:")) continue;
      const resource = resourceOf(entry.body);
      if (resource.includes(state.rootA) && resource.includes(state.rootB)) {
        state.grants.push({ resource, status: "refused-by-runner", body: entry.body });
        return "cross";
      }
      if (resource.startsWith("elastos://inspect/submit_agent_plan")) continue;
      const reply = await call("POST", "/api/apps/inbox/actions", state.inboxToken, { action_id: action });
      state.grants.push({ resource, status: reply.status, body: entry.body, result: reply.text.slice(0, 180) });
      acted = true;
    }
    const files = interestingFiles();
    const own = [state.rootA, state.rootB].every((root) => (
      files.some((file) => file.path.includes(rootSuffix(root)))
      || state.grants.some((grant) => grant.status === 200 && String(grant.resource).includes(root))
    ));
    if (own && !acted) return "ready";
    await sleep(500);
  }
  return "timeout";
}

async function stopAgent(agentId) {
  return call("POST", "/api/apps/system/agents/stop", state.systemToken, { agent_id: agentId });
}

function planCards(summary) {
  return entries(summary).filter((entry) => (
    entry.kind === "agent_plan"
    || String(entry.action_ref?.action_id || "").startsWith("agent-plan-approve-request:")
  ));
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function stopServe() {
  const pid = Number(fs.readFileSync(pidFile, "utf8").trim());
  try { process.kill(-pid, "SIGTERM"); } catch { try { process.kill(pid, "SIGTERM"); } catch { /* already gone */ } }
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline && alive(pid)) await sleep(200);
  if (alive(pid)) {
    try { process.kill(-pid, "SIGKILL"); } catch { /* already gone */ }
  }
}

async function startServe() {
  const log = fs.openSync(logPath, "a");
  const env = { ...process.env, HOME: home, ELASTOS_QUIET_RUNTIME_NOTICES: "1" };
  delete env.XDG_DATA_HOME;
  delete env.XDG_CONFIG_HOME;
  delete env.XDG_STATE_HOME;
  delete env.XDG_CACHE_HOME;
  const child = spawn(serveBin, ["gateway", "--addr", gatewayAddr], {
    cwd: home,
    env,
    detached: true,
    stdio: ["ignore", log, log],
  });
  child.unref();
  fs.writeFileSync(pidFile, String(child.pid));
  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(pageOrigin + "/api/auth/passkey/status", {
        headers: {
          origin: pageOrigin,
          referer: pageOrigin + "/home/",
          "sec-fetch-site": "same-origin",
        },
      });
      if (response.ok) {
        const ensured = await call("POST", "/api/apps/home/runtime/ensure", state.homeToken);
        if (ensured.json?.running) return;
      }
    } catch { /* gateway still starting */ }
    await sleep(500);
  }
  throw new Error("restarted gateway did not ensure its Home runtime");
}

function writeReceipt() {
  const assertions = names.map((name) => marks.get(name) || { name, status: "not reached", detail: "" });
  const install = fs.existsSync(path.join(out, "install.json"))
    ? readJson(path.join(out, "install.json"))
    : {};
  const receipt = {
    route: "POST /api/apps/system/agents/launch",
    step_up_operation: "agent.start",
    plan_step_up_operation: "agent_plan.approve",
    source_commit: process.env.A15R_SOURCE_COMMIT || "",
    source_tree: process.env.A15R_SOURCE_TREE || "",
    install,
    timings_ms: { ...timings, total: Date.now() - started },
    assertions,
    card: state.card,
    grants: state.grants,
    launches: { a: state.launchA, b: state.launchB },
    screenshots,
    notes,
    stopped,
  };
  fs.writeFileSync(path.join(out, "receipt.json"), JSON.stringify(receipt, null, 2) + "\n");
  return assertions.some((item) => item.status !== "pass") ? 1 : 0;
}

async function main() {
  const install = readJson(path.join(out, "install.json"));
  const keyGone = !fs.existsSync(path.join(data, ".a15r-publisher.key"));
  if (install.signer_did && install.release_sha256 && install.key_deleted && keyGone) {
    pass("release_signed", install.signer_did);
  } else halt("release_signed", "install.json is missing a signed release");
  if (install.key_deleted && keyGone) pass("signing_key_deleted");
  else halt("signing_key_deleted", "disposable key is still present");
  if (install.runtime_sha256 && install.wasm_sha256 && install.components_sha256 && install.bundle_cid) {
    pass("installed_identity_recorded", {
      runtime_sha256: install.runtime_sha256,
      wasm_sha256: install.wasm_sha256,
      components_sha256: install.components_sha256,
      bundle_cid: install.bundle_cid,
    });
  } else halt("installed_identity_recorded", "install identity is incomplete");
  pass("gateway_started", gateway);

  const playwright = loadPlaywright();
  if (!playwright) {
    screenshots.push({ name: "unlock", status: "skipped", detail: "playwright is not installed" });
    halt("owner_passkey_created", "playwright is not installed");
  }
  browser = await playwright.chromium.launch({ headless: true });
  const adminContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  adminPage = await adminContext.newPage();
  await addAuthenticator(adminContext, adminPage);
  await adminPage.goto(pageOrigin + "/home/", { waitUntil: "domcontentloaded", timeout: 30000 });
  await shot(adminPage, "unlock");
  let owner;
  try {
    owner = await enroll(adminPage, "Owner", false);
  } catch (error) {
    const bodyText = await adminPage.locator("body").innerText().catch(() => "");
    halt("owner_passkey_created", `${error.message || error} page: ${bodyText.slice(0, 240)}`);
  }
  if (!owner.home_token) halt("owner_passkey_created", "register complete had no home token");
  state.homeToken = owner.home_token;
  pass("owner_passkey_created", owner.principal_id || "owner");
  timings.owner_ms = Date.now() - started;

  const ensured = await call("POST", "/api/apps/home/runtime/ensure", state.homeToken);
  if (!ensured.json?.running || !ensured.json?.api_url) {
    halt("home_runtime_ensured", { status: ensured.status, body: ensured.text.slice(0, 500) });
  }
  pass("home_runtime_ensured", ensured.json.api_url);
  pass("runtime_started", ensured.json.api_url);

  const system = await launchApp(state.homeToken, "system");
  if (!system.token) halt("u3_agents_enabled", clip(system.reply.text));
  state.systemToken = system.token;
  const enabled = await call("POST", "/api/apps/system/agents/enable", state.systemToken, {});
  if (enabled.status !== 200 || enabled.json?.enabled !== true) {
    halt("u3_agents_enabled", { status: enabled.status, body: enabled.text.slice(0, 300) });
  }
  pass("u3_agents_enabled");
  const guestRegistration = await call(
    "POST", "/api/apps/system/access/guest-registration", state.systemToken, { enabled: true },
  );
  if (guestRegistration.status !== 200) {
    halt("u3_guest_refused", "guest registration was not enabled: " + guestRegistration.text.slice(0, 240));
  }

  const guestContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const guestPage = await guestContext.newPage();
  await addAuthenticator(guestContext, guestPage);
  let guest;
  try {
    guest = await enroll(guestPage, "Guest", true);
  } catch (error) {
    halt("u3_guest_refused", String(error.message || error));
  }
  await guestContext.close();
  if (!guest.home_token) halt("u3_guest_refused", "guest passkey completed without a home token");
  state.guestToken = guest.home_token;
  const guestSystem = await launchApp(state.guestToken, "system");
  state.guestSystemToken = guestSystem.token;
  const guestCreate = await call("POST", "/api/apps/system/agents/create", state.guestSystemToken || state.guestToken, {
    display_name: "Guest Agent", agent_host: "agent-host", request_id: "a15r-s9b-guest",
  });
  const guestRefused = guestCreate.status === 403 && guestCreate.text.includes(adminRequired);
  if (!guestRefused) {
    halt("u3_guest_refused", { status: guestCreate.status, body: guestCreate.text.slice(0, 300), launch: guestSystem.reply.status });
  }
  pass("u3_guest_refused", { status: guestCreate.status, body: guestCreate.text.slice(0, 180) });

  const spoof = await call("POST", "/api/apps/system/agents/create", state.systemToken, {
    display_name: "Spoof", agent_host: "agent-host", request_id: "a15r-s9b-spoof", owner: "person:spoof",
  });
  if (spoof.status !== 409 || !spoof.text.includes("agent request is invalid")) {
    halt("u3_owner_field_refused", { status: spoof.status, body: spoof.text.slice(0, 300) });
  }
  pass("u3_owner_field_refused", spoof.text.slice(0, 180));

  const createdA = await call("POST", "/api/apps/system/agents/create", state.systemToken, {
    display_name: "Agent A", agent_host: "agent-host", request_id: "a15r-s9b-agent-a",
  });
  state.agentA = createdA.json?.agent_id || "";
  if (createdA.status !== 200 || !/^agent:v2:[0-9a-f]{32}$/.test(state.agentA) || createdA.json.active !== false) {
    halt("u3_agent_created", { status: createdA.status, body: createdA.text.slice(0, 400) });
  }
  pass("u3_agent_created", state.agentA);

  const unknownActivate = await call("POST", "/api/apps/system/agents/activate", state.systemToken, {
    agent_id: unknownId, active: true,
  });
  let unknownLaunch = { status: 0, text: "step-up not attempted" };
  try {
    const unknownStep = await stepUp(state.systemToken, "agent.start", { agent_id: unknownId });
    unknownLaunch = await call("POST", "/api/apps/system/agents/launch", state.systemToken, {
      agent_id: unknownId, step_up_token: unknownStep,
    });
  } catch (error) {
    unknownLaunch = { status: 0, text: String(error.message || error) };
  }
  const unknownRefused = unknownActivate.status === 409 && unknownActivate.text.includes(noSuchAgent)
    && unknownLaunch.status === 409 && unknownLaunch.text.includes(noSuchAgent);
  if (!unknownRefused) {
    halt("u3_unknown_id_refused", {
      activate: { status: unknownActivate.status, body: unknownActivate.text.slice(0, 220) },
      launch: { status: unknownLaunch.status, body: String(unknownLaunch.text).slice(0, 220) },
    });
  }
  pass("u3_unknown_id_refused", noSuchAgent);

  const activatedA = await call("POST", "/api/apps/system/agents/activate", state.systemToken, {
    agent_id: state.agentA, active: true,
  });
  if (activatedA.status !== 200 || activatedA.json?.active !== true) {
    halt("u3_agent_activated", { status: activatedA.status, body: activatedA.text.slice(0, 300) });
  }
  pass("u3_agent_activated", state.agentA);
  const startedA = await (async () => {
    const step = await stepUp(state.systemToken, "agent.start", { agent_id: state.agentA });
    return call("POST", "/api/apps/system/agents/launch", state.systemToken, {
      agent_id: state.agentA, step_up_token: step,
    });
  })();
  state.launchA = startedA.json;
  if (startedA.status !== 200 || !startedA.json?.session_id) {
    halt("u3_agent_started", { status: startedA.status, body: startedA.text.slice(0, 400) });
  }
  pass("u3_agent_started", { session_id: startedA.json.session_id, status: startedA.json.status });

  const createdB = await call("POST", "/api/apps/system/agents/create", state.systemToken, {
    display_name: "Agent B", agent_host: "agent-host", request_id: "a15r-s9b-agent-b",
  });
  state.agentB = createdB.json?.agent_id || "";
  if (createdB.status !== 200 || state.agentB === state.agentA || !/^agent:v2:[0-9a-f]{32}$/.test(state.agentB)) {
    halt("u4_second_agent_created", { status: createdB.status, body: createdB.text.slice(0, 300) });
  }
  pass("u4_second_agent_created", state.agentB);
  const activatedB = await call("POST", "/api/apps/system/agents/activate", state.systemToken, {
    agent_id: state.agentB, active: true,
  });
  if (activatedB.status !== 200) halt("u4_both_running", activatedB.text.slice(0, 240));
  const startedB = await (async () => {
    const step = await stepUp(state.systemToken, "agent.start", { agent_id: state.agentB });
    return call("POST", "/api/apps/system/agents/launch", state.systemToken, {
      agent_id: state.agentB, step_up_token: step,
    });
  })();
  state.launchB = startedB.json;
  const rows = agentRows();
  const rowA = rows.find((row) => row.id === state.agentA);
  const rowB = rows.find((row) => row.id === state.agentB);
  state.rootA = rowA?.root || "";
  state.rootB = rowB?.root || "";
  const listed = await capsules();
  const both = startedA.status === 200 && startedB.status === 200
    && liveSessions(listed, [state.launchA, state.launchB]).length === 2;
  if (!both) {
    halt("u4_both_running", {
      a: state.launchA, b: state.launchB, list: listed.text.slice(0, 400),
    });
  }
  pass("u4_both_running", {
    a: state.launchA.session_id, b: state.launchB.session_id,
  });
  const distinct = state.rootA.startsWith("localhost://UsersAI/")
    && state.rootB.startsWith("localhost://UsersAI/")
    && state.rootA !== state.rootB;
  if (!distinct) halt("u4_distinct_roots", { a: state.rootA, b: state.rootB });
  pass("u4_distinct_roots", { a: state.rootA, b: state.rootB });

  const inboxLaunch = await launchApp(state.homeToken, "inbox");
  if (!inboxLaunch.token) halt("journal_in_agent_root", inboxLaunch.reply.text.slice(0, 240));
  state.inboxToken = inboxLaunch.token;
  const grantResult = await approveGrants(240000);
  const filesAfterGrants = interestingFiles();
  const crossed = state.grants.some((grant) => (
    String(grant.resource).includes(state.rootA) && String(grant.resource).includes(state.rootB)
  )) || filesAfterGrants.some((file) => (
    file.path.includes(rootSuffix(state.rootA)) && file.path.includes(rootSuffix(state.rootB))
  ));
  const separated = !crossed && state.rootA !== state.rootB && state.grants.some((grant) => (
    grant.status === 200 && String(grant.resource).includes(rootSuffix(state.rootA))
  )) && state.grants.some((grant) => (
    grant.status === 200 && String(grant.resource).includes(rootSuffix(state.rootB))
  ));
  if (!separated) {
    halt("u4_no_cross_read", { grantResult, grants: state.grants, files: filesAfterGrants });
  }
  pass("u4_no_cross_read", {
    grants: state.grants.map((grant) => grant.resource),
    files: filesAfterGrants.map((file) => file.path),
  });
  notes.push("The real agent-host does not attempt a cross-read. Isolation is the approved resource of each agent and the file path under that agent's root.");
  const journalA = filesAfterGrants.some((file) => file.path.includes(rootSuffix(state.rootA)))
    || state.grants.some((grant) => grant.status === 200 && String(grant.resource).includes(rootSuffix(state.rootA)) && String(grant.resource).includes("agent-host"));
  if (!journalA) halt("journal_in_agent_root", { grantResult, grants: state.grants, files: filesAfterGrants });
  pass("journal_in_agent_root", { grantResult, root: state.rootA });

  const stoppedB = await stopAgent(state.agentB);
  if (stoppedB.status !== 200) notes.push("stop of the second agent returned " + stoppedB.status + " " + stoppedB.text.slice(0, 160));
  const before = interestingFiles();
  const ownerBefore = ownerFiles(before);
  let plan = null;
  const planDeadline = Date.now() + 90000;
  while (Date.now() < planDeadline && !plan) {
    const summary = await inbox();
    const submits = entries(summary).filter((entry) => (
      String(entry.action_ref?.action_id || "").startsWith("capability-approve-request:")
      && resourceOf(entry.body).startsWith("elastos://inspect/submit_agent_plan")
    ));
    if (submits.length === 1) {
      await call("POST", "/api/apps/inbox/actions", state.inboxToken, {
        action_id: submits[0].action_ref.action_id,
      });
    } else if (submits.length > 1) {
      halt("plan_card_captured", "more than one plan submit request remained");
    }
    const cards = planCards(summary);
    if (cards.length === 1) plan = cards[0];
    else if (cards.length > 1) halt("one_pending_record", "more than one agent plan card");
    if (!plan) await sleep(500);
  }
  if (!plan) halt("plan_card_captured", "no agent plan card appeared");
  state.card = {
    kind: plan.kind,
    title: plan.title,
    body: plan.body,
    action_id: plan.action_ref?.action_id || "",
    request_binding: plan.request_binding || null,
  };
  state.requestId = state.card.action_id.replace("agent-plan-approve-request:", "");
  pass("plan_card_captured", state.card);
  const pending = inspectRecords().filter((record) => record.status === "pending");
  if (pending.length !== 1 || pending[0].request_id !== state.requestId) {
    halt("one_pending_record", pending.map((record) => ({ id: record.request_id, status: record.status })));
  }
  pass("one_pending_record", state.requestId);

  const refused = await call("POST", "/api/apps/inbox/actions", state.inboxToken, {
    action_id: state.card.action_id,
    request_binding: state.card.request_binding,
  });
  if (refused.status !== 403 || !refused.text.includes(freshPasskey)) {
    halt("approve_without_step_up_refused", { status: refused.status, body: refused.text.slice(0, 300) });
  }
  pass("approve_without_step_up_refused", refused.text.slice(0, 180));
  const stillPending = inspectRecords().filter((record) => record.status === "pending");
  if (stillPending.length !== 1) halt("approve_without_step_up_refused", "pending count changed");

  const keep = (name, ok, detail) => {
    mark(name, ok ? "pass" : "fail", detail);
    return ok;
  };
  try {
    const approvedStep = await stepUp(state.inboxToken, "agent_plan.approve", { request_id: state.requestId });
    state.approveBody = {
      action_id: state.card.action_id,
      request_binding: state.card.request_binding,
      step_up_token: approvedStep,
    };
  } catch (error) {
    mark("step_up_approve", "fail", String(error.message || error));
  }
  if (state.approveBody) {
    const approved = await call("POST", "/api/apps/inbox/actions", state.inboxToken, state.approveBody);
    keep("step_up_approve", approved.status === 200, approved.text.slice(0, 300));
  }
  let settled = null;
  const settleDeadline = Date.now() + 30000;
  while (Date.now() < settleDeadline) {
    settled = inspectRecords().find((record) => record.request_id === state.requestId) || null;
    if (settled && settled.status !== "pending") break;
    await sleep(300);
  }
  const recordResources = JSON.stringify(settled || {}).match(/localhost:\/\/[^"\\\s]+/g) || [];
  const ownDocument = recordResources.some((resource) => (
    resource.startsWith(state.rootA) && resource.endsWith("/Documents/note.txt")
  ));
  const filesAfter = interestingFiles();
  const written = filesAfter.filter((file) => (
    file.path.includes(rootSuffix(state.rootA)) && file.path.endsWith("Documents/note.txt")
  ));
  const authorised = settled?.status === "completed"
    && settled?.result?.status === "ok"
    && ownDocument
    && written.length === 1
    && !before.some((file) => file.path === written[0].path);
  keep("one_authorised_write", authorised, authorised ? { resources: recordResources, file: written[0] } : {
    status: settled?.status,
    result: settled?.result,
    resources: recordResources,
    files: written,
    note: "The installed guest submits localhost://Users/self/Documents/note.txt. An agent root is localhost://UsersAI/<id>. This runner does not rewrite that path.",
  });
  const ownerAfter = ownerFiles(filesAfter);
  keep("owner_document_unchanged", JSON.stringify(ownerBefore) === JSON.stringify(ownerAfter), {
    before: ownerBefore, after: ownerAfter,
  });
  const receiptOk = Boolean(settled
    && settled.principal_id
    && settled.requester_id === state.agentA
    && settled.request_binding
    && settled.result
    && settled.status === "completed"
    && inspectRecords().length === 1);
  keep("one_result_and_receipt", receiptOk, {
    schema: "elastos.agent-plan.result/v1",
    count: inspectRecords().length,
    status: settled?.status,
    requester_id: settled?.requester_id,
  });
  const startedAudits = signedCount("agent_plan.dispatch.started");
  const completedAudits = signedCount("agent_plan.dispatch.completed");
  keep("signed_start_audit", startedAudits === 1, { count: startedAudits });
  keep("signed_completion_audit", completedAudits === 1, { count: completedAudits });
  const afterCard = planCards(await inbox());
  keep("card_removed", afterCard.length === 0, afterCard.map((card) => card.action_ref?.action_id));

  const recordBeforeReplay = JSON.stringify(inspectRecords());
  const auditsBeforeReplay = JSON.stringify(auditEvents().map((event) => event.event_type));
  const filesBeforeReplay = JSON.stringify(interestingFiles());
  const replay = state.approveBody
    ? await call("POST", "/api/apps/inbox/actions", state.inboxToken, state.approveBody)
    : { status: 0, text: "no approve body" };
  const replayClean = replay.status !== 200
    && JSON.stringify(inspectRecords()) === recordBeforeReplay
    && JSON.stringify(auditEvents().map((event) => event.event_type)) === auditsBeforeReplay
    && JSON.stringify(interestingFiles()) === filesBeforeReplay;
  keep("replay_zero", replayClean, { status: replay.status, body: replay.text.slice(0, 240) });

  try {
    await stopServe();
    await startServe();
    const relaunched = await launchApp(state.homeToken, "inbox");
    if (relaunched.token) state.inboxToken = relaunched.token;
    const recordBeforeRestart = JSON.stringify(inspectRecords());
    const auditsBeforeRestart = JSON.stringify(auditEvents().map((event) => event.event_type));
    const filesBeforeRestart = JSON.stringify(interestingFiles());
    const restart = state.approveBody
      ? await call("POST", "/api/apps/inbox/actions", state.inboxToken, state.approveBody)
      : { status: 0, text: "no approve body" };
    const restartClean = restart.status !== 200
      && JSON.stringify(inspectRecords()) === recordBeforeRestart
      && JSON.stringify(auditEvents().map((event) => event.event_type)) === auditsBeforeRestart
      && JSON.stringify(interestingFiles()) === filesBeforeRestart;
    keep("restart_zero", restartClean, { status: restart.status, body: restart.text.slice(0, 240) });
  } catch (error) {
    mark("restart_zero", "fail", String(error.message || error));
  }
  timings.done_ms = Date.now() - started;
}

notes.push("The host is elastos gateway. The owner calls POST /api/apps/home/runtime/ensure, which starts the managed Home runtime. Launch then uses POST /api/apps/system/agents/launch.");
notes.push("The disposable key signs the capsule and the release envelope, then the runner deletes it. holder-canary-fixture.py is unchanged.");
notes.push("A non-admin is a second passkey guest. An unknown id is agent:v2: followed by 32 f digits, refused by activate and by launch.");
notes.push("U4 launches the real agent-host twice. No probe guest is added.");

main().catch((error) => {
  stopped = clip(error && (error.detail || error.stack || error.message) || error);
}).finally(async () => {
  if (browser) await browser.close().catch(() => {});
  const code = writeReceipt();
  process.exit(code);
});
