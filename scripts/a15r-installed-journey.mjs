#!/usr/bin/env node
// POST /api/apps/system/agents/launch after enable, create, activate,
// and passkey step-up operation agent.start.

import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

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
  "u4_distinct_roots", "u4_route_refuses_user_area", "journal_in_agent_root",
  "plan_card_captured", "one_pending_record", "approve_without_step_up_refused",
  "step_up_approve", "one_authorised_write", "owner_document_unchanged",
  "one_result_and_receipt", "signed_start_audit", "signed_completion_audit",
  "card_removed", "replay_zero", "restart_zero",
];

const marks = new Map();
const started = Date.now();
const timings = {};
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

export const OWNER_DOCUMENT = Buffer.from("a15r owner document\n");

// Launch posts to the agent runtime (agent_plane::live_coords). The managed
// Home runtime does not hold those sessions, so the live list reads this file.
export const LIVE_SESSION_COORDS = "agent-runtime-coords.json";

// The document the guest used to submit. For this owner, Users/self is that
// person's stored Users root, so the file is Documents/note.txt there.
export const OWNER_NOTE = "Documents/note.txt";

// The installed guest has no request channel, and this route is not the Bus
// read. These in-Runtime rows are the isolation words this journey does not cover.
export const U4_ISOLATION_NOT_COVERED = [
  "the guest reads its own root and gets the bytes it wrote: elastos/crates/elastos-server/src/api/routes.rs:4846 an_agents_guest_serves_its_own_root_on_the_component_bridge",
  "another agent's root is refused over 56 spellings: elastos/crates/elastos-server/src/api/routes.rs:5051 an_agents_guest_is_refused_every_other_spelling_of_another_agents_root",
  "Y's canary stays out of the answer: elastos/crates/elastos-server/src/api/routes.rs:5123 an_agents_guest_is_refused_every_other_spelling_of_another_agents_root",
  "no capability request names Y's root: elastos/crates/elastos-server/src/api/routes.rs:5163 an_agents_guest_is_refused_every_other_spelling_of_another_agents_root",
  "the protected path refuses the other agent's root: elastos/crates/elastos-server/src/api/routes.rs:5202 an_agents_guest_cannot_reach_another_agents_root_on_the_protected_path",
];

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function agentStartRequestSha256(agentId) {
  return crypto.createHash("sha256").update(canonicalJson({ agent_id: agentId })).digest("hex");
}

export function gatewayHealthOk(status, body) {
  return status === 200 && String(body ?? "").trim() === "OK";
}

export function runtimeHealthOk(status, body) {
  if (status !== 200 || typeof body !== "string") return false;
  try {
    return JSON.parse(body).status === "ok";
  } catch {
    return false;
  }
}

function wantedAgentIds(agentIds) {
  const wanted = Array.isArray(agentIds) ? agentIds : [];
  if (wanted.length === 0 || wanted.some((id) => typeof id !== "string" || id.length === 0)) {
    return [];
  }
  return wanted;
}

function signedEvent(event) {
  return typeof event?.signature === "string" && event.signature.length > 0;
}

function reasonObject(event) {
  const reason = event?.reason;
  if (reason && typeof reason === "object") return reason;
  if (typeof reason !== "string") return null;
  try {
    const parsed = JSON.parse(reason);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

// The start row carries agent_id on the event or in its reason. A principal
// id is not that field, and a step-up hash is not that field.
export function carriedAgentId(event) {
  if (typeof event?.agent_id === "string" && event.agent_id.length > 0) return event.agent_id;
  const reason = reasonObject(event);
  if (typeof reason?.agent_id === "string" && reason.agent_id.length > 0) return reason.agent_id;
  return "";
}

export function agentStartStepUps(events, agentIds) {
  const wanted = wantedAgentIds(agentIds);
  if (wanted.length === 0) return { ok: false, matched: [] };
  const matched = new Set();
  for (const event of events || []) {
    if (event?.event_type !== "auth.passkey_step_up.completed") continue;
    if (!signedEvent(event)) continue;
    const reason = reasonObject(event);
    if (!reason || reason.operation !== "agent.start") continue;
    for (const id of wanted) {
      if (reason.request_sha256 === agentStartRequestSha256(id)) matched.add(id);
    }
  }
  return { ok: wanted.every((id) => matched.has(id)), matched: [...matched] };
}

export function signedAgentStarts(events, agentIds) {
  const wanted = wantedAgentIds(agentIds);
  if (wanted.length === 0) return { ok: false, matched: [] };
  const list = events || [];
  const matched = [];
  for (const id of wanted) {
    const requestedAt = list.findIndex((event) => (
      signedEvent(event)
      && event.event_type === "agent.start.requested"
      && carriedAgentId(event) === id
    ));
    if (requestedAt < 0) continue;
    const completed = list.slice(requestedAt + 1).some((event) => (
      signedEvent(event)
      && event.event_type === "agent.start.completed"
      && event.result === "ok"
      && carriedAgentId(event) === id
    ));
    if (completed) matched.push(id);
  }
  return { ok: wanted.every((id) => matched.includes(id)), matched };
}

export function signedStartAudit(events, agentIds) {
  const stepUp = agentStartStepUps(events, agentIds);
  const started = signedAgentStarts(events, agentIds);
  return { ok: stepUp.ok && started.ok, step_up: stepUp, started };
}

function plantedRouteMarker(path) {
  const rel = String(path || "").replaceAll("\\", "/").replace(/^\/+/, "");
  const base = rel.slice(rel.lastIndexOf("/") + 1);
  return base === "own-marker.txt" || base === "cross-read.txt";
}

// A root is ready when the guest has a file there or the owner approved a
// grant for it. The route row's own marker files are not the guest's files.
export function grantWaitSatisfied(files, roots, grants) {
  const wanted = Array.isArray(roots) ? roots : [];
  if (wanted.length === 0) return false;
  return wanted.every((root) => {
    const suffix = rootSuffix(root);
    if (!suffix || suffix.includes("..")) return false;
    const fileHit = (files || []).some((file) => {
      const rel = String(file?.path || "").replaceAll("\\", "/").replace(/^\/+/, "");
      return !plantedRouteMarker(rel) && rel.includes(suffix);
    });
    const grantHit = (grants || []).some((grant) => (
      grant?.status === 200 && String(grant.resource || "").includes(root)
    ));
    return fileHit || grantHit;
  });
}

export function journalFileInRoot(files, root) {
  const suffix = rootSuffix(root);
  if (!suffix || suffix.includes("..")) return false;
  return (files || []).some((file) => {
    const rel = String(file?.path || "").replaceAll("\\", "/").replace(/^\/+/, "");
    const base = rel.slice(rel.lastIndexOf("/") + 1);
    return base === "journal" && rel.startsWith(`${suffix}/`);
  });
}

export function ownerNoteRelative(ownerRoot) {
  if (typeof ownerRoot !== "string" || !ownerRoot.startsWith("localhost://Users/")) return "";
  if (ownerRoot.startsWith("localhost://UsersAI/")) return "";
  const suffix = rootSuffix(ownerRoot);
  if (!suffix || suffix === "Users" || suffix.includes("..")) return "";
  if (suffix.split("/").includes("UsersAI")) return "";
  return `${suffix}/${OWNER_NOTE}`;
}

export function ownerDocumentUnchanged(before, after) {
  if (!Buffer.isBuffer(before) || !Buffer.isBuffer(after) || before.length === 0) return false;
  return before.equals(after);
}

function routeReadRefused(attempt) {
  if (!attempt || attempt.called !== true) return false;
  if (typeof attempt.session !== "string" || attempt.session.length === 0) return false;
  if (typeof attempt.root !== "string" || !attempt.root.startsWith("localhost://UsersAI/")) return false;
  if (typeof attempt.resource !== "string" || !attempt.resource.startsWith(`${attempt.root}/`)) return false;
  if (typeof attempt.marker !== "string" || attempt.marker.length === 0) return false;
  if (attempt.runtime !== LIVE_SESSION_COORDS) return false;
  if (String(attempt.body ?? "").includes(attempt.marker)) return false;
  return attempt.status === 403 || attempt.status === 404;
}

// Both calls use the capsule provider route. A refusal here is the route
// closing every user-area path. It passes only when the own read is refused
// too, so a lone cross-read refusal cannot stand for isolation.
export function userAreaRouteRefused(pair) {
  const own = pair?.own;
  const other = pair?.other;
  if (!routeReadRefused(own) || !routeReadRefused(other)) return false;
  if (own.session !== other.session) return false;
  if (own.root === other.root || own.resource === other.resource) return false;
  return true;
}

export function createdAgentOwnedBy(row, ownerId) {
  if (!row || typeof row.id !== "string" || !row.id.startsWith("agent:v2:")) return false;
  if (typeof row.owner !== "string" || row.owner.length === 0) return false;
  if (typeof ownerId !== "string" || ownerId.length === 0) return false;
  return row.owner === ownerId && row.owner !== row.id;
}

export function shellFailStatuses(failed) {
  const established = ["release_signed", "signing_key_deleted"];
  const cut = names.indexOf(failed);
  return names.map((name, index) => {
    if (name === failed) return "fail";
    if (cut > 0 && index < cut && established.includes(name)) return "pass";
    return "not reached";
  });
}

function storedOwnerRoot(principalId) {
  if (!principalId) return "";
  const file = path.join(data, "ElastOS/System/Auth/auth-state.json");
  if (!fs.existsSync(file)) return "";
  const row = (readJson(file).principals || []).find((principal) => principal.principal_id === principalId);
  const root = String(row?.localhost_root || "");
  if (!root.startsWith("localhost://Users/") || root.startsWith("localhost://UsersAI/")) return "";
  return root;
}

function readFileOrNull(file) {
  try {
    return fs.readFileSync(file);
  } catch {
    return null;
  }
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

async function runtimeToken(coordFile) {
  const coords = readJson(path.join(data, coordFile));
  const response = await fetch(String(coords.api_url).replace(/\/$/, "") + "/api/auth/attach", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ secret: coords.attach_secret, scope: "shell" }),
  });
  const body = await response.json();
  if (!response.ok || !body.token) throw new Error("runtime attach failed: " + coordFile);
  return { token: body.token, api: String(coords.api_url).replace(/\/$/, "") };
}

async function readThroughCapsuleRoute(session, root, fileName) {
  const marker = `a15r-marker-${crypto.randomBytes(8).toString("hex")}`;
  const resource = `${root}/Documents/${fileName}`;
  const attempt = {
    called: false,
    runtime: LIVE_SESSION_COORDS,
    session,
    resource,
    root,
    status: 0,
    body: "",
    marker,
  };
  if (!root || !session) return attempt;
  const full = path.join(data, rootSuffix(root), "Documents", fileName);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, marker);
  try {
    const attached = await runtimeToken(LIVE_SESSION_COORDS);
    const response = await fetch(`${attached.api}/api/provider/localhost/read`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${attached.token}`,
        "content-type": "application/json",
        "x-elastos-capsule-id": session,
      },
      body: JSON.stringify({ path: resource }),
    });
    attempt.called = true;
    attempt.status = response.status;
    attempt.body = await response.text();
  } catch (error) {
    attempt.body = String(error.message || error);
  }
  return attempt;
}

async function attemptUserAreaRoute() {
  const session = String(state.launchA?.session_id || "");
  const own = await readThroughCapsuleRoute(session, String(state.rootA || ""), "own-marker.txt");
  const other = await readThroughCapsuleRoute(session, String(state.rootB || ""), "cross-read.txt");
  return { own, other };
}

function routeAttemptDetail(attempt) {
  const marker = typeof attempt?.marker === "string" ? attempt.marker : "";
  return {
    called: attempt?.called === true,
    runtime: attempt?.runtime || "",
    status: attempt?.status || 0,
    session: attempt?.session || "",
    resource: attempt?.resource || "",
    marker_returned: marker.length > 0 && String(attempt?.body || "").includes(marker),
  };
}

async function capsules() {
  const attached = await runtimeToken(LIVE_SESSION_COORDS);
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
    if (grantWaitSatisfied(files, [state.rootA, state.rootB], state.grants) && !acted) {
      return "ready";
    }
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
  let gatewayProbe;
  try {
    const response = await fetch(`${pageOrigin}/healthz`);
    gatewayProbe = { status: response.status, body: await response.text() };
  } catch (error) {
    halt("gateway_started", String(error.message || error));
  }
  if (!gatewayHealthOk(gatewayProbe.status, gatewayProbe.body)) {
    halt("gateway_started", { status: gatewayProbe.status, body: String(gatewayProbe.body).slice(0, 200) });
  }
  pass("gateway_started", { status: gatewayProbe.status });

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
  let runtimeApi = "";
  try {
    const coords = readJson(path.join(data, "home-runtime-coords.json"));
    runtimeApi = String(coords.api_url || "").replace(/\/$/, "");
  } catch (error) {
    halt("runtime_started", String(error.message || error));
  }
  if (!runtimeApi) halt("runtime_started", "runtime coords have no api_url");
  let runtimeProbe;
  try {
    const response = await fetch(`${runtimeApi}/api/health`);
    runtimeProbe = { status: response.status, body: await response.text() };
  } catch (error) {
    halt("runtime_started", String(error.message || error));
  }
  if (!runtimeHealthOk(runtimeProbe.status, runtimeProbe.body)) {
    halt("runtime_started", {
      api: runtimeApi,
      status: runtimeProbe.status,
      body: String(runtimeProbe.body).slice(0, 200),
    });
  }
  pass("runtime_started", { api: runtimeApi, status: runtimeProbe.status });

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
  const storedA = agentRows().find((row) => row.id === state.agentA);
  if (
    createdA.status !== 200
    || !/^agent:v2:[0-9a-f]{32}$/.test(state.agentA)
    || createdA.json.active !== false
    || !createdAgentOwnedBy(storedA, owner.principal_id)
  ) {
    halt("u3_agent_created", {
      status: createdA.status,
      body: createdA.text.slice(0, 400),
      stored_owner: storedA?.owner || "",
      owner: owner.principal_id || "",
    });
  }
  pass("u3_agent_created", { agent: state.agentA, owner: storedA.owner });

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

  const routeReads = await attemptUserAreaRoute();
  if (!userAreaRouteRefused(routeReads)) {
    halt("u4_route_refuses_user_area", {
      own: routeAttemptDetail(routeReads.own),
      other: routeAttemptDetail(routeReads.other),
      isolation_not_covered: U4_ISOLATION_NOT_COVERED,
    });
  }
  pass("u4_route_refuses_user_area", {
    own: routeAttemptDetail(routeReads.own),
    other: routeAttemptDetail(routeReads.other),
    isolation_not_covered: U4_ISOLATION_NOT_COVERED,
  });

  const inboxLaunch = await launchApp(state.homeToken, "inbox");
  if (!inboxLaunch.token) halt("journal_in_agent_root", inboxLaunch.reply.text.slice(0, 240));
  state.inboxToken = inboxLaunch.token;
  const grantResult = await approveGrants(240000);
  const filesAfterGrants = interestingFiles();
  const journalFiles = filesAfterGrants.filter((file) => journalFileInRoot([file], state.rootA));
  if (journalFiles.length === 0) {
    halt("journal_in_agent_root", { grantResult, files: filesAfterGrants.map((file) => file.path) });
  }
  pass("journal_in_agent_root", { root: state.rootA, files: journalFiles.map((file) => file.path) });

  await stopAgent(state.agentB);
  const ownerRoot = storedOwnerRoot(owner.principal_id);
  const ownerNoteRel = ownerNoteRelative(ownerRoot);
  const ownerDocPath = ownerNoteRel ? path.join(data, ownerNoteRel) : "";
  let ownerDocBefore = null;
  if (ownerDocPath) {
    fs.mkdirSync(path.dirname(ownerDocPath), { recursive: true });
    fs.writeFileSync(ownerDocPath, OWNER_DOCUMENT);
    ownerDocBefore = fs.readFileSync(ownerDocPath);
  }
  const before = interestingFiles();
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
  });
  const ownerDocAfter = ownerDocPath ? readFileOrNull(ownerDocPath) : null;
  keep("owner_document_unchanged", ownerDocumentUnchanged(ownerDocBefore, ownerDocAfter), {
    alias: "localhost://Users/self/Documents/note.txt",
    path: ownerNoteRel,
    before_sha256: ownerDocBefore ? crypto.createHash("sha256").update(ownerDocBefore).digest("hex") : "",
    after_sha256: ownerDocAfter ? crypto.createHash("sha256").update(ownerDocAfter).digest("hex") : "",
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
  const startedAudits = signedStartAudit(auditEvents(), [state.agentA, state.agentB]);
  const completedAudits = signedCount("agent_plan.dispatch.completed");
  keep("signed_start_audit", startedAudits.ok, {
    step_up: startedAudits.step_up,
    started: startedAudits.started,
  });
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
}

function shellFailReceipt() {
  const failed = process.env.FAILED || "";
  const reason = process.env.REASON || "";
  const statuses = shellFailStatuses(failed);
  const assertions = names.map((name, index) => ({
    name,
    status: statuses[index],
    detail: name === failed ? clip(reason) : "",
  }));
  const installPath = path.join(out, "install.json");
  const receipt = {
    route: "POST /api/apps/system/agents/launch",
    step_up_operation: "agent.start",
    plan_step_up_operation: "agent_plan.approve",
    source_commit: process.env.A15R_SOURCE_COMMIT || "",
    source_tree: process.env.A15R_SOURCE_TREE || "",
    install: fs.existsSync(installPath) ? readJson(installPath) : {},
    timings_ms: {},
    assertions,
    card: null,
    grants: [],
    launches: { a: null, b: null },
    screenshots: [],
    stopped: clip(reason),
  };
  fs.writeFileSync(path.join(out, "receipt.json"), JSON.stringify(receipt, null, 2) + "\n");
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  return import.meta.url === pathToFileURL(path.resolve(entry)).href;
}

if (invokedDirectly()) {
  if (process.argv[2] === "--shell-fail") {
    shellFailReceipt();
    process.exit(1);
  }
  main().catch((error) => {
    stopped = clip(error && (error.detail || error.stack || error.message) || error);
  }).finally(async () => {
    if (browser) await browser.close().catch(() => {});
    const code = writeReceipt();
    process.exit(code);
  });
}
