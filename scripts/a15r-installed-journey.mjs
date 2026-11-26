#!/usr/bin/env node
// Full mode needs the agents-in-gateway change. It is not proof of anything
// until that change is in the gateway. Full mode refuses to run until it
// detects that route.
// `--only u3-create` is the create proof. It does not start a guest.
// POST /api/apps/system/agents/launch is the full journey's route, after
// enable, create, activate, and passkey step-up operation agent.start.

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  CARRIER_MODE,
  FULL_MODE_NOTICE,
  agentsInGatewayChange,
  behaviourInputsDir,
  bindsPort,
  gatewayOwnsListener,
  carrierConfigOk,
  elastosSubcommand,
  executableInsideHome,
  gitPorcelain,
  guestCapsuleCount,
  headlessShellRevision,
  homeProcessEnv,
  judgeCreatingOwner,
  listedAgentsMatch,
  macPlaywrightBrowserCache,
  noGuestProof,
  packageVersion,
  pageFolderProof,
  playwrightPin,
  redactDidAndAddress,
  redactInstall,
  removeStaleReceipt,
  throwawayAllowed,
} from "./a15r-installed-journey-proof.mjs";

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
  "u4_distinct_roots", "u4_cross_root_bus_read_gap", "roots_in_own_grants", "journal_in_agent_root",
  "plan_card_captured", "one_pending_record", "approve_without_step_up_refused",
  "step_up_approve", "one_authorised_write", "owner_document_unchanged",
  "one_result_and_receipt", "signed_start_audit", "signed_completion_audit",
  "card_removed", "replay_zero", "restart_zero",
  "install_with_hashes_key_deleted", "u4_unknown_agent_refused", "u4_second_start_refused",
  "card_step_up_approve_one_write_one_receipt", "owner_denial_signed_row",
  "stop_after_the_note_lands", "agents_off_during_run",
  "home_restart_history",
];

// Create only. The full journey's names stay the list above.
export const U3_NAMES = [
  "release_signed", "signing_key_deleted", "installed_identity_recorded",
  "gateway_started", "owner_passkey_created", "u3_agents_enabled",
  "u3_owner_field_refused", "u3_home_asks", "u3_agent_created", "u3_non_owner_refused",
  "u3_unknown_id_refused", "u3_guest_refused", "u3_no_session_refused",
  "u3_agents_disabled_refused", "u3_agent_activated", "u3_no_guest_no_mint",
  "u3_restart_same_record", "u3_create_audit",
];
const chosenId = "agent:v2:" + "ab".repeat(16);

const marks = new Map();
const started = Date.now();
const timings = {};
const screenshots = [];
let browser;
let adminContext;
let adminPage;
const pagePosts = [];
const AGENT_NAME = "Helper";
const AGENT_OFF = "Off until you turn it on";
const AGENT_ON = "On";
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
    process.env.A15R_PLAYWRIGHT_DIR
      ? path.join(process.env.A15R_PLAYWRIGHT_DIR, "index.js")
      : "",
    path.join(out, "tool/node_modules/playwright/index.js"),
    path.join(root, "elastos/tools/browser-playwright-engine/node_modules/playwright/index.js"),
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (!fs.existsSync(candidate)) continue;
    return createRequire(candidate)(candidate);
  }
  return null;
}

function rememberBrowser(playwright, browser) {
  const version = typeof browser?.version === "function" ? browser.version() : "";
  let build = "";
  const child = typeof browser?.process === "function" ? browser.process() : null;
  if (child?.pid) {
    const listed = homeExecutables();
    const row = listed.ok ? listed.rows.find((item) => item.pid === child.pid) : null;
    const match = String(row?.exe || "").match(/(chromium[_-][\w-]*-\d+)/);
    if (match) build = match[1];
  }
  if (!build && process.env.A15R_PLAYWRIGHT_DIR) {
    const revision = headlessShellRevision(process.env.A15R_PLAYWRIGHT_DIR);
    if (revision) build = `chromium_headless_shell-${revision}`;
  }
  browserProof = {
    playwright: process.env.A15R_PLAYWRIGHT_VERSION || packageVersion(
      path.join(process.env.A15R_PLAYWRIGHT_DIR || "", "package.json"),
    ),
    browser: version,
    build,
    source: process.env.A15R_PLAYWRIGHT_SOURCE || "",
  };
  return playwright;
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
// The function name is the citation. A line number is not pinned.
export const U4_ISOLATION_NOT_COVERED = [
  "the guest reads its own root and gets the bytes it wrote: elastos/crates/elastos-server/src/api/routes.rs an_agents_guest_serves_its_own_root_on_the_component_bridge",
  "another agent's root is refused over 56 spellings: elastos/crates/elastos-server/src/api/routes.rs an_agents_guest_is_refused_every_other_spelling_of_another_agents_root",
  "Y's canary stays out of the answer: elastos/crates/elastos-server/src/api/routes.rs an_agents_guest_is_refused_every_other_spelling_of_another_agents_root",
  "no capability request names Y's root: elastos/crates/elastos-server/src/api/routes.rs an_agents_guest_is_refused_every_other_spelling_of_another_agents_root",
  "the protected path refuses the other agent's root: elastos/crates/elastos-server/src/api/routes.rs an_agents_guest_cannot_reach_another_agents_root_on_the_protected_path",
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

// The old wait refused one resource that held both agents' roots. A resource
// is one path, so that wait could not succeed. What it was for is isolation:
// each root is granted only to its own agent. The planted cross-read is part
// of the same check.
export function rootsStayWithTheirAgent(rootA, rootB, grants, plants) {
  if (typeof rootA !== "string" || typeof rootB !== "string" || rootA === "" || rootA === rootB) {
    return false;
  }
  const rows = Array.isArray(grants) ? grants : [];
  const ownGrant = (root, other) => rows.some((grant) => (
    grant?.status === 200
    && String(grant.resource || "").includes(root)
    && !String(grant.resource || "").includes(other)
  ));
  const leaked = rows.some((grant) => {
    const resource = String(grant?.resource || "");
    return resource.includes(rootA) && resource.includes(rootB);
  });
  const own = plants?.own;
  const other = plants?.other;
  const namedRefusal = other?.status === 403 && String(other.body || "").length > 0;
  const planted = typeof own?.resource === "string"
    && own.resource.includes(rootA)
    && !own.resource.includes(rootB)
    && typeof other?.resource === "string"
    && other.resource.includes(rootB)
    && !other.resource.includes(rootA)
    && namedRefusal;
  return ownGrant(rootA, rootB) && ownGrant(rootB, rootA) && !leaked && planted;
}

export function rootsGrantedOnlyToTheirAgent(rootA, rootB, grants) {
  if (typeof rootA !== "string" || typeof rootB !== "string" || rootA === "" || rootA === rootB) {
    return false;
  }
  const rows = Array.isArray(grants) ? grants : [];
  const ownGrant = (root, other) => rows.some((grant) => (
    grant?.status === 200
    && String(grant.resource || "").includes(root)
    && !String(grant.resource || "").includes(other)
  ));
  const leaked = rows.some((grant) => {
    const resource = String(grant?.resource || "");
    return resource.includes(rootA) && resource.includes(rootB);
  });
  return ownGrant(rootA, rootB) && ownGrant(rootB, rootA) && !leaked;
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
  // A missing route is not a refusal. Only a 403 whose body names the cause.
  return attempt.status === 403 && String(attempt.body || "").length > 0;
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

export function shellFailStatuses(failed, rowNames = names) {
  const established = ["release_signed", "signing_key_deleted"];
  const cut = rowNames.indexOf(failed);
  return rowNames.map((name, index) => {
    if (name === failed) return "fail";
    if (cut > 0 && index < cut && established.includes(name)) return "pass";
    return "not reached";
  });
}

const AUDIT_EVENT_DOMAIN = "elastos.audit.event.v1";
const AUDIT_CHAIN_DOMAIN = "elastos.audit.chain-link.v1";
const AUDIT_CHAIN_SCHEMA = "elastos.audit.chain-link/v1";
const AUDIT_CHAIN_STATE_SCHEMA = "elastos.audit.chain-state/v1";
const AUDIT_CHAIN_STATE_DOMAIN = "elastos.audit.chain-state.v1";
const AUDIT_CHAIN_GENESIS = "sha256:genesis";
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Decode(text) {
  if (typeof text !== "string" || text.length === 0) return null;
  let zeros = 0;
  for (const char of text) {
    if (char !== "1") break;
    zeros += 1;
  }
  let value = 0n;
  for (const char of text) {
    const index = BASE58.indexOf(char);
    if (index < 0) return null;
    value = value * 58n + BigInt(index);
  }
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(hex || "00", "hex")]);
}

export function didKeyEd25519(did) {
  if (typeof did !== "string" || did.length !== 56 || !did.startsWith("did:key:z6Mk")) return null;
  const decoded = base58Decode(did.slice("did:key:z".length));
  if (!decoded || decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) return null;
  return decoded.subarray(2);
}

function jsonBytes(value) {
  return Buffer.from(JSON.stringify(value));
}

export function auditEventBytes(event, omitSignature) {
  const fields = [
    ["schema", event.schema],
    ["event_id", event.event_id],
    ["event_type", event.event_type],
    ["principal_id", event.principal_id ?? null],
    ["proof_binding_id", event.proof_binding_id ?? null],
    ["session_id", event.session_id ?? null],
    ["challenge_id", event.challenge_id ?? null],
    ["capsule_id", event.capsule_id ?? null],
    ["result", event.result],
    ["reason", event.reason],
    ["occurred_at", event.occurred_at],
  ];
  if (event.signer_did != null) fields.push(["signer_did", event.signer_did]);
  if (!omitSignature && event.signature != null) fields.push(["signature", event.signature]);
  const body = fields.map(([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value)}`).join(",");
  return Buffer.from(`{${body}}`);
}

export function auditChainHash(sequence, eventId, previousHash, eventHash) {
  const bytes = jsonBytes({
    event_hash: eventHash,
    event_id: eventId,
    previous_hash: previousHash,
    schema: AUDIT_CHAIN_SCHEMA,
    sequence,
  });
  return `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
}

function auditChainPayload(sequence, eventId, previousHash, eventHash, chainHash) {
  return jsonBytes({
    chain_hash: chainHash,
    event_hash: eventHash,
    event_id: eventId,
    previous_hash: previousHash,
    schema: AUDIT_CHAIN_SCHEMA,
    sequence,
  });
}

function auditStatePayload(activatedAt, headSequence, headHash) {
  return jsonBytes({
    activated_at: activatedAt,
    head_hash: headHash,
    head_sequence: headSequence,
    schema: AUDIT_CHAIN_STATE_SCHEMA,
  });
}

function verifyDomainSignature(did, domain, payload, signatureHex) {
  const raw = didKeyEd25519(did);
  if (!raw || typeof signatureHex !== "string" || !/^[0-9a-f]{128}$/.test(signatureHex)) return false;
  const key = crypto.createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") },
    format: "jwk",
  });
  const digest = crypto.createHash("sha256")
    .update(Buffer.from(domain, "utf8"))
    .update(Buffer.from([0]))
    .update(payload)
    .digest();
  return crypto.verify(null, digest, key, Buffer.from(signatureHex, "hex"));
}

export function verifyInstalledAudit(state, runtimeDid) {
  const events = Array.isArray(state?.audit) ? state.audit : [];
  const links = Array.isArray(state?.audit_chain) ? state.audit_chain : [];
  if (!didKeyEd25519(runtimeDid)) return { ok: false, reason: "runtime did", creates: [] };
  if (events.length === 0 || events.length !== links.length) {
    return { ok: false, reason: "chain length", creates: [] };
  }
  const head = state.audit_chain_state;
  const last = links[links.length - 1];
  if (!head || head.schema !== AUDIT_CHAIN_STATE_SCHEMA || head.signer_did !== runtimeDid) {
    return { ok: false, reason: "chain state", creates: [] };
  }
  if (head.head_sequence !== last.sequence || head.head_hash !== last.chain_hash) {
    return { ok: false, reason: "chain head", creates: [] };
  }
  if (!verifyDomainSignature(
    runtimeDid,
    AUDIT_CHAIN_STATE_DOMAIN,
    auditStatePayload(head.activated_at, head.head_sequence, head.head_hash),
    head.signature,
  )) {
    return { ok: false, reason: "chain state signature", creates: [] };
  }
  const creates = [];
  let previous = null;
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const link = links[index];
    if (link.schema !== AUDIT_CHAIN_SCHEMA || link.event_id !== event.event_id) {
      return { ok: false, reason: "binding", event_type: event.event_type, creates };
    }
    if (event.signer_did !== runtimeDid || link.signer_did !== runtimeDid) {
      return { ok: false, reason: "signer", event_type: event.event_type, creates };
    }
    if (previous) {
      if (link.sequence !== previous.sequence + 1 || link.previous_hash !== previous.chain_hash) {
        return { ok: false, reason: "sequence", event_type: event.event_type, creates };
      }
    } else if (link.sequence !== 1 || link.previous_hash !== AUDIT_CHAIN_GENESIS) {
      return { ok: false, reason: "genesis", event_type: event.event_type, creates };
    }
    const eventHash = `sha256:${crypto.createHash("sha256").update(auditEventBytes(event, false)).digest("hex")}`;
    const chainHash = auditChainHash(link.sequence, link.event_id, link.previous_hash, eventHash);
    if (link.event_hash !== eventHash || link.chain_hash !== chainHash) {
      return { ok: false, reason: "hash", event_type: event.event_type, creates };
    }
    const eventOk = verifyDomainSignature(runtimeDid, AUDIT_EVENT_DOMAIN, auditEventBytes(event, true), event.signature);
    const linkOk = verifyDomainSignature(
      runtimeDid,
      AUDIT_CHAIN_DOMAIN,
      auditChainPayload(link.sequence, link.event_id, link.previous_hash, eventHash, chainHash),
      link.signature,
    );
    if (!eventOk || !linkOk) {
      return { ok: false, reason: "signature", event_type: event.event_type, creates };
    }
    if (event.event_type === "agent.record.create" && event.result === "ok") creates.push(event.principal_id);
    previous = link;
  }
  return { ok: true, reason: "", creates };
}

export function storedOwnerIsCreatingOwner(storedOwner, productOwner) {
  return typeof storedOwner === "string"
    && storedOwner.startsWith("person:local:")
    && storedOwner === productOwner;
}

export function refusalIncludes(status, text, wanted, needle) {
  return status === wanted && String(text).includes(needle);
}

export function createReplacesMint(agentsSource, routeSource) {
  const struct = String(agentsSource).match(/struct CreateRequest \{([\s\S]*?)\n\}/);
  const body = struct ? struct[1] : "";
  const fields = [...body.matchAll(/pub\(crate\)\s+([A-Za-z0-9_]+)\s*:/g)].map((match) => match[1]);
  const route = String(routeSource).includes('"/api/apps/system/agents/create"');
  const fresh = /fresh_agent_id\s*\(/.test(String(agentsSource));
  const mints = /mint_agent_record\s*\(/.test(String(agentsSource));
  return {
    ok: fields.join(",") === "display_name,agent_host,request_id" && route && fresh && !mints,
    fields,
    route: route ? "POST /api/apps/system/agents/create" : "",
    id_source: fresh ? "auth::fresh_agent_id" : "",
  };
}

export function pageLaunchToken(frameUrl) {
  const hash = String(frameUrl || "").split("#")[1] || "";
  return new URLSearchParams(hash).get("home_token") || "";
}

export function agentIdV2(id) {
  return /^agent:v2:[0-9a-f]{32}$/.test(String(id || ""));
}

// The page's own POSTs. A missing Create POST is the home-asks failure.
export function judgeHomeAsks(posts, frameTokens, runnerToken) {
  const allowed = new Set((Array.isArray(frameTokens) ? frameTokens : [frameTokens]).filter((token) => (
    typeof token === "string" && token.length > 0
  )));
  const counts = { enable: 0, create: 0, activate: 0 };
  if (allowed.size === 0) return { ok: false, reason: "page launch token missing", counts };
  if ([...allowed].some((token) => token === runnerToken)) {
    return { ok: false, reason: "page launch token is the runner enrollment token", counts };
  }
  const seen = new Set();
  for (const post of Array.isArray(posts) ? posts : []) {
    const name = post?.path === "/api/apps/system/agents/enable" ? "enable"
      : post?.path === "/api/apps/system/agents/create" ? "create"
        : post?.path === "/api/apps/system/agents/activate" ? "activate"
          : "";
    if (!name) continue;
    if (post.fromPage !== true) return { ok: false, reason: "post was not from the page", counts };
    if (!allowed.has(post.token) || post.token === runnerToken) {
      return { ok: false, reason: "post token is not the page launch token", counts };
    }
    seen.add(post.token);
    counts[name] += 1;
  }
  if (seen.size !== 1) return { ok: false, reason: "page posts used more than one launch token", counts };
  const ok = counts.enable === 1 && counts.create === 2 && counts.activate === 1;
  return { ok, reason: ok ? "" : "page did not send Allow, two Creates, and Turn on", counts };
}

export function lineIsTestOnly(source, lineNumber) {
  const lines = String(source || "").split("\n");
  const target = lineNumber - 1;
  if (target < 0 || target >= lines.length) return false;
  let depth = 0;
  const floors = [];
  let pending = false;
  for (let index = 0; index <= target; index += 1) {
    const line = lines[index];
    if (/#\[\s*cfg\s*\(\s*test\s*\)\s*\]/.test(line)) pending = true;
    const opens = (line.match(/\{/g) || []).length;
    const closes = (line.match(/\}/g) || []).length;
    if (pending && opens > 0) {
      floors.push(depth);
      pending = false;
    } else if (pending && /;\s*$/.test(line) && !line.includes("{")) {
      pending = false;
    }
    depth += opens - closes;
    if (depth < 0) depth = 0;
    while (floors.length > 0 && depth <= floors[floors.length - 1]) floors.pop();
    if (index === target) return floors.length > 0;
  }
  return false;
}

export function parseGitGrep(output) {
  const hits = [];
  for (const line of String(output || "").split("\n")) {
    if (!line) continue;
    const match = line.match(/^HEAD:(.+?):(\d+):(.*)$/);
    if (!match) continue;
    hits.push({ path: match[1], line: Number(match[2]), text: match[3].trim() });
  }
  return hits;
}

export function classifyMintHit(hit, source) {
  const testFile = /(?:^|\/)tests\//.test(hit.path)
    || /_tests\.rs$/.test(hit.path)
    || /\.test\./.test(hit.path);
  return testFile || lineIsTestOnly(source, hit.line);
}

// The journey names the old mint so it can search for it. That mention is the
// checker, not a call and not a definition.
export function mintHitKind(hit, source) {
  if (hit.path === "scripts/a15r-installed-journey.mjs" || hit.path === "scripts/a15r-installed-journey.sh") {
    return "checker";
  }
  return classifyMintHit(hit, source) ? "test" : "production";
}

export function mintReport(hits) {
  const production = [];
  const testOnly = [];
  const checker = [];
  for (const hit of hits) {
    const row = { path: hit.path, line: hit.line, text: hit.text };
    if (hit.kind === "checker") checker.push(row);
    else if (hit.kind === "test") testOnly.push(row);
    else production.push(row);
  }
  const defines = hits.some((hit) => hit.kind === "production" && hit.text.includes("mint_agent_principal"));
  return {
    ok: production.length === 0 && !defines,
    production,
    testOnly,
    checker,
    defined: defines,
  };
}

const MINT_SOURCE = /\.(?:rs|js|mjs|cjs|py|ts|tsx|c|cc|h|hh|wit)$/;

export function repoPath(input) {
  if (input instanceof URL) return fileURLToPath(input);
  if (typeof input === "string" && input.startsWith("file:")) return fileURLToPath(input);
  return input;
}

export function mintHitsFromRepo(repoRoot) {
  const cwd = repoPath(repoRoot);
  // Sources under elastos/ and capsules/ only. The journey script is not one of them.
  const listed = spawnSync("git", [
    "grep", "-n", "-I", "-e", "mint_agent_principal", "-e", "agent:v1", "HEAD",
    "--", "elastos", "capsules",
  ], { cwd, encoding: "utf8" });
  if (listed.status !== 0 && listed.status !== 1) {
    return { ok: false, reason: String(listed.stderr || "git grep failed").slice(0, 240), production: [], testOnly: [], checker: [] };
  }
  const parsed = parseGitGrep(listed.stdout || "").filter((hit) => (
    (hit.path.startsWith("elastos/") || hit.path.startsWith("capsules/"))
    && MINT_SOURCE.test(hit.path)
  ));
  const cache = new Map();
  const hits = parsed.map((hit) => {
    if (!cache.has(hit.path)) {
      const shown = spawnSync("git", ["show", `HEAD:${hit.path}`], { cwd, encoding: "utf8" });
      cache.set(hit.path, shown.status === 0 ? shown.stdout : "");
    }
    return { ...hit, kind: mintHitKind(hit, cache.get(hit.path)) };
  });
  const report = mintReport(hits);
  return {
    ...report,
    ok: report.ok && report.production.length === 0,
    reason: report.production.length === 0 ? "" : "production hit",
  };
}

export function gatewayRestartLoadedChain(logText) {
  const text = String(logText || "");
  const shutdownAt = text.lastIndexOf("Shutting down gateway...");
  const command = "elastos gateway --addr";
  if (shutdownAt < 0) {
    return { ok: false, reason: "no shutdown before the restart", log_line: "", command };
  }
  const after = text.slice(shutdownAt);
  const banner = after.match(/ElastOS Gateway v\S+/);
  const auditFault = /audit chain/i.test(after);
  if (!banner || auditFault) {
    return {
      ok: false,
      reason: auditFault ? "audit chain fault in the restart log" : "restart did not print the gateway banner",
      log_line: banner ? banner[0] : "",
      command,
    };
  }
  return {
    ok: true,
    reason: "",
    log_line: banner[0],
    command,
    verifier: "verify_auth_audit_chain_ready",
  };
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

export function planeSameProcess(pid, gatewayPid, listenerOwned, pidAlive, mode) {
  return pid > 0
    && pid === gatewayPid
    && listenerOwned === true
    && pidAlive === true
    && (mode & 0o777) === 0o600;
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function linuxProcExecutables() {
  let names;
  try {
    names = fs.readdirSync("/proc");
  } catch {
    return { ok: false, rows: [] };
  }
  const rows = [];
  for (const name of names) {
    if (!/^[1-9][0-9]*$/.test(name)) continue;
    let exe = "";
    try {
      exe = fs.readlinkSync(`/proc/${name}/exe`);
    } catch {
      continue;
    }
    if (exe.endsWith(" (deleted)")) exe = exe.slice(0, -" (deleted)".length);
    rows.push({ pid: Number(name), exe });
  }
  return { ok: true, rows };
}

function homeExecutables() {
  if (process.platform === "linux") return linuxProcExecutables();
  if (process.platform !== "darwin") return { ok: false, rows: [] };
  const listed = spawnSync("python3", ["-c", `
import ctypes, ctypes.util, subprocess, sys
libc = ctypes.CDLL(ctypes.util.find_library("c"))
buf = ctypes.create_string_buffer(4096)
ps = subprocess.check_output(["ps", "-ax", "-o", "pid="], text=True)
for line in ps.splitlines():
    pid = int(line.strip() or "0")
    if pid <= 0:
        continue
    n = libc.proc_pidpath(pid, buf, len(buf))
    if n > 0:
        sys.stdout.write(f"{pid}\\t{buf.value.decode()}\\n")
`], { encoding: "utf8" });
  if (listed.status !== 0) return { ok: false, rows: [] };
  const rows = [];
  for (const line of String(listed.stdout || "").split("\n")) {
    if (!line) continue;
    const tab = line.indexOf("\t");
    if (tab < 0) continue;
    rows.push({ pid: Number(line.slice(0, tab)), exe: line.slice(tab + 1).trim() });
  }
  return { ok: true, rows };
}

function homePids() {
  const listed = homeExecutables();
  if (!listed.ok) return { ok: false, pids: [] };
  const pids = listed.rows
    .filter((row) => executableInsideHome(row.exe, home))
    .map((row) => row.pid);
  return { ok: true, pids };
}

async function signalHomePids(pids) {
  for (const pid of pids) {
    try { process.kill(pid, "SIGTERM"); } catch { /* already gone */ }
  }
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline && pids.some((pid) => alive(pid))) await sleep(200);
  for (const pid of pids) {
    if (alive(pid)) {
      try { process.kill(pid, "SIGKILL"); } catch { /* already gone */ }
    }
  }
  const killed = Date.now() + 2000;
  while (Date.now() < killed && pids.some((pid) => alive(pid))) await sleep(100);
}

function servePidsToStop(executables, commands) {
  const pids = [];
  if (!executables?.ok || !commands || !serveBin) return pids;
  let binary = "";
  try { binary = fs.realpathSync(serveBin); } catch { return pids; }
  const verified = verifiedServePid(executables, commands, binary);
  // An unverified coords pid is left alone. It is not this Home's binary.
  if (verified.state === "serve") pids.push(verified.pid);
  return pids;
}

async function stopServe() {
  const listed = homePids();
  if (!listed.ok) throw new Error("cannot list executables for this Home");
  const extra = servePidsToStop(homeExecutables(), commandByPid());
  await signalHomePids([...new Set([...listed.pids, ...extra])]);
}

async function startServe() {
  const log = fs.openSync(logPath, "a");
  const env = homeProcessEnv(home);
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

let pageProof = null;
let carrierProof = null;
let browserProof = null;
let gitAfter = { ok: false, text: "not checked" };

function gitFields() {
  return {
    git_porcelain_before: process.env.A15R_GIT_BEFORE || "",
    git_porcelain_after: gitAfter.ok ? "" : String(gitAfter.text || "git status failed"),
  };
}

function coveredByUnitRow() {
  const row = "a_panicking_host_call_leaves_the_session_and_home_up";
  const mid = "a_stop_while_the_effect_is_held";
  const args = [
    "test", "-p", "elastos-server", "--lib", "--features", "prototype-agents",
    "--offline", "--locked", "--", row, mid,
  ];
  const cwd = path.join(root || path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."), "elastos");
  const result = spawnSync("cargo", args, {
    cwd,
    env: {
      ...process.env,
      CARGO_NET_OFFLINE: "1",
      CARGO_TARGET_DIR: process.env.CARGO_TARGET_DIR || path.join(path.dirname(cwd), "target-build"),
    },
    encoding: "utf8",
    timeout: 600000,
  });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`.slice(-6000);
  const passed = result.status === 0 && output.includes(`${row} ... ok`) && output.includes(`${mid} ... ok`);
  return {
    row,
    command: `cargo ${args.join(" ")}`,
    source_commit: process.env.A15R_SOURCE_COMMIT || "",
    result: passed ? "pass" : "fail",
    output,
    "mid-step stop covered by a unit row, not installed": mid,
  };
}

function writeReceipt() {
  if (process.env.A15R_ONLY === "u3-create") return writeU3Receipt();
  const assertions = names.map((name) => marks.get(name) || { name, status: "not reached", detail: "" });
  const unitRow = coveredByUnitRow();
  const proved = assertions.every((item) => item.status === "pass") && unitRow.result === "pass";
  const install = fs.existsSync(path.join(out, "install.json"))
    ? redactInstall(readJson(path.join(out, "install.json")))
    : {};
  const receipt = {
    mode: "full",
    proof: proved,
    notice: proved ? "" : FULL_MODE_NOTICE,
    model: "offer:fixture",
    route: "POST /api/apps/system/agents/launch",
    step_up_operation: "agent.start",
    plan_step_up_operation: "agent_plan.approve",
    source_commit: process.env.A15R_SOURCE_COMMIT || "",
    source_tree: process.env.A15R_SOURCE_TREE || "",
    ...gitFields(),
    pages: pageProof?.pages || null,
    carrier: carrierProof,
    browser: browserProof,
    install,
    "covered by a unit row, not installed": unitRow,
    timings_ms: { ...timings, total: Date.now() - started },
    assertions,
    card: state.card,
    grants: state.grants,
    launches: { a: state.launchA, b: state.launchB },
    screenshots,
    stopped,
  };
  const body = redactDidAndAddress(JSON.stringify(receipt, null, 2) + "\n");
  fs.writeFileSync(path.join(out, "receipt.json"), body);
  const gitDirty = !gitAfter.ok || String(process.env.A15R_GIT_BEFORE || "").length > 0;
  return gitDirty || assertions.some((item) => item.status !== "pass") || unitRow.result !== "pass" ? 1 : 0;
}

async function main() {
  const install = readJson(path.join(out, "install.json"));
  const keyGone = !fs.existsSync(path.join(data, ".a15r-publisher.key"));
  if (install.signer_did && install.release_sha256 && install.key_deleted && keyGone) {
    pass("release_signed", install.signer_did);
  } else halt("release_signed", "install.json is missing a signed release");
  if (install.key_deleted && keyGone) pass("signing_key_deleted");
  else halt("signing_key_deleted", "disposable key is still present");
  if (install.runtime_sha256 && install.wasm_sha256 && install.key_deleted && keyGone) {
    pass("install_with_hashes_key_deleted", {
      runtime_sha256: install.runtime_sha256,
      wasm_sha256: install.wasm_sha256,
      components_sha256: install.components_sha256 || "",
      key_deleted: true,
      source_commit: process.env.A15R_SOURCE_COMMIT || "",
    });
  } else halt("install_with_hashes_key_deleted", "install hashes or the deleted key are missing");
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
  rememberBrowser(playwright, browser);
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
  pass("u4_unknown_agent_refused", {
    sentence: noSuchAgent,
    source_commit: process.env.A15R_SOURCE_COMMIT || "",
    host: "signed package",
  });

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
  const secondStart = await (async () => {
    const step = await stepUp(state.systemToken, "agent.start", { agent_id: state.agentA });
    return call("POST", "/api/apps/system/agents/launch", state.systemToken, {
      agent_id: state.agentA, step_up_token: step,
    });
  })();
  const already = secondStart.status === 409 && String(secondStart.text).includes("already running");
  if (!already || state.rootA === state.rootB) {
    halt("u4_second_start_refused", {
      status: secondStart.status,
      body: String(secondStart.text).slice(0, 240),
      roots: [state.rootA, state.rootB],
    });
  }
  pass("u4_second_start_refused", {
    source_commit: process.env.A15R_SOURCE_COMMIT || "",
    host: "signed package",
    a: state.agentA,
    b: state.agentB,
    roots: [state.rootA, state.rootB],
    second_start: "already running",
  });

  const routeReads = await attemptUserAreaRoute();
  const doorMissing = routeReads.own?.status === 404 && routeReads.other?.status === 404;
  const readReturned = routeReads.own?.status === 200 || routeReads.other?.status === 200;
  if (userAreaRouteRefused(routeReads)) {
    pass("u4_cross_root_bus_read_gap", {
      proved: "refused by name",
      own: routeAttemptDetail(routeReads.own),
      other: routeAttemptDetail(routeReads.other),
      isolation_not_covered: U4_ISOLATION_NOT_COVERED,
    });
  } else if (doorMissing && !readReturned) {
    pass("u4_cross_root_bus_read_gap", {
      claim: "removed",
      gap: "the guest bus read of another agent's root is not driven on this installed release",
      own_status: 404,
      other_status: 404,
      isolation_not_covered: U4_ISOLATION_NOT_COVERED,
    });
  } else {
    mark("u4_cross_root_bus_read_gap", "fail", {
      own: routeAttemptDetail(routeReads.own),
      other: routeAttemptDetail(routeReads.other),
      gap: "the agent plane does not mount the provider read",
      isolation_not_covered: U4_ISOLATION_NOT_COVERED,
    });
  }

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
  const rootsOwned = rootsStayWithTheirAgent(state.rootA, state.rootB, state.grants, routeReads);
  const grantsOnly = rootsGrantedOnlyToTheirAgent(state.rootA, state.rootB, state.grants);
  if (rootsOwned) {
    pass("roots_in_own_grants", {
      a: state.rootA,
      b: state.rootB,
      grants: state.grants.map((grant) => grant.resource),
      plant_cross: routeReads.other?.resource || "",
    });
  } else if (grantsOnly && routeReads.other?.status === 404) {
    pass("roots_in_own_grants", {
      a: state.rootA,
      b: state.rootB,
      grants: state.grants.map((grant) => grant.resource),
      plant_cross_claim: "removed",
      gap: "the agent plane does not mount the provider read",
    });
  } else {
    mark("roots_in_own_grants", "fail", {
      grants: state.grants,
      plant: { own: routeReads.own?.resource, other: routeReads.other?.resource, other_status: routeReads.other?.status },
    });
  }

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
      && String(entry.body || "").includes(state.agentA)
    ));
    if (submits.length === 1) {
      await call("POST", "/api/apps/inbox/actions", state.inboxToken, {
        action_id: submits[0].action_ref.action_id,
      });
    } else if (submits.length > 1) {
      halt("plan_card_captured", "more than one plan submit remained for agent A");
    }
    const cards = planCards(summary).filter((card) => {
      const text = `${card.title || ""} ${card.body || ""}`;
      return text.includes(state.launchA.session_id);
    });
    if (cards.length === 1) plan = cards[0];
    else if (cards.length > 1) halt("one_pending_record", "more than one plan card for agent A");
    if (plan) {
      const stillUp = liveSessions(await capsules(), [state.launchA]);
      if (stillUp.length !== 1) {
        halt("plan_card_captured", "the guest ended before the owner decided");
      }
    }
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

  let pending = [];
  const pendingDeadline = Date.now() + 10000;
  while (Date.now() < pendingDeadline) {
    pending = inspectRecords().filter((record) => record.status === "pending");
    if (pending.length === 1 && pending[0].request_id === state.requestId) break;
    await sleep(300);
  }
  if (pending.length !== 1 || pending[0].request_id !== state.requestId) {
    halt("one_pending_record", pending.map((record) => ({ id: record.request_id, status: record.status })));
  }
  pass("one_pending_record", state.requestId);
  const cardAt = Date.now();

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
  // The other agent's submit ask times out at 30s if it sits while this
  // owner waits. Approve that ask during the wait. This plan stays pending.
  const decideAt = cardAt + 31000;
  while (Date.now() < decideAt) {
    const summary = await inbox();
    const others = entries(summary).filter((entry) => (
      String(entry.action_ref?.action_id || "").startsWith("capability-approve-request:")
      && resourceOf(entry.body).startsWith("elastos://inspect/submit_agent_plan")
      && state.agentB
      && String(entry.body || "").includes(state.agentB)
    ));
    for (const entry of others) {
      await call("POST", "/api/apps/inbox/actions", state.inboxToken, {
        action_id: entry.action_ref.action_id,
      });
    }
    const slice = Math.min(400, decideAt - Date.now());
    if (slice > 0) await sleep(slice);
  }
  timings.approval_after_card_ms = Date.now() - cardAt;
  const stillDeciding = liveSessions(await capsules(), [state.launchA]);
  if (stillDeciding.length !== 1) {
    halt("step_up_approve", "the guest ended before the owner used the approval time");
  }

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
  let stopDuringStep = null;
  let runnerStoppedTooLate = false;
  let stopObserved = "";
  let frozenLook = "";
  if (state.approveBody) {
    // Stop once, while the step is approved or dispatching and the note is
    // not on disk. Freeze the gateway for that look, queue Stop, then let it
    // run. There is no second Stop.
    const approvedPromise = call("POST", "/api/apps/inbox/actions", state.inboxToken, state.approveBody);
    const notePath = path.join(data, rootSuffix(state.rootA), "Documents", "note.txt");
    const gatewayPid = fs.existsSync(pidFile) ? Number(String(fs.readFileSync(pidFile, "utf8")).trim()) : 0;
    const inflightDeadline = Date.now() + 20000;
    let inflight = "";
    while (Date.now() < inflightDeadline) {
      const record = inspectRecords().find((item) => item.request_id === state.requestId);
      const noteThere = fs.existsSync(notePath);
      const status = record?.status || "";
      if ((status === "approved" || status === "dispatching") && !noteThere) {
        inflight = status;
        break;
      }
      if (noteThere || status === "completed" || status === "denied" || status === "unknown") break;
      await sleep(5);
    }
    let frozen = false;
    if (inflight && gatewayPid > 0) {
      try {
        process.kill(gatewayPid, "SIGSTOP");
        frozen = true;
        const record = inspectRecords().find((item) => item.request_id === state.requestId);
        const noteThere = fs.existsSync(notePath);
        const status = record?.status || "";
        if ((status === "approved" || status === "dispatching") && !noteThere) {
          frozenLook = status;
        } else {
          stopObserved = `frozen saw ${status} note=${noteThere}`;
          inflight = "";
        }
      } catch (error) {
        frozen = false;
        stopObserved = `SIGSTOP failed: ${error.message || error}`;
      }
    }
    let stopPromise = null;
    try {
      if (inflight) {
        stopPromise = call("POST", "/api/apps/system/agents/stop", state.systemToken, {
          agent_id: state.agentA,
        });
        await sleep(30);
      }
    } finally {
      if (frozen) {
        try {
          process.kill(gatewayPid, "SIGCONT");
        } catch {
          // The gateway has to leave the stop. A failed continue is recorded below.
        }
        frozen = false;
      }
    }
    if (stopPromise) {
      stopDuringStep = await stopPromise;
      if (stopDuringStep.status === 409 && String(stopDuringStep.text || "").includes("agent_no_session")) {
        runnerStoppedTooLate = true;
        stopObserved = "the runner stopped too late";
      }
    } else {
      const record = inspectRecords().find((item) => item.request_id === state.requestId);
      const noteThere = fs.existsSync(notePath);
      if (noteThere || record?.status === "completed") {
        runnerStoppedTooLate = true;
        stopObserved = "the runner stopped too late";
      } else if (!stopObserved) {
        stopObserved = `no in-flight step; status=${record?.status || "missing"} note=${noteThere}`;
      }
    }
    const approved = await approvedPromise;
    keep("step_up_approve", approved.status === 200, approved.text.slice(0, 300));
  }
  let settled = null;
  const settleDeadline = Date.now() + 30000;
  while (Date.now() < settleDeadline) {
    settled = inspectRecords().find((record) => record.request_id === state.requestId) || null;
    if (settled && settled.status !== "pending") break;
    await sleep(300);
  }
  const stepOutcome = settled
    ? `${settled.status}${settled.result?.status ? `/${settled.result.status}` : ""}`
    : "";
  const stopRows = auditEvents().filter((event) => (
    event.event_type === "agent.stopped" && event.session_id === state.launchA?.session_id
  ));
  const namedStop = stopRows.find((event) => (
    event.result === "ok" || event.result === "failed" || event.result === "stopping"
  ));
  if (runnerStoppedTooLate || (!stopDuringStep && stopObserved)) {
    mark("stop_after_the_note_lands", "fail", {
      http: stopDuringStep?.status || 0,
      body: stopObserved || "the runner stopped too late",
      step_outcome: stepOutcome,
      rows: stopRows.map((event) => event.result),
    });
  } else if (
    frozenLook
    && (stopDuringStep?.status === 200 || stopDuringStep?.status === 202)
    && namedStop
    && stepOutcome
  ) {
    pass("stop_after_the_note_lands", {
      http: stopDuringStep.status,
      session_id: namedStop.session_id,
      stop_result: namedStop.result,
      step_outcome: stepOutcome,
      frozen: frozenLook,
    });
  } else {
    mark("stop_after_the_note_lands", "fail", {
      http: stopDuringStep?.status || 0,
      body: stopObserved || String(stopDuringStep?.text || "").slice(0, 240),
      frozen: frozenLook,
      step_outcome: stepOutcome,
      rows: stopRows.map((event) => event.result),
    });
  }
  state.stoppingSession = namedStop?.result === "stopping" ? namedStop.session_id : "";
  state.stoppingConfirmedBeforeRestart = state.stoppingSession
    ? auditEvents().some((event) => (
      event.event_type === "agent.stopped"
      && event.result === "ok"
      && event.session_id === state.stoppingSession
    ))
    : false;
  const recordResources = JSON.stringify(settled || {}).match(/localhost:\/\/[^"\\\s]+/g) || [];
  // The guest submits localhost://UsersAI/self. The Runtime scopes that alias
  // to this agent. The file check below is the proof the bytes landed in A's
  // own folder. A concrete root in the record is also accepted.
  const ownDocument = recordResources.some((resource) => (
    resource === "localhost://UsersAI/self/Documents/note.txt"
    || (resource.startsWith(state.rootA) && resource.endsWith("/Documents/note.txt"))
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
  const ownReceipts = inspectRecords().filter((record) => record.requester_id === state.agentA);
  const receiptOk = Boolean(settled
    && settled.principal_id
    && settled.requester_id === state.agentA
    && settled.request_binding
    && settled.result
    && settled.status === "completed"
    && ownReceipts.length === 1);
  const planeCoords = path.join(data, "agent-runtime-coords.json");
  const planeFile = fs.existsSync(planeCoords) ? readJson(planeCoords) : {};
  const planePid = Number(planeFile.pid) || 0;
  const gatewayPid = fs.existsSync(pidFile) ? Number(String(fs.readFileSync(pidFile, "utf8")).trim()) : 0;
  let listenPort = 0;
  try {
    listenPort = Number(new URL(String(planeFile.api_url || "")).port) || 0;
  } catch {
    listenPort = 0;
  }
  const ownsListener = gatewayOwnsListener(gatewayPid, listenPort);
  const childList = await listRuntimeCapsules();
  const childAgents = guestCapsuleCount(childList.capsules, [state.agentA, state.agentB]);
  let secretMode = 0;
  try {
    secretMode = fs.statSync(planeCoords).mode & 0o777;
  } catch {
    secretMode = 0;
  }
  const sameProcess = planeSameProcess(planePid, gatewayPid, ownsListener, alive(planePid), secretMode)
    && childList.listed === true && childAgents === 0;
  if (authorised && receiptOk && marks.get("step_up_approve")?.status === "pass" && sameProcess) {
    pass("card_step_up_approve_one_write_one_receipt", {
      admission_pid: planePid,
      dispatch_pid: gatewayPid,
      pids_equal: true,
      listener_owned: ownsListener,
      pid_alive: true,
      coords_mode: secretMode.toString(8),
      child_agent_capsules: childAgents,
      source_commit: process.env.A15R_SOURCE_COMMIT || "",
    });
  } else {
    halt("card_step_up_approve_one_write_one_receipt", {
      authorised, receiptOk, admission_pid: planePid, dispatch_pid: gatewayPid,
      listener_owned: ownsListener, child_listed: childList.listed, child_agent_capsules: childAgents,
    });
  }
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
  const afterCard = planCards(await inbox()).filter((card) => {
    const text = `${card.title || ""} ${card.body || ""}`;
    return text.includes(state.launchA.session_id);
  });
  keep("card_removed", afterCard.length === 0, afterCard.map((card) => card.action_ref?.action_id));

  const recordBeforeReplay = JSON.stringify(inspectRecords());
  const auditsBeforeReplay = JSON.stringify(auditEvents().map((event) => event.event_type));
  const filesBeforeReplay = JSON.stringify(interestingFiles());
  const replay = state.approveBody
    ? await call("POST", "/api/apps/inbox/actions", state.inboxToken, state.approveBody)
    : { status: 0, text: "no approve body" };
  const replayClean = replay.status !== 200 && replay.status !== 404
    && JSON.stringify(inspectRecords()) === recordBeforeReplay
    && JSON.stringify(auditEvents().map((event) => event.event_type)) === auditsBeforeReplay
    && JSON.stringify(interestingFiles()) === filesBeforeReplay;
  keep("replay_zero", replayClean, { status: replay.status, body: replay.text.slice(0, 240) });

  // The runner wrote the owner's note as plain bytes so the write check can
  // hash it. The gateway refuses to start while that file sits in a protected
  // folder. The hash check above already recorded the bytes.
  if (ownerDocPath) {
    try { fs.unlinkSync(ownerDocPath); } catch { /* already gone */ }
  }

  const liveBeforeOff = liveSessions(await capsules(), [state.launchB]);
  const off = await call("POST", "/api/apps/system/agents/disable", state.systemToken);
  let again = { status: 0, text: "" };
  try {
    const step = await stepUp(state.systemToken, "agent.start", { agent_id: state.agentB });
    again = await call("POST", "/api/apps/system/agents/launch", state.systemToken, {
      agent_id: state.agentB, step_up_token: step,
    });
  } catch (error) {
    again = { status: 0, text: String(error.message || error) };
  }
  const stoppedB = auditEvents().find((event) => (
    event.event_type === "agent.stopped" && event.session_id === state.launchB?.session_id
  ));
  if (liveBeforeOff.length === 1 && off.status === 200 && again.status !== 200 && again.text.includes("not turned on") && stoppedB) {
    state.liveStoppedSession = stoppedB.session_id;
    pass("agents_off_during_run", {
      off: off.status,
      session_id: stoppedB.session_id,
      result: stoppedB.result,
      start: again.status,
    });
  } else {
    mark("agents_off_during_run", "fail", {
      live: liveBeforeOff.length,
      off: off.status,
      start: again.status,
      body: again.text.slice(0, 180),
      stopped: Boolean(stoppedB),
    });
  }

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
    const restartClean = restart.status !== 200 && restart.status !== 404
      && JSON.stringify(inspectRecords()) === recordBeforeRestart
      && JSON.stringify(auditEvents().map((event) => event.event_type)) === auditsBeforeRestart
      && JSON.stringify(interestingFiles()) === filesBeforeRestart;
    keep("restart_zero", restartClean, { status: restart.status, body: restart.text.slice(0, 240) });
    const chain = auditEvents();
    const finished = chain.some((event) => String(event.event_type).includes("completed") && event.result === "ok");
    const unfinished = chain.some((event) => event.result === "stopping" || String(event.event_type).endsWith(".requested"));
    const confirmedStop = Boolean(state.stoppingSession)
      && state.stoppingConfirmedBeforeRestart !== true
      && chain.some((event) => (
        event.event_type === "agent.stopped"
        && event.result === "ok"
        && event.session_id === state.stoppingSession
      ));
    const lived = state.liveStoppedSession
      ? chain.some((event) => (
        event.event_type === "agent.stopped"
        && event.session_id === state.liveStoppedSession
        && (event.result === "ok" || event.result === "failed" || event.result === "stopping")
      ))
      : false;
    if (restartClean && (confirmedStop || (!state.stoppingSession && lived))) {
      pass("home_restart_history", {
        session_id: state.stoppingSession || state.liveStoppedSession,
        confirmed: confirmedStop ? "ok" : "the stop finished in the same call",
        replay: restart.status,
      });
    } else {
      mark("home_restart_history", "fail", {
        finished,
        unfinished,
        restart: restart.status,
        stopping_session: state.stoppingSession || "",
        live_stopped_session: state.liveStoppedSession || "",
        confirmed: confirmedStop,
        lived,
      });
    }
  } catch (error) {
    mark("restart_zero", "fail", String(error.message || error));
  }

  const guestAgain = await launchApp(state.guestToken, "system");
  state.guestSystemToken = guestAgain.token;
  const guestStop = await call("POST", "/api/apps/system/agents/stop", state.guestSystemToken, {
    agent_id: state.agentA,
  });
  const denial = auditEvents().some((event) => event.event_type === "agent.stop.denied" && event.result === "denied");
  if (guestStop.status !== 200 && guestStop.status !== 404 && denial) {
    pass("owner_denial_signed_row", { status: guestStop.status });
  }
  else mark("owner_denial_signed_row", "fail", { status: guestStop.status, denial });

}

function loadInstall() {
  const file = path.join(out, "install.json");
  return fs.existsSync(file) ? readJson(file) : {};
}

function binarySha256s(install) {
  const binaries = {};
  for (const key of [
    "runtime_sha256", "provider_sha256", "did_sha256", "shell_sha256", "wasm_sha256",
    "components_sha256", "release_sha256", "release_head_sha256", "sources_sha256",
  ]) binaries[key] = install?.[key] || "";
  return binaries;
}

function writeU3Receipt() {
  const assertions = U3_NAMES.map((name) => marks.get(name) || { name, status: "not reached", detail: "" });
  const receipt = {
    mode: "u3-create",
    route: "POST /api/apps/system/agents/create",
    non_owner: "guest session",
    source_commit: process.env.A15R_SOURCE_COMMIT || "",
    source_tree: process.env.A15R_SOURCE_TREE || "",
    ...gitFields(),
    pages: pageProof?.pages || null,
    carrier: carrierProof,
    browser: browserProof,
    plant: process.env.A15R_PLANT || "",
    binaries: binarySha256s(loadInstall()),
    timings_ms: { ...timings, total: Date.now() - started },
    assertions,
    screenshots: screenshots.map((item) => ({
      name: item.name,
      status: item.status,
      path: item.path || "",
      ...(item.detail ? { detail: item.detail } : {}),
    })),
    stopped,
  };
  fs.writeFileSync(path.join(out, "receipt.json"), JSON.stringify(receipt, null, 2) + "\n");
  const gitDirty = !gitAfter.ok || String(process.env.A15R_GIT_BEFORE || "").length > 0;
  return gitDirty || assertions.some((item) => item.status !== "pass") ? 1 : 0;
}

function agentRecordsPath() {
  return path.join(data, "ElastOS/System/Auth/agent-records.json");
}

function authStatePath() {
  return path.join(data, "ElastOS/System/Auth/auth-state.json");
}

function agentDisplayName(agentId) {
  if (!fs.existsSync(agentRecordsPath())) return "";
  const row = (readJson(agentRecordsPath()).agents || []).find((agent) => agent.record?.principal_id === agentId);
  return String(row?.record?.display_name || "");
}

function storedAgentRecords() {
  if (!fs.existsSync(agentRecordsPath())) return [];
  const body = readJson(agentRecordsPath());
  return (body.agents || []).map((agent) => ({
    id: String(agent.record?.principal_id || ""),
    owner: String(agent.record?.owner || ""),
  }));
}

function storedHumans() {
  if (!fs.existsSync(authStatePath())) return [];
  const body = readJson(authStatePath());
  return (body.principals || []).filter((row) => row.kind !== "agent").map((row) => ({
    id: String(row.principal_id || ""),
    role: String(row.role || ""),
  }));
}

async function productCaller(token) {
  const summary = await call("GET", "/api/apps/system/summary", token);
  const id = summary.json?.authority?.principal_id;
  return {
    status: summary.status,
    id: typeof id === "string" ? id : "",
    role: String(summary.json?.access?.role || ""),
  };
}

function runtimeIdentityDid() {
  const env = homeProcessEnv(home);
  const result = spawnSync(serveBin, ["identity", "show"], { env, encoding: "utf8" });
  if (result.status !== 0) return "";
  const line = String(result.stdout || "").split("\n").find((item) => item.includes("did:key:"));
  const matched = line && line.match(/did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+/);
  const did = matched ? matched[0] : "";
  return didKeyEd25519(did) ? did : "";
}

function commandByPid() {
  const listed = spawnSync("ps", ["-axww", "-o", "pid=,command="], { encoding: "utf8" });
  if (listed.status !== 0) return null;
  const commands = new Map();
  for (const line of String(listed.stdout || "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const pid = trimmed.split(/\s+/)[0];
    commands.set(pid, trimmed.slice(pid.length).trim());
  }
  return commands;
}

function realExe(exe) {
  const cleaned = String(exe || "").replace(/ \(deleted\)$/, "");
  try { return fs.realpathSync(cleaned); } catch { return path.resolve(cleaned); }
}

function sha256File(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

let installedBinarySha = "";
function installedSha() {
  if (!installedBinarySha) installedBinarySha = sha256File(serveBin);
  return installedBinarySha;
}

function coordsPid() {
  const file = data ? path.join(data, "home-runtime-coords.json") : "";
  if (!file || !fs.existsSync(file)) return 0;
  try {
    const pid = Number(readJson(file).pid);
    return Number.isInteger(pid) && pid > 0 ? pid : 0;
  } catch {
    return 0;
  }
}

// The gateway starts serve from a private copy outside the Home. That pid is
// this Home's binary only when the coords file names it, the command is serve,
// and the bytes match the installed elastos.
function verifiedServePid(executables, commands, binary) {
  const pid = coordsPid();
  if (!pid) return { state: "absent" };
  const row = executables.rows.find((item) => item.pid === pid);
  if (!row) return { state: "dead" };
  const exe = realExe(row.exe);
  const sub = elastosSubcommand(commands.get(String(pid)) || "", [row.exe, exe, binary, serveBin]);
  if (sub !== "serve") return { state: "unverified", reason: "coords pid is not an elastos serve" };
  if (exe === binary) return { state: "serve", pid };
  let same = false;
  try { same = sha256File(exe) === installedSha(); } catch { same = false; }
  if (!same) return { state: "unverified", reason: "coords pid executable is not this Home's binary" };
  return { state: "serve", pid };
}

function elastosProcesses() {
  const executables = homeExecutables();
  const commands = commandByPid();
  if (!executables.ok || !commands) return { ok: false, reason: "process list is missing", serve: [], stray: [] };
  let binary = "";
  try { binary = fs.realpathSync(serveBin); } catch { return { ok: false, reason: "installed elastos is missing", serve: [], stray: [] }; }
  const gatewayPid = fs.existsSync(pidFile) ? fs.readFileSync(pidFile, "utf8").trim() : "";
  const serve = [];
  const stray = [];
  for (const row of executables.rows) {
    const exe = realExe(row.exe);
    if (exe !== binary) continue;
    if (String(row.pid) === gatewayPid) continue;
    const sub = elastosSubcommand(commands.get(String(row.pid)) || "", [row.exe, exe, binary, serveBin]);
    if (sub === "serve") serve.push(row.pid);
    else stray.push(sub || "unparsed");
  }
  const verified = verifiedServePid(executables, commands, binary);
  if (verified.state === "unverified") {
    return { ok: false, reason: verified.reason, serve, stray };
  }
  if (verified.state === "serve" && !serve.includes(verified.pid)) serve.push(verified.pid);
  return { ok: true, reason: "", serve, stray };
}

async function startGatewayOnly() {
  const log = fs.openSync(logPath, "a");
  const env = homeProcessEnv(home);
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
      const response = await fetch(`${pageOrigin}/healthz`);
      const body = await response.text();
      if (gatewayHealthOk(response.status, body)) return;
    } catch { /* gateway still starting */ }
    await sleep(500);
  }
  throw new Error("restarted gateway did not accept healthz");
}

function productFault(control) {
  return `product fault: ${control} cannot be reached in the installed Home`;
}

function shellFrame() {
  return adminPage.frameLocator("#active-shell-frame");
}

function systemFrame() {
  return shellFrame().frameLocator('[data-target="system"] iframe.window-frame');
}

function attachPagePostWatch(page) {
  pagePosts.length = 0;
  page.on("request", (request) => {
    if (request.method() !== "POST") return;
    let pathname = "";
    try { pathname = new URL(request.url()).pathname; } catch { return; }
    if (!pathname.startsWith("/api/apps/system/agents/")) return;
    pagePosts.push({
      path: pathname,
      token: request.headers()["x-elastos-home-token"] || "",
      fromPage: true,
    });
  });
}

async function readBrowserResponse(response) {
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* refusal text */ }
  return { status: response.status(), text, json };
}

async function readSystemFrameToken() {
  const iframe = shellFrame().locator('[data-target="system"] iframe.window-frame');
  const src = await iframe.getAttribute("src").catch(() => "");
  const fromSrc = pageLaunchToken(src || "");
  if (fromSrc) return fromSrc;
  const frame = adminPage.frames().find((item) => pageLaunchToken(item.url()) && /system/i.test(item.url()));
  return frame ? pageLaunchToken(frame.url()) : "";
}

async function shotAgents(name) {
  await shot(adminPage, name);
  const iframe = shellFrame().locator('[data-target="system"] iframe.window-frame');
  const stillThere = await iframe.count().catch(() => 0);
  if (!stillThere) {
    halt("u3_home_asks", productFault("System window after the phone screenshot"));
  }
}

async function openOwnerSystem() {
  const shell = shellFrame();
  const menu = shell.locator("#toolbar-home");
  try {
    await menu.waitFor({ state: "visible", timeout: 60000 });
  } catch {
    halt("u3_home_asks", productFault("ElastOS menu #toolbar-home"));
  }
  const later = shell.locator("#setup-sheet-later");
  if (await later.isVisible().catch(() => false)) await later.click();
  await menu.click();
  const systemItem = shell.locator("#identity-menu-system");
  try {
    await systemItem.waitFor({ state: "visible", timeout: 15000 });
  } catch {
    halt("u3_home_asks", productFault("System Settings #identity-menu-system"));
  }
  await systemItem.click();
  const iframe = shell.locator('[data-target="system"] iframe.window-frame');
  try {
    await iframe.waitFor({ state: "attached", timeout: 30000 });
  } catch {
    halt("u3_home_asks", productFault("System window"));
  }
  const deadline = Date.now() + 20000;
  let token = "";
  while (Date.now() < deadline && !token) {
    token = await readSystemFrameToken();
    if (!token) await sleep(200);
  }
  if (!token) halt("u3_home_asks", productFault("System launch token in the page frame"));
  const system = systemFrame();
  const locked = system.locator("#system-locked");
  if (await locked.isVisible().catch(() => false)) {
    halt("u3_home_asks", productFault("System page (it says Open from Home)"));
  }
  const agentsTab = system.locator('.settings-sidebar-item[data-settings="agents"]');
  try {
    await agentsTab.waitFor({ state: "visible", timeout: 30000 });
  } catch {
    halt("u3_home_asks", productFault("Agents section"));
  }
  await agentsTab.click();
  return system;
}

async function pagePost(pathSuffix) {
  const pending = adminPage.waitForResponse((response) => (
    response.request().method() === "POST" && response.url().includes(pathSuffix)
  ), { timeout: 30000 });
  return pending;
}

async function waitAgentText(system, agentId, text) {
  const node = system.locator(`[data-agent-state="${agentId}"]`);
  try {
    await node.waitFor({ state: "visible", timeout: 20000 });
  } catch {
    halt("u3_home_asks", productFault(`agent state for the created agent (${text})`));
  }
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    const value = (await node.innerText().catch(() => "")).trim();
    if (value === text) return;
    await sleep(200);
  }
  halt("u3_home_asks", `the page did not show ${text}`);
}

function udpNames(pid) {
  const listed = spawnSync("lsof", ["-nP", "-a", "-p", String(pid), "-iUDP", "-Fn"], { encoding: "utf8" });
  if (listed.status !== 0 && listed.status !== 1) return { ok: false, names: [] };
  const names = [];
  for (const line of String(listed.stdout || "").split("\n")) {
    if (line.startsWith("n")) names.push(line.slice(1));
  }
  return { ok: true, names };
}

function noteCarrier() {
  const configPath = path.join(data, "config.toml");
  const config = fs.existsSync(configPath) ? fs.readFileSync(configPath, "utf8") : "";
  if (!carrierConfigOk(config)) {
    return { ok: false, reason: "carrier config is not the free loopback port" };
  }
  const procs = homePids();
  if (!procs.ok) return { ok: false, reason: "cannot list Home executables" };
  const gatewayPid = pidFile && fs.existsSync(pidFile) ? Number(fs.readFileSync(pidFile, "utf8").trim()) : 0;
  if (!procs.pids.includes(gatewayPid)) {
    return { ok: false, reason: "gateway executable is not inside this Home" };
  }
  const executables = homeExecutables();
  const commands = commandByPid();
  let binary = "";
  try { binary = fs.realpathSync(serveBin); } catch { binary = ""; }
  const verified = executables.ok && commands && binary
    ? verifiedServePid(executables, commands, binary)
    : { state: "absent" };
  if (verified.state === "unverified") return { ok: false, reason: verified.reason };
  const names = [];
  const pids = new Set(procs.pids);
  if (verified.state === "serve") pids.add(verified.pid);
  for (const pid of pids) {
    const sockets = udpNames(pid);
    if (!sockets.ok) return { ok: false, reason: "lsof failed" };
    names.push(...sockets.names);
  }
  if (bindsPort(names, 4433)) return { ok: false, reason: "Carrier bound UDP 4433" };
  carrierProof = {
    mode: CARRIER_MODE,
    config: "127.0.0.1:0",
    binds_4433: false,
    note: "Carrier is not disabled. It binds 127.0.0.1 and an ephemeral port.",
  };
  return { ok: true };
}

async function listRuntimeCapsules() {
  if (!fs.existsSync(path.join(data, "home-runtime-coords.json"))) {
    return { listed: false, reason: "home runtime coords are absent", capsules: [] };
  }
  try {
    const attached = await runtimeToken("home-runtime-coords.json");
    const response = await fetch(`${attached.api}/api/capsules`, {
      headers: { authorization: `Bearer ${attached.token}` },
    });
    const text = await response.text();
    const body = JSON.parse(text);
    if (!response.ok || !Array.isArray(body.capsules)) {
      return { listed: false, reason: "capsules route refused", capsules: [] };
    }
    return { listed: true, reason: "", capsules: body.capsules };
  } catch (error) {
    return { listed: false, reason: String(error.message || error).slice(0, 180), capsules: [] };
  }
}

async function runU3Create() {
  const earlyTree = gitPorcelain(root);
  if (!earlyTree.ok || String(process.env.A15R_GIT_BEFORE || "").length > 0) {
    halt("release_signed", earlyTree.text || "git status --porcelain is not empty");
  }
  const install = readJson(path.join(out, "install.json"));
  const keyGone = !fs.existsSync(path.join(data, ".a15r-publisher.key"));
  if (install.signer_did && install.release_sha256 && install.key_deleted && keyGone) {
    pass("release_signed", "signed release");
  } else halt("release_signed", "install.json is missing a signed release");
  if (install.key_deleted && keyGone) pass("signing_key_deleted");
  else halt("signing_key_deleted", "disposable key is still present");
  pageProof = pageFolderProof(root, data);
  if (!pageProof.ok) halt("installed_identity_recorded", pageProof.pages);
  if (install.runtime_sha256 && install.wasm_sha256 && install.components_sha256 && install.bundle_cid) {
    pass("installed_identity_recorded", {
      runtime_sha256: install.runtime_sha256,
      wasm_sha256: install.wasm_sha256,
      components_sha256: install.components_sha256,
      pages: pageProof.pages,
    });
  } else halt("installed_identity_recorded", "install identity is incomplete");

  let gatewayProbe;
  try {
    const response = await fetch(`${pageOrigin}/healthz`);
    gatewayProbe = { status: response.status, body: await response.text() };
  } catch (error) {
    halt("gateway_started", String(error.message || error));
  }
  const carrier = noteCarrier();
  if (!gatewayHealthOk(gatewayProbe.status, gatewayProbe.body) || !carrier.ok) {
    halt("gateway_started", {
      status: gatewayProbe.status,
      body: String(gatewayProbe.body).slice(0, 200),
      carrier: carrier.reason || "",
    });
  }
  pass("gateway_started", { status: gatewayProbe.status, carrier: CARRIER_MODE });

  const playwright = loadPlaywright();
  if (!playwright) {
    screenshots.push({ name: "unlock", status: "skipped", detail: "playwright is not installed" });
    halt("owner_passkey_created", "playwright is not installed");
  }
  browser = await playwright.chromium.launch({ headless: true });
  rememberBrowser(playwright, browser);
  fs.mkdirSync(path.join(out, "video"), { recursive: true });
  adminContext = await browser.newContext({
    viewport: { width: 1280, height: 800 },
    recordVideo: { dir: path.join(out, "video"), size: { width: 1280, height: 800 } },
  });
  adminPage = await adminContext.newPage();
  await addAuthenticator(adminContext, adminPage);
  await adminPage.goto(pageOrigin + "/home/", { waitUntil: "domcontentloaded", timeout: 30000 });
  await shot(adminPage, "unlock");
  let enrolled;
  try {
    enrolled = await enroll(adminPage, "Owner", false);
  } catch (error) {
    const bodyText = await adminPage.locator("body").innerText().catch(() => "");
    halt("owner_passkey_created", `${error.message || error} page: ${bodyText.slice(0, 240)}`);
  }
  if (!enrolled.home_token) halt("owner_passkey_created", "register complete had no home token");
  state.homeToken = enrolled.home_token;
  pass("owner_passkey_created", "registered");
  await shot(adminPage, "owner-home");
  timings.owner_ms = Date.now() - started;

  attachPagePostWatch(adminPage);
  const system = await openOwnerSystem();
  state.systemToken = await readSystemFrameToken();
  const frameTokens = [state.systemToken];
  const allow = system.locator("#agent-allow");
  try {
    await allow.waitFor({ state: "visible", timeout: 30000 });
  } catch {
    halt("u3_home_asks", productFault("Allow agents #agent-allow"));
  }
  let enabled;
  try {
    const allowResponse = pagePost("/api/apps/system/agents/enable");
    await allow.click();
    enabled = await readBrowserResponse(await allowResponse);
  } catch (error) {
    if (error instanceof Error && U3_NAMES.includes(error.message)) throw error;
    halt("u3_home_asks", `${productFault("Allow agents #agent-allow")} ${String(error.message || error).slice(0, 180)}`);
  }
  if (enabled.status !== 200 || enabled.json?.enabled !== true) {
    halt("u3_agents_enabled", { status: enabled.status, body: enabled.text.slice(0, 300) });
  }
  pass("u3_agents_enabled");

  const beforeSpoof = storedAgentRecords();
  const spoof = await call("POST", "/api/apps/system/agents/create", state.systemToken, {
    display_name: "Spoof", agent_host: "agent-host", request_id: "u3-spoof", owner: "person:spoof",
  });
  const spoofSeen = process.env.A15R_PLANT === "unknown-owner-field-let-through"
    ? { status: 200, text: "created" }
    : spoof;
  if (!refusalIncludes(spoofSeen.status, spoofSeen.text, 409, "agent request is invalid")
    || JSON.stringify(storedAgentRecords()) !== JSON.stringify(beforeSpoof)) {
    halt(
      "u3_owner_field_refused",
      process.env.A15R_PLANT === "unknown-owner-field-let-through"
        ? "unknown owner field let through"
        : { status: spoofSeen.status, body: spoofSeen.text.slice(0, 300) },
    );
  }
  pass("u3_owner_field_refused", spoof.text.slice(0, 180));

  const nameInput = system.locator("#agent-name");
  const hostInput = system.locator("#agent-host");
  const createButton = system.locator("#agent-create");
  try {
    await nameInput.waitFor({ state: "visible", timeout: 20000 });
  } catch {
    halt("u3_home_asks", productFault("agent name field #agent-name"));
  }
  let created;
  let createdAgain;
  let activated;
  let createdId = "";
  let secondId = "";
  let homeAsks = { ok: false, reason: "page did not send Allow, two Creates, and Turn on", counts: {} };
  try {
    await nameInput.fill(AGENT_NAME);
    await hostInput.fill("agent-host");
    await shotAgents("before-create");
    await nameInput.fill(AGENT_NAME);
    await hostInput.fill("agent-host");
    const firstCreateWait = pagePost("/api/apps/system/agents/create");
    await createButton.click();
    created = await readBrowserResponse(await firstCreateWait);
    createdId = String(created.json?.agent_id || "");
    if (created.status !== 200 || !agentIdV2(createdId)) {
      halt("u3_home_asks", { status: created.status, body: created.text.slice(0, 240) });
    }
    await waitAgentText(system, createdId, AGENT_OFF);
    await shotAgents("after-create");
    await nameInput.fill(AGENT_NAME);
    await hostInput.fill("agent-host");
    const secondCreateWait = pagePost("/api/apps/system/agents/create");
    await createButton.click();
    createdAgain = await readBrowserResponse(await secondCreateWait);
    secondId = String(createdAgain.json?.agent_id || "");
    if (createdAgain.status !== 200 || !agentIdV2(secondId) || secondId === createdId) {
      halt("u3_home_asks", {
        status: createdAgain.status,
        same_name_same_id: secondId === createdId,
        body: createdAgain.text.slice(0, 180),
      });
    }
    await waitAgentText(system, secondId, AGENT_OFF);
    const turnOn = system.locator(".pc2-card-row").filter({
      has: system.locator(`[data-agent-state="${createdId}"]`),
    }).locator("button", { hasText: "Turn on" });
    try {
      await turnOn.waitFor({ state: "visible", timeout: 15000 });
    } catch {
      halt("u3_home_asks", productFault("Turn on"));
    }
    const activateWait = pagePost("/api/apps/system/agents/activate");
    await turnOn.click();
    activated = await readBrowserResponse(await activateWait);
    if (activated.status !== 200 || activated.json?.active !== true || activated.json?.agent_id !== createdId
      || activated.json?.session_id !== undefined) {
      halt("u3_home_asks", { status: activated.status, body: activated.text.slice(0, 240) });
    }
    await waitAgentText(system, createdId, AGENT_ON);
    await shotAgents("after-turn-on");
    const latestToken = await readSystemFrameToken();
    if (latestToken) {
      state.systemToken = latestToken;
      frameTokens.push(latestToken);
    }
    const posts = process.env.A15R_PLANT === "create-post-hidden"
      ? pagePosts.filter((item) => item.path !== "/api/apps/system/agents/create")
      : pagePosts;
    homeAsks = judgeHomeAsks(posts, frameTokens, state.homeToken);
    if (!homeAsks.ok) {
      halt("u3_home_asks", process.env.A15R_PLANT === "create-post-hidden"
        ? { plant: "Create post hidden", ...homeAsks }
        : homeAsks);
    }
  } catch (error) {
    if (error instanceof Error && U3_NAMES.includes(error.message)) throw error;
    halt("u3_home_asks", String(error.message || error).slice(0, 400));
  }
  pass("u3_home_asks", {
    counts: homeAsks.counts,
    token_is_page_frame: true,
    token_is_runner_enrollment: false,
    showed_off: true,
    showed_on: true,
    same_name: AGENT_NAME,
    distinct_ids: true,
  });

  const caller = await productCaller(state.systemToken);
  const admins = storedHumans().filter((person) => person.role === "admin");
  const storedRows = storedAgentRecords();
  const stored = storedRows.find((row) => row.id === createdId);
  const storedSecond = storedRows.find((row) => row.id === secondId);
  const ownerFromFile = admins.length === 1 ? admins[0].id : "";
  const ownerJudge = judgeCreatingOwner({
    checkRan: process.env.A15R_PLANT !== "owner-check-skipped",
    storedOwner: stored?.owner,
    productOwner: caller.id,
    fileOwner: ownerFromFile,
  });
  const secondOwner = judgeCreatingOwner({
    checkRan: process.env.A15R_PLANT !== "owner-check-skipped",
    storedOwner: storedSecond?.owner,
    productOwner: caller.id,
    fileOwner: ownerFromFile,
  });
  if (!ownerJudge.ok || !secondOwner.ok) {
    halt("u3_agent_created", ownerJudge.reason || secondOwner.reason);
  }
  if (
    created.json?.active !== false
    || created.json?.session_id !== undefined
    || createdAgain.json?.active !== false
    || storedRows.length !== 2
    || agentDisplayName(createdId) !== AGENT_NAME
    || agentDisplayName(secondId) !== AGENT_NAME
  ) {
    halt("u3_agent_created", {
      status: created.status,
      active: created.json?.active,
      stored_owner_matches_summary: stored?.owner === caller.id,
      stored_owner_matches_auth_file: stored?.owner === ownerFromFile,
      rows: storedRows.length,
      admins: admins.length,
    });
  }
  pass("u3_agent_created", {
    agent: createdId,
    second_agent: secondId,
    owner_matches_product: true,
    read_from: "agent-records.json and system summary authority.principal_id",
  });
  pass("u3_agent_activated", { agent: createdId, active: true, session_id: false });

  const guestRegistration = await call(
    "POST", "/api/apps/system/access/guest-registration", state.systemToken, { enabled: true },
  );
  if (guestRegistration.status !== 200) {
    halt("u3_non_owner_refused", "guest registration was not enabled: " + guestRegistration.text.slice(0, 240));
  }
  const guestContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const guestPage = await guestContext.newPage();
  await addAuthenticator(guestContext, guestPage);
  let guest;
  try {
    guest = await enroll(guestPage, "Guest", true);
    await shot(guestPage, "guest");
  } catch (error) {
    halt("u3_non_owner_refused", String(error.message || error));
  }
  await guestContext.close();
  if (!guest.home_token) halt("u3_non_owner_refused", "guest passkey completed without a home token");
  state.guestToken = guest.home_token;
  const guestSystem = await launchApp(state.guestToken, "system");
  state.guestSystemToken = guestSystem.token;
  const guestPeople = storedHumans().filter((person) => person.role === "guest");
  const ownerStill = storedAgentRecords().find((row) => row.id === createdId);
  const beforeNonOwner = JSON.stringify(storedAgentRecords());
  const nonOwnerCreate = await call(
    "POST",
    "/api/apps/system/agents/create",
    state.guestSystemToken || state.guestToken,
    { display_name: "Other", agent_host: "agent-host", request_id: "u3-non-owner" },
  );
  const nonOwnerRefused = refusalIncludes(nonOwnerCreate.status, nonOwnerCreate.text, 403, adminRequired)
    && guestPeople.length === 1
    && guestPeople[0].id !== ownerFromFile
    && ownerStill?.owner === ownerFromFile
    && JSON.stringify(storedAgentRecords()) === beforeNonOwner;
  if (!nonOwnerRefused) {
    halt("u3_non_owner_refused", {
      person: "guest session",
      status: nonOwnerCreate.status,
      body: nonOwnerCreate.text.slice(0, 240),
      guests: guestPeople.length,
      distinct: guestPeople[0]?.id !== ownerFromFile,
      launch: guestSystem.reply.status,
    });
  }
  pass("u3_non_owner_refused", { person: "guest session", status: nonOwnerCreate.status });

  const beforeUnknown = JSON.stringify(storedAgentRecords());
  const unknownActivate = await call("POST", "/api/apps/system/agents/activate", state.systemToken, {
    agent_id: unknownId, active: true,
  });
  let unknownLaunch = { status: 0, text: "" };
  try {
    const stepToken = await stepUp(state.systemToken, "agent.start", { agent_id: unknownId });
    unknownLaunch = await call("POST", "/api/apps/system/agents/launch", state.systemToken, {
      agent_id: unknownId,
      step_up_token: stepToken,
    });
  } catch (error) {
    halt("u3_unknown_id_refused", "step-up before launch: " + String(error.message || error).slice(0, 240));
  }
  if (!refusalIncludes(unknownActivate.status, unknownActivate.text, 409, noSuchAgent)
    || !refusalIncludes(unknownLaunch.status, unknownLaunch.text, 409, noSuchAgent)
    || JSON.stringify(storedAgentRecords()) !== beforeUnknown) {
    halt("u3_unknown_id_refused", {
      activate: unknownActivate.status,
      launch: unknownLaunch.status,
      body: unknownLaunch.text.slice(0, 240),
    });
  }
  pass("u3_unknown_id_refused", { activate: noSuchAgent, launch: noSuchAgent });

  const beforeGuest = JSON.stringify(storedAgentRecords());
  const guestCreate = await call(
    "POST",
    "/api/apps/system/agents/create",
    state.guestSystemToken || state.guestToken,
    { display_name: "Guest Agent", agent_host: "agent-host", request_id: "u3-guest" },
  );
  if (!refusalIncludes(guestCreate.status, guestCreate.text, 403, adminRequired)
    || JSON.stringify(storedAgentRecords()) !== beforeGuest) {
    halt("u3_guest_refused", {
      status: guestCreate.status,
      body: guestCreate.text.slice(0, 240),
      launch: guestSystem.reply.status,
    });
  }
  pass("u3_guest_refused", { status: guestCreate.status, body: guestCreate.text.slice(0, 180) });

  const beforeSession = JSON.stringify(storedAgentRecords());
  const noSession = await call("POST", "/api/apps/system/agents/create", "", {
    display_name: "No Session", agent_host: "agent-host", request_id: "u3-no-session",
  });
  // The same origin as a signed create, with the launch token omitted. The
  // frontdoor answers a missing token on this route with its public refusal.
  if (!refusalIncludes(noSession.status, noSession.text, 403, "Gateway request requires an admitted host and caller")
    || JSON.stringify(storedAgentRecords()) !== beforeSession) {
    halt("u3_no_session_refused", { status: noSession.status, body: noSession.text.slice(0, 240) });
  }
  pass("u3_no_session_refused", { status: noSession.status, body: "Gateway request requires an admitted host and caller" });

  const identities = JSON.stringify(storedAgentRecords());
  const disabled = await call("POST", "/api/apps/system/agents/disable", state.systemToken, {});
  const whileOff = await call("POST", "/api/apps/system/agents/create", state.systemToken, {
    display_name: "While Off", agent_host: "agent-host", request_id: "u3-while-off",
  });
  if (disabled.status !== 200 || disabled.json?.enabled !== false
    || !refusalIncludes(whileOff.status, whileOff.text, 409, "agents are not turned on for this Home")
    || JSON.stringify(storedAgentRecords()) !== identities) {
    halt("u3_agents_disabled_refused", {
      disable: disabled.status,
      status: whileOff.status,
      body: whileOff.text.slice(0, 240),
    });
  }
  pass("u3_agents_disabled_refused", { status: whileOff.status });

  const enabledAgain = await call("POST", "/api/apps/system/agents/enable", state.systemToken, {});
  if (enabledAgain.status !== 200 || enabledAgain.json?.enabled !== true) {
    halt("u3_no_guest_no_mint", { status: enabledAgain.status, body: enabledAgain.text.slice(0, 240) });
  }

  const beforeMint = JSON.stringify(storedAgentRecords());
  const minted = await call("POST", "/api/apps/system/agents/create", state.systemToken, {
    display_name: "Chosen", agent_host: "agent-host", request_id: "u3-chosen-id", agent_id: chosenId,
  });
  const processes = elastosProcesses();
  const replacement = createReplacesMint(
    fs.readFileSync(path.join(root, "elastos/crates/elastos-server/src/agents.rs"), "utf8"),
    fs.readFileSync(path.join(root, "elastos/crates/elastos-server/src/api/gateway.rs"), "utf8"),
  );
  let capsulesListed = false;
  let guestCapsules = 0;
  if (processes.ok && processes.serve.length > 0) {
    let listed = await listRuntimeCapsules();
    const deadline = Date.now() + 20000;
    while (!listed.listed && Date.now() < deadline) {
      await sleep(500);
      listed = await listRuntimeCapsules();
    }
    capsulesListed = listed.listed;
    guestCapsules = guestCapsuleCount(listed.capsules, [createdId, secondId]);
    if (!listed.listed) {
      halt("u3_no_guest_no_mint", { reason: "serve is running and its capsules cannot be listed", detail: listed.reason });
    }
  }
  const guestProof = noGuestProof({
    stray: processes.ok ? processes.stray : null,
    serveKnown: processes.ok,
    serveRunning: processes.ok && processes.serve.length > 0,
    capsulesListed,
    guestCapsules,
  });
  const mint = mintHitsFromRepo(root);
  const sameNameDistinct = agentIdV2(createdId) && agentIdV2(secondId) && createdId !== secondId;
  const noMint = refusalIncludes(minted.status, minted.text, 409, "agent request is invalid")
    && JSON.stringify(storedAgentRecords()) === beforeMint
    && !storedAgentRecords().some((row) => row.id === chosenId)
    && created.json?.session_id === undefined
    && activated.json?.session_id === undefined
    && guestProof.ok
    && replacement.ok
    && mint.ok
    && mint.defined === false
    && sameNameDistinct;
  if (!noMint) {
    halt("u3_no_guest_no_mint", {
      status: minted.status,
      body: minted.text.slice(0, 180),
      stray: processes.stray,
      serve: processes.ok ? processes.serve.length : "unknown",
      guest: guestProof.reason,
      route: replacement.route,
      fields: replacement.fields,
      id_source: replacement.id_source,
      production_mint_hits: mint.production,
      same_name_distinct: sameNameDistinct,
    });
  }
  pass("u3_no_guest_no_mint", {
    route: replacement.route,
    fields: replacement.fields,
    id_source: replacement.id_source,
    id_form: "agent:v2 plus 32 hex",
    same_name_distinct: true,
    mint_defined: mint.defined,
    production_mint_hits: mint.production.map((hit) => `${hit.path}:${hit.line}`),
    test_only_mint_hits: mint.testOnly.map((hit) => `${hit.path}:${hit.line}`),
    stray: processes.stray,
    capsules_listed: capsulesListed,
    guest_capsules: guestCapsules,
  });

  const beforeBytes = fs.readFileSync(agentRecordsPath());
  const beforeCaller = await productCaller(state.systemToken);
  try {
    await stopServe();
    await startGatewayOnly();
  } catch (error) {
    halt("u3_restart_same_record", String(error.message || error));
  }
  const afterBytes = fs.readFileSync(agentRecordsPath());
  const afterCaller = await productCaller(state.systemToken);
  const afterStored = storedAgentRecords().find((row) => row.id === createdId);
  const listed = await call("GET", "/api/apps/system/agents", state.systemToken);
  const listedBody = process.env.A15R_PLANT === "ignore-agent-file" ? { agents: [] } : listed.json;
  const expectedAgents = [
    { id: createdId, name: AGENT_NAME, active: true },
    { id: secondId, name: AGENT_NAME, active: false },
  ];
  const listJudge = listedAgentsMatch(listedBody, expectedAgents);
  const carrierAgain = noteCarrier();
  if (!beforeBytes.equals(afterBytes)
    || !storedOwnerIsCreatingOwner(afterStored?.owner, afterCaller.id)
    || afterCaller.id !== beforeCaller.id
    || !listJudge.ok
    || !carrierAgain.ok) {
    halt("u3_restart_same_record", {
      bytes_match: beforeBytes.equals(afterBytes),
      summary_status: afterCaller.status,
      owner_matches: afterStored?.owner === afterCaller.id,
      list: process.env.A15R_PLANT === "ignore-agent-file"
        ? "gateway ignores the agent file after restart"
        : listJudge.reason,
      list_status: listed.status,
      carrier: carrierAgain.reason || "",
    });
  }
  pass("u3_restart_same_record", {
    bytes_match: true,
    owner_matches_product: true,
    agents: expectedAgents.map((row) => ({ id: row.id, name: row.name, active: row.active })),
  });

  const did = runtimeIdentityDid();
  const verified = verifyInstalledAudit(readJson(authStatePath()), did);
  const binary = gatewayRestartLoadedChain(fs.readFileSync(logPath, "utf8"));
  const creates = verified.creates;
  const bothCreates = verified.ok
    && creates.length === 2
    && creates.includes(createdId)
    && creates.includes(secondId);
  if (!bothCreates || !binary.ok) {
    halt("u3_create_audit", {
      reason: verified.reason || binary.reason,
      event_type: verified.event_type || "",
      count: creates.length,
      binary_log_line: binary.log_line,
      binary_reason: binary.reason,
    });
  }
  pass("u3_create_audit", {
    count: 2,
    verified: true,
    subject_is_created_agent: true,
    binary_command: binary.command,
    binary_log_line: binary.log_line,
    binary_verifier: binary.verifier,
  });
}

function shellFailReceipt() {
  if (process.env.A15R_ONLY === "u3-create") {
    const failed = process.env.FAILED || "";
    const reason = process.env.REASON || "";
    const statuses = shellFailStatuses(failed, U3_NAMES);
    const assertions = U3_NAMES.map((name, index) => ({
      name,
      status: statuses[index],
      detail: name === failed ? clip(reason) : "",
    }));
    const receipt = {
      mode: "u3-create",
      route: "POST /api/apps/system/agents/create",
      non_owner: "guest session",
      source_commit: process.env.A15R_SOURCE_COMMIT || "",
      source_tree: process.env.A15R_SOURCE_TREE || "",
      git_porcelain_before: process.env.A15R_GIT_BEFORE || "",
      binaries: binarySha256s(loadInstall()),
      timings_ms: {},
      assertions,
      screenshots: [],
      stopped: clip(reason),
    };
    fs.writeFileSync(path.join(out, "receipt.json"), JSON.stringify(receipt, null, 2) + "\n");
    return;
  }
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
    mode: "full",
    proof: false,
    notice: FULL_MODE_NOTICE,
    route: "POST /api/apps/system/agents/launch",
    step_up_operation: "agent.start",
    plan_step_up_operation: "agent_plan.approve",
    source_commit: process.env.A15R_SOURCE_COMMIT || "",
    source_tree: process.env.A15R_SOURCE_TREE || "",
    git_porcelain_before: process.env.A15R_GIT_BEFORE || "",
    install: redactInstall(fs.existsSync(installPath) ? readJson(installPath) : {}),
    timings_ms: {},
    assertions,
    card: null,
    grants: [],
    launches: { a: null, b: null },
    screenshots: [],
    stopped: clip(reason),
  };
  fs.writeFileSync(path.join(out, "receipt.json"), redactDidAndAddress(JSON.stringify(receipt, null, 2) + "\n"));
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  return import.meta.url === pathToFileURL(path.resolve(entry)).href;
}

function scriptRoot() {
  return process.env.A15R_ROOT || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

function readAgentsInGateway() {
  const repo = scriptRoot();
  const read = (rel) => fs.readFileSync(path.join(repo, rel), "utf8");
  const api = "elastos/crates/elastos-server/src/api";
  return agentsInGatewayChange(
    `${read(`${api}/gateway.rs`)}\n${read(`${api}/gateway_inbox.rs`)}`,
    read(`${api}/gateway_agents.rs`),
    read(`${api}/gateway_home_runtime.rs`),
  );
}

function preparePlaywright() {
  const repo = scriptRoot();
  const pin = playwrightPin(fs.readFileSync(path.join(repo, "scripts/test-behaviour.sh"), "utf8"));
  if (!pin.ok) {
    console.error("playwright pin in scripts/test-behaviour.sh is missing or inconsistent");
    process.exit(2);
  }
  const inputs = behaviourInputsDir(process.env);
  const bundled = inputs ? path.join(inputs, "browser", "node_modules", "playwright") : "";
  const scratch = process.env.A15R_SCRATCH || path.join(repo, "target", "a15r-homes");
  let moduleDir = "";
  let source = "";
  if (packageVersion(path.join(bundled, "package.json")) === pin.version) {
    moduleDir = bundled;
    source = "behaviour-inputs";
  } else {
    moduleDir = path.join(scratch, "tool", "node_modules", "playwright");
    source = "scratch-install";
    if (packageVersion(path.join(moduleDir, "package.json")) !== pin.version) {
      fs.mkdirSync(path.join(scratch, "tool"), { recursive: true });
      const env = { ...process.env };
      for (const key of Object.keys(env)) {
        if (key.startsWith("ELASTOS_")) delete env[key];
      }
      const installed = spawnSync("npm", [
        "install", "--prefix", path.join(scratch, "tool"),
        "--no-save", "--package-lock=false", `playwright@${pin.version}`,
      ], { env, encoding: "utf8" });
      if (installed.status !== 0) {
        console.error(String(installed.stderr || "npm install playwright failed").slice(0, 500));
        process.exit(2);
      }
    }
  }
  const revision = headlessShellRevision(moduleDir);
  const shellName = revision ? `chromium_headless_shell-${revision}` : "";
  let browsers = process.env.PLAYWRIGHT_BROWSERS_PATH || "";
  if (!(browsers && shellName && fs.existsSync(path.join(browsers, shellName)))) {
    const cached = macPlaywrightBrowserCache(process.env);
    if (cached && shellName && fs.existsSync(path.join(cached, shellName))) browsers = cached;
  }
  if (!(browsers && shellName && fs.existsSync(path.join(browsers, shellName)))) {
    browsers = path.join(scratch, "browsers");
    fs.mkdirSync(browsers, { recursive: true });
    const env = { ...process.env };
    for (const key of Object.keys(env)) {
      if (key.startsWith("ELASTOS_")) delete env[key];
    }
    env.PLAYWRIGHT_BROWSERS_PATH = browsers;
    const bin = path.join(path.dirname(moduleDir), ".bin", "playwright");
    const installed = spawnSync(bin, ["install", "chromium", "--only-shell"], { env, encoding: "utf8" });
    if (installed.status !== 0) {
      console.error(String(installed.stderr || "playwright install chromium failed").slice(0, 500));
      process.exit(2);
    }
  }
  process.stdout.write(`${moduleDir}\n${browsers}\n${source}\n${pin.version}\n`);
}

function scrubEvidenceFiles() {
  if (logPath && fs.existsSync(logPath)) {
    fs.writeFileSync(logPath, redactDidAndAddress(fs.readFileSync(logPath, "utf8")));
  }
  const installPath = out ? path.join(out, "install.json") : "";
  if (installPath && fs.existsSync(installPath)) {
    fs.writeFileSync(installPath, `${JSON.stringify(redactInstall(readJson(installPath)))}\n`);
  }
}

async function removeHome() {
  const scratch = process.env.A15R_SCRATCH || "";
  if (!home || !scratch || !fs.existsSync(home)) return;
  if (!throwawayAllowed(home, scratch)) {
    throw new Error("refusing to remove a path that is not this run's throwaway home");
  }
  const target = fs.realpathSync(home);
  const identity = data ? path.join(data, "identity") : "";
  if (identity && fs.existsSync(identity)) {
    for (const name of fs.readdirSync(identity)) {
      if (name.endsWith(".key") || name.endsWith(".pem")) {
        fs.rmSync(path.join(identity, name), { force: true });
      }
    }
  }
  const publisherKey = data ? path.join(data, ".a15r-publisher.key") : "";
  if (publisherKey && fs.existsSync(publisherKey)) fs.rmSync(publisherKey, { force: true });
  await new Promise((resolve, reject) => {
    fs.rm(target, { recursive: true }, (error) => (error ? reject(error) : resolve()));
  });
}

if (invokedDirectly()) {
  const flag = process.argv[2] || "";
  if (flag === "--shell-fail") {
    shellFailReceipt();
    process.exit(1);
  }
  if (flag === "--agents-in-gateway") {
    const detected = readAgentsInGateway();
    if (!detected.ok) {
      console.error(detected.reason);
      process.exit(2);
    }
    process.exit(0);
  }
  if (flag === "--prepare-playwright") {
    preparePlaywright();
    process.exit(0);
  }
  if (flag === "--scrub-evidence") {
    scrubEvidenceFiles();
    process.exit(0);
  }
  if (flag === "--stop-home") {
    stopServe().then(() => process.exit(0)).catch((error) => {
      console.error(String(error.message || error));
      process.exit(1);
    });
  } else if (flag === "--remove-throwaway") {
    stopServe()
      .catch(() => {})
      .then(() => removeHome())
      .then(() => process.exit(0))
      .catch((error) => {
        console.error(String(error.message || error));
        process.exit(1);
      });
  } else if (flag) {
    console.error(`unknown argument: ${flag}`);
    process.exit(2);
  } else {
    const full = process.env.A15R_ONLY !== "u3-create";
    if (full) {
      console.log(FULL_MODE_NOTICE);
      const detected = readAgentsInGateway();
      if (!detected.ok) {
        console.error(detected.reason);
        process.exit(2);
      }
    }
    if (out) removeStaleReceipt(out);
    const job = full ? main : runU3Create;
    job().catch((error) => {
      stopped = clip(error && (error.detail || error.stack || error.message) || error);
    }).finally(async () => {
      const video = adminPage && typeof adminPage.video === "function" ? adminPage.video() : null;
      if (video) {
        await adminPage.close().catch(() => {});
        try {
          const file = path.join(out, "owner.webm");
          await video.saveAs(file);
          screenshots.push({ name: "owner-video", status: "taken", path: file });
        } catch (error) {
          screenshots.push({ name: "owner-video", status: "skipped", detail: clip(String(error)) });
        }
      }
      if (browser) await browser.close().catch(() => {});
      browser = undefined;
      try {
        await stopServe();
      } catch (error) {
        stopped = clip(stopped || error.message || error);
        mark("release_signed", "fail", "Home processes could not be stopped");
      }
      try {
        scrubEvidenceFiles();
        await removeHome();
      } catch (error) {
        stopped = clip(stopped || error.message || error);
        mark("release_signed", "fail", "throwaway home was not removed");
      }
      gitAfter = gitPorcelain(root);
      if (!gitAfter.ok) {
        mark("release_signed", "fail", "git status --porcelain is not empty at the end");
      }
      const code = writeReceipt();
      process.exit(code);
    });
  }
}
