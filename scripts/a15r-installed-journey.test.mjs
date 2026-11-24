import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  OWNER_DOCUMENT,
  OWNER_NOTE,
  U3_NAMES,
  U4_ISOLATION_NOT_COVERED,
  agentStartRequestSha256,
  agentStartStepUps,
  auditChainHash,
  auditEventBytes,
  carriedAgentId,
  createReplacesMint,
  createdAgentOwnedBy,
  LIVE_SESSION_COORDS,
  gatewayHealthOk,
  grantWaitSatisfied,
  journalFileInRoot,
  ownerDocumentUnchanged,
  ownerNoteRelative,
  refusalIncludes,
  runtimeHealthOk,
  shellFailStatuses,
  signedAgentStarts,
  signedStartAudit,
  storedOwnerIsCreatingOwner,
  userAreaRouteRefused,
  verifyInstalledAudit,
  pageLaunchToken,
  agentIdV2,
  judgeHomeAsks,
  lineIsTestOnly,
  parseGitGrep,
  classifyMintHit,
  mintHitKind,
  mintHitsFromRepo,
  gatewayRestartLoadedChain,
} from "./a15r-installed-journey.mjs";
import {
  agentsInGatewayChange,
  bindsPort,
  carrierConfigOk,
  elastosSubcommand,
  executableInsideHome,
  FULL_MODE_NOTICE,
  gitTreeHash,
  homeProcessEnv,
  judgeCreatingOwner,
  listedAgentsMatch,
  noGuestProof,
  pageFolderProof,
  playwrightPin,
  redactDidAndAddress,
  redactInstall,
  removeStaleReceipt,
  throwawayAllowed,
} from "./a15r-installed-journey-proof.mjs";

const agentA = "agent:v2:" + "a".repeat(32);
const agentB = "agent:v2:" + "b".repeat(32);
const ownerId = "person:local:owner";
const rootA = "localhost://UsersAI/aaaaaaaaaaaa";
const rootB = "localhost://UsersAI/bbbbbbbbbbbb";

function startEvent(agentId, signature = "signed") {
  return {
    event_type: "auth.passkey_step_up.completed",
    signature,
    reason: JSON.stringify({
      operation: "agent.start",
      request_sha256: agentStartRequestSha256(agentId),
    }),
  };
}

test("the live session list reads the agent runtime", () => {
  assert.equal(LIVE_SESSION_COORDS, "agent-runtime-coords.json");
  assert.notEqual(LIVE_SESSION_COORDS, "home-runtime-coords.json");
});

test("gateway health is the gateway body", () => {
  assert.equal(gatewayHealthOk(200, "OK"), true);
  assert.equal(gatewayHealthOk(200, "OK\n"), true);
  assert.equal(gatewayHealthOk(200, ""), false);
  assert.equal(gatewayHealthOk(200, "{\"status\":\"ok\"}"), false);
  assert.equal(gatewayHealthOk(500, "OK"), false);
});

test("runtime health is the runtime status", () => {
  assert.equal(runtimeHealthOk(200, "{\"status\":\"ok\",\"version\":\"1\"}"), true);
  assert.equal(runtimeHealthOk(200, "{\"running\":true,\"api_url\":\"http://127.0.0.1:9\"}"), false);
  assert.equal(runtimeHealthOk(200, "OK"), false);
  assert.equal(runtimeHealthOk(503, "{\"status\":\"ok\"}"), false);
});

function lifecycleEvent(type, agentId, options = {}) {
  const signature = options.signature === undefined ? "signed" : options.signature;
  const result = options.result === undefined ? "ok" : options.result;
  const event = { event_type: type, signature, result, reason: "seq=1" };
  if (options.carry === "reason") event.reason = JSON.stringify({ agent_id: agentId });
  else if (options.carry === "principal") event.principal_id = agentId;
  else event.agent_id = agentId;
  return event;
}

function startedPair(agentId, carry = "field") {
  return [
    lifecycleEvent("agent.start.requested", agentId, { carry }),
    lifecycleEvent("agent.start.completed", agentId, { carry }),
  ];
}

test("step-up binding stays its own check", () => {
  const digest = agentStartRequestSha256(agentA);
  assert.equal(digest, crypto.createHash("sha256").update(`{"agent_id":"${agentA}"}`).digest("hex"));
  const dispatchOnly = [{
    event_type: "agent_plan.dispatch.started",
    signature: "signed",
    reason: "claimed by Runtime",
  }];
  assert.equal(agentStartStepUps(dispatchOnly, [agentA, agentB]).ok, false);
  assert.equal(agentStartStepUps([startEvent(agentA, "")], [agentA]).ok, false);
  assert.equal(agentStartStepUps([startEvent(agentA)], [agentA, agentB]).ok, false);
  const both = agentStartStepUps([
    startEvent("agent:v2:" + "f".repeat(32)),
    startEvent(agentA),
    startEvent(agentB),
  ], [agentA, agentB]);
  assert.equal(both.ok, true);
  assert.deepEqual(both.matched.sort(), [agentA, agentB].sort());
});

test("signed start requires requested then completed ok by agent_id", () => {
  const stepUps = [startEvent(agentA), startEvent(agentB)];
  assert.equal(signedAgentStarts(stepUps, [agentA, agentB]).ok, false);
  assert.equal(carriedAgentId({ principal_id: agentA }), "");
  assert.equal(signedAgentStarts([
    lifecycleEvent("agent.start.completed", agentA),
    lifecycleEvent("agent.start.requested", agentA),
  ], [agentA]).ok, false);
  assert.equal(signedAgentStarts([
    lifecycleEvent("agent.start.requested", agentA),
    lifecycleEvent("agent.start.completed", agentA, { result: "success" }),
  ], [agentA]).ok, false);
  assert.equal(signedAgentStarts([
    lifecycleEvent("agent.start.requested", agentA, { signature: "" }),
    lifecycleEvent("agent.start.completed", agentA),
  ], [agentA]).ok, false);
  assert.equal(signedAgentStarts(startedPair(agentA), [agentA, agentB]).ok, false);
  assert.equal(signedAgentStarts([
    lifecycleEvent("agent.start.requested", agentA, { carry: "principal" }),
    lifecycleEvent("agent.start.completed", agentA, { carry: "principal" }),
  ], [agentA]).ok, false);
  const both = signedAgentStarts([
    ...startedPair(agentA),
    ...startedPair(agentB, "reason"),
  ], [agentA, agentB]);
  assert.equal(both.ok, true);
  assert.deepEqual(both.matched, [agentA, agentB]);
  const audit = signedStartAudit([...stepUps, ...startedPair(agentA), ...startedPair(agentB)], [agentA, agentB]);
  assert.equal(audit.step_up.ok, true);
  assert.equal(audit.started.ok, true);
  assert.equal(audit.ok, true);
  const consentOnly = signedStartAudit(stepUps, [agentA, agentB]);
  assert.equal(consentOnly.step_up.ok, true);
  assert.equal(consentOnly.started.ok, false);
  assert.equal(consentOnly.ok, false);
  const startedOnly = signedStartAudit([...startedPair(agentA), ...startedPair(agentB)], [agentA, agentB]);
  assert.equal(startedOnly.step_up.ok, false);
  assert.equal(startedOnly.started.ok, true);
  assert.equal(startedOnly.ok, false);
});

test("grant wait ignores the route row's marker files", () => {
  const markers = [
    { path: "UsersAI/aaaaaaaaaaaa/Documents/own-marker.txt" },
    { path: "UsersAI/bbbbbbbbbbbb/Documents/cross-read.txt" },
  ];
  assert.equal(grantWaitSatisfied(markers, [rootA, rootB], []), false);
  const journal = markers.concat([
    { path: "UsersAI/aaaaaaaaaaaa/.AppData/Agents/agent-host/tasks/demo/journal" },
    { path: "UsersAI/bbbbbbbbbbbb/.AppData/Agents/agent-host/tasks/demo/journal" },
  ]);
  assert.equal(grantWaitSatisfied(journal, [rootA, rootB], []), true);
  assert.equal(grantWaitSatisfied([], [rootA, rootB], [
    { status: 200, resource: rootA },
    { status: 200, resource: rootB },
  ]), true);
});

test("journal row requires the file under the agent root", () => {
  const journal = "UsersAI/aaaaaaaaaaaa/.AppData/Agents/agent-host/tasks/demo/journal";
  assert.equal(journalFileInRoot([{ path: journal }], rootA), true);
  assert.equal(journalFileInRoot([{ path: "UsersAI/aaaaaaaaaaaa-other/journal" }], rootA), false);
  assert.equal(journalFileInRoot([{ path: "UsersAI/bbbbbbbbbbbb/journal" }], rootA), false);
  assert.equal(journalFileInRoot([], rootA), false);
  assert.equal(journalFileInRoot([{
    path: "grant",
    resource: `${rootA}/.AppData/Agents/agent-host/tasks/demo/journal`,
    status: 200,
  }], rootA), false);
});

test("owner document is the old note path and compares its bytes", () => {
  assert.equal(OWNER_NOTE, "Documents/note.txt");
  assert.equal(ownerNoteRelative("localhost://Users/self"), "Users/self/Documents/note.txt");
  assert.equal(ownerNoteRelative("localhost://Users/abc123"), "Users/abc123/Documents/note.txt");
  assert.equal(ownerNoteRelative("localhost://UsersAI/abc123"), "");
  assert.equal(ownerNoteRelative("localhost://Users/self/../secret"), "");
  assert.equal(ownerNoteRelative(""), "");
  assert.equal(ownerDocumentUnchanged(OWNER_DOCUMENT, Buffer.from(OWNER_DOCUMENT)), true);
  assert.equal(ownerDocumentUnchanged(OWNER_DOCUMENT, Buffer.from("three lines")), false);
  assert.equal(ownerDocumentUnchanged(null, null), false);
  assert.equal(ownerDocumentUnchanged(Buffer.alloc(0), Buffer.alloc(0)), false);
  assert.equal(ownerDocumentUnchanged(OWNER_DOCUMENT, null), false);
});

test("user-area route row requires both reads refused", () => {
  const marker = "secret-marker";
  const refused = (root, file) => ({
    called: true,
    session: "session-a",
    root,
    resource: `${root}/Documents/${file}`,
    status: 403,
    body: "Capsules cannot access a localhost user area root",
    marker,
  });
  const pair = { own: refused(rootA, "own-marker.txt"), other: refused(rootB, "cross-read.txt") };
  assert.equal(userAreaRouteRefused(pair), true);
  assert.equal(userAreaRouteRefused({ other: pair.other }), false);
  assert.equal(userAreaRouteRefused({ own: { ...pair.own, status: 200, body: marker }, other: pair.other }), false);
  assert.equal(userAreaRouteRefused({ own: pair.own, other: { ...pair.other, status: 200, body: marker } }), false);
  assert.equal(userAreaRouteRefused({ own: { ...pair.own, called: false }, other: pair.other }), false);
  assert.equal(userAreaRouteRefused({ own: pair.own, other: { ...pair.other, body: `refused ${marker}` } }), false);
  assert.equal(userAreaRouteRefused({ own: pair.own, other: { ...pair.other, session: "session-b" } }), false);
  assert.equal(userAreaRouteRefused({ own: pair.own, other: { ...pair.other, root: rootA, resource: `${rootA}/Documents/other.txt` } }), false);
  assert.equal(userAreaRouteRefused({ grants: [`${rootA}/journal`, `${rootB}/journal`] }), false);
  const routes = fs.readFileSync(new URL("../elastos/crates/elastos-server/src/api/routes.rs", import.meta.url), "utf8");
  for (const line of U4_ISOLATION_NOT_COVERED) {
    assert.equal(line.includes("routes.rs:"), false);
    const named = line.match(/an_agents_guest_[a-z0-9_]+/);
    assert.ok(named, line);
    assert.ok(routes.includes(`fn ${named[0]}`), named[0]);
  }
});

test("created agent stores the creating owner", () => {
  const row = { id: agentA, owner: ownerId, root: rootA, active: false };
  assert.equal(createdAgentOwnedBy(row, ownerId), true);
  assert.equal(createdAgentOwnedBy({ ...row, owner: "person:spoof" }, ownerId), false);
  assert.equal(createdAgentOwnedBy({ ...row, owner: "" }, ownerId), false);
  assert.equal(createdAgentOwnedBy(undefined, ownerId), false);
  assert.equal(createdAgentOwnedBy({ ...row, owner: agentA }, agentA), false);
});

test("a shell failure does not pass a row the node did not check", () => {
  const later = shellFailStatuses("u3_agent_started");
  const byName = (statusList, name) => statusList[[
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
  ].indexOf(name)];
  assert.equal(byName(later, "u3_agent_started"), "fail");
  assert.equal(byName(later, "gateway_started"), "not reached");
  assert.equal(byName(later, "runtime_started"), "not reached");
  assert.equal(byName(later, "signed_start_audit"), "not reached");
  const atGateway = shellFailStatuses("gateway_started");
  assert.equal(byName(atGateway, "gateway_started"), "fail");
  assert.equal(byName(atGateway, "release_signed"), "pass");
  assert.equal(byName(atGateway, "signing_key_deleted"), "pass");
  assert.equal(byName(atGateway, "runtime_started"), "not reached");
});

test("u3 create mode names the create rows and no start row", () => {
  assert.equal(U3_NAMES.includes("u3_agent_started"), false);
  assert.equal(U3_NAMES.includes("u3_agent_created"), true);
  assert.equal(U3_NAMES.includes("u3_home_asks"), true);
  assert.equal(U3_NAMES.at(-1), "u3_create_audit");
  assert.equal(U3_NAMES.includes("u3_guest_refused"), false);
  assert.equal(U3_NAMES.includes("u3_non_owner_refused"), true);
  assert.equal(U3_NAMES.filter((name) => name === "u3_non_owner_refused").length, 1);
  const failed = shellFailStatuses("u3_agent_created", U3_NAMES);
  assert.equal(failed[U3_NAMES.indexOf("u3_agent_created")], "fail");
  assert.equal(failed[U3_NAMES.indexOf("release_signed")], "pass");
  assert.equal(failed[U3_NAMES.indexOf("u3_create_audit")], "not reached");
  assert.equal(failed.length, U3_NAMES.length);
});

test("stored owner is the product caller, not a different runner value", () => {
  const product = "person:local:abc";
  assert.equal(storedOwnerIsCreatingOwner(product, product), true);
  assert.equal(storedOwnerIsCreatingOwner("person:spoof", product), false);
  assert.equal(storedOwnerIsCreatingOwner(product, "person:local:other"), false);
  assert.equal(storedOwnerIsCreatingOwner("", product), false);
});

test("create refusals keep their status and reason", () => {
  assert.equal(refusalIncludes(409, "agent request is invalid: unknown field", 409, "agent request is invalid"), true);
  assert.equal(refusalIncludes(200, "agent request is invalid", 409, "agent request is invalid"), false);
  assert.equal(refusalIncludes(403, "admin passkey required", 403, "admin passkey required"), true);
  assert.equal(refusalIncludes(403, "missing home launch token", 403, "missing home launch token"), true);
  assert.equal(
    refusalIncludes(403, "Gateway request requires an admitted host and caller", 403, "Gateway request requires an admitted host and caller"),
    true,
  );
  assert.equal(refusalIncludes(409, "agents are not turned on for this Home", 409, "agents are not turned on"), true);
});

test("create route replaced a caller-chosen mint", () => {
  const agents = fs.readFileSync(new URL("../elastos/crates/elastos-server/src/agents.rs", import.meta.url), "utf8");
  const route = fs.readFileSync(new URL("../elastos/crates/elastos-server/src/api/gateway.rs", import.meta.url), "utf8");
  const replacement = createReplacesMint(agents, route);
  assert.equal(replacement.ok, true);
  assert.deepEqual(replacement.fields, ["display_name", "agent_host", "request_id"]);
  assert.equal(replacement.route, "POST /api/apps/system/agents/create");
  assert.equal(replacement.id_source, "auth::fresh_agent_id");
  const accepted = agents.replace(
    "pub(crate) request_id: String,\n}",
    "pub(crate) request_id: String,\n    pub(crate) owner: String,\n}",
  );
  assert.equal(createReplacesMint(accepted, route).ok, false);
});

test("home asks counts the page posts and refuses a hidden create", () => {
  const frame = "page-launch-token";
  const runner = "runner-enrollment-token";
  const post = (path) => ({ path, token: frame, fromPage: true });
  const posts = [
    post("/api/apps/system/agents/enable"),
    post("/api/apps/system/agents/create"),
    post("/api/apps/system/agents/create"),
    post("/api/apps/system/agents/activate"),
  ];
  assert.equal(judgeHomeAsks(posts, [frame], runner).ok, true);
  const hidden = posts.filter((item) => item.path !== "/api/apps/system/agents/create");
  assert.equal(judgeHomeAsks(hidden, [frame], runner).ok, false);
  assert.equal(judgeHomeAsks(posts, [runner], runner).ok, false);
  assert.equal(judgeHomeAsks(posts.map((item) => ({ ...item, fromPage: false })), [frame], runner).ok, false);
  assert.equal(judgeHomeAsks(posts, ["other-token"], runner).ok, false);
});

test("a page launch token is the hash, and two v2 ids are not a name hash", () => {
  assert.equal(pageLaunchToken("https://home.example/apps/system/#home_token=abc"), "abc");
  assert.equal(pageLaunchToken("https://home.example/apps/system/"), "");
  assert.equal(agentIdV2("agent:v2:" + "ab".repeat(16)), true);
  assert.equal(agentIdV2("agent:v1:" + "ab".repeat(16)), false);
  assert.equal(agentIdV2("agent:v2:" + "ab".repeat(15)), false);
});

test("restart log shows the binary banner only after shutdown", () => {
  const banner = "ElastOS Gateway v2.0.1-dev";
  const log = [
    "[gateway] ElastOS 2.0.1-dev starting on 127.0.0.1:9",
    banner,
    "Shutting down gateway...",
    "[gateway] ElastOS 2.0.1-dev starting on 127.0.0.1:9",
    banner,
  ].join("\n");
  const loaded = gatewayRestartLoadedChain(log);
  assert.equal(loaded.ok, true, loaded.reason);
  assert.equal(loaded.log_line, banner);
  assert.equal(loaded.command, "elastos gateway --addr");
  assert.equal(gatewayRestartLoadedChain("Shutting down gateway...\naudit chain rollback detected").ok, false);
  assert.equal(gatewayRestartLoadedChain(banner).ok, false);
});

test("mint grep at head has no production hit", () => {
  const source = [
    "fn fresh() { let id = agent_v2(); }",
    "#[cfg(test)]",
    "mod tests {",
    "    fn keeps_agent_v1() { let _id = \"agent:v1:abc\"; }",
    "}",
  ].join("\n");
  assert.equal(lineIsTestOnly(source, 1), false);
  assert.equal(lineIsTestOnly(source, 4), true);
  const hits = parseGitGrep([
    "HEAD:elastos/crates/elastos-server/src/auth.rs:4:\"agent:v1:abc\"",
    "HEAD:elastos/crates/elastos-server/src/agents.rs:1:mint_agent_principal()",
  ].join("\n"));
  assert.equal(hits.length, 2);
  assert.equal(classifyMintHit(hits[0], source), true);
  assert.equal(classifyMintHit(hits[1], source), false);
  assert.equal(mintHitKind({ path: "scripts/a15r-installed-journey.mjs", line: 1 }, source), "checker");
  const live = mintHitsFromRepo(fileURLToPath(new URL("..", import.meta.url)));
  assert.equal(live.ok, true, JSON.stringify(live.production));
  assert.equal(live.production.length, 0);
  assert.equal(live.defined, false);
  assert.ok(live.testOnly.length >= 2);
  assert.ok(live.testOnly.every((hit) => hit.path.startsWith("elastos/") || hit.path.startsWith("capsules/")));
  assert.ok(live.testOnly.every((hit) => hit.path.endsWith(".rs") || hit.path.endsWith(".mjs")));
  assert.equal(live.checker.length, 0);
});

test("restart list is both Helper rows, first on and second off", () => {
  const first = "agent:v2:" + "a".repeat(32);
  const second = "agent:v2:" + "b".repeat(32);
  const expected = [
    { id: first, name: "Helper", active: true },
    { id: second, name: "Helper", active: false },
  ];
  const body = {
    agents: [
      { agent_id: second, display_name: "Helper", active: false },
      { agent_id: first, display_name: "Helper", active: true },
    ],
  };
  assert.equal(listedAgentsMatch(body, expected).ok, true);
  assert.equal(listedAgentsMatch({ agents: [] }, expected).ok, false);
  assert.equal(listedAgentsMatch({
    agents: [{ agent_id: first, display_name: "Helper", active: false }],
  }, expected).ok, false);
  assert.equal(listedAgentsMatch({
    agents: [
      { agent_id: first, display_name: "Other", active: true },
      { agent_id: second, display_name: "Helper", active: false },
    ],
  }, expected).ok, false);
  assert.equal(listedAgentsMatch({
    agents: [
      { agent_id: first, display_name: "Helper", active: false },
      { agent_id: second, display_name: "Helper", active: true },
    ],
  }, expected).ok, false);
});

test("no guest proof fails closed when serve cannot be listed", () => {
  assert.equal(noGuestProof({ stray: [], serveKnown: true, serveRunning: false }).ok, true);
  assert.equal(noGuestProof({
    stray: [],
    serveKnown: true,
    serveRunning: true,
    capsulesListed: true,
    guestCapsules: 0,
  }).ok, true);
  const hidden = noGuestProof({
    stray: [],
    serveKnown: true,
    serveRunning: true,
    capsulesListed: false,
    guestCapsules: 0,
  });
  assert.equal(hidden.ok, false);
  assert.match(hidden.reason, /cannot be listed/);
  assert.equal(noGuestProof({
    stray: ["capsule"],
    serveKnown: true,
    serveRunning: false,
  }).ok, false);
  assert.equal(noGuestProof({ serveKnown: false, stray: [] }).ok, false);
});

test("a skipped owner check is not a pass", () => {
  const owner = "person:local:abc";
  assert.equal(judgeCreatingOwner({
    checkRan: true,
    storedOwner: owner,
    productOwner: owner,
    fileOwner: owner,
  }).ok, true);
  const skipped = judgeCreatingOwner({
    checkRan: false,
    storedOwner: owner,
    productOwner: owner,
    fileOwner: owner,
  });
  assert.equal(skipped.ok, false);
  assert.equal(skipped.reason, "owner check skipped");
  assert.equal(judgeCreatingOwner({
    checkRan: true,
    storedOwner: "person:spoof",
    productOwner: owner,
    fileOwner: owner,
  }).ok, false);
});

test("full mode notice names the missing agents-in-gateway change", () => {
  assert.match(FULL_MODE_NOTICE, /not proof of anything until/);
  const refused = agentsInGatewayChange(
    'route("/api/apps/system/agents/launch", post(agents_launch))',
    "async fn agents_launch() { launch_runtime_agent(&state.data_dir).await?; }",
  );
  assert.equal(refused.ok, false);
  assert.equal(refused.route, "/api/apps/system/agents/launch");
  assert.match(refused.reason, /asks the runtime/);
  const unregistered = agentsInGatewayChange(
    'route("/api/apps/system/agents/stop", post(agents_stop))',
    "async fn agents_launch() { start_in_gateway(); }",
  );
  assert.equal(unregistered.ok, false);
  assert.match(unregistered.reason, /not registered/);
  const ready = agentsInGatewayChange(
    'route("/api/apps/system/agents/launch", post(agents_launch))',
    "async fn start_agent() { start_in_gateway(); }",
  );
  assert.equal(ready.ok, true);
});

test("playwright pin is the version in test-behaviour.sh", () => {
  const text = fs.readFileSync(new URL("./test-behaviour.sh", import.meta.url), "utf8");
  const pin = playwrightPin(text);
  assert.equal(pin.ok, true);
  // The version is read from the script, not pinned here. Both pin lines in
  // the script must name the same version.
  const installed = [...text.matchAll(/installed\s+"?\$?browser"?\s+playwright\s+(\d+\.\d+\.\d+)/g)].map((m) => m[1]);
  const installs = [...text.matchAll(/playwright@(\d+\.\d+\.\d+)/g)].map((m) => m[1]);
  assert.ok(installed.length > 0 && installs.length > 0);
  assert.equal(pin.version, installed[0]);
  assert.equal(pin.version, installs[0]);
  assert.deepEqual([...new Set(installed)], [pin.version]);
  // Behaviour comes from fixture text, never from the live tree state.
  const fixture = playwrightPin('installed "$browser" playwright 7.8.9\nplaywright@7.8.9\n');
  assert.equal(fixture.ok, true);
  assert.equal(fixture.version, "7.8.9");
  assert.equal(playwrightPin("installed \"$browser\" playwright 1.0.0\nplaywright@1.2.0\n").ok, false);
});

test("home env drops inherited ELASTOS variables", () => {
  const env = homeProcessEnv("/tmp/home", {
    PATH: "/bin",
    HOME: "/Users/someone",
    ELASTOS_CARRIER_NETWORK: "public",
    ELASTOS_QUIET_RUNTIME_NOTICES: "0",
    SECRET: "no",
  });
  assert.equal(env.HOME, "/tmp/home");
  assert.equal(env.PATH, "/bin");
  assert.equal(env.ELASTOS_QUIET_RUNTIME_NOTICES, "1");
  assert.equal(env.ELASTOS_CARRIER_NETWORK, undefined);
  assert.equal(env.SECRET, undefined);
});

test("a serve command is read after the Home path, spaces included", () => {
  const bin = "/tmp/Library/Application Support/elastos/bin/elastos";
  const copy = "/var/folders/xx/T/executable";
  assert.equal(elastosSubcommand(`${bin} serve --addr 127.0.0.1:9`, bin), "serve");
  assert.equal(elastosSubcommand(`${bin} gateway --addr 127.0.0.1:9`, [bin]), "gateway");
  assert.equal(elastosSubcommand(`${copy} serve --addr 127.0.0.1:9`, copy), "serve");
  assert.equal(elastosSubcommand(`${bin} serve --addr 127.0.0.1:9`, copy), "");
});

test("carrier config is a free loopback port and 4433 is a bind", () => {
  assert.equal(carrierConfigOk('carrier_bind_addr = "127.0.0.1:0"\n'), true);
  assert.equal(carrierConfigOk('carrier_bind_addr = "0.0.0.0:4433"\n'), false);
  assert.equal(bindsPort(["127.0.0.1:54000->9.9.9.9:4433"], 4433), false);
  assert.equal(bindsPort(["*:4433"], 4433), true);
  assert.equal(bindsPort(["127.0.0.1:44330"], 4433), false);
});

test("redaction removes the DID and the address", () => {
  const did = "did:key:z6Mk" + "1".repeat(44);
  const text = redactDidAndAddress(`carrier ${did} on 127.0.0.1:4433 and [::1]:9`);
  assert.equal(text.includes(did), false);
  assert.equal(text.includes("127.0.0.1"), false);
  assert.equal(text.includes("[::1]"), false);
  const install = redactInstall({ signer_did: did, runtime_sha256: "ab", note: `see ${did}` });
  assert.equal(install.signer_did, "redacted");
  assert.equal(JSON.stringify(install).includes("did:key:z6Mk"), false);
  assert.equal(install.runtime_sha256, "ab");
});

test("a pid is killed only inside the throwaway home", () => {
  assert.equal(executableInsideHome("/tmp/a15r/run/bin/elastos", "/tmp/a15r/run"), true);
  assert.equal(executableInsideHome("/usr/bin/elastos", "/tmp/a15r/run"), false);
  assert.equal(executableInsideHome("/tmp/a15r/run-extra/bin/elastos", "/tmp/a15r/run"), false);
});

test("throwaway removal stays inside its scratch directory", () => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "a15r-scratch-"));
  const home = path.join(scratch, "run-1");
  fs.mkdirSync(home);
  assert.equal(throwawayAllowed(home, scratch), false);
  fs.writeFileSync(path.join(home, ".a15r-throwaway"), `${home}\n`);
  assert.equal(throwawayAllowed(home, scratch), true);
  assert.equal(throwawayAllowed(scratch, scratch), false);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "a15r-outside-"));
  fs.writeFileSync(path.join(outside, ".a15r-throwaway"), `${outside}\n`);
  assert.equal(throwawayAllowed(outside, scratch), false);
  fs.rmSync(scratch, { recursive: true });
  fs.rmSync(outside, { recursive: true });
});

test("an old receipt is removed before a new run writes one", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a15r-receipt-"));
  fs.writeFileSync(path.join(dir, "receipt.json"), "{}\n");
  assert.equal(removeStaleReceipt(dir), true);
  assert.equal(fs.existsSync(path.join(dir, "receipt.json")), false);
  fs.rmSync(dir, { recursive: true });
});

test("installed page folders hash to the committed trees", () => {
  const repo = fileURLToPath(new URL("..", import.meta.url));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "a15r-pages-"));
  const data = path.join(dir, "data");
  fs.mkdirSync(path.join(data, "capsules"), { recursive: true });
  for (const folder of ["home", "system", "inbox", "home-gui"]) {
    const dest = path.join(data, "capsules", folder);
    fs.mkdirSync(dest);
    const archived = spawnSync("git", ["archive", "--format=tar", `HEAD:capsules/${folder}`], {
      cwd: repo,
      maxBuffer: 32 * 1024 * 1024,
    });
    assert.equal(archived.status, 0, archived.stderr?.toString());
    const extracted = spawnSync("tar", ["-x", "-C", dest], { input: archived.stdout });
    assert.equal(extracted.status, 0);
  }
  const proof = pageFolderProof(repo, data);
  assert.equal(proof.ok, true, JSON.stringify(proof.pages));
  const mutated = path.join(data, "capsules", "home", "a15r-plant.txt");
  fs.writeFileSync(mutated, "plant\n");
  assert.notEqual(gitTreeHash(path.join(data, "capsules", "home")), proof.pages.home.committed);
  fs.rmSync(dir, { recursive: true });
});

test("audit bytes match the signed fixture chain", () => {
  const fixture = JSON.parse(fs.readFileSync(
    new URL("../elastos/crates/elastos-server/fixtures/auth-state-populated.json", import.meta.url),
    "utf8",
  ));
  const event = fixture.audit[0];
  const link = fixture.audit_chain[0];
  const eventHash = `sha256:${crypto.createHash("sha256").update(auditEventBytes(event, false)).digest("hex")}`;
  assert.equal(eventHash, link.event_hash);
  assert.equal(auditChainHash(link.sequence, link.event_id, link.previous_hash, eventHash), link.chain_hash);
  const verified = verifyInstalledAudit(fixture, event.signer_did);
  assert.equal(verified.ok, true, verified.reason);
  const tampered = structuredClone(fixture);
  tampered.audit[0].signature = `${"ab".repeat(63)}cd`;
  assert.equal(verifyInstalledAudit(tampered, event.signer_did).ok, false);
});

function shFunction(source, name) {
  const match = source.match(new RegExp(`(?:^|\\n)${name}\\(\\) \\{\\n[\\s\\S]*?\\n\\}(?=\\n|$)`));
  assert.ok(match, `${name}() found in the runner script`);
  return match[0].replace(/^\n/, "");
}

test("cleanup stops and removes only the home this run created", () => {
  const sh = fs.readFileSync(new URL("./a15r-installed-journey.sh", import.meta.url), "utf8");
  const cleanup = shFunction(sh, "cleanup");
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "a15r-cleanup-"));
  const scratch = path.join(work, "scratch");
  const home = path.join(scratch, "run-1");
  const out = path.join(work, "out");
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(out, { recursive: true });
  const calls = path.join(work, "calls.log");
  const harness = [
    cleanup,
    'node_proof() { printf \'%s\\n\' "$*" >> "$CALLS"; }',
    `OUT=${JSON.stringify(out)}`,
    `HOME_ROOT=${JSON.stringify(home)}`,
    `SCRATCH=${JSON.stringify(scratch)}`,
    `DATA=${JSON.stringify(path.join(home, "Library", "Application Support", "elastos"))}`,
    `CALLS=${JSON.stringify(calls)}`,
  ].join("\n");
  // Without this run's marker the trap must stop and remove nothing.
  const idle = spawnSync("bash", ["-c", `${harness}\ncleanup`], { encoding: "utf8" });
  assert.equal(idle.status, 0, idle.stderr);
  assert.equal(fs.existsSync(calls), false);
  assert.equal(fs.existsSync(home), true);
  // With CREATED=1 the trap stops the serve, scrubs evidence and removes the throwaway.
  fs.writeFileSync(path.join(home, ".a15r-throwaway"), `${fs.realpathSync(home)}\n`);
  const active = spawnSync("bash", ["-c", `${harness}\nCREATED=1\ncleanup`], { encoding: "utf8" });
  assert.equal(active.status, 0, active.stderr);
  assert.deepEqual(fs.readFileSync(calls, "utf8").trim().split("\n"), [
    "--stop-home", "--scrub-evidence", "--remove-throwaway",
  ]);
  fs.rmSync(work, { recursive: true });
});

test("stopping the serve requires the throwaway marker", () => {
  const journeyPath = fileURLToPath(new URL("./a15r-installed-journey.mjs", import.meta.url));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "a15r-stop-"));
  const scratch = path.join(work, "scratch");
  const home = path.join(scratch, "run-1");
  const out = path.join(work, "out");
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(out, { recursive: true });
  const binDir = path.join(work, "bin");
  fs.mkdirSync(binDir);
  const env = {
    PATH: binDir,
    A15R_OUT: out,
    A15R_HOME: home,
    A15R_SCRATCH: scratch,
    A15R_DATA: path.join(home, "Library", "Application Support", "elastos"),
  };
  const stopped = (extra) => spawnSync(process.execPath, [journeyPath, "--stop-home"], {
    env: { ...env, ...extra },
    encoding: "utf8",
  });
  // No marker: the serve must not be touched.
  const refused = stopped({});
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /refusing to stop a Home/);
  // This run's marked throwaway home passes the same marker check as the removal.
  fs.writeFileSync(path.join(home, ".a15r-throwaway"), `${fs.realpathSync(home)}\n`);
  const allowed = stopped({});
  // With the marker the gate opens: the run either stops nothing (no listed
  // serve processes) or fails at the serve listing, never at the marker check.
  assert.ok(allowed.status === 0 || /cannot list executables/.test(allowed.stderr), allowed.stderr);
  assert.doesNotMatch(allowed.stderr, /refusing to stop/);
  fs.rmSync(work, { recursive: true });
});

test("the runner refuses a dot or dot-dot output basename", () => {
  const sh = fs.readFileSync(new URL("./a15r-installed-journey.sh", import.meta.url), "utf8");
  const dotBase = shFunction(sh, "dot_base");
  const judge = (value) => spawnSync("bash", [
    "-c", `${dotBase}\nif dot_base "$1"; then echo refused; else echo ok; fi`, "bash", value,
  ], { encoding: "utf8" }).stdout.trim();
  assert.equal(judge("."), "refused");
  assert.equal(judge(".."), "refused");
  assert.equal(judge("run-1"), "ok");
  assert.equal(judge("a/b/run-1"), "ok");
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "a15r-basename-"));
  for (const bad of [".", "..", "sub/.."]) {
    const result = spawnSync("bash", [
      fileURLToPath(new URL("./a15r-installed-journey.sh", import.meta.url)), bad,
    ], { cwd, encoding: "utf8" });
    assert.equal(result.status, 2, bad);
    assert.match(result.stderr, /must not be \. or \.\./);
  }
  assert.deepEqual(fs.readdirSync(cwd), []);
  fs.rmSync(cwd, { recursive: true });
});
