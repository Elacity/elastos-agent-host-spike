import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
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
  rootsStayWithTheirAgent,
  coordsCurrent,
  ownerStopDenial,
  planeSameProcess,
  processElapsedMs,
  restartHistory,
  journalFileInRoot,
  ownerDocumentUnchanged,
  ownerNoteRelative,
  refusalIncludes,
  runtimeHealthOk,
  names,
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
  gatewayOwnsListener,
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

test("a plane is the gateway process and its coordinates stay owner-only", () => {
  assert.equal(planeSameProcess(4, 4, true, true, 0o600, true), true);
  assert.equal(planeSameProcess(4, 5, true, true, 0o600, true), false);
  assert.equal(planeSameProcess(4, 4, true, false, 0o600, true), false);
  assert.equal(planeSameProcess(4, 4, true, true, 0o644, true), false);
  assert.equal(planeSameProcess(4, 4, true, true, 0o600, false), false);
  assert.equal(coordsCurrent(12_000, 10_000), true);
  assert.equal(coordsCurrent(1_000, 10_000), false);
  assert.equal(processElapsedMs("01:02"), 62_000);
  assert.equal(processElapsedMs("01:02:03"), 3_723_000);
  assert.equal(processElapsedMs("1-01:02:03"), 90_123_000);
  assert.equal(processElapsedMs("stale"), null);
});

test("an owner denial names the targeted agent after the attempt", () => {
  const row = {
    event_type: "agent.stop.denied",
    result: "denied",
    signature: "ab",
    occurred_at: 50,
    reason: JSON.stringify({ agent_id: "agent:v2:aa", cause: "not the owner" }),
  };
  assert.equal(ownerStopDenial([row], "agent:v2:aa", 50), true);
  assert.equal(ownerStopDenial([row], "agent:v2:bb", 50), false);
  assert.equal(ownerStopDenial([row], "agent:v2:aa", 51), false);
  assert.equal(ownerStopDenial([{ ...row, signature: "" }], "agent:v2:aa", 50), false);
  assert.equal(ownerStopDenial([{ ...row, occurred_at: 10 }], "agent:v2:aa", 50), false);
});

test("the restart row needs a held pending step of a live run, closed once by the restart", () => {
  const requested = { event_type: "agent.start.requested", result: "ok", session_id: "" };
  const closed = { event_type: "agent.plan.closed", result: "instance ended", challenge_id: "r2" };
  const pending = { request_id: "r2", status: "pending" };
  const ended = { request_id: "r2", status: "instance ended" };
  const before = { chain: [requested], records: [pending] };
  assert.equal(restartHistory(before, { chain: [requested, closed], records: [ended] }, "r2", "s1").closed, true);
  assert.equal(restartHistory(
    { chain: [requested], records: [{ request_id: "r1", status: "completed" }] },
    { chain: [requested], records: [{ request_id: "r1", status: "completed" }] },
    "",
    "",
  ).closed, false, "nothing held is not a restart proof");
  const stopped = { event_type: "agent.stopped", result: "ok", session_id: "s1" };
  const early = restartHistory({ chain: [stopped], records: [pending] }, { chain: [stopped, closed], records: [ended] }, "r2", "s1");
  assert.equal(early.step.open, false, "a run stopped before the restart was not held");
  const twice = restartHistory(before, { chain: [closed, closed], records: [ended] }, "r2", "s1");
  assert.equal(twice.step.closed, false, "two close rows are not one");
  const approved = restartHistory({ chain: [requested], records: [{ request_id: "r2", status: "approved" }] }, { chain: [closed], records: [ended] }, "r2", "s1");
  assert.equal(approved.step.open, false, "only a pending step is held");
  const denied = restartHistory(before, { chain: [{ ...closed, result: "denied" }], records: [{ request_id: "r2", status: "denied" }] }, "r2", "s1");
  assert.equal(denied.step.closed, false, "the restart closes the step as instance ended");
  const unsigned = restartHistory(before, { chain: [requested], records: [ended] }, "r2", "s1");
  assert.equal(unsigned.step.closed, false, "the closed step has its signed row");
});

test("each root stays in its own grant, including the planted cross-read", () => {
  const grants = [
    { status: 200, resource: `${rootA}/journal` },
    { status: 200, resource: `${rootB}/journal` },
  ];
  const plants = {
    own: { resource: `${rootA}/Documents/own-marker.txt`, status: 403, body: "refused" },
    other: { resource: `${rootB}/Documents/cross-read.txt`, status: 403, body: "refused" },
  };
  assert.equal(rootsStayWithTheirAgent(rootA, rootB, grants, plants), true);
  assert.equal(rootsStayWithTheirAgent(rootA, rootB, grants, {
    own: plants.own,
    other: { resource: `${rootB}/Documents/cross-read.txt`, status: 404, body: "missing" },
  }), false);
  assert.equal(rootsStayWithTheirAgent(rootA, rootB, [
    { status: 200, resource: `${rootA}/${rootB}` },
  ], plants), false);
  assert.equal(rootsStayWithTheirAgent(rootA, rootB, grants, {
    own: plants.own,
    other: { resource: `${rootB}/Documents/cross-read.txt`, status: 200 },
  }), false);
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
    runtime: LIVE_SESSION_COORDS,
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
  assert.equal(userAreaRouteRefused({
    own: { ...pair.own, status: 404, body: "" },
    other: { ...pair.other, status: 404, body: "" },
  }), false);
  assert.equal(userAreaRouteRefused({
    own: { ...pair.own, status: 403, body: "" },
    other: pair.other,
  }), false);
  assert.equal(userAreaRouteRefused({
    own: { ...pair.own, runtime: "home-runtime-coords.json" },
    other: pair.other,
  }), false);
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
  const byName = (statusList, name) => statusList[names.indexOf(name)];
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

test("full mode notice names the missing agents-in-gateway route", () => {
  assert.match(FULL_MODE_NOTICE, /not proof of anything until/);
  const read = (rel) => fs.readFileSync(new URL(`../elastos/crates/elastos-server/src/api/${rel}`, import.meta.url), "utf8");
  const gateway = `${read("gateway.rs")}\n${read("gateway_inbox.rs")}`;
  const launch = read("gateway_agents.rs");
  const homeRuntime = read("gateway_home_runtime.rs");
  const detected = agentsInGatewayChange(gateway, launch, homeRuntime);
  assert.equal(detected.ok, true, detected.reason);
  assert.equal(detected.route, "/api/apps/system/agents/launch");
  const child = agentsInGatewayChange(
    'route("/api/apps/system/agents/launch", post(agents_launch))',
    "launch_runtime_agent();",
    "async fn launch_runtime_agent",
  );
  assert.equal(child.ok, false);
  const ready = agentsInGatewayChange(
    'route("/api/apps/system/agents/launch", post(agents_launch))\ndispatch_approved_agent_plan()',
    "agent_plane::ensure_running(); launch_runtime_agent();",
    "agent_plane::live_coords(data)\nasync fn launch_runtime_agent() {}",
  );
  assert.equal(ready.ok, false);
  assert.match(ready.reason, /empty/);
  const filled = agentsInGatewayChange(
    'route("/api/apps/system/agents/launch", post(agents_launch))\ndispatch_approved_agent_plan()',
    "agent_plane::ensure_running(); launch_runtime_agent();",
    "async fn launch_runtime_agent() {\n  agent_plane::live_coords(data);\n  return;\n}",
  );
  assert.equal(filled.ok, true, filled.reason);
  const outside = agentsInGatewayChange(
    'route("/api/apps/system/agents/launch", post(agents_launch))\ndispatch_approved_agent_plan()',
    "agent_plane::ensure_running(); launch_runtime_agent();",
    "agent_plane::live_coords(data)\nasync fn launch_runtime_agent() {\n  return;\n}",
  );
  assert.equal(outside.ok, false);
  assert.match(outside.reason, /live coordinates/);
  const followed = agentsInGatewayChange(
    'route("/api/apps/system/agents/launch", post(agents_launch))\ndispatch_approved_agent_plan()',
    "agent_plane::ensure_running(); launch_runtime_agent();",
    "async fn live_agent_coords() {\n  agent_plane::live_coords(data);\n}\nasync fn launch_runtime_agent() {\n  live_agent_coords();\n}",
  );
  assert.equal(followed.ok, true, followed.reason);
  const noHop = agentsInGatewayChange(
    'route("/api/apps/system/agents/launch", post(agents_launch))',
    "agent_plane::ensure_running(); launch_runtime_agent();",
    "fn something_else() {}",
  );
  assert.equal(noHop.ok, false);
  const commented = agentsInGatewayChange(
    '// route("/api/apps/system/agents/launch", post(agents_launch))\n// dispatch_approved_agent_plan()',
    "// agent_plane::ensure_running(); launch_runtime_agent();",
    "// agent_plane::live_coords(data)\n// async fn launch_runtime_agent() { return; }",
  );
  assert.equal(commented.ok, false);
  const sentence = "Nothing ran. A fresh passkey is needed.";
  const blocked = /\b(runtime mirror|projection|schema|derived facts?|capsules?|providers?|capabilit(?:y|ies)|affordances?|authority boundary|provider boundary|gate preview|runtime-owned|launch token|hostcall|request failed|failed to fetch|unauthorized|forbidden|[45]\d\d)\b|engine_[a-z_]+/i;
  assert.equal(blocked.test(sentence), false);
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/inbox.js", import.meta.url), "utf8");
  assert.match(inbox, /text\.startsWith\("Nothing ran\."\)/);
});

test("the gateway pid owns the listening port", async () => {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  assert.equal(gatewayOwnsListener(process.pid, port), true);
  assert.equal(gatewayOwnsListener(1, port), false);
  assert.equal(gatewayOwnsListener(process.pid, 0), false);
  await new Promise((resolve) => server.close(resolve));
});

test("playwright pin is the version in test-behaviour.sh", () => {
  const text = fs.readFileSync(new URL("./test-behaviour.sh", import.meta.url), "utf8");
  const pin = playwrightPin(text);
  assert.equal(pin.ok, true);
  assert.equal(pin.version, "1.60.0");
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
