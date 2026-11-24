import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  OWNER_DOCUMENT,
  OWNER_NOTE,
  U4_ISOLATION_NOT_COVERED,
  agentStartRequestSha256,
  agentStartStepUps,
  carriedAgentId,
  createdAgentOwnedBy,
  LIVE_SESSION_COORDS,
  gatewayHealthOk,
  journalFileInRoot,
  ownerDocumentUnchanged,
  ownerNoteRelative,
  runtimeHealthOk,
  shellFailStatuses,
  signedAgentStarts,
  signedStartAudit,
  userAreaRouteRefused,
} from "./a15r-installed-journey.mjs";

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
  assert.ok(U4_ISOLATION_NOT_COVERED.some((line) => line.includes("elastos/crates/elastos-server/src/api/routes.rs:4825")));
  assert.ok(U4_ISOLATION_NOT_COVERED.some((line) => line.includes("elastos/crates/elastos-server/src/api/routes.rs:4884")));
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
