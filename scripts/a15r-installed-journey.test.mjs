import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  OWNER_DOCUMENT,
  agentStartRequestSha256,
  createdAgentOwnedBy,
  crossReadRefused,
  gatewayHealthOk,
  journalFileInRoot,
  ownerDocumentUnchanged,
  runtimeHealthOk,
  shellFailStatuses,
  signedAgentStarts,
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

test("signed start names both agent starts", () => {
  const digest = agentStartRequestSha256(agentA);
  assert.equal(digest, crypto.createHash("sha256").update(`{"agent_id":"${agentA}"}`).digest("hex"));
  const dispatchOnly = [{
    event_type: "agent_plan.dispatch.started",
    signature: "signed",
    reason: "claimed by Runtime",
  }];
  assert.equal(signedAgentStarts(dispatchOnly, [agentA, agentB]).ok, false);
  assert.equal(signedAgentStarts([startEvent(agentA, "")], [agentA]).ok, false);
  assert.equal(signedAgentStarts([startEvent(agentA)], [agentA, agentB]).ok, false);
  const both = signedAgentStarts([
    startEvent("agent:v2:" + "f".repeat(32)),
    startEvent(agentA),
    startEvent(agentB),
  ], [agentA, agentB]);
  assert.equal(both.ok, true);
  assert.deepEqual(both.matched.sort(), [agentA, agentB].sort());
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

test("owner document compares the seeded bytes", () => {
  assert.equal(ownerDocumentUnchanged(OWNER_DOCUMENT, Buffer.from(OWNER_DOCUMENT)), true);
  assert.equal(ownerDocumentUnchanged(OWNER_DOCUMENT, Buffer.from("three lines")), false);
  assert.equal(ownerDocumentUnchanged(null, null), false);
  assert.equal(ownerDocumentUnchanged(Buffer.alloc(0), Buffer.alloc(0)), false);
  assert.equal(ownerDocumentUnchanged(OWNER_DOCUMENT, null), false);
});

test("cross read passes only after a refused attempt", () => {
  const marker = "secret-marker";
  const refused = {
    called: true,
    session: "session-a",
    root: rootB,
    resource: `${rootB}/Documents/cross-read.txt`,
    status: 403,
    body: "Capsules cannot access a localhost user area root",
    marker,
  };
  assert.equal(crossReadRefused(refused), true);
  assert.equal(crossReadRefused({ ...refused, called: false }), false);
  assert.equal(crossReadRefused({ ...refused, session: "" }), false);
  assert.equal(crossReadRefused({ ...refused, status: 200, body: marker }), false);
  assert.equal(crossReadRefused({ ...refused, body: `refused ${marker}` }), false);
  assert.equal(crossReadRefused({ ...refused, status: 404 }), false);
  assert.equal(crossReadRefused({
    grants: [`${rootA}/journal`, `${rootB}/journal`],
  }), false);
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
    "u4_distinct_roots", "u4_no_cross_read", "journal_in_agent_root",
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
