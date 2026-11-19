import assert from "node:assert/strict";
import test from "node:test";

import { bindAgents } from "../capsules/system/browser/agents-section.js";

const NAMED = "owner_sees_on_only_after_the_activate_route";
const OFF = "Off until you turn it on";
const REASON = "owner already has the most agents a Home allows";
const AGENT_ID = "agent:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

function element(tag) {
  return {
    tag,
    id: "",
    className: "",
    textContent: "",
    hidden: false,
    disabled: false,
    type: "",
    value: "",
    dataset: {},
    children: [],
    handlers: {},
    append(...kids) {
      this.children.push(...kids);
    },
    replaceChildren(...kids) {
      this.children = kids;
    },
    addEventListener(type, fn) {
      (this.handlers[type] ||= []).push(fn);
    },
    click() {
      for (const fn of this.handlers.click || []) fn();
    },
  };
}

function matches(node, selector) {
  if (!node || typeof node !== "object") return false;
  if (selector.startsWith("#")) return node.id === selector.slice(1);
  const attr = selector.match(/^\[data-agent-state="(.*)"\]$/);
  return Boolean(attr && node.dataset && node.dataset.agentState === attr[1]);
}

function query(node, selector) {
  if (matches(node, selector)) return node;
  for (const child of node.children || []) {
    const found = query(child, selector);
    if (found) return found;
  }
  return null;
}

function findButton(node, label) {
  if (node.tag === "button" && node.textContent === label) return node;
  for (const child of node.children || []) {
    const found = findButton(child, label);
    if (found) return found;
  }
  return null;
}

function mount(request) {
  const nodes = {
    "#agents-list": element("div"),
    "#agents-status": element("p"),
    "#agent-name": element("input"),
    "#agent-host": Object.assign(element("input"), { value: "agent-host" }),
    "#agent-create": element("button"),
    "#agent-retry": Object.assign(element("button"), { hidden: true }),
  };
  for (const [id, node] of Object.entries(nodes)) node.id = id.slice(1);
  const doc = {
    defaultView: { crypto: { randomUUID: () => "11111111-1111-4111-8111-111111111111" } },
    createElement: element,
    querySelector: (selector) => nodes[selector] || query({ children: Object.values(nodes) }, selector),
  };
  bindAgents(doc, request);
  return {
    status: nodes["#agents-status"],
    name: nodes["#agent-name"],
    host: nodes["#agent-host"],
    create: nodes["#agent-create"],
    retry: nodes["#agent-retry"],
    list: nodes["#agents-list"],
    state(id) {
      return doc.querySelector(`[data-agent-state="${id}"]`)?.textContent ?? "";
    },
    button(label) {
      return findButton(nodes["#agents-list"], label);
    },
  };
}

test("create shows Off, turn on shows On, and On follows the activate route", async () => {
  const agent = { agent_id: AGENT_ID, display_name: "Helper", active: false };
  const createGate = deferred();
  const listOff = deferred();
  const activateGate = deferred();
  const listOn = deferred();
  const calls = [];
  const ui = mount((path, init = {}) => {
    const call = {
      path,
      method: init.method || "GET",
      body: init.body ? JSON.parse(init.body) : null,
    };
    calls.push(call);
    if (path.endsWith("/create")) return createGate.promise;
    if (path.endsWith("/activate")) return activateGate.promise;
    const lists = calls.filter((item) => item.method === "GET");
    return lists.length === 1 ? listOff.promise : listOn.promise;
  });
  ui.name.value = "Helper";
  ui.create.click();
  await flush();
  assert.equal(ui.status.textContent, "Creating");
  assert.equal(calls[0].path, "/api/apps/system/agents/create");
  assert.deepEqual(calls[0].body, {
    display_name: "Helper",
    agent_host: "agent-host",
    request_id: "11111111-1111-4111-8111-111111111111",
  });
  createGate.resolve(agent);
  await flush();
  listOff.resolve({ agents: [agent] });
  await flush();
  assert.equal(ui.state(AGENT_ID), OFF);
  assert.equal(calls.some((call) => call.path.endsWith("/activate")), false);

  ui.button("Turn on").click();
  await flush();
  const activate = () => calls.filter((call) => call.path.endsWith("/activate"));
  if (activate().length === 1 && ui.state(AGENT_ID) === "Turning on") {
    activateGate.resolve({ ...agent, active: true });
    await flush();
    listOn.resolve({ agents: [{ ...agent, active: true }] });
    await flush();
  }
  assert.equal(ui.state(AGENT_ID), "On", NAMED);
  assert.equal(activate().length, 1, NAMED);
  assert.equal(activate()[0]?.body.active, true, NAMED);
});

test("a refused create shows the server reason and retry sends the same request", async () => {
  const gates = [];
  let accepted = null;
  const ui = mount((path, init = {}) => {
    if (path.endsWith("/agents") && !(init.method === "POST")) {
      return Promise.resolve({ agents: accepted ? [accepted] : [] });
    }
    if (!path.endsWith("/create")) throw new Error(`unexpected ${path}`);
    const gate = deferred();
    gates.push({ body: JSON.parse(init.body), gate });
    return gate.promise.then((agent) => {
      accepted = agent;
      return agent;
    });
  });
  ui.name.value = "Helper";
  ui.create.click();
  await flush();
  assert.equal(ui.status.textContent, "Creating");
  gates[0].gate.reject(new Error(`request failed: 409 ${REASON}`));
  await flush();
  assert.equal(ui.status.textContent, REASON);
  assert.equal(ui.retry.hidden, false);
  ui.retry.click();
  await flush();
  assert.equal(ui.status.textContent, "Creating");
  assert.equal(gates.length, 2);
  assert.deepEqual(gates[1].body, gates[0].body);
  gates[1].gate.resolve({ agent_id: AGENT_ID, display_name: "Helper", active: false });
  await flush();
  await flush();
  assert.equal(ui.state(AGENT_ID), OFF);
  assert.equal(ui.status.textContent, "");
  assert.equal(ui.retry.hidden, true);
});
