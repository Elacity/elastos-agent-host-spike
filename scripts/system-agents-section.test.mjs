import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { bindAgents } from "../capsules/system/browser/agents-section.js";

const NAMED = "owner_sees_on_only_after_the_activate_route";
const ALLOW_NAMED = "allow_agents_calls_the_enable_route";
const OFF = "Off until you turn it on";
const REASON = "owner already has the most agents a Home allows";
const NOT_BUILT = "agents are not built into this Runtime";
const NOT_ON = "agents are not turned on for this Home";
const CREATE_ON_REFUSED = "create_reply_that_is_on_is_refused";
const AGENT_ID = "agent:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_ID = "agent:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
  const state = selector.match(/^\[data-agent-state="(.*)"\]$/);
  if (state) return Boolean(node.dataset && node.dataset.agentState === state[1]);
  const id = selector.match(/^\[data-agent-id="(.*)"\]$/);
  return Boolean(id && node.dataset && node.dataset.agentId === id[1]);
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

function callOf(path, init = {}) {
  return {
    path,
    method: init.method || "GET",
    body: init.body ? JSON.parse(init.body) : null,
  };
}

function mount(request, confirmStepUp) {
  const nodes = {
    "#agents-list": element("div"),
    "#agents-status": element("p"),
    "#agent-form": element("div"),
    "#agent-name": element("input"),
    "#agent-host": Object.assign(element("input"), { value: "agent-host" }),
    "#agent-create": element("button"),
    "#agent-allow": Object.assign(element("button"), { hidden: true }),
    "#agent-retry": Object.assign(element("button"), { hidden: true }),
  };
  for (const [id, node] of Object.entries(nodes)) node.id = id.slice(1);
  const doc = {
    defaultView: { crypto: { randomUUID: () => "11111111-1111-4111-8111-111111111111" } },
    createElement: element,
    querySelector: (selector) => nodes[selector] || query({ children: Object.values(nodes) }, selector),
  };
  const bound = bindAgents(doc, request, confirmStepUp);
  return {
    status: nodes["#agents-status"],
    name: nodes["#agent-name"],
    host: nodes["#agent-host"],
    create: nodes["#agent-create"],
    allow: nodes["#agent-allow"],
    retry: nodes["#agent-retry"],
    form: nodes["#agent-form"],
    list: nodes["#agents-list"],
    load: bound.load,
    state(id) {
      return doc.querySelector(`[data-agent-state="${id}"]`)?.textContent ?? "";
    },
    agentId(id) {
      return query(nodes["#agents-list"], `[data-agent-id="${id}"]`)?.textContent ?? "";
    },
    button(label) {
      return findButton(nodes["#agents-list"], label);
    },
  };
}

function agentsPage() {
  const html = readFileSync(new URL("../capsules/system/browser/index.html", import.meta.url), "utf8");
  const start = html.indexOf('<section class="settings-content" data-settings="agents"');
  const end = html.indexOf('<section class="settings-content" data-settings="about"');
  return html.slice(start, end);
}

test("create shows Off, turn on shows On, and On follows the activate route", async () => {
  const agent = { agent_id: AGENT_ID, display_name: "Helper", active: false };
  const createGate = deferred();
  const listOff = deferred();
  const activateGate = deferred();
  const listOn = deferred();
  const calls = [];
  const ui = mount((path, init = {}) => {
    const call = callOf(path, init);
    calls.push(call);
    if (path.endsWith("/create")) return createGate.promise;
    if (path.endsWith("/activate")) return activateGate.promise;
    const lists = calls.filter((item) => item.method === "GET");
    if (lists.length === 1) return Promise.resolve({ agents: [] });
    return lists.length === 2 ? listOff.promise : listOn.promise;
  });
  await ui.load();
  assert.equal(ui.form.hidden, false);
  ui.name.value = "Helper";
  ui.create.click();
  await flush();
  assert.equal(ui.status.textContent, "Creating");
  const created = calls.filter((call) => call.path.endsWith("/create"));
  assert.equal(created.length, 1);
  assert.equal(created[0].path, "/api/apps/system/agents/create");
  assert.deepEqual(created[0].body, {
    display_name: "Helper",
    agent_host: "agent-host",
    request_id: "11111111-1111-4111-8111-111111111111",
  });
  createGate.resolve(agent);
  await flush();
  listOff.resolve({ agents: [agent] });
  await flush();
  assert.equal(ui.state(AGENT_ID), OFF);
  assert.equal(ui.name.value, "");
  assert.equal(calls.some((call) => call.path.endsWith("/activate")), false);

  ui.button("Turn on").click();
  await flush();
  const activate = () => calls.filter((call) => call.path.endsWith("/activate"));
  assert.equal(activate().length, 1);
  assert.equal(activate()[0].body.active, true);
  assert.equal(ui.state(AGENT_ID), "Turning on");
  activateGate.resolve({ ...agent, active: true });
  await flush();
  listOn.resolve({ agents: [{ ...agent, active: true }] });
  await flush();
  assert.equal(ui.state(AGENT_ID), "On", NAMED);
  assert.equal(activate().length, 1, NAMED);
  assert.equal(activate()[0]?.body.active, true, NAMED);
});

test("a refused create shows the server reason and offers no retry", async () => {
  const gates = [];
  const ui = mount((path, init = {}) => {
    if ((init.method || "GET") === "GET") return Promise.resolve({ agents: [] });
    if (!path.endsWith("/create")) throw new Error(`unexpected ${path}`);
    const gate = deferred();
    gates.push({ body: JSON.parse(init.body), gate });
    return gate.promise;
  });
  await ui.load();
  ui.name.value = "Helper";
  ui.create.click();
  await flush();
  assert.equal(ui.status.textContent, "Creating");
  gates[0].gate.reject(new Error(`request failed: 409 ${REASON}`));
  await flush();
  assert.equal(ui.status.textContent, REASON);
  assert.equal(ui.retry.hidden, true);
  assert.equal(ui.name.value, "Helper");
  ui.retry.click();
  await flush();
  assert.equal(gates.length, 1);
});

test("retry is offered for a lost answer and for a 5xx, and it sends the same request", async () => {
  const lost = mount((path, init = {}) => {
    if ((init.method || "GET") === "GET") return Promise.resolve({ agents: [] });
    return Promise.reject(new Error("Failed to fetch"));
  });
  await lost.load();
  lost.name.value = "Helper";
  lost.create.click();
  await flush();
  assert.equal(lost.status.textContent, "The Home did not answer.");
  assert.equal(lost.retry.hidden, false);
  assert.equal(lost.name.value, "Helper");

  const gates = [];
  let accepted = null;
  const ui = mount((path, init = {}) => {
    if ((init.method || "GET") === "GET") return Promise.resolve({ agents: accepted ? [accepted] : [] });
    const gate = deferred();
    gates.push({ body: JSON.parse(init.body), gate });
    return gate.promise.then((agent) => {
      accepted = agent;
      return agent;
    });
  });
  await ui.load();
  ui.name.value = "Helper";
  ui.create.click();
  await flush();
  gates[0].gate.reject(new Error("request failed: 503 the Home could not store that change"));
  await flush();
  assert.equal(ui.status.textContent, "the Home could not store that change");
  assert.equal(ui.retry.hidden, false);
  assert.equal(ui.name.value, "Helper");
  ui.retry.click();
  await flush();
  assert.equal(gates.length, 2);
  assert.deepEqual(gates[1].body, gates[0].body);
  gates[1].gate.resolve({ agent_id: AGENT_ID, display_name: "Helper", active: false });
  await flush();
  await flush();
  assert.equal(ui.state(AGENT_ID), OFF);
  assert.equal(ui.name.value, "");
  assert.equal(ui.retry.hidden, true);
});

test("a Runtime without agents says so and offers no create or retry", async () => {
  const calls = [];
  const ui = mount((path, init = {}) => {
    calls.push(callOf(path, init));
    return Promise.reject(new Error(`request failed: 409 ${NOT_BUILT}`));
  });
  await ui.load();
  assert.equal(ui.status.textContent, "Agents are not built into this Runtime");
  assert.equal(ui.form.hidden, true);
  assert.equal(ui.allow.hidden, true);
  assert.equal(ui.retry.hidden, true);
  assert.equal(ui.list.children.length, 0);
  ui.create.click();
  ui.allow.click();
  ui.retry.click();
  await flush();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "GET");
  assert.equal(calls[0].path, "/api/apps/system/agents");
});

test("agents off offers allow, and allow calls the enable route before create", async () => {
  const page = agentsPage();
  assert.match(page, /id="agent-allow"[^>]*hidden[^>]*>Allow agents on this Home</);
  const formBlock = page.match(/<div id="agent-form" hidden>([\s\S]*?)<button id="agent-retry"/);
  assert.ok(formBlock, "the create form is hidden until agents are on");
  const opens = (formBlock[1].match(/<div\b/g) || []).length;
  const closes = (formBlock[1].match(/<\/div>/g) || []).length;
  assert.equal(closes, opens + 1, "retry sits outside the create form");

  const calls = [];
  let listed = 0;
  const enableGate = deferred();
  const ui = mount((path, init = {}) => {
    const call = callOf(path, init);
    calls.push(call);
    if (path.endsWith("/enable")) return enableGate.promise;
    if (path.endsWith("/create")) {
      return Promise.resolve({ agent_id: AGENT_ID, display_name: "Helper", active: false });
    }
    listed += 1;
    if (listed === 1) return Promise.reject(new Error(`request failed: 409 ${NOT_ON}`));
    if (listed === 2) return Promise.resolve({ agents: [] });
    return Promise.resolve({ agents: [{ agent_id: AGENT_ID, display_name: "Helper", active: false }] });
  });
  await ui.load();
  assert.equal(ui.status.textContent, "Agents are off for this Home");
  assert.equal(ui.allow.hidden, false);
  assert.equal(ui.form.hidden, true);
  assert.equal(ui.retry.hidden, true);
  assert.equal(ui.list.children.length, 0);
  assert.equal(calls.filter((call) => call.path.endsWith("/enable")).length, 0);
  ui.allow.click();
  await flush();
  const enables = calls.filter((call) => call.path === "/api/apps/system/agents/enable");
  assert.equal(enables.length, 1, ALLOW_NAMED);
  assert.equal(enables[0].method, "POST", ALLOW_NAMED);
  assert.equal(enables[0].body, null, ALLOW_NAMED);
  assert.equal(ui.status.textContent, "Allowing");
  enableGate.resolve({ enabled: true });
  await flush();
  await flush();
  assert.equal(ui.form.hidden, false);
  assert.equal(ui.allow.hidden, true);
  assert.equal(ui.status.textContent, "");
  ui.name.value = "Helper";
  ui.create.click();
  await flush();
  await flush();
  assert.equal(ui.state(AGENT_ID), OFF);
  assert.equal(ui.name.value, "");
  assert.equal(calls.some((call) => call.path.endsWith("/activate")), false);
});

test("a failed turn on or off shows the server reason and offers no retry", async () => {
  const off = { agent_id: AGENT_ID, display_name: "Helper", active: false };
  const on = { agent_id: OTHER_ID, display_name: "Notes", active: true };
  const reasons = {
    [AGENT_ID]: "the caller owns no agent with that id",
    [OTHER_ID]: "agent is already retired",
  };
  const ui = mount((path, init = {}) => {
    if (path.endsWith("/activate")) {
      const body = JSON.parse(init.body);
      return Promise.reject(new Error(`request failed: 409 ${reasons[body.agent_id]}`));
    }
    return Promise.resolve({ agents: [off, on] });
  });
  await ui.load();
  assert.equal(ui.state(AGENT_ID), OFF);
  assert.equal(ui.state(OTHER_ID), "On");
  ui.button("Turn on").click();
  await flush();
  assert.equal(ui.status.textContent, reasons[AGENT_ID]);
  assert.equal(ui.retry.hidden, true);
  assert.equal(ui.state(AGENT_ID), OFF);
  ui.button("Turn off").click();
  await flush();
  assert.equal(ui.status.textContent, reasons[OTHER_ID]);
  assert.equal(ui.retry.hidden, true);
  assert.equal(ui.state(OTHER_ID), "On");
});

function sourceLines(url) {
  return readFileSync(url, "utf8").split("\n");
}

test("a create reply whose agent is on is refused by the page", async () => {
  const created = { agent_id: AGENT_ID, display_name: "Helper", active: true };
  const calls = [];
  const ui = mount((path, init = {}) => {
    const call = callOf(path, init);
    calls.push(call);
    if (path.endsWith("/create")) return Promise.resolve(created);
    const createdAlready = calls.some((item) => item.path.endsWith("/create"));
    return Promise.resolve({ agents: createdAlready ? [created] : [] });
  });
  await ui.load();
  ui.name.value = "Helper";
  ui.create.click();
  await flush();
  await flush();
  assert.equal(ui.status.textContent, "The Home did not confirm that change.", CREATE_ON_REFUSED);
  assert.equal(ui.state(AGENT_ID), "", CREATE_ON_REFUSED);
  assert.equal(ui.name.value, "Helper", CREATE_ON_REFUSED);
  assert.equal(ui.retry.hidden, true, CREATE_ON_REFUSED);
  assert.equal(ui.form.hidden, false);
  assert.equal(calls.filter((call) => call.path.endsWith("/create")).length, 1, CREATE_ON_REFUSED);
  assert.equal(calls.filter((call) => call.path.endsWith("/activate")).length, 0, CREATE_ON_REFUSED);
  ui.retry.click();
  await flush();
  assert.equal(calls.filter((call) => call.path.endsWith("/create")).length, 1, CREATE_ON_REFUSED);
});

test("a bad list or turn is refused without retry, and a real 502 still offers it", async () => {
  const listCalls = [];
  const badList = mount((path, init = {}) => {
    listCalls.push(callOf(path, init));
    return Promise.resolve({ agents: { id: AGENT_ID } });
  });
  await badList.load();
  assert.equal(badList.status.textContent, "The Home did not list agents.");
  assert.equal(badList.retry.hidden, true);
  assert.equal(badList.form.hidden, true);
  badList.retry.click();
  await flush();
  assert.equal(listCalls.length, 1);

  const agent = { agent_id: AGENT_ID, display_name: "Helper", active: false };
  const turnCalls = [];
  const turn = mount((path, init = {}) => {
    const call = callOf(path, init);
    turnCalls.push(call);
    if (path.endsWith("/activate")) return Promise.resolve({ ...agent, active: false });
    return Promise.resolve({ agents: [agent] });
  });
  await turn.load();
  turn.button("Turn on").click();
  await flush();
  await flush();
  assert.equal(turn.status.textContent, "The Home did not confirm that change.");
  assert.equal(turn.retry.hidden, true);
  assert.equal(turn.state(AGENT_ID), OFF);
  turn.retry.click();
  await flush();
  assert.equal(turnCalls.filter((call) => call.path.endsWith("/activate")).length, 1);

  const real = mount((path, init = {}) => {
    if ((init.method || "GET") === "GET") return Promise.resolve({ agents: [] });
    return Promise.reject(new Error("request failed: 502 the gateway timed out"));
  });
  await real.load();
  real.name.value = "Helper";
  real.create.click();
  await flush();
  assert.equal(real.status.textContent, "the gateway timed out");
  assert.equal(real.retry.hidden, false);
  assert.equal(real.name.value, "Helper");
});

test("start shows the agent id before the passkey, then posts the launch", async () => {
  const calls = [];
  const step = deferred();
  const ui = mount((path, init = {}) => {
    calls.push(callOf(path, init));
    if ((init.method || "GET") === "GET") {
      return Promise.resolve({
        agents: [{ agent_id: AGENT_ID, display_name: "Helper", active: true }],
      });
    }
    return Promise.resolve({ agent_id: AGENT_ID, session_id: "session-1", status: "starting" });
  }, () => step.promise.then(() => "step-token"));
  await ui.load();
  assert.equal(ui.button("Start") !== null, true);
  ui.button("Start").click();
  await flush();
  assert.equal(ui.agentId(AGENT_ID), AGENT_ID, "the agent id is on the page before the passkey");
  assert.equal(ui.state(AGENT_ID), `Start ${AGENT_ID}`);
  assert.equal(calls.some((call) => call.path.endsWith("/launch")), false);
  step.resolve();
  await flush();
  await flush();
  const launch = calls.filter((call) => call.path.endsWith("/launch"));
  assert.equal(launch.length, 1);
  assert.deepEqual(launch[0].body, { agent_id: AGENT_ID, step_up_token: "step-token" });
  assert.equal(calls[0].method, "GET");
  assert.equal(calls[1].path, "/api/apps/system/agents/launch");
});

test("stop posts the agent id and does not ask for the passkey", async () => {
  const calls = [];
  let steps = 0;
  const ui = mount((path, init = {}) => {
    calls.push(callOf(path, init));
    if ((init.method || "GET") === "GET") {
      return Promise.resolve({
        agents: [{ agent_id: AGENT_ID, display_name: "Helper", active: true }],
      });
    }
    return Promise.resolve({
      agent_id: AGENT_ID,
      stopped: [{ session_id: "session-1", status: "stopped" }],
    });
  }, () => {
    steps += 1;
    return Promise.resolve("step-token");
  });
  await ui.load();
  assert.equal(ui.button("Stop") !== null, true);
  ui.button("Stop").click();
  await flush();
  await flush();
  const stopped = calls.filter((call) => call.path.endsWith("/stop"));
  assert.equal(stopped.length, 1);
  assert.deepEqual(stopped[0].body, { agent_id: AGENT_ID });
  assert.equal(steps, 0);
});

test("an agent that is off has Stop and no Start", async () => {
  const calls = [];
  const ui = mount((path, init = {}) => {
    calls.push(callOf(path, init));
    if ((init.method || "GET") === "GET") {
      return Promise.resolve({
        agents: [{ agent_id: AGENT_ID, display_name: "Helper", active: false }],
      });
    }
    return Promise.resolve({
      agent_id: AGENT_ID,
      stopped: [{ session_id: "session-1", status: "stopped" }],
    });
  });
  await ui.load();
  assert.equal(ui.agentId(AGENT_ID), AGENT_ID);
  assert.equal(ui.button("Start"), null);
  assert.equal(ui.button("Turn on") !== null, true);
  assert.equal(ui.button("Stop") !== null, true);
  ui.button("Stop").click();
  await flush();
  await flush();
  const stopped = calls.filter((call) => call.path.endsWith("/stop"));
  assert.equal(stopped.length, 1);
  assert.deepEqual(stopped[0].body, { agent_id: AGENT_ID });
});

test("the page's two refusal sentences are the server's", () => {
  const rust = sourceLines(new URL("../elastos/crates/elastos-server/src/agents.rs", import.meta.url));
  const page = sourceLines(new URL("../capsules/system/browser/agents-section.js", import.meta.url));
  const count = (lines, line) => lines.filter((item) => item === line).length;
  assert.equal(count(rust, `pub(crate) const FEATURE_OFF: &str = "${NOT_BUILT}";`), 1);
  assert.equal(count(rust, `pub(crate) const NOT_ENABLED: &str = "${NOT_ON}";`), 1);
  assert.equal(count(page, `const NOT_BUILT = "${NOT_BUILT}";`), 1);
  assert.equal(count(page, `const NOT_ON = "${NOT_ON}";`), 1);
});
