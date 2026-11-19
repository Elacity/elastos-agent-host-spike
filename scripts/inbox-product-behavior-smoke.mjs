#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class FakeClassList {
  constructor(owner) {
    this.owner = owner;
  }

  add(name) {
    this.toggle(name, true);
  }

  remove(name) {
    this.toggle(name, false);
  }

  toggle(name, enabled) {
    const names = new Set(String(this.owner.className || "").split(/\s+/).filter(Boolean));
    enabled ? names.add(name) : names.delete(name);
    this.owner.className = [...names].join(" ");
  }
}

class FakeElement {
  constructor(tagName) {
    this.tagName = String(tagName).toUpperCase();
    this.children = [];
    this.className = "";
    this.classList = new FakeClassList(this);
    this.dataset = {};
    this.hidden = false;
    this.open = false;
    this.textContent = "";
    this.attributes = new Map();
    this.listeners = new Map();
    this.disabled = false;
    this.type = "";
  }

  append(...children) {
    this.children.push(...children);
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren(...children) {
    this.children = [...children];
  }

  addEventListener(type, callback) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(callback);
    this.listeners.set(type, listeners);
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) || null;
  }

  querySelectorAll(selector) {
    const nodes = descendants(this).slice(1);
    if (selector === "button") {
      return nodes.filter((node) => node.tagName === "BUTTON");
    }
    if (selector === ".entry-row") {
      return nodes.filter((node) => String(node.className || "").split(/\s+/).includes("entry-row"));
    }
    return [];
  }

  focus() {}

  scrollIntoView() {}
}

function descendants(node) {
  return [node, ...(node.children || []).flatMap(descendants)];
}

function jsonResponse(payload) {
  return {
    ok: true,
    status: 200,
    async json() {
      return payload;
    },
    async text() {
      return JSON.stringify(payload);
    },
  };
}

function textResponse(status, text) {
  return {
    ok: false,
    status,
    async json() {
      throw new Error("error body is not json");
    },
    async text() {
      return text;
    },
  };
}

function plainJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function inboxSummary() {
  const now = Math.floor(Date.now() / 1000);
  return {
    notifications: {
      attention_count: 1,
      unread_count: 0,
      entries: [
        {
          id: "entry-review",
          kind: "contact_request",
          title: "Review request",
          body: "Contact approval needs review",
          severity: "attention",
          read: true,
          created_at: now - 60,
          source_app: "people",
          action_ref: { action_id: "contact-accept-request:entry-review" },
        },
        {
          id: "entry-wallet",
          kind: "wallet_approval_request",
          title: "Wallet request",
          body: "Review wallet request",
          severity: "info",
          read: true,
          created_at: now - 3600,
          source_app: "wallet",
          action_ref: { action_id: "wallet-review-request:wallet-request-1" },
        },
      ],
    },
  };
}

async function settle() {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

function extractInboxScript(html) {
  assert.match(html, /<script src="\.\/inbox\.js(?:\?[^"\s]*)?"><\/script>/, "Inbox script reference not found");
  return fs.readFileSync(new URL("../capsules/inbox/browser/inbox.js", import.meta.url), "utf8");
}

async function runInboxHomeChromeSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const topMessages = [];
  const parentMessages = [];
  const fetchCalls = [];
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const windowListeners = new Map();
  const documentListeners = new Map();
  const topFrame = {
    postMessage(message, origin) {
      topMessages.push({ message, origin });
    },
  };
  const parentFrame = {
    postMessage(message, origin) {
      parentMessages.push({ message, origin });
    },
  };
  const documentElement = { dataset: {} };
  const document = {
    hidden: false,
    documentElement,
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener(type, callback) {
      documentListeners.set(type, callback);
    },
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&presentation=rail",
        hash: "#home_token=inbox-test-token",
      },
      top: topFrame,
      parent: parentFrame,
      addEventListener(type, callback) {
        const listeners = windowListeners.get(type) || [];
        listeners.push(callback);
        windowListeners.set(type, listeners);
      },
      removeEventListener(type, callback) {
        const listeners = windowListeners.get(type) || [];
        windowListeners.set(type, listeners.filter((entry) => entry !== callback));
      },
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async (path) => {
      fetchCalls.push(path);
      return jsonResponse(inboxSummary());
    },
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();

  // Contact and service names remain visible even when they contain technical words.
  for (const kind of ["contact_request", "service_access_request", "service_access_grant"]) {
    for (const name of ["Model Capsule", "<b>Provider</b>"]) {
      const entry = { ...inboxSummary().notifications.entries[0], kind, title: `${name} requests access`, body: `${name} needs your review.` };
      context.renderDetail(entry);
      for (const view of [context.createRow(entry), context.createRailCard(entry), nodes.get("entry-detail")]) {
        const texts = descendants(view).map(node => node.textContent);
        assert(texts.includes(entry.title), "Named identity missing from Inbox view");
        assert(texts.includes(entry.body), "Named details missing from Inbox view");
        assert(!descendants(view).some(node => node.tagName === "B"), "Named identity became markup");
      }
    }
  }
  assert.equal(context.inboxEntryText({ kind: "contact_request", title: "" }, "title", "Request"), "Request");
  assert.equal(context.inboxEntryText({ kind: "external_http_request", body: "provider boundary failed" }, "body", "Review"), "Review");
  const route = {
    id: "model-egress-fixture", provider: "Venice", offer_id: "validation:venice",
    method: "GET", origin: "https://api.venice.ai", path: "/api/v1/models",
    url_sha256: "a".repeat(64), recipient: "api.venice.ai", payer: "this Home",
    purpose: "Load hosted model choices", requested_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 600,
  };
  for (const [status, expectedAction] of [
    ["pending", "model-egress-approve:model-egress-fixture"],
    ["approved", "model-egress-end:model-egress-fixture"],
    ["denied", null],
    ["ended", null],
  ]) {
    const [entry] = context.inboxEntries({ notifications: { entries: [] }, hosted_routes: [{ ...route, status }] });
    assert.equal(entry.action_ref?.action_id || null, expectedAction);
    assert(entry.body.includes("Origin: https://api.venice.ai"));
    assert(entry.body.includes("Recipient: api.venice.ai"));
    assert(entry.body.includes("Payer: this Home"));
    assert(entry.body.includes("Expires:"));
    assert.equal(context.inboxEntryText(entry, "body", "Review"), entry.body);
    const actions = new FakeElement("div");
    context.fillEntryActions(actions, entry);
    const end = actions.children.find(node => node.dataset.actionId === "model-egress-end:model-egress-fixture");
    assert.equal(Boolean(end), status === "pending" || status === "approved");
    if (end) assert.equal(end.type, "button");
  }
  // Community presence: four answers, no Dismiss; the Runtime keeps the card
  // until the person decides.
  {
    const actions = new FakeElement("div");
    context.fillEntryActions(actions, {
      id: "community-presence-request:42", kind: "community_presence_request",
      source_app: "chat-room", title: "Show yourself in Community?", body: "",
      action_ref: { app: "inbox", action_id: "community-presence-always:42" },
    });
    const decisions = actions.children.filter(node => node.dataset.actionId).map(node => [node.textContent, node.dataset.actionId]);
    assert.deepEqual(decisions, [
      ["Always while Home is online", "community-presence-always:42"],
      ["Only while Community is open", "community-presence-open:42"],
      ["Later", "community-presence-later:42"],
      ["Never", "community-presence-never:42"],
    ]);
    assert(!actions.children.some(node => String(node.dataset.actionId || "").startsWith("notification-dismiss:")));
  }
  // An agent plan card carries every stored step, the full binding hash and the
  // exact binding its approve click sends back. It offers that one action and
  // no Dismiss control.
  {
    const hash = "b".repeat(64);
    const binding = {
      schema: "elastos.esp.request-binding/v1",
      request_id: "inspect-act-9-abc",
      principal: "person:local:owner",
      capsule: "capsule:agent-host",
      interface: null,
      method: "status",
      resources: ["elastos://availability/status"],
      sha256: hash,
      bytes: 128,
      truncated: false,
      preview: {
        owner: "person:local:owner",
        requester: "agent:v2:requester",
        session: "session:agent-1",
        step: { scheme: "availability", operation: "status", request: { principal: "person:other" } },
      },
    };
    const entry = {
      id: "agent-plan-request:inspect-act-9-abc",
      kind: "agent_plan",
      source_app: "inbox",
      title: "Agent plan for capsule:agent-host",
      body: [
        'Step 1: {"operation":"status","request":{"capsule":"capsule:impostor","principal":"person:other"},"scheme":"availability"}',
        "Gate preview: Capability elastos://availability/status: read.",
        `Binding sha256: ${hash}`,
      ].join("\n"),
      action_ref: { app: "inbox", action_id: "agent-plan-approve-request:inspect-act-9-abc" },
      request_binding: binding,
      severity: "attention",
      read: false,
      created_at: Math.floor(Date.now() / 1000),
    };
    assert.equal(context.inboxEntryText(entry, "body", "Review"), entry.body);
    context.renderDetail(entry);
    const detail = nodes.get("entry-detail");
    const detailText = descendants(detail).map(node => node.textContent).join("");
    for (const line of entry.body.split("\n")) {
      assert(detailText.includes(line), `Agent plan card lost: ${line}`);
    }
    assert(detailText.includes(hash), "Agent plan card lost the binding hash");
    const facts = descendants(detail).find(node => String(node.className || "").split(/\s+/).includes("entry-facts"));
    assert(Boolean(facts), "Agent plan card is not rendered as facts");
    const buttons = descendants(detail).filter(node => node.tagName === "BUTTON");
    assert.deepEqual(buttons.map(button => button.textContent), ["Approve"], "Agent plan card offers exactly the approve action");
    assert.equal(buttons[0].dataset.actionId, entry.action_ref.action_id);
    assert(!buttons.some(button => String(button.dataset.actionId || "").startsWith("notification-dismiss:")));
  }
  context.setStatus("unauthorized provider");
  assert.equal(nodes.get("status-text").textContent, "Inbox action could not be completed.");

  const menuManifest = topMessages.find((entry) => entry.message.type === "home:menu-manifest");
  assert.deepEqual(
    plainJson(topMessages.find((entry) => entry.message.type === "home:app-ready")),
    {
      message: { type: "home:app-ready", homeToken: "inbox-test-token" },
      origin: "http://localhost:61180",
    },
  );
  assert.deepEqual(plainJson(menuManifest), {
    message: {
      type: "home:menu-manifest",
      homeToken: "inbox-test-token",
      menus: [
        {
          title: "File",
          items: [
            { label: "Refresh", cmd: "refresh" },
            { label: "Close Window", cmd: "__close-window" },
          ],
        },
        {
          title: "View",
          items: [
            { label: "All", cmd: "filter-all" },
            { label: "Needs Review", cmd: "filter-review" },
          ],
        },
      ],
    },
    origin: "http://localhost:61180",
  });
  assert.deepEqual(
    plainJson(parentMessages),
    [
      {
        message: {
          type: "inbox:pending-count",
          count: 0,
        },
        origin: "*",
      },
    ],
  );
  assert.equal(
    topMessages.some((entry) => entry.message.type === "inbox:pending-count"),
    false,
  );
  assert.equal(documentElement.dataset.inboxPresentation, "rail");
  assert.equal(fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length, 1);

  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "filter-review" },
    });
  }
  await settle();
  assert.equal(nodes.get("list-title").textContent, "Needs Review");
  assert.equal(nodes.get("entry-rows").children.length, 1);

  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" },
    });
  }
  await settle();
  assert.equal(fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length, 2);

  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:inbox-chrome-command", cmd: "refresh" },
    });
  }
  await settle();
  assert.equal(fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length, 3);

  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "http://localhost:61180",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" },
    });
    callback({
      origin: "null",
      source: {},
      data: { type: "elastos:inbox-chrome-command", cmd: "refresh" },
    });
  }
  await settle();
  assert.equal(fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length, 3);

  const originalFetch = context.fetch;
  context.fetch = async (path) => {
    fetchCalls.push(path);
    return jsonResponse({
      notifications: {
        attention_count: 0,
        unread_count: 0,
        entries: [
          {
            id: "entry-wallet",
            kind: "wallet_approval_request",
            title: "Wallet request",
            body: "Review wallet request",
            severity: "info",
            read: true,
            created_at: Math.floor(Date.now() / 1000) - 3600,
            source_app: "wallet",
            action_ref: { action_id: "wallet-review-request:wallet-request-1" },
          },
        ],
      },
    });
  };
  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" },
    });
  }
  await settle();
  for (const callback of windowListeners.get("message") || []) {
    callback({
      origin: "null",
      source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "filter-review" },
    });
  }
  await settle();
  assert.equal(nodes.get("empty-title").textContent, "No requests need review");
  context.fetch = originalFetch;

  const serviceActions = [];
  context.fetch = async (path, options = {}) => {
    if (path === "/api/apps/inbox/actions") {
      serviceActions.push(JSON.parse(options.body).action_id);
    }
    return jsonResponse({ notifications: { entries: [{
      id: "entry-service", kind: "service_access_request", title: "Browser Exit access",
      body: "A contact requests Browser Exit access.", severity: "attention", read: false,
      source_app: "inbox", action_ref: { app: "inbox", action_id: "service-approve-request:service-1" },
    }] } });
  };
  for (const callback of windowListeners.get("message") || []) {
    callback({ origin: "null", source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" } });
  }
  await settle();
  const buttons = descendants(nodes.get("entry-rows")).filter(node => node.tagName === "BUTTON");
  // Services is hidden, so a service request offers no Open; Inbox decides it.
  assert.deepEqual(buttons.map(button => button.textContent), ["Approve", "Deny"]);
  assert.deepEqual(serviceActions, [], "Viewing a service request must preserve its pending state");
  for (const label of ["Approve", "Deny"]) {
    const button = descendants(nodes.get("entry-rows")).find(node => node.tagName === "BUTTON" && node.textContent === label);
    for (const callback of button.listeners.get("click") || []) callback();
    await settle();
  }
  assert.deepEqual(serviceActions, ["service-approve-request:service-1", "service-deny-request:service-1"]);

  const grantActions = [];
  let grantRevoked = false;
  const grantEntry = {
    id: "entry-grant",
    kind: "service_access_grant",
    title: "Seed may use your AI model",
    body: "Seed may use Mac model. Revoke access to stop new runs and cancel open runs.",
    severity: "info",
    read: true,
    source_app: "inbox",
    action_ref: { action_id: "service-deny-request:grant-1" },
  };
  context.fetch = async (path, options = {}) => {
    fetchCalls.push(path);
    if (path === "/api/apps/inbox/actions") {
      grantActions.push(JSON.parse(options.body).action_id);
      grantRevoked = true;
      return textResponse(503, "service access request delivery failed");
    }
    return jsonResponse({
      notifications: {
        attention_count: 0,
        unread_count: 0,
        entries: grantRevoked ? [] : [grantEntry],
      },
    });
  };
  for (const callback of windowListeners.get("message") || []) {
    callback({ origin: "null", source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "filter-all" } });
  }
  await settle();
  const summariesBeforeRevoke = fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length;
  for (const callback of windowListeners.get("message") || []) {
    callback({ origin: "null", source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" } });
  }
  await settle();
  assert.equal(nodes.get("pending-count").textContent, "0");
  // The All list holds a grant card; the count beside it names only pending requests.
  assert.equal(filterAll.getAttribute("aria-label"), "All, 0 pending requests");
  assert.equal(nodes.get("list-title").textContent, "All");
  assert.equal(nodes.get("review-count").textContent, "0");
  const grantButtons = descendants(nodes.get("entry-rows")).filter(node => node.tagName === "BUTTON");
  assert.deepEqual(grantButtons.map(button => button.textContent), ["Revoke access"]);
  assert.deepEqual(grantActions, [], "Viewing an approved grant must preserve its access");
  const revoke = grantButtons.find(button => button.textContent === "Revoke access");
  for (const callback of revoke.listeners.get("click") || []) callback();
  await settle();
  assert.deepEqual(grantActions, ["service-deny-request:grant-1"]);
  assert.ok(
    fetchCalls.filter((path) => path === "/api/apps/inbox/summary").length > summariesBeforeRevoke,
    "503 after a saved revoke must refresh Inbox summary",
  );
  assert.deepEqual(
    descendants(nodes.get("entry-rows")).filter(node => node.tagName === "BUTTON").map(button => button.textContent),
    [],
  );
  assert.equal(nodes.get("pending-count").textContent, "0");
  assert.equal(
    nodes.get("status-text").textContent,
    "service access request delivery failed",
  );

  context.fetch = async () => jsonResponse({ notifications: {
    attention_count: 1,
    unread_count: 1,
    entries: [
      {
        id: "entry-service",
        kind: "service_access_request",
        title: "Browser Exit access",
        body: "A contact requests Browser Exit access.",
        severity: "attention",
        read: false,
        source_app: "inbox",
        action_ref: { action_id: "service-approve-request:service-1" },
      },
      {
        id: "entry-grant",
        kind: "service_access_grant",
        title: "Seed may use your AI model",
        body: "Seed may use Mac model. Revoke access to stop new runs and cancel open runs.",
        severity: "info",
        read: true,
        source_app: "inbox",
        action_ref: { action_id: "service-deny-request:grant-1" },
      },
    ],
  } });
  for (const callback of windowListeners.get("message") || []) {
    callback({ origin: "null", source: parentFrame,
      data: { type: "elastos:menu-command", cmd: "refresh" } });
  }
  await settle();
  assert.equal(nodes.get("pending-count").textContent, "1");
  assert.equal(filterAll.getAttribute("aria-label"), "All, 1 pending request");
  assert.equal(nodes.get("review-count").textContent, "1");

  // The approve click asks for one fresh passkey bound to this request and
  // sends the exact binding the card showed with its token.
  {
    const hash = "c".repeat(64);
    const binding = {
      schema: "elastos.esp.request-binding/v1",
      request_id: "inspect-act-9-abc",
      principal: "person:local:owner",
      capsule: "capsule:agent-host",
      interface: null,
      method: "status",
      resources: ["elastos://availability/status"],
      sha256: hash,
      bytes: 128,
      truncated: false,
      preview: {
        owner: "person:local:owner",
        requester: "agent:v2:requester",
        session: "session:agent-1",
        step: { scheme: "availability", operation: "status", request: { principal: "person:other" } },
      },
    };
    const entry = {
      id: "agent-plan-request:inspect-act-9-abc",
      kind: "agent_plan",
      source_app: "inbox",
      title: "Agent plan for capsule:agent-host",
      body: "Binding sha256: " + hash,
      action_ref: { app: "inbox", action_id: "agent-plan-approve-request:inspect-act-9-abc" },
      request_binding: binding,
    };
    const approvals = [];
    const stepUpRequests = [];
    const previousFetch = context.fetch;
    const previousTop = context.window.top;
    const previousSetTimeout = context.window.setTimeout;
    const previousClearTimeout = context.window.clearTimeout;
    // The fake clock fires timers immediately; a real Home answers the
    // passkey request a round trip later, so keep the timeout pending until
    // the click has registered its result listener.
    context.window.setTimeout = () => 1;
    context.window.clearTimeout = () => {};
    context.fetch = async (path, options = {}) => {
      fetchCalls.push(path);
      if (path === "/api/apps/inbox/actions") {
        approvals.push(JSON.parse(options.body));
        return jsonResponse({ message: "Approved agent plan." });
      }
      return previousFetch(path, options);
    };
    const stepUpTop = {
      postMessage(message, origin) {
        if (message.type !== "elastos.home.passkey-step-up.request/v1") {
          return;
        }
        stepUpRequests.push({ message, origin });
        for (const callback of windowListeners.get("message") || []) {
          callback({
            source: stepUpTop,
            origin: "http://localhost:61180",
            data: {
              type: "elastos.home.passkey-step-up.result/v1",
              requestId: message.requestId,
              stepUpToken: "agent-plan-step-up",
            },
          });
        }
      },
    };
    context.window.top = stepUpTop;
    try {
      const actions = new FakeElement("div");
      context.fillEntryActions(actions, entry);
      const approve = actions.children.find(node => node.tagName === "BUTTON" && node.textContent === "Approve");
      assert(Boolean(approve), "Agent plan card has no approve action");
      assert(!actions.children.some(node => String(node.dataset.actionId || "").startsWith("notification-dismiss:")));
      for (const callback of approve.listeners.get("click") || []) callback();
      await settle();
      assert.equal(approvals.length, 1, "Agent plan approval was not sent");
      assert.equal(approvals[0].action_id, "agent-plan-approve-request:inspect-act-9-abc");
      assert.deepEqual(plainJson(approvals[0].request_binding), plainJson(binding));
      assert.equal(stepUpRequests.length, 1, "Agent plan approval must ask for a fresh passkey");
      assert.equal(stepUpRequests[0].message.type, "elastos.home.passkey-step-up.request/v1");
      assert.equal(stepUpRequests[0].message.operation, "agent_plan.approve");
      assert.deepEqual(plainJson(stepUpRequests[0].message.request), { request_id: "inspect-act-9-abc" });
      assert.equal(stepUpRequests[0].origin, "http://localhost:61180");
      assert.equal(approvals[0].step_up_token, "agent-plan-step-up");
    } finally {
      context.window.top = previousTop;
      context.window.setTimeout = previousSetTimeout;
      context.window.clearTimeout = previousClearTimeout;
    }
  }
}

async function runInboxLaunchSelectionSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  const document = {
    hidden: false,
    documentElement: { dataset: {} },
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener() {},
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&notification_id=entry-wallet",
        hash: "#home_token=inbox-test-token",
      },
      top: { postMessage() {} },
      parent: { postMessage() {} },
      addEventListener() {},
      removeEventListener() {},
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async () => jsonResponse(inboxSummary()),
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();

  assert.equal(nodes.get("entry-rows").children.length, 2);
  assert.equal(nodes.get("entry-rows").children[1].getAttribute("aria-selected"), "true");
  const detailText = descendants(nodes.get("entry-detail"))
    .map((node) => node.textContent || "")
    .join(" ");
  assert(detailText.includes("Wallet request"), "Inbox did not keep the requested notification selected", detailText);
}

async function runInboxMissingLaunchSelectionSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  const document = {
    hidden: false,
    documentElement: { dataset: {} },
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener() {},
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&notification_id=missing-entry",
        hash: "#home_token=inbox-test-token",
      },
      top: { postMessage() {} },
      parent: { postMessage() {} },
      addEventListener() {},
      removeEventListener() {},
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async () => jsonResponse(inboxSummary()),
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();

  const selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows.length, 0, "Inbox selected a different request after an explicit missing launch id");
  const detailText = descendants(nodes.get("entry-detail"))
    .map((node) => node.textContent || "")
    .join(" ");
  assert(detailText.includes("no longer available"), "Inbox did not show the explicit request as unavailable", detailText);
  assert.equal(
    descendants(nodes.get("entry-detail")).filter((node) => node.tagName === "BUTTON").length,
    0,
    "Inbox exposed actions for a missing explicit launch id",
  );
}

async function runInboxRemovedLaunchSelectionSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  let fetchCount = 0;
  const document = {
    hidden: false,
    documentElement: { dataset: {} },
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener() {},
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&notification_id=entry-wallet",
        hash: "#home_token=inbox-test-token",
      },
      top: { postMessage() {} },
      parent: { postMessage() {} },
      addEventListener() {},
      removeEventListener() {},
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async () => {
      fetchCount += 1;
      if (fetchCount === 1) {
        return jsonResponse(inboxSummary());
      }
      const summary = inboxSummary();
      summary.notifications.entries = summary.notifications.entries.filter((entry) => entry.id !== "entry-wallet");
      return jsonResponse(summary);
    },
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();
  await nodes.get("refresh").listeners.get("click")[0]();
  await settle();

  const selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows.length, 0, "Inbox selected a different request after the explicit request disappeared");
  const detailText = descendants(nodes.get("entry-detail"))
    .map((node) => node.textContent || "")
    .join(" ");
  assert(detailText.includes("no longer available"), "Inbox did not keep the vanished explicit request unavailable", detailText);
  assert.equal(
    descendants(nodes.get("entry-detail")).filter((node) => node.tagName === "BUTTON").length,
    0,
    "Inbox exposed actions after the explicit request disappeared on refresh",
  );
}

async function runInboxRequestedSelectionAppearsLaterSmoke() {
  const inbox = fs.readFileSync(new URL("../capsules/inbox/browser/index.html", import.meta.url), "utf8");
  const inboxScript = extractInboxScript(inbox);
  const nodes = new Map([
    ["locked-shell", new FakeElement("section")],
    ["inbox-shell", new FakeElement("section")],
    ["status-text", new FakeElement("p")],
    ["pending-count", new FakeElement("strong")],
    ["review-count", new FakeElement("strong")],
    ["refresh", new FakeElement("button")],
    ["entry-rows", new FakeElement("section")],
    ["entry-detail", new FakeElement("section")],
    ["entry-split", new FakeElement("div")],
    ["empty-state", new FakeElement("section")],
    ["empty-title", new FakeElement("h2")],
    ["list-title", new FakeElement("h1")],
  ]);
  const filterAll = new FakeElement("button");
  filterAll.className = "summary-card active";
  filterAll.dataset.filter = "all";
  const filterReview = new FakeElement("button");
  filterReview.className = "summary-card";
  filterReview.dataset.filter = "review";
  let fetchCount = 0;
  const document = {
    hidden: false,
    documentElement: { dataset: {} },
    getElementById(id) {
      return nodes.get(id) || null;
    },
    querySelectorAll(selector) {
      if (selector === ".summary-card[data-filter]") {
        return [filterAll, filterReview];
      }
      return [];
    },
    addEventListener() {},
    createElement(tagName) {
      return new FakeElement(tagName);
    },
  };
  const context = {
    console,
    document,
    window: {
      crypto: { randomUUID: () => "inbox-fixture-document" },
      location: {
        search: "?home_origin=http%3A%2F%2Flocalhost%3A61180&notification_id=entry-wallet",
        hash: "#home_token=inbox-test-token",
      },
      top: { postMessage() {} },
      parent: { postMessage() {} },
      addEventListener() {},
      removeEventListener() {},
      setInterval() {
        return 1;
      },
      setTimeout(callback) {
        callback();
        return 1;
      },
      clearTimeout() {},
    },
    URLSearchParams,
    Intl,
    Date,
    Promise,
    setTimeout,
    clearTimeout,
    fetch: async () => {
      fetchCount += 1;
      const summary = inboxSummary();
      if (fetchCount === 1) {
        summary.notifications.entries = [summary.notifications.entries[0]];
      }
      return jsonResponse(summary);
    },
  };

  vm.runInNewContext(inboxScript, context, {
    filename: "capsules/inbox/browser/inbox.js",
  });
  await settle();

  let selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows.length, 0, "Inbox selected the wrong request before the explicit request appeared");

  await nodes.get("refresh").listeners.get("click")[0]();
  await settle();

  selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows.length, 1);
  assert.equal(selectedRows[0], nodes.get("entry-rows").children[1], "Inbox did not reselect the requested request when it appeared");

  const keydown = nodes.get("entry-rows").listeners.get("keydown")[0];
  keydown({
    key: "ArrowUp",
    preventDefault() {},
  });
  await settle();
  selectedRows = nodes.get("entry-rows").children
    .filter((row) => row.getAttribute("aria-selected") === "true");
  assert.equal(selectedRows[0], nodes.get("entry-rows").children[0], "Keyboard selection did not clear the pinned request");
}

await runInboxHomeChromeSmoke();
await runInboxLaunchSelectionSmoke();
await runInboxMissingLaunchSelectionSmoke();
await runInboxRemovedLaunchSelectionSmoke();
await runInboxRequestedSelectionAppearsLaterSmoke();
console.log("inbox-product-behavior-smoke: PASS");
