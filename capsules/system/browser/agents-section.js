const OFF = "Off until you turn it on";
const ON = "On";

function text(value) {
  return typeof value === "string" ? value.trim() : "";
}

function reason(error) {
  const found = text(error && error.message).match(/^request failed: \d{3}\s+([\s\S]+)$/);
  return (found && found[1].trim()) || "The Home did not answer.";
}

function stateText(agent, pending) {
  if (pending) return pending;
  if (agent.active === true) return ON;
  if (agent.active === false) return OFF;
  return "The Home did not say whether this agent is on.";
}

function el(doc, tag, className, textContent) {
  const node = doc.createElement(tag);
  if (className) node.className = className;
  if (textContent) node.textContent = textContent;
  return node;
}

export function bindAgents(doc, request) {
  const [listNode, statusNode, nameInput, hostInput, createButton, retryButton] = [
    "#agents-list", "#agents-status", "#agent-name", "#agent-host", "#agent-create", "#agent-retry",
  ].map((id) => doc.querySelector(id));
  if (!listNode || !statusNode || !nameInput || !hostInput || !createButton || !retryButton) return { load() {} };
  let agents = [], pendingId = "", pendingLabel = "", failure = "", retry = null, busy = false;

  function paint() {
    statusNode.textContent = failure || (pendingId === "create" ? pendingLabel : "");
    retryButton.hidden = !retry;
    createButton.disabled = busy;
    const rows = agents.map((agent) => {
      const pending = pendingId === agent.agent_id ? pendingLabel : "";
      const state = el(doc, "div", "pc2-card-sublabel", stateText(agent, pending));
      state.dataset.agentState = agent.agent_id;
      const button = el(doc, "button", "pc2-btn pc2-btn-secondary", agent.active === true ? "Turn off" : "Turn on");
      button.type = "button";
      button.disabled = busy || (agent.active !== true && agent.active !== false);
      button.addEventListener("click", () => run(turnJob(agent, agent.active !== true)));
      const copy = el(doc, "div");
      copy.append(el(doc, "div", "pc2-card-label", text(agent.display_name) || "Unnamed agent"), state);
      const row = el(doc, "div", "pc2-card-row");
      row.append(copy, button);
      return row;
    });
    if (!rows.length && !failure && pendingId !== "create") rows.push(el(doc, "p", "pc2-card-sublabel", "You have no agents."));
    listNode.replaceChildren(...rows);
  }

  async function run(job) {
    if (busy || !job) return;
    busy = true;
    failure = "";
    retry = null;
    paint();
    try {
      await job();
    } catch (error) {
      failure = reason(error);
      retry = job;
    } finally {
      busy = false;
      pendingId = "";
      pendingLabel = "";
      paint();
    }
  }

  async function load() {
    const body = await request("/api/apps/system/agents");
    if (!body || !Array.isArray(body.agents)) throw new Error("request failed: 502 The Home did not list agents.");
    agents = body.agents;
  }

  function post(id, label, path, body, accept) {
    return async () => {
      pendingId = id;
      pendingLabel = label;
      paint();
      const reply = await request(path, { method: "POST", body: JSON.stringify(body) });
      if (!accept(reply)) throw new Error("request failed: 502 The Home did not confirm that change.");
      await load();
    };
  }

  function createJob() {
    const crypto = doc.defaultView && doc.defaultView.crypto;
    const raw = crypto && crypto.randomUUID ? crypto.randomUUID() : `r${Date.now()}`;
    const requestId = String(raw).replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 128) || "request";
    return post("create", "Creating", "/api/apps/system/agents/create", {
      display_name: text(nameInput.value),
      agent_host: text(hostInput.value),
      request_id: requestId,
    }, (created) => created && typeof created.agent_id === "string" && created.active === false);
  }

  function turnJob(agent, active) {
    return post(agent.agent_id, active ? "Turning on" : "Turning off", "/api/apps/system/agents/activate", {
      agent_id: agent.agent_id,
      active,
    }, (updated) => updated && updated.agent_id === agent.agent_id && updated.active === active);
  }

  createButton.addEventListener("click", () => run(createJob()));
  retryButton.addEventListener("click", () => run(retry));
  paint();
  return { load: () => run(load) };
}
