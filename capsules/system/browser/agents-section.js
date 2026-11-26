const OFF = "Off until you turn it on";
const ON = "On";
const NOT_BUILT = "agents are not built into this Runtime";
const NOT_ON = "agents are not turned on for this Home";
const HOME_OFF = "Agents are off for this Home";

function text(value) {
  return typeof value === "string" ? value.trim() : "";
}

function refusal(error) {
  const found = text(error && error.message).match(/^request failed: \d{3}\s+([\s\S]+)$/);
  const body = (found && found[1].trim()) || "";
  if (body.charAt(0) === "{") {
    try {
      const parsed = JSON.parse(body);
      if (parsed && typeof parsed.code === "string") {
        const sentence = text(parsed.reason);
        return { code: parsed.code, text: sentence || body };
      }
    } catch (ignored) {
      text(ignored);
    }
  }
  return { code: "", text: body || "The Home did not answer." };
}

function reason(error) {
  return refusal(error).text;
}

// A bad reply is this page's refusal. 422 keeps Retry off. A lost answer has no
// status, and a real 5xx still comes from the server as 500 or higher.
function pageRefusal(message) {
  return new Error(`request failed: 422 ${message}`);
}

function retryable(error) {
  const code = text(error && error.message).match(/^request failed: (\d{3})\b/);
  return !code || Number(code[1]) >= 500;
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

export function bindAgents(doc, request, confirmStepUp) {
  const [listNode, statusNode, formNode, nameInput, hostInput, createButton, allowButton, retryButton] = [
    "#agents-list", "#agents-status", "#agent-form", "#agent-name", "#agent-host", "#agent-create", "#agent-allow", "#agent-retry",
  ].map((id) => doc.querySelector(id));
  if (!listNode || !statusNode || !formNode || !nameInput || !hostInput || !createButton || !allowButton || !retryButton) return { load() {} };
  let agents = [], pendingId = "", pendingLabel = "", failure = "", retry = null, busy = false, gate = "wait", stopping = new Set(), running = new Set(), unknownNotes = new Map();

  function paint() {
    const banner = failure || (pendingId === "create" || pendingId === "allow" ? pendingLabel : "");
    statusNode.textContent = banner || (gate === "missing" ? "Agents are not built into this Runtime" : gate === "off" ? HOME_OFF : "");
    formNode.hidden = gate !== "ready";
    allowButton.hidden = gate !== "off";
    allowButton.disabled = busy;
    retryButton.hidden = !retry;
    createButton.disabled = busy || gate !== "ready";
    const rows = agents.map((agent) => {
      const pending = pendingId === agent.agent_id ? pendingLabel : "";
      const named = unknownNotes.get(agent.agent_id);
      const label = pending || (named ? `${stopping.has(agent.agent_id) ? "Stopping. " : ""}Unknown step: ${named}` : stopping.has(agent.agent_id) ? "Stopping" : running.has(agent.agent_id) ? "Running" : stateText(agent, ""));
      const state = el(doc, "div", "pc2-card-sublabel", label);
      state.dataset.agentState = agent.agent_id;
      const agentId = el(doc, "div", "pc2-card-sublabel", text(agent.agent_id));
      agentId.dataset.agentId = agent.agent_id;
      const button = el(doc, "button", "pc2-btn pc2-btn-secondary", agent.active === true ? "Turn off" : "Turn on");
      button.type = "button";
      button.disabled = busy || (agent.active !== true && agent.active !== false);
      button.addEventListener("click", () => run(turnJob(agent, agent.active !== true)));
      const actions = el(doc, "div");
      actions.append(button);
      if (agent.active === true) {
        const start = el(doc, "button", "pc2-btn pc2-btn-secondary", "Start");
        start.type = "button";
        start.disabled = busy || stopping.has(agent.agent_id) || running.has(agent.agent_id);
        start.addEventListener("click", () => run(startJob(agent)));
        actions.append(start);
      }
      // Stop stays while the agent is off, so a guest that is already running
      // can be ended without turning the agent back on.
      const stop = el(doc, "button", "pc2-btn pc2-btn-secondary", "Stop");
      stop.type = "button";
      stop.disabled = busy;
      stop.addEventListener("click", () => run(stopJob(agent)));
      actions.append(stop);
      const copy = el(doc, "div");
      copy.append(el(doc, "div", "pc2-card-label", text(agent.display_name) || "Unnamed agent"), agentId, state);
      const row = el(doc, "div", "pc2-card-row");
      row.append(copy, actions);
      return row;
    });
    for (const [id, named] of unknownNotes) {
      if (agents.some((agent) => agent.agent_id === id)) continue;
      const state = el(doc, "div", "pc2-card-sublabel", `Unknown step: ${named}`);
      state.dataset.agentState = id; rows.push(state);
    }
    if (gate === "ready" && !rows.length && !failure && pendingId !== "create") rows.push(el(doc, "p", "pc2-card-sublabel", "You have no agents on this Home. Agents created on another Home stay there."));
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
      if (retryable(error)) retry = job;
    } finally {
      busy = false;
      pendingId = "";
      pendingLabel = "";
      paint();
    }
  }

  async function load() {
    let body;
    try {
      body = await request("/api/apps/system/agents");
    } catch (error) {
      const why = reason(error);
      if (why === NOT_BUILT || why === NOT_ON) {
        gate = why === NOT_ON ? "off" : "missing";
        agents = [];
        return;
      }
      throw error;
    }
    if (!body || !Array.isArray(body.agents)) throw pageRefusal("The Home did not list agents.");
    agents = body.agents;
    gate = "ready";
    // The list is this Home's agent file. It does not read the Runtime's
    // stopping mark, so a reload shows the stored on/off state.
    stopping.clear(); running.clear(); unknownNotes.clear();
  }

  function post(id, label, path, body, accept) {
    return async () => {
      pendingId = id;
      pendingLabel = label;
      paint();
      const reply = await request(path, { method: "POST", body: body ? JSON.stringify(body) : undefined });
      if (!accept(reply)) throw pageRefusal("The Home did not confirm that change.");
      if (id === "create") nameInput.value = "";
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

  function allowJob() {
    return post("allow", "Allowing", "/api/apps/system/agents/enable", null, (reply) => reply && reply.enabled === true);
  }

  function startJob(agent) {
    const id = agent.agent_id;
    return async () => {
      pendingId = id;
      pendingLabel = `Start ${id}`;
      paint();
      if (typeof confirmStepUp !== "function") {
        throw pageRefusal("Open System from Home to verify your passkey.");
      }
      const stepUpToken = await confirmStepUp(agent);
      let reply;
      try {
        reply = await request("/api/apps/system/agents/launch", {
          method: "POST",
          body: JSON.stringify({ agent_id: id, step_up_token: stepUpToken }),
        });
      } catch (error) {
        const found = refusal(error);
        if (found.code === "agent_stopping") stopping.add(id);
        if (found.code === "agent_already_running") running.add(id);
        throw error;
      }
      if (!reply || reply.agent_id !== id || typeof reply.session_id !== "string") {
        throw pageRefusal("The Home did not confirm that change.");
      }
      await load();
    };
  }

  function stopJob(agent) {
    const id = agent.agent_id;
    return async () => {
      pendingId = id;
      pendingLabel = "Stopping";
      paint();
      let reply;
      try {
        reply = await request("/api/apps/system/agents/stop", { method: "POST", body: JSON.stringify({ agent_id: id }) });
      } catch (error) {
        const found = refusal(error);
        if (found.code === "agent_already_stopped" || found.code === "agent_no_session") {
          stopping.delete(id);
          running.delete(id);
        }
        throw error;
      }
      const stopped = reply && Array.isArray(reply.stopped) ? reply.stopped : [];
      const still = reply && Array.isArray(reply.stopping) ? reply.stopping : [];
      const unknown = reply && Array.isArray(reply.unknown) ? reply.unknown : [];
      if (!reply || reply.agent_id !== id || (!stopped.length && !still.length && !unknown.length)) {
        throw pageRefusal("The Home did not confirm that change.");
      }
      const note = unknown.map((step) => `${text(step.request_id)} ${text(step.outcome)}`.trim()).filter(Boolean).join(", ");
      try { await load(); } catch (error) { if (note) unknownNotes.set(id, note); if (still.length) stopping.add(id); else stopping.delete(id); throw error; }
      if (note) unknownNotes.set(id, note);
      if (still.length) stopping.add(id);
      else stopping.delete(id);
      running.delete(id);
    };
  }

  createButton.addEventListener("click", () => { if (gate === "ready") run(createJob()); });
  allowButton.addEventListener("click", () => { if (gate === "off") run(allowJob()); });
  retryButton.addEventListener("click", () => run(retry));
  paint();
  return { load: () => run(load) };
}
