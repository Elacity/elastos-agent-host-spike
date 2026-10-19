/* Home shows versions the journal already recorded. This screen does not
   mint a grant, and choosing a row does not change the page. The saved
   page is examples/agent-host/file-versions.json. */

export function hostPath(text) {
  return (
    typeof text === "string" &&
    (text.startsWith("/") || text.includes("\\") || text.split("/").some((part) => part === ".."))
  );
}

export function versionRows(resource, observations) {
  if (typeof resource !== "string" || resource.length === 0 || hostPath(resource)) {
    return [];
  }
  const rows = [];
  for (const row of Array.isArray(observations) ? observations : []) {
    if (!row || row.resource !== resource || typeof row.text !== "string") {
      continue;
    }
    if (!Number.isSafeInteger(row.version) || row.version < 0) {
      continue;
    }
    const existing = rows.find((item) => item.version === row.version);
    if (existing) {
      existing.text = row.text;
    } else {
      rows.push({ version: row.version, text: row.text });
    }
  }
  rows.sort((left, right) => left.version - right.version);
  return rows;
}

export function currentVersion(resource, observations) {
  if (typeof resource !== "string" || resource.length === 0 || hostPath(resource)) {
    return null;
  }
  const list = Array.isArray(observations) ? observations : [];
  for (let index = list.length - 1; index >= 0; index -= 1) {
    const row = list[index];
    if (row && row.resource === resource && Number.isSafeInteger(row.version)) {
      return row.version;
    }
  }
  return null;
}

export function proposeRestore(resource, observations, version) {
  const rows = versionRows(resource, observations);
  const found = rows.find((row) => row.version === version);
  if (!found) {
    return { error: "unknown", step: null };
  }
  if (currentVersion(resource, observations) !== version) {
    return { error: "stale", step: null };
  }
  return {
    error: null,
    step: {
      kind: "restore",
      resource,
      version,
      text: found.text,
      state: "prepared",
      grant: null,
    },
  };
}

export function fileVersionsFromSummary(summary) {
  const block =
    summary && typeof summary.file_versions === "object" && summary.file_versions
      ? summary.file_versions
      : null;
  if (!block) {
    return { resource: "", observations: [] };
  }
  const resource = typeof block.resource === "string" ? block.resource : "";
  const observations = Array.isArray(block.observations) ? block.observations : [];
  return { resource, observations };
}

export function denyWithoutGrant(step) {
  if (!step || step.grant != null || step.state !== "prepared") {
    return step;
  }
  return { ...step, state: "denied" };
}

function statusCopy(code) {
  if (code === "stale") {
    return "That wording is not current. Read it again before restoring.";
  }
  if (code === "unknown") {
    return "That version is not in the list.";
  }
  if (code === "prepared") {
    return "Restore is prepared. The page is unchanged.";
  }
  if (code === "denied") {
    return "Denied. Nothing was written.";
  }
  if (code === "empty") {
    return "This file has not been read.";
  }
  return "";
}

export function mountVersionList(root, model = {}) {
  const resource = typeof model.resource === "string" ? model.resource : "";
  const observations = Array.isArray(model.observations) ? model.observations : [];
  const rows = versionRows(resource, observations);
  const current = currentVersion(resource, observations);
  const currentRow = rows.find((row) => row.version === current) || null;
  let step = null;

  root.replaceChildren();
  const panel = document.createElement("div");
  panel.className = "version-list-panel";

  const title = document.createElement("h2");
  title.className = "version-list-title";
  title.id = "version-list-title";
  title.textContent = "Versions";
  panel.appendChild(title);

  const name = document.createElement("p");
  name.className = "version-list-resource";
  name.textContent = resource && !hostPath(resource) ? resource : "No file";
  panel.appendChild(name);

  const pageLabel = document.createElement("p");
  pageLabel.className = "version-list-kicker";
  pageLabel.textContent = "Current page";
  panel.appendChild(pageLabel);

  const page = document.createElement("pre");
  page.className = "version-list-page";
  page.dataset.currentPage = "";
  page.textContent = currentRow ? currentRow.text : "";
  panel.appendChild(page);

  const list = document.createElement("ol");
  list.className = "version-list-rows";
  if (rows.length === 0) {
    const empty = document.createElement("li");
    empty.className = "version-list-empty";
    empty.textContent = statusCopy("empty");
    list.appendChild(empty);
  }
  for (const row of rows) {
    const item = document.createElement("li");
    item.className = "version-list-row";
    item.dataset.versionRow = String(row.version);
    if (row.version === current) {
      item.setAttribute("aria-current", "true");
    }
    const number = document.createElement("span");
    number.className = "version-list-number";
    number.textContent = String(row.version);
    const text = document.createElement("span");
    text.className = "version-list-text";
    text.textContent = row.text;
    const restore = document.createElement("button");
    restore.className = "el-button version-list-restore";
    restore.type = "button";
    restore.dataset.restore = String(row.version);
    restore.textContent = `Restore version ${row.version}`;
    restore.addEventListener("click", () => {
      const result = proposeRestore(resource, observations, row.version);
      if (result.step) {
        step = result.step;
      }
      renderProposal();
      setStatus(result.error || "prepared");
    });
    item.append(number, text, restore);
    list.appendChild(item);
  }
  panel.appendChild(list);

  const status = document.createElement("p");
  status.className = "version-list-status";
  status.dataset.status = rows.length === 0 ? "empty" : "ready";
  status.setAttribute("role", "status");
  status.textContent = rows.length === 0 ? statusCopy("empty") : "The list is not a grant.";
  panel.appendChild(status);

  const proposal = document.createElement("p");
  proposal.className = "version-list-proposal";
  proposal.dataset.proposal = "";
  proposal.dataset.grant = "absent";
  proposal.hidden = true;
  panel.appendChild(proposal);

  const send = document.createElement("button");
  send.className = "el-button el-button-primary version-list-send";
  send.type = "button";
  send.dataset.send = "";
  send.disabled = true;
  send.textContent = "Send";
  send.addEventListener("click", () => {
    if (!step) {
      return;
    }
    step = denyWithoutGrant(step);
    renderProposal();
    setStatus(step?.state === "denied" ? "denied" : "prepared");
  });
  panel.appendChild(send);

  function setStatus(code) {
    status.dataset.status = code;
    status.textContent = statusCopy(code);
  }

  function renderProposal() {
    if (!step) {
      proposal.hidden = true;
      proposal.dataset.proposal = "";
      proposal.dataset.grant = "absent";
      proposal.textContent = "";
      send.disabled = true;
      return;
    }
    proposal.hidden = false;
    proposal.dataset.proposal = step.state;
    proposal.dataset.grant = step.grant == null ? "absent" : "present";
    proposal.textContent =
      step.state === "denied"
        ? "Denied. The page was not written."
        : "Prepared. Waiting for a grant that this screen does not have.";
    send.disabled = step.state !== "prepared";
  }

  root.appendChild(panel);
  return { rows, current, pageText: page.textContent };
}

let versionSheet = null;
let versionBody = null;
let readVersionModel = () => ({ resource: "", observations: [] });

export function bindVersionList(options = {}) {
  if (typeof options.readModel === "function") {
    readVersionModel = options.readModel;
  }
  if (versionSheet) {
    return;
  }
  versionSheet = document.querySelector("#version-list-sheet");
  versionBody = document.querySelector("#version-list-body");
  document.querySelector("#identity-menu-versions")?.addEventListener("click", () => {
    const model = readVersionModel();
    window.setTimeout(() => {
      loadSavedVersions(model).then((loaded) => showVersionList(loaded));
    }, 0);
  });
  document.querySelector("#version-list-close")?.addEventListener("click", () => {
    hideVersionList();
  });
}

export async function loadSavedVersions(model) {
  const resource = typeof model?.resource === "string" ? model.resource : "";
  if (resource.length > 0) {
    return model || { resource: "", observations: [] };
  }
  try {
    const response = await fetch(new URL("./file-versions.json", import.meta.url));
    if (!response.ok) {
      return { resource: "", observations: [] };
    }
    const saved = await response.json();
    if (!saved || typeof saved.resource !== "string" || hostPath(saved.resource)) {
      return { resource: "", observations: [] };
    }
    return {
      resource: saved.resource,
      observations: Array.isArray(saved.observations) ? saved.observations : [],
    };
  } catch (_error) {
    return { resource: "", observations: [] };
  }
}

export function showVersionList(model) {
  if (!versionSheet || !versionBody) {
    return;
  }
  versionSheet.hidden = false;
  versionSheet.removeAttribute("inert");
  mountVersionList(versionBody, model || { resource: "", observations: [] });
}

export function hideVersionList() {
  if (!versionSheet) {
    return;
  }
  versionSheet.hidden = true;
  versionSheet.setAttribute("inert", "");
}
