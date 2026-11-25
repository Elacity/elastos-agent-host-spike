// The owner's Home paints one stored frame. Text is text. An image is its
// resource name. Nothing here builds a script, a link, or a byte URL.

export function bindV2App(root, appId) {
  if (!root) return;
  const id = typeof appId === "string" ? appId : "";
  if (id) root.dataset.app = id;
  else delete root.dataset.app;
  if (!id) root.replaceChildren();
}

export function clearV2App(root) {
  bindV2App(root, "");
}

export function paintFrame(root, frame) {
  root.replaceChildren();
  const nodes = frame && Array.isArray(frame.nodes) ? frame.nodes : [];
  const doc = root.ownerDocument;
  for (const node of nodes) {
    const line = doc.createElement("p");
    if (node && node.kind === "image") {
      line.textContent = String(node.resource == null ? "" : node.resource);
    } else {
      line.textContent = String(node && node.text != null ? node.text : "");
    }
    root.appendChild(line);
  }
  if (nodes.length === 0) root.setAttribute("hidden", "");
  else root.removeAttribute("hidden");
}

export function startHomeFrame(root, readFrame, intervalMs = 2000, options = {}) {
  const deadlineMs = options.deadlineMs == null ? 1500 : options.deadlineMs;
  let failures = 0;
  let busy = false;
  const hidden = () => {
    if (typeof options.hidden === "function") return options.hidden();
    return typeof document !== "undefined" && document.hidden;
  };
  const tick = async () => {
    if (hidden() || busy) return;
    busy = true;
    const controller = typeof AbortController === "undefined" ? null : new AbortController();
    let timer = 0;
    try {
      const frame = await Promise.race([
        Promise.resolve(readFrame(controller ? controller.signal : undefined)),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            if (controller) controller.abort();
            reject(new Error("deadline"));
          }, deadlineMs);
        }),
      ]);
      failures = 0;
      paintFrame(root, frame);
    } catch {
      failures += 1;
      if (failures >= 2) paintFrame(root, { nodes: [] });
    } finally {
      clearTimeout(timer);
      busy = false;
    }
  };
  tick();
  const poll = setInterval(tick, intervalMs);
  if (typeof document !== "undefined" && typeof options.hidden !== "function") {
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) tick();
    });
  }
  return poll;
}
