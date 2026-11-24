// The owner's Home paints one stored frame. Text is text. An image is its
// resource name. Nothing here builds a script, a link, or a byte URL.

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

export function startHomeFrame(root, readFrame) {
  const tick = async () => {
    try {
      paintFrame(root, await readFrame());
    } catch {
      paintFrame(root, { nodes: [] });
    }
  };
  tick();
  return setInterval(tick, 2000);
}
