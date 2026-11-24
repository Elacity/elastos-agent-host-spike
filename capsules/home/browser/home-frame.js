// The owner's Home paints one stored document. Each block is an element.
// Text is textContent. An image is its name, unless the caller supplies a
// read of a grant this owner already holds. Nothing here builds a script,
// a link, or a byte URL.

export function paintFrame(root, frame, readImage) {
  const doc = root.ownerDocument;
  root.replaceChildren();
  root.dir = "auto";
  root.style.maxWidth = "100%";
  root.style.overflowWrap = "anywhere";
  const nodes = frame && Array.isArray(frame.nodes) ? frame.nodes : [];
  for (const block of nodes) {
    root.appendChild(paintBlock(doc, block, readImage));
  }
  if (nodes.length === 0) root.setAttribute("hidden", "");
  else root.removeAttribute("hidden");
}

function paintBlock(doc, block, readImage) {
  const kind = block && typeof block.kind === "string" ? block.kind : "";
  if (kind === "heading") {
    const level = Number(block.level);
    const tag = level >= 1 && level <= 6 ? "h" + level : "p";
    return spans(doc.createElement(tag), block.spans, doc);
  }
  if (kind === "paragraph") return spans(doc.createElement("p"), block.spans, doc);
  if (kind === "code") {
    const pre = box(doc.createElement("pre"));
    const code = box(doc.createElement("code"));
    code.textContent = String(block.text == null ? "" : block.text);
    pre.appendChild(code);
    return pre;
  }
  if (kind === "quote") {
    const quote = box(doc.createElement("blockquote"));
    const paragraphs = Array.isArray(block.paragraphs) ? block.paragraphs : [];
    for (const paragraph of paragraphs) {
      quote.appendChild(spans(doc.createElement("p"), paragraph, doc));
    }
    return quote;
  }
  if (kind === "list") {
    const list = box(doc.createElement(block.ordered === true ? "ol" : "ul"));
    const items = Array.isArray(block.items) ? block.items : [];
    for (const item of items) {
      const line = box(doc.createElement("li"));
      if (item && Array.isArray(item.blocks)) {
        for (const nested of item.blocks) line.appendChild(paintBlock(doc, nested, readImage));
      } else {
        spans(line, item && item.spans, doc);
      }
      list.appendChild(line);
    }
    return list;
  }
  if (kind === "rule") return box(doc.createElement("hr"));
  if (kind === "image") return paintImage(doc, block, readImage);
  return spans(doc.createElement("p"), [], doc);
}

function paintImage(doc, block, readImage) {
  const resource = String(block.resource == null ? "" : block.resource);
  const alt = String(block.alt == null ? "" : block.alt);
  const name = alt !== "" ? alt : resource;
  if (block.empty === true || typeof readImage !== "function") {
    const place = box(doc.createElement("p"));
    place.textContent = name;
    return place;
  }
  const shown = readImage(resource);
  if (!shown) {
    const place = box(doc.createElement("p"));
    place.textContent = name;
    return place;
  }
  const image = box(doc.createElement("img"));
  image.alt = alt;
  image.src = String(shown);
  return image;
}

function spans(el, list, doc) {
  box(el);
  const spans = Array.isArray(list) ? list : [];
  for (const span of spans) {
    const style = span && span.style;
    const tag = style === "strong" ? "strong" : style === "emphasis" ? "em" : style === "code" ? "code" : "span";
    const node = box(doc.createElement(tag));
    node.textContent = String(span && span.text != null ? span.text : "");
    el.appendChild(node);
  }
  return el;
}

function box(el) {
  el.dir = "auto";
  el.style.maxWidth = "100%";
  el.style.overflowWrap = "anywhere";
  return el;
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
