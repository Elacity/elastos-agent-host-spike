// Documents: the render-only surface for the docs-viewer pages.
//
// It holds nothing but the launch token Runtime put in this frame's fragment,
// and reads only one route: the pages bound to this launch. The core already
// parsed every document into typed blocks of text, so the page only draws
// them: each block and span becomes an element whose text is set with
// textContent. It never builds a path or URI (the `uri` fields are dropped
// unread), never follows a link (a link is text), never loads an image (an
// image is text), and has no storage, messages or other network.
//
// Everything it touches comes in through `env` (the window in a browser), so
// the tests can drive it with a fake fetch and a fake document.
//
// The structure follows examples/photo-viewer/surface/browser/photos.js.

export const PAGES_ROUTE = "/api/viewers/docs-reader/pages";
export const PAGES_SCHEMA = "elastos.docs-viewer.pages/v1";
export const TOKEN_HEADER = "x-elastos-home-token";

// The same bounds the docs-viewer core applies (examples/docs-viewer).
export const MAX_DOCUMENTS = 8;
export const MAX_BLOCKS = 512;
export const MAX_SPANS = 256;
export const MAX_ITEMS = 256;
const MAX_TITLE_CHARS = 120;
const MAX_MESSAGE_CHARS = 200;
// A span is at most a whole document; this only guards the page.
const MAX_TEXT_CHARS = 20000;
const STYLES = { plain: "span", strong: "strong", em: "em", code: "code" };

/** The element for a span style: only STYLES' own names, anything else is plain. */
function styleTag(style) {
  return typeof style === "string" && Object.hasOwn(STYLES, style) ? STYLES[style] : "span";
}

/** The launch token from `#home_token=...`, or "". */
export function launchToken(hash) {
  return new URLSearchParams(String(hash || "").replace(/^#/, "")).get("home_token") || "";
}

function isPosition(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function cut(value, chars, fallback) {
  const text = typeof value === "string" ? value : fallback;
  return text.length > chars ? `${text.slice(0, chars)}…` : text;
}

function readSpans(spans) {
  if (!Array.isArray(spans) || spans.length > MAX_SPANS) return null;
  return spans.map((span) => ({
    tag: styleTag(span && span.style),
    text: cut(span && span.text, MAX_TEXT_CHARS, ""),
  }));
}

/** One block, or null when it is not one of the six kinds. */
function readBlock(block) {
  switch (block && block.kind) {
    case "heading": {
      const spans = readSpans(block.spans);
      if (!spans || !Number.isSafeInteger(block.level)) return null;
      return { kind: "heading", level: Math.min(6, Math.max(1, block.level)), spans };
    }
    case "paragraph":
    case "quote": {
      const spans = readSpans(block.spans);
      return spans && { kind: block.kind, spans };
    }
    case "list": {
      if (!Array.isArray(block.items) || block.items.length > MAX_ITEMS) return null;
      const items = block.items.map(readSpans);
      if (items.some((item) => !item)) return null;
      return { kind: "list", ordered: block.ordered === true, items };
    }
    case "code":
      return { kind: "code", text: cut(block.text, MAX_TEXT_CHARS, "") };
    case "rule":
      return { kind: "rule" };
    default:
      return null;
  }
}

/**
 * What to show, from the pages' JSON. Throws on pages that are not ones.
 * A document that cannot be read becomes a "not shown" line; nothing from a
 * document is used except its position, title and blocks.
 */
export function readPages(value) {
  if (!value || typeof value !== "object" || value.schema !== PAGES_SCHEMA) {
    throw new Error("These are not Documents pages.");
  }
  const documentsIn = Array.isArray(value.documents) ? value.documents : [];
  const skippedIn = Array.isArray(value.skipped) ? value.skipped : [];
  if (documentsIn.length > MAX_DOCUMENTS) {
    throw new Error(`The pages have more than ${MAX_DOCUMENTS} documents.`);
  }
  const documents = [];
  const skipped = [];
  const seen = new Set();
  for (const document of documentsIn) {
    const order = document && document.order;
    if (!isPosition(order) || seen.has(order)) {
      skipped.push({ order: isPosition(order) ? order : null, message: "This entry could not be read." });
      continue;
    }
    seen.add(order);
    const blocksIn = Array.isArray(document.blocks) ? document.blocks : null;
    if (!blocksIn || blocksIn.length > MAX_BLOCKS) {
      skipped.push({ order, message: "This document could not be read." });
      continue;
    }
    const blocks = blocksIn.map(readBlock);
    if (blocks.some((block) => !block)) {
      skipped.push({ order, message: "This document has a block that could not be read." });
      continue;
    }
    documents.push({ order, title: cut(document.title, MAX_TITLE_CHARS, `Document ${order + 1}`), blocks });
  }
  for (const skip of skippedIn.slice(0, MAX_DOCUMENTS)) {
    const order = skip && skip.order;
    skipped.push({
      order: isPosition(order) ? order : null,
      message: cut(skip && skip.message, MAX_MESSAGE_CHARS, "Not shown."),
    });
  }
  documents.sort((a, b) => a.order - b.order);
  skipped.sort((a, b) => (a.order ?? Infinity) - (b.order ?? Infinity));
  return { documents, skipped };
}

/** The only request this page makes. */
export function readerClient(fetchFn, token) {
  return {
    async pages() {
      const response = await fetchFn(PAGES_ROUTE, {
        method: "GET",
        headers: { [TOKEN_HEADER]: token },
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
      });
      if (!response.ok) {
        let reason = "";
        try {
          const body = await response.json();
          reason = body && typeof body.error === "string" ? body.error : "";
        } catch {
          reason = "";
        }
        const error = new Error(cut(reason || null, MAX_MESSAGE_CHARS, `Documents could not read this (${response.status}).`));
        error.status = response.status;
        throw error;
      }
      return response.json();
    },
  };
}

/** Draws one block as elements; every text goes through textContent. */
function drawBlock(doc, block) {
  const spansInto = (parent, spans) => {
    for (const span of spans) {
      const element = doc.createElement(span.tag);
      element.textContent = span.text;
      parent.appendChild(element);
    }
    return parent;
  };
  switch (block.kind) {
    case "heading":
      return spansInto(doc.createElement(`h${block.level}`), block.spans);
    case "paragraph":
      return spansInto(doc.createElement("p"), block.spans);
    case "quote":
      return spansInto(doc.createElement("blockquote"), block.spans);
    case "list": {
      const list = doc.createElement(block.ordered ? "ol" : "ul");
      for (const item of block.items) list.appendChild(spansInto(doc.createElement("li"), item));
      return list;
    }
    case "code": {
      const pre = doc.createElement("pre");
      const code = doc.createElement("code");
      code.textContent = block.text;
      pre.appendChild(code);
      return pre;
    }
    default:
      return doc.createElement("hr");
  }
}

/** Mounts the reader on `env.document`. Returns its controls (for tests). */
export function mountReader(env) {
  const doc = env.document;
  const byId = (id) => doc.getElementById(id);
  const view = {
    titles: byId("titles"),
    article: byId("article"),
    status: byId("status"),
    skipped: byId("skipped"),
    skippedTitle: byId("skipped-title"),
  };
  const state = { documents: [], index: 0, buttons: [], ready: null };
  const setStatus = (text) => {
    view.status.textContent = text;
  };

  const token = launchToken(env.location && env.location.hash);
  if (!token) {
    setStatus("Open Documents from Home.");
    state.ready = Promise.resolve();
    return controls();
  }
  const client = readerClient(env.fetch.bind(env), token);

  function show(index) {
    if (state.documents.length === 0) return;
    state.index = ((index % state.documents.length) + state.documents.length) % state.documents.length;
    const document = state.documents[state.index];
    view.article.replaceChildren(...document.blocks.map((block) => drawBlock(doc, block)));
    state.buttons.forEach((button, at) => {
      button.ariaCurrent = at === state.index ? "page" : null;
    });
  }

  function renderSkipped(skipped) {
    for (const skip of skipped) {
      const line = doc.createElement("li");
      line.textContent = skip.order === null ? skip.message : `Document ${skip.order + 1}: ${skip.message}`;
      view.skipped.appendChild(line);
    }
    view.skippedTitle.hidden = skipped.length === 0;
  }

  doc.addEventListener("keydown", (event) => {
    if (event.key === "ArrowLeft") show(state.index - 1);
    else if (event.key === "ArrowRight") show(state.index + 1);
    else return;
    event.preventDefault();
  });

  state.ready = (async () => {
    try {
      const { documents, skipped } = readPages(await client.pages());
      state.documents = documents;
      renderSkipped(skipped);
      documents.forEach((document, at) => {
        const item = doc.createElement("li");
        const button = doc.createElement("button");
        button.type = "button";
        button.textContent = document.title;
        button.addEventListener("click", () => show(at));
        item.appendChild(button);
        view.titles.appendChild(item);
        state.buttons.push(button);
      });
      if (documents.length === 0) {
        setStatus("There are no documents to show.");
        return;
      }
      show(0);
    } catch (error) {
      setStatus(error.message);
    }
  })();

  function controls() {
    return {
      state,
      ready: () => state.ready,
      next: () => show(state.index + 1),
      previous: () => show(state.index - 1),
    };
  }
  return controls();
}
