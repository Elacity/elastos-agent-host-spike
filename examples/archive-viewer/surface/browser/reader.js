// Archive: the render-only surface for the archive-viewer view.
//
// It holds nothing but the launch token Runtime put in this frame's fragment,
// and reads only one route: the view bound to this launch. The core already
// listed every entry and turned each shown text entry into the documents
// model's typed blocks, so the page only draws them: each text goes through
// `textContent`, and every entry path is shown as text, never as a path.
//
// It never builds a path or URI (the `uri` fields are dropped unread), never
// fetches an entry, draws no image on Bus v1 (an image entry is a listed row
// only), and has no storage, messages or other network.
//
// Everything it touches comes in through `env` (the window in a browser), so
// the tests can drive it with a fake fetch and a fake document.
//
// The structure follows examples/docs-viewer/surface/browser/reader.js.

export const VIEW_ROUTE = "/api/viewers/archive-reader/view";
export const VIEW_SCHEMA = "elastos.archive-viewer.view/v1";
export const TOKEN_HEADER = "x-elastos-home-token";

// The same bounds the archive-viewer core applies (examples/archive-viewer):
// P8's 256 entries, the request's eight shown entries, and the documents
// model's block caps.
export const MAX_ENTRIES = 256;
export const MAX_PREVIEWS = 8;
export const MAX_BLOCKS = 512;
export const MAX_SPANS = 256;
export const MAX_ITEMS = 256;
const MAX_TEXT_CHARS = 20000;
const MAX_MESSAGE_CHARS = 200;

/** A view field that the view itself holds; an inherited name is not its own. */
function own(value, key) {
  return Object.hasOwn(Object(value), key) ? value[key] : undefined;
}

/** An entry's kind: only this table's own names select a label. */
const KINDS = { file: "File", directory: "Directory", archive: "Archive", other: "Other" };

function kindLabel(kind) {
  return typeof kind === "string" && Object.hasOwn(KINDS, kind) ? KINDS[kind] : "Other";
}

const STYLES = { plain: "span", strong: "strong", em: "em", code: "code" };

function styleTag(style) {
  return typeof style === "string" && Object.hasOwn(STYLES, style) ? STYLES[style] : "span";
}

/** The launch token from `#home_token=...`, or "". */
export function launchToken(hash) {
  return new URLSearchParams(String(hash || "").replace(/^#/, "")).get("home_token") || "";
}

function isCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function cut(value, chars, fallback) {
  const text = typeof value === "string" ? value : fallback;
  return text.length > chars ? `${text.slice(0, chars)}…` : text;
}

function readSpans(spans) {
  if (!Array.isArray(spans) || spans.length > MAX_SPANS) return null;
  return spans.map((span) => ({
    tag: styleTag(own(span, "style")),
    text: cut(own(span, "text"), MAX_TEXT_CHARS, ""),
  }));
}

/** One block of a preview, or null when it is not one of the six kinds. */
function readBlock(block) {
  switch (own(block, "kind")) {
    case "heading": {
      const spans = readSpans(own(block, "spans"));
      const level = own(block, "level");
      if (!spans || !Number.isSafeInteger(level)) return null;
      return { kind: "heading", level: Math.min(6, Math.max(1, level)), spans };
    }
    case "paragraph":
    case "quote": {
      const spans = readSpans(own(block, "spans"));
      return spans && { kind: own(block, "kind"), spans };
    }
    case "list": {
      const items = own(block, "items");
      if (!Array.isArray(items) || items.length > MAX_ITEMS) return null;
      const read = items.map(readSpans);
      if (read.some((item) => !item)) return null;
      return { kind: "list", ordered: own(block, "ordered") === true, items: read };
    }
    case "code":
      return { kind: "code", text: cut(own(block, "text"), MAX_TEXT_CHARS, "") };
    case "rule":
      return { kind: "rule" };
    default:
      return null;
  }
}

/** One listed entry, or null when it is not one this page can draw. */
function readEntry(entry) {
  const index = own(entry, "index");
  const compressed = own(entry, "compressed_size");
  const uncompressed = own(entry, "uncompressed_size");
  const method = own(entry, "method");
  if (!isCount(index) || !isCount(compressed) || !isCount(uncompressed) || !isCount(method)) return null;
  return {
    index,
    path: cut(own(entry, "path"), MAX_TEXT_CHARS, ""),
    kind: kindLabel(own(entry, "kind")),
    compressed,
    uncompressed,
    method,
    status: cut(own(entry, "status"), MAX_MESSAGE_CHARS, ""),
    reason: cut(own(entry, "reason"), MAX_MESSAGE_CHARS, ""),
  };
}

/** One shown entry's preview, or null when its blocks are not readable ones. */
function readPreview(preview) {
  const index = own(preview, "index");
  const blocksIn = own(preview, "blocks");
  if (!isCount(index) || !Array.isArray(blocksIn) || blocksIn.length > MAX_BLOCKS) return null;
  const blocks = blocksIn.map(readBlock);
  if (blocks.some((block) => !block)) return null;
  return { index, blocks };
}

/**
 * What to draw, from the view's JSON. Throws on a view that is not one.
 * An entry or preview that cannot be read becomes a "not shown" line; nothing
 * from the view is used except the fields named here, and no `uri` is kept.
 */
export function readView(value) {
  if (!value || typeof value !== "object" || own(value, "schema") !== VIEW_SCHEMA) {
    throw new Error("These are not Archive views.");
  }
  const entriesIn = own(value, "entries");
  const previewsIn = own(value, "previews");
  const skippedIn = own(value, "skipped");
  if (Array.isArray(entriesIn) ? entriesIn.length > MAX_ENTRIES : entriesIn !== undefined) {
    throw new Error(`The view has more than ${MAX_ENTRIES} entries.`);
  }
  if (Array.isArray(previewsIn) ? previewsIn.length > MAX_PREVIEWS : previewsIn !== undefined) {
    throw new Error(`The view has more than ${MAX_PREVIEWS} previews.`);
  }

  const archiveIn = own(value, "archive");
  const archive = {
    uri: cut(own(archiveIn, "uri"), MAX_TEXT_CHARS, ""),
    size: isCount(own(archiveIn, "size")) ? own(archiveIn, "size") : 0,
  };

  const entries = [];
  const skipped = [];
  for (const entry of Array.isArray(entriesIn) ? entriesIn : []) {
    const read = readEntry(entry);
    if (read) entries.push(read);
    else skipped.push({ index: null, message: "This entry could not be read." });
  }
  entries.sort((a, b) => a.index - b.index);

  const previews = [];
  for (const preview of Array.isArray(previewsIn) ? previewsIn : []) {
    const read = readPreview(preview);
    if (read) previews.push(read);
    else skipped.push({ index: null, message: "This preview could not be read." });
  }
  previews.sort((a, b) => a.index - b.index);

  for (const skip of (Array.isArray(skippedIn) ? skippedIn : []).slice(0, MAX_PREVIEWS)) {
    const index = own(skip, "index");
    skipped.push({
      index: isCount(index) ? index : null,
      message: cut(own(skip, "message"), MAX_MESSAGE_CHARS, "Not shown."),
    });
  }

  const refusedIn = own(value, "refused");
  const refused = refusedIn && typeof refusedIn === "object"
    ? {
        message:
          cut(own(refusedIn, "message"), MAX_MESSAGE_CHARS, "This archive could not be read.") ||
          "This archive could not be read.",
      }
    : null;
  return { archive, entries, previews, skipped, refused };
}

/** The only request this page makes. */
export function readerClient(fetchFn, token) {
  return {
    async view() {
      const response = await fetchFn(VIEW_ROUTE, {
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
        const error = new Error(cut(reason || null, MAX_MESSAGE_CHARS, `Archive could not read this (${response.status}).`));
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

/** One entry as a listed row: its path is text, and its facts are text. */
function drawEntry(doc, entry) {
  const row = doc.createElement("li");
  const path = doc.createElement("span");
  path.textContent = entry.path;
  row.appendChild(path);
  const facts = doc.createElement("span");
  facts.textContent =
    `${entry.kind}; method ${entry.method}; declared ${entry.compressed} compressed, ` +
    `${entry.uncompressed} uncompressed; ${entry.status}`;
  if (entry.reason) facts.textContent += `; ${entry.reason}`;
  row.appendChild(facts);
  return row;
}

/** One preview: the entry's path as text, then its blocks. */
function drawPreview(doc, preview, pathFor) {
  const section = doc.createElement("section");
  const title = doc.createElement("h3");
  title.textContent = pathFor(preview.index);
  section.appendChild(title);
  for (const block of preview.blocks) section.appendChild(drawBlock(doc, block));
  return section;
}

/** Mounts the viewer on `env.document`. Returns its state (for tests). */
export function mountReader(env) {
  const doc = env.document;
  const byId = (id) => doc.getElementById(id);
  const view = {
    archive: byId("archive"),
    entries: byId("entries"),
    previews: byId("previews"),
    status: byId("status"),
    skipped: byId("skipped"),
    skippedTitle: byId("skipped-title"),
  };
  const state = { archive: null, entries: [], previews: [], ready: null };
  const setStatus = (text) => {
    view.status.textContent = text;
  };

  function renderSkipped(skipped) {
    for (const skip of skipped) {
      const line = doc.createElement("li");
      line.textContent = skip.index === null ? skip.message : `Entry ${skip.index + 1}: ${skip.message}`;
      view.skipped.appendChild(line);
    }
    view.skippedTitle.hidden = skipped.length === 0;
  }

  const token = launchToken(env.location && env.location.hash);
  if (!token) {
    setStatus("Open an archive from Home.");
    state.ready = Promise.resolve();
    return { state, ready: () => state.ready };
  }
  const client = readerClient(env.fetch.bind(env), token);

  state.ready = (async () => {
    try {
      const read = readView(await client.view());
      state.archive = read.archive;
      view.archive.textContent = read.archive.uri
        ? `${read.archive.uri} (${read.archive.size} bytes)`
        : `Archive (${read.archive.size} bytes)`;
      // A refused archive has no listing to trust: the reason is the whole
      // view, and any entries or previews beside it are not drawn.
      if (read.refused) {
        state.entries = [];
        state.previews = [];
        setStatus(read.refused.message);
        return;
      }
      state.entries = read.entries;
      state.previews = read.previews;
      renderSkipped(read.skipped);

      for (const entry of read.entries) view.entries.appendChild(drawEntry(doc, entry));

      const byIndex = new Map(read.entries.map((entry) => [entry.index, entry.path]));
      for (const preview of read.previews) {
        const pathFor = (index) => byIndex.get(index) ?? `Entry ${index + 1}`;
        view.previews.appendChild(drawPreview(doc, preview, pathFor));
      }

      if (read.entries.length === 0) setStatus("This archive has no entries to show.");
      else if (read.previews.length === 0) setStatus("No text preview is shown.");
    } catch (error) {
      setStatus(error.message);
    }
  })();

  return { state, ready: () => state.ready };
}
