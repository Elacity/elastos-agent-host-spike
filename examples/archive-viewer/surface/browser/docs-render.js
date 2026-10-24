// Docs model: the one block renderer for a typed document (kit item A5).
//
// The core has already parsed each document into typed blocks of text, so a
// page only draws them: each block and span becomes an element whose text is
// set with textContent. Nothing in a block becomes markup, a path or a
// request.
//
// This file is the one owner. A page that draws the docs model ships a copy
// at browser/docs-render.js, made by its build, and its surface test pins the
// copy to these bytes. Page glue (launch token, client, document list, page
// bounds) stays in the page.
//
// Browser-safe ESM: no node imports.

// The same bounds the docs-viewer core applies (examples/docs-viewer).
export const MAX_BLOCKS = 512;
export const MAX_SPANS = 256;
export const MAX_ITEMS = 256;
// A span is at most a whole document; this only guards the page.
export const MAX_TEXT_CHARS = 20000;

// The span style map: only its own names become an element.
export const STYLES = { plain: "span", strong: "strong", em: "em", code: "code" };

/** The element for a span style: only STYLES' own names, anything else is plain. */
export function styleTag(style) {
  return typeof style === "string" && Object.hasOwn(STYLES, style) ? STYLES[style] : "span";
}

/** `value` as a string, cut to `chars` characters. */
export function cut(value, chars, fallback) {
  const text = typeof value === "string" ? value : fallback;
  return text.length > chars ? `${text.slice(0, chars)}…` : text;
}

/** The spans of one block, or null when they are not spans. */
export function readSpans(spans) {
  if (!Array.isArray(spans) || spans.length > MAX_SPANS) return null;
  return spans.map((span) => ({
    tag: styleTag(span && span.style),
    text: cut(span && span.text, MAX_TEXT_CHARS, ""),
  }));
}

/** One block, or null when it is not one of the six kinds. */
export function readBlock(block) {
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

/** Draws one block as elements; every text goes through textContent. */
export function drawBlock(doc, block) {
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
