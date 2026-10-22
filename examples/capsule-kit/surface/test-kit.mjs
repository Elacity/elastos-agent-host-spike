// The fakes a render-only page's node tests drive it with (capsule kit item
// A5): elements, a document and fetch responses. Moved here from
// examples/photo-viewer/surface/photos.test.mjs and
// examples/docs-viewer/surface/reader.test.mjs; each test file keeps its own
// fake window, which differs by what the page uses.

/** An element: text, flags, children and listeners. */
export function element(tag = "div") {
  return {
    tag,
    textContent: "",
    hidden: false,
    src: undefined,
    alt: "",
    type: "",
    ariaCurrent: null,
    children: [],
    listeners: {},
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    replaceChildren(...children) {
      this.children = children;
    },
    addEventListener(type, listener) {
      this.listeners[type] = listener;
    },
  };
}

/** A document with one element for each id, and its own listeners. */
export function fakeDocument(ids) {
  const elements = Object.fromEntries(ids.map((id) => [id, element()]));
  return {
    elements,
    listeners: {},
    getElementById: (id) => elements[id] ?? null,
    createElement: (tag) => element(tag),
    addEventListener(type, listener) {
      this.listeners[type] = listener;
    },
  };
}

/** A fetch response. `kind: "text"` makes `json()` parse `body` as text. */
export function response(status, body, kind = "json") {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => (kind === "json" ? body : JSON.parse(body)),
    arrayBuffer: async () => body,
  };
}
