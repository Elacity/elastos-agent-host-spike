// The Archive surface against a fake fetch and a fake view.
// Run: node --test examples/archive-viewer/surface/reader.test.mjs
//
// The fake elements, document and responses are the capsule kit's
// (examples/capsule-kit/surface/test-kit.mjs).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  MAX_BLOCKS,
  MAX_ENTRIES,
  MAX_ITEMS,
  MAX_PREVIEWS,
  MAX_SPANS,
  TOKEN_HEADER,
  VIEW_ROUTE,
  VIEW_SCHEMA,
  launchToken,
  mountReader,
  readView,
} from "./browser/reader.js";
import {
  PAGES_ROUTE,
  PAGES_SCHEMA,
  readPages,
  mountReader as mountDocsReader,
} from "../../docs-viewer/surface/browser/reader.js";
import { fakeDocument as kitDocument, response } from "../../capsule-kit/surface/test-kit.mjs";

const TOKEN = "launch-token-for-this-frame";
const HOSTILE = '<img src=x onerror="fetch(\'/api/apps/home/state\')">';
const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

const IDS = ["archive", "entries", "previews", "status", "skipped", "skipped-title"];
const fakeDocument = () => kitDocument(IDS);

/** A window with a fake fetch that serves `routes` and records each request. */
function world({ hash = `#home_token=${TOKEN}`, routes = {} } = {}) {
  const requests = [];
  const env = {
    document: fakeDocument(),
    location: { hash },
    fetch(url, options) {
      requests.push({ url, options, self: this });
      const route = routes[url];
      if (!route) return Promise.resolve(response(404, { error: "not a route here" }));
      return Promise.resolve(typeof route === "function" ? route() : route);
    },
  };
  return { env, requests };
}

const entry = (index, extra = {}) => ({
  compressed_size: 10,
  index,
  kind: "file",
  method: 0,
  path: `entry-${index}.txt`,
  status: "listed",
  uncompressed_size: 10,
  ...extra,
});

const span = (text, style = "plain") => ({ style, text });

function view({ entries = [], previews = [], skipped = [], refused } = {}) {
  return {
    archive: { size: 4096, uri: "localhost://Users/self/Downloads/trip.zip" },
    entries,
    previews,
    schema: VIEW_SCHEMA,
    skipped,
    ...(refused ? { refused } : {}),
  };
}

/** The tag and text tree of an element. */
function tree(node) {
  if (node.children.length === 0) return [node.tag, node.textContent];
  return [node.tag, node.children.map(tree)];
}

/** Every tag in the tree below `node`. */
function tags(node) {
  return [node.tag, ...node.children.flatMap(tags)];
}

async function mounted(routes, options = {}) {
  const w = world({ routes, ...options });
  const reader = mountReader(w.env);
  await reader.ready();
  return { ...w, reader, view: w.env.document.elements };
}

test("the token comes from the fragment only", () => {
  assert.equal(launchToken(`#home_token=${TOKEN}`), TOKEN);
  assert.equal(launchToken("#other=1"), "");
  assert.equal(launchToken(""), "");
});

test("it draws the listing with every entry field as text", async () => {
  const { view: drawn } = await mounted({
    [VIEW_ROUTE]: response(
      200,
      view({
        entries: [
          entry(0),
          entry(1, { kind: "directory", path: "photos/", uncompressed_size: 0, compressed_size: 0 }),
          entry(2, { kind: "blocked", status: "blocked", reason: "control_character" }),
        ],
      }),
    ),
  });
  assert.deepEqual(drawn.entries.children.map(tree), [
    ["li", [["span", "entry-0.txt"], ["span", "File; method 0; declared 10 compressed, 10 uncompressed; listed"]]],
    ["li", [["span", "photos/"], ["span", "Directory; method 0; declared 0 compressed, 0 uncompressed; listed"]]],
    [
      "li",
      [
        ["span", "entry-2.txt"],
        ["span", "Other; method 0; declared 10 compressed, 10 uncompressed; blocked; control_character"],
      ],
    ],
  ]);
  assert.equal(drawn.archive.textContent, "localhost://Users/self/Downloads/trip.zip (4096 bytes)");
});

test("an entry path is text", async () => {
  const { view: drawn } = await mounted({
    [VIEW_ROUTE]: response(200, view({ entries: [entry(0, { path: HOSTILE })] })),
  });
  assert.deepEqual(drawn.entries.children.map(tree), [
    ["li", [["span", HOSTILE], ["span", "File; method 0; declared 10 compressed, 10 uncompressed; listed"]]],
  ]);
  assert.ok(!tags(drawn.entries).includes("img"));
});

test("the page draws no image on bus v1", async () => {
  const { view: drawn } = await mounted({
    [VIEW_ROUTE]: response(
      200,
      view({
        entries: [entry(0, { kind: "image", path: "photos/cat.png" })],
        previews: [
          {
            index: 0,
            blocks: [
              { kind: "image", src: "localhost://Users/self/photos/cat.png" },
              { kind: "paragraph", spans: [span(`[image: cat] ${HOSTILE}`)] },
            ],
          },
        ],
      }),
    ),
  });
  // The image kind is a listed row and an unknown kind, and the image block is
  // not readable: no image element is made, and no entry is fetched.
  assert.equal(drawn.entries.children.length, 1);
  assert.match(drawn.entries.children[0].children[1].textContent, /^Other; /);
  assert.equal(drawn.previews.children.length, 0);
  assert.deepEqual(drawn.skipped.children.map((line) => line.textContent), ["This preview could not be read."]);
  assert.ok(!tags(drawn.entries).includes("img"));
  assert.ok(!tags(drawn.previews).includes("img"));
});

test("a kind named after an inherited property is not drawn", () => {
  const { entries } = readView(
    view({ entries: ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"].map((kind, index) => entry(index, { kind })) }),
  );
  assert.deepEqual(entries.map((each) => each.kind), ["Other", "Other", "Other", "Other", "Other"]);
  // "Other" is a name this page can draw, not an object it found by prototype.
  for (const each of entries) assert.equal(typeof each.kind, "string");
});

test("a view key named after an inherited property is not read", () => {
  const inherited = Object.create({ entries: [entry(0)], previews: [] });
  Object.assign(inherited, { schema: VIEW_SCHEMA, archive: { size: 1, uri: "" }, skipped: [] });
  const { entries, previews } = readView(inherited);
  assert.deepEqual(entries, []);
  assert.deepEqual(previews, []);
});

test("it draws the documents model's blocks with text only", async () => {
  const blocks = [
    { kind: "heading", level: 2, spans: [span("Notes")] },
    { kind: "paragraph", spans: [span("a "), span("b", "strong"), span(" "), span("c", "em"), span("d", "code")] },
    { kind: "list", ordered: false, items: [[span("one")], [span("two")]] },
    { kind: "list", ordered: true, items: [[span("first")]] },
    { kind: "quote", spans: [span("q")] },
    { kind: "rule" },
    { kind: "code", text: `fn x() {}\n${HOSTILE}` },
  ];
  const { view: drawn } = await mounted({
    [VIEW_ROUTE]: response(200, view({ entries: [entry(0)], previews: [{ index: 0, blocks }] })),
  });
  assert.deepEqual(drawn.previews.children.map(tree), [
    [
      "section",
      [
        ["h3", "entry-0.txt"],
        ["h2", [["span", "Notes"]]],
        ["p", [["span", "a "], ["strong", "b"], ["span", " "], ["em", "c"], ["code", "d"]]],
        ["ul", [["li", [["span", "one"]]], ["li", [["span", "two"]]]]],
        ["ol", [["li", [["span", "first"]]]]],
        ["blockquote", [["span", "q"]]],
        ["hr", ""],
        ["pre", [["code", `fn x() {}\n${HOSTILE}`]]],
      ],
    ],
  ]);
});

test("an unknown style is plain and a heading level stays within 1 to 6", () => {
  const { previews } = readView(
    view({
      previews: [
        {
          index: 0,
          blocks: [
            { kind: "heading", level: 9, spans: [span("deep")] },
            { kind: "heading", level: 0, spans: [span("top")] },
            { kind: "paragraph", spans: [{ style: "script", text: "x" }, { style: "link", text: "y" }] },
          ],
        },
      ],
    }),
  );
  const [deep, top, paragraph] = previews[0].blocks;
  assert.equal(deep.level, 6);
  assert.equal(top.level, 1);
  assert.deepEqual(paragraph.spans.map((each) => each.tag), ["span", "span"]);
});

test("a style named after an inherited property is plain", () => {
  const names = ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf"];
  const { previews } = readView(
    view({ previews: [{ index: 0, blocks: [{ kind: "paragraph", spans: names.map((style) => ({ style, text: style })) }] }] }),
  );
  const tags = previews[0].blocks[0].spans.map((each) => each.tag);
  assert.deepEqual(tags, names.map(() => "span"));
  for (const tag of tags) assert.equal(typeof tag, "string");
});

test("it makes one request, a GET with the launch token and nothing else", async () => {
  const { requests } = await mounted({ [VIEW_ROUTE]: response(200, view()) });
  assert.equal(requests.length, 1);
  const [{ url, options }] = requests;
  assert.equal(url, VIEW_ROUTE);
  assert.deepEqual(options, {
    method: "GET",
    headers: { [TOKEN_HEADER]: TOKEN },
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
  });
});

test("it never requests an entry: the uri fields are dropped unread", async () => {
  const { requests, reader } = await mounted({
    [VIEW_ROUTE]: response(
      200,
      view({
        entries: [entry(0, { uri: "localhost://Users/self/secret.png" })],
        previews: [{ index: 0, blocks: [{ kind: "paragraph", spans: [span("x")] }], uri: "localhost://Users/self/x" }],
      }),
    ),
  });
  assert.deepEqual(requests.map((request) => request.url), [VIEW_ROUTE]);
  assert.deepEqual(Object.keys(reader.state.entries[0]).sort(), [
    "compressed",
    "index",
    "kind",
    "method",
    "path",
    "reason",
    "status",
    "uncompressed",
  ]);
  assert.deepEqual(Object.keys(reader.state.previews[0]).sort(), ["blocks", "index"]);
});

test("without a launch token it asks for nothing", async () => {
  const { requests, view: drawn } = await mounted({ [VIEW_ROUTE]: response(200, view()) }, { hash: "" });
  assert.equal(requests.length, 0);
  assert.equal(drawn.status.textContent, "Open an archive from Home.");
});

test("a refusal is shown as its text", async () => {
  const refused = await mounted({ [VIEW_ROUTE]: response(403, { error: "this launch is not bound to a view" }) });
  assert.equal(refused.view.status.textContent, "this launch is not bound to a view");
  const unreadable = await mounted({ [VIEW_ROUTE]: response(500, null) });
  assert.equal(unreadable.view.status.textContent, "Archive could not read this (500).");
  const long = await mounted({ [VIEW_ROUTE]: response(403, { error: "x".repeat(500) }) });
  assert.equal(long.view.status.textContent.length, 201);
});

test("a blank refusal reason is not shown as blank", async () => {
  for (const error of ["   ", "\t\n", ""]) {
    const refused = await mounted({ [VIEW_ROUTE]: response(403, { error }) });
    assert.equal(refused.view.status.textContent, "Archive could not read this (403).", JSON.stringify(error));
  }
});

test("views that are not ones are refused", () => {
  assert.throws(() => readView(null), /not Archive views/);
  assert.throws(() => readView({ ...view(), schema: "elastos.archive-viewer.open/v1" }), /not Archive views/);
  assert.throws(
    () => readView(view({ entries: Array.from({ length: MAX_ENTRIES + 1 }, (_, index) => entry(index)) })),
    new RegExp(`more than ${MAX_ENTRIES} entries`),
  );
  assert.throws(
    () => readView(view({ previews: Array.from({ length: MAX_PREVIEWS + 1 }, (_, index) => ({ blocks: [], index })) })),
    new RegExp(`more than ${MAX_PREVIEWS} previews`),
  );
});

test("a preview with more spans than the model allows is not shown", () => {
  const spans = Array.from({ length: MAX_SPANS + 1 }, () => span("x"));
  const { previews, skipped } = readView(
    view({ previews: [{ index: 0, blocks: [{ kind: "paragraph", spans }] }] }),
  );
  assert.deepEqual(previews, []);
  assert.deepEqual(skipped.map((skip) => skip.message), ["This preview could not be read."]);
});

test("a preview with more list items than the model allows is not shown", () => {
  const items = Array.from({ length: MAX_ITEMS + 1 }, () => [span("x")]);
  const { previews, skipped } = readView(
    view({ previews: [{ index: 0, blocks: [{ kind: "list", ordered: false, items }] }] }),
  );
  assert.deepEqual(previews, []);
  assert.deepEqual(skipped.map((skip) => skip.message), ["This preview could not be read."]);
});

test("a preview with more blocks than the model allows is not shown", () => {
  const blocks = Array.from({ length: MAX_BLOCKS + 1 }, () => ({ kind: "rule" }));
  const { previews, skipped } = readView(view({ previews: [{ index: 0, blocks }] }));
  assert.deepEqual(previews, []);
  assert.deepEqual(skipped.map((skip) => skip.message), ["This preview could not be read."]);
});

test("a view that is not one is not drawn", async () => {
  const shown = await mounted({ [VIEW_ROUTE]: response(200, { schema: "other" }) });
  assert.equal(shown.view.status.textContent, "These are not Archive views.");
  assert.equal(shown.view.entries.children.length, 0);
  assert.equal(shown.view.previews.children.length, 0);
});

test("an unreadable entry or preview is not shown, and the rest are", async () => {
  const { view: drawn } = await mounted({
    [VIEW_ROUTE]: response(
      200,
      view({
        entries: [{ index: "not a number", path: "x" }, entry(1)],
        previews: [
          { index: 0, blocks: [{ kind: "script", text: "alert(1)" }] },
          { index: 1, blocks: [{ kind: "paragraph", spans: [span("kept")] }] },
        ],
      }),
    ),
  });
  assert.deepEqual(drawn.entries.children.map((row) => row.children[0].textContent), ["entry-1.txt"]);
  assert.deepEqual(drawn.previews.children.map((section) => section.children[0].textContent), ["entry-1.txt"]);
  assert.deepEqual(drawn.skipped.children.map((line) => line.textContent), [
    "This entry could not be read.",
    "This preview could not be read.",
  ]);
});

test("a malformed refusal field rejects the view", async () => {
  const withRefused = (refused) => ({ ...view({ entries: [entry(0)], previews: [{ index: 0, blocks: [{ kind: "paragraph", spans: [span("not drawn")] }] }] }), refused });
  for (const malformed of [true, false, "denied", [], 1]) {
    assert.throws(() => readView(withRefused(malformed)), /not Archive views/, String(malformed));
  }
  const { view: drawn } = await mounted({ [VIEW_ROUTE]: response(200, withRefused("denied")) });
  assert.equal(drawn.status.textContent, "These are not Archive views.");
  assert.equal(drawn.entries.children.length, 0);
  assert.equal(drawn.previews.children.length, 0);
});

test("a refused archive with a blank reason still says why", async () => {
  const { view: drawn } = await mounted({
    [VIEW_ROUTE]: response(
      200,
      view({
        entries: [entry(0)],
        previews: [{ index: 0, blocks: [{ kind: "paragraph", spans: [span("not drawn")] }] }],
        refused: { code: "ambiguous_end", message: "   " },
      }),
    ),
  });
  assert.equal(drawn.status.textContent, "This archive could not be read.");
  assert.equal(drawn.entries.children.length, 0);
  assert.equal(drawn.previews.children.length, 0);
});

test("a skipped preview with a blank message still explains why", async () => {
  const { view: drawn } = await mounted({
    [VIEW_ROUTE]: response(
      200,
      view({
        skipped: [
          { index: 0, reason: "not_text", message: "   " },
          { index: 1, reason: "ratio", message: "The entry is over the ratio cap." },
        ],
      }),
    ),
  });
  assert.deepEqual(drawn.skipped.children.map((line) => line.textContent), [
    "Entry 1: Not shown. (not_text)",
    "Entry 2: The entry is over the ratio cap. (ratio)",
  ]);
});

test("a refused archive is shown with its reason and lists no entry", async () => {
  // Content beside a refusal is not drawn: the refusal is the whole view.
  const { view: drawn, reader } = await mounted({
    [VIEW_ROUTE]: response(
      200,
      view({
        entries: [entry(0)],
        previews: [{ index: 0, blocks: [{ kind: "paragraph", spans: [span("not drawn")] }] }],
        refused: { code: "ambiguous_end", message: "The archive has two end records." },
        skipped: [{ index: 0, message: "Not read.", reason: "read_budget" }],
      }),
    ),
  });
  assert.equal(drawn.status.textContent, "The archive has two end records.");
  assert.equal(drawn.entries.children.length, 0);
  assert.equal(drawn.previews.children.length, 0);
  assert.equal(drawn.skipped.children.length, 0);
  assert.deepEqual(reader.state.entries, []);
  assert.deepEqual(reader.state.previews, []);
});

test("a refused archive without a reason still says why", async () => {
  const { view: drawn } = await mounted({
    [VIEW_ROUTE]: response(200, view({ refused: { code: "ambiguous_end", message: "" } })),
  });
  assert.equal(drawn.status.textContent, "This archive could not be read.");
});

test("the page has no way to hold or reach anything else", () => {
  const page = source("./browser/reader.js");
  const main = source("./browser/main.js");
  for (const code of [page, main]) {
    for (const forbidden of [
      "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(",
      "localStorage", "sessionStorage", "indexedDB", "document.cookie", "postMessage", "WebSocket",
      "XMLHttpRequest", "EventSource", "sendBeacon", "import(", "http://", "https://", "window.open",
      "href", "src", "setAttribute", "location.assign", "createElementNS", "img",
    ]) {
      assert.ok(!code.includes(forbidden), `${forbidden} in the page`);
    }
  }
  // One fetch call site, inside the client.
  assert.equal(page.match(/fetchFn\(/g).length, 1);
  assert.ok(!/[^.]\bfetch\(/.test(page), "no other fetch");
  assert.equal(main.trim(), 'import { mountReader } from "./reader.js";\n\nmountReader(window);');

  const html = source("./browser/index.html");
  assert.ok(!/<script(?![^>]*\bsrc=)/.test(html), "no inline script");
  assert.ok(!/\son[a-z]+=/i.test(html), "no inline handler");
  assert.ok(!/<style/i.test(html), "no inline style");
  const loaded = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(loaded, ["./reader.css", "./main.js"]);

  const manifest = JSON.parse(source("./capsule.json"));
  assert.equal(manifest.name, "archive-reader");
  assert.equal(manifest.role, "viewer");
  assert.equal(manifest.execution, "web-projection");
  assert.deepEqual(manifest.capabilities ?? [], []);
  assert.deepEqual(manifest.permissions ?? {}, {});
  assert.deepEqual(manifest.requires ?? [], []);
});

const DOC_IDS = ["titles", "article", "status", "skipped", "skipped-title"];

/** The documents page's rendered blocks for one block list. */
async function documentsBlocks(blocks) {
  const document = kitDocument(DOC_IDS);
  const pages = {
    schema: PAGES_SCHEMA,
    shelf: "localhost://Users/self/.AppData/App/docs-viewer/shelf.json",
    documents: [{ order: 0, title: "t", blocks }],
    skipped: [],
  };
  const env = {
    document,
    location: { hash: `#home_token=${TOKEN}` },
    fetch: async () => response(200, pages),
  };
  const reader = mountDocsReader(env);
  await reader.ready();
  return document.elements.article.children;
}

/** One function's exact text in a source file. */
function functionSource(file, name) {
  const text = source(file);
  const start = text.indexOf(`function ${name}`);
  const open = text.indexOf("{", start);
  let depth = 0;
  for (let at = open; at < text.length; at += 1) {
    if (text[at] === "{") depth += 1;
    else if (text[at] === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(start, at + 1);
    }
  }
  throw new Error(`${name} not found in ${file}`);
}

/** One object declaration's exact text in a source file. */
function objectSource(file, name) {
  const text = source(file);
  const start = text.search(new RegExp(`(?:export )?const ${name} = `));
  const open = text.indexOf("{", start);
  let depth = 0;
  for (let at = open; at < text.length; at += 1) {
    if (text[at] === "{") depth += 1;
    else if (text[at] === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(start, at + 1);
    }
  }
  throw new Error(`${name} not found in ${file}`);
}

/** One numeric constant's value in a source file. */
function constantSource(file, name) {
  const match = source(file).match(new RegExp(`(?:export )?const ${name} = ([0-9]+);`));
  if (!match) throw new Error(`${name} not found in ${file}`);
  return match[1];
}

test("the block functions are the documents page's own", () => {
  // One text owns the rules: every function, table and cap the block rules
  // use is the documents page's, character for character, and any edit to
  // one copy is caught here.
  const documents = "../../docs-viewer/surface/browser/reader.js";
  for (const name of ["styleTag", "readSpans", "readBlock", "drawBlock", "cut"]) {
    assert.equal(functionSource("./browser/reader.js", name), functionSource(documents, name), name);
  }
  assert.equal(objectSource("./browser/reader.js", "STYLES"), objectSource(documents, "STYLES"), "STYLES");
  for (const name of ["MAX_BLOCKS", "MAX_SPANS", "MAX_ITEMS", "MAX_TEXT_CHARS", "MAX_MESSAGE_CHARS"]) {
    assert.equal(constantSource("./browser/reader.js", name), constantSource(documents, name), name);
  }
});

test("the previews follow the documents page rules", async () => {
  // One block format, two pages: every block rule of this page is compared
  // with the documents page's, so a change in either is caught here.
  const levels = [-1, 0, 1, 2, 3, 4, 5, 6, 7, 9, 3.5, "3"];
  const styleNames = ["plain", "strong", "em", "code", "script", "constructor", "__proto__", "toString", undefined, 1];
  const texts = ["", "x", HOSTILE, "x".repeat(20000), "x".repeat(20001)];
  // A seeded generator, so the comparison covers inputs no one listed.
  let seed = 12345;
  const random = () => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 2 ** 32;
  };
  const pick = (list) => list[Math.floor(random() * list.length)];
  const kinds = ["heading", "paragraph", "quote", "list", "code", "rule", "script", undefined];
  const blocks = [
    ...levels.map((level) => [{ kind: "heading", level, spans: [span("Title")] }]),
    ...styleNames.map((style) => [{ kind: "paragraph", spans: [{ style, text: String(style) }] }]),
    ...texts.map((text) => [{ kind: "code", text }]),
    [{ kind: "heading", level: 2, spans: [span("Title")] }],
    [{ kind: "paragraph", spans: [span("a "), span("b", "strong"), span("c", "em"), span("d", "code")] }],
    [{ kind: "list", ordered: false, items: [[span("one")], [span("two")]] }],
    [{ kind: "list", ordered: true, items: [[span("first")]] }],
    [{ kind: "quote", spans: [span("q")] }],
    [{ kind: "code", text: "fn x() {}\n<b>not bold</b>" }],
    [{ kind: "rule" }],
    [{ kind: "script", text: "alert(1)" }],
    [{ kind: "paragraph", spans: "not a list" }],
    [{ kind: "paragraph", spans: Array.from({ length: MAX_SPANS + 1 }, () => span("x")) }],
    [{ kind: "list", ordered: false, items: Array.from({ length: MAX_ITEMS + 1 }, () => [span("x")]) }],
    [{ kind: "list", ordered: false, items: [[span("a")], "not a list"] }],
    [{ kind: "heading", level: 9, spans: [span("deep")] }, { kind: "heading", level: 0, spans: [span("top")] }],
    [{ kind: "paragraph", spans: ["constructor", "__proto__", "toString", "hasOwnProperty"].map((style) => span(style, style)) }],
    [{ kind: "code", text: "x".repeat(20001) }],
    Array.from({ length: MAX_BLOCKS + 1 }, () => ({ kind: "rule" })),
    // Fields read through the prototype: both pages treat these the same.
    [Object.create({ kind: "paragraph", spans: [span("inherited")] })],
    [Object.assign(Object.create({ spans: [span("inherited")] }), { kind: "paragraph" })],
    [{ kind: "paragraph", spans: [Object.create({ style: "strong", text: "x" })] }],
    [Object.create({ kind: "code", text: "x" })],
    [Object.create({ kind: "script", text: "x" })],
    [null],
    ["not a block"],
    [42],
    ...Array.from({ length: 80 }, () => {
      const block = { kind: pick(kinds) };
      if (random() < 0.6) {
        block.spans = Array.from({ length: Math.floor(random() * 4) }, () => ({
          style: pick(styleNames),
          text: pick(texts),
        }));
      }
      if (random() < 0.4) block.level = pick(levels);
      if (random() < 0.3) block.items = Array.from({ length: Math.floor(random() * 4) }, () => [span("x")]);
      if (random() < 0.3) block.ordered = random() < 0.5;
      if (random() < 0.4) block.text = pick(texts);
      return [block];
    }),
  ];
  for (const [at, each] of blocks.entries()) {
    const pages = {
      schema: PAGES_SCHEMA,
      shelf: "localhost://Users/self/.AppData/App/docs-viewer/shelf.json",
      documents: [{ order: 0, title: "t", blocks: each }],
      skipped: [],
    };
    const shown = readPages(pages);
    const { previews } = readView(view({ entries: [entry(0)], previews: [{ index: 0, blocks: each }] }));
    assert.equal(previews.length > 0, shown.documents.length > 0, `case ${at}: one page keeps it, the other does not`);
    if (previews.length > 0 && shown.documents.length > 0) {
      assert.deepEqual(previews[0].blocks, shown.documents[0].blocks, `case ${at}: the block rules differ`);
      // The drawing is one rule too: the same elements and text.
      const { view: drawn } = await mounted({
        [VIEW_ROUTE]: response(200, view({ entries: [entry(0)], previews: [{ index: 0, blocks: each }] })),
      });
      const archive = drawn.previews.children[0].children.slice(1).map(tree);
      const documents = (await documentsBlocks(each)).map(tree);
      assert.deepEqual(archive, documents, `case ${at}: the block drawing differs`);
    }
  }
});

test("it reads the view the core writes, and shows its markup as text", async () => {
  const written = JSON.parse(source("./fixtures/view.json"));
  const { entries, previews, skipped } = readView(written);
  assert.deepEqual(entries.map((each) => each.index), written.entries.map((each) => each.index));
  assert.deepEqual(previews.map((each) => each.index), written.previews.map((each) => each.index));
  assert.equal(skipped.length, written.skipped.length);
  for (const [at, preview] of previews.entries()) {
    assert.equal(preview.blocks.length, written.previews[at].blocks.length, "no block was dropped");
  }

  const { view: drawn } = await mounted({ [VIEW_ROUTE]: response(200, written) });
  const paths = drawn.entries.children.map((row) => row.children[0].textContent);
  assert.deepEqual(paths, written.entries.map((each) => each.path));
  assert.ok(paths.some((path) => path.includes("<img")), "the fixture has a hostile path");
  const texts = drawn.previews.children.flatMap((section) => section.children.flatMap((block) => block.children.map((child) => child.textContent)));
  assert.ok(texts.some((text) => text.includes(HOSTILE)), texts.join("|"));
  assert.ok(!tags(drawn.entries).includes("img"));
  assert.ok(!tags(drawn.previews).includes("img"));
});
