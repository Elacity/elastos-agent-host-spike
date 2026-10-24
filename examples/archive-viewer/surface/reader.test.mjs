// The Archive surface against a fake fetch and a fake view.
// Run: node --test examples/archive-viewer/surface/reader.test.mjs
//
// The fake elements, document and responses are the capsule kit's
// (examples/capsule-kit/surface/test-kit.mjs). The documents model's block
// rules are not this page's: its previews are drawn by ./browser/docs-render.js,
// the kit's one owner, which the first test pins to the owner's bytes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { MAX_BLOCKS } from "./browser/docs-render.js";
import {
  MAX_ENTRIES,
  MAX_PREVIEWS,
  TOKEN_HEADER,
  VIEW_ROUTE,
  VIEW_SCHEMA,
  launchToken,
  mountReader,
  readView,
} from "./browser/reader.js";
import { fakeDocument as kitDocument, response } from "../../capsule-kit/surface/test-kit.mjs";

const TOKEN = "launch-token-for-this-frame";
const HOSTILE = '<img src=x onerror="fetch(\'/api/apps/home/state\')">';
const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const bytes = (path) => readFileSync(new URL(path, import.meta.url));

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

test("the shipped renderer matches the kit owner", () => {
  // One owner: examples/capsule-kit/surface/docs-render.js. The page ships a
  // copy (script-src 'self' serves its own folder) and this pins the bytes.
  assert.deepEqual(bytes("./browser/docs-render.js"), bytes("../../capsule-kit/surface/docs-render.js"));
});

test("the page keeps the renderer in one place", () => {
  const page = source("./browser/reader.js");
  const importLine = page.match(/^import .*from "\.\/docs-render\.js";$/m);
  assert.ok(importLine, "the page imports the shared renderer");
  for (const name of ["MAX_BLOCKS", "cut", "drawBlock", "readBlock"]) {
    assert.ok(importLine[0].includes(name), `${name} comes from the shared renderer`);
  }
  // No second copy of a renderer rule: the functions and the style table are
  // the owner's, and this page only draws its own listing rows.
  for (const name of ["readBlock", "drawBlock", "readSpans", "styleTag"]) {
    assert.ok(!new RegExp(`function ${name}\\b`).test(page), `${name} is defined here`);
    assert.ok(!new RegExp(`\\bconst ${name}\\b`).test(page), `${name} is defined here`);
  }
  assert.ok(!/\bSTYLES\b/.test(page), "the style table is the owner's");
});

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
  // F37: the path is a name from the archive, so it reaches the row as text.
  const { view: drawn } = await mounted({
    [VIEW_ROUTE]: response(200, view({ entries: [entry(0, { path: HOSTILE })] })),
  });
  assert.deepEqual(drawn.entries.children.map(tree), [
    ["li", [["span", HOSTILE], ["span", "File; method 0; declared 10 compressed, 10 uncompressed; listed"]]],
  ]);
  assert.ok(!tags(drawn.entries).includes("img"));
});

test("the page draws no image on bus v1", async () => {
  // F38: an image entry is a listed row, and an image block is not a block
  // the documents model can read. Nothing here makes an image element.
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
  assert.equal(drawn.entries.children.length, 1);
  assert.match(drawn.entries.children[0].children[1].textContent, /^Other; /);
  assert.equal(drawn.previews.children.length, 0);
  assert.deepEqual(drawn.skipped.children.map((line) => line.textContent), ["This preview could not be read."]);
  assert.ok(!tags(drawn.entries).includes("img"));
  assert.ok(!tags(drawn.previews).includes("img"));
});

test("a kind named after an inherited property is not drawn", () => {
  // F39: only KINDS' own names select a label, so an inherited Object name
  // cannot pick a drawing branch.
  const { entries } = readView(
    view({
      entries: ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"].map((kind, index) =>
        entry(index, { kind }),
      ),
    }),
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

test("it draws the shared renderer's blocks with text only", async () => {
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
  assert.throws(() => readView({ ...view(), entries: "x" }), /not Archive views/);
  assert.throws(() => readView({ ...view(), previews: { 0: {} } }), /not Archive views/);
  assert.throws(
    () => readView(view({ entries: Array.from({ length: MAX_ENTRIES + 1 }, (_, index) => entry(index)) })),
    new RegExp(`more than ${MAX_ENTRIES} entries`),
  );
  assert.throws(
    () => readView(view({ previews: Array.from({ length: MAX_PREVIEWS + 1 }, (_, index) => ({ blocks: [], index })) })),
    new RegExp(`more than ${MAX_PREVIEWS} previews`),
  );
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
  const withRefused = (refused) => ({
    ...view({
      entries: [entry(0)],
      previews: [{ index: 0, blocks: [{ kind: "paragraph", spans: [span("not drawn")] }] }],
    }),
    refused,
  });
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
  const shipped = ["./browser/reader.js", "./browser/docs-render.js", "./browser/main.js", "./browser/reader.css"];
  for (const path of shipped) {
    const code = source(path);
    for (const forbidden of [
      "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(",
      "localStorage", "sessionStorage", "indexedDB", "document.cookie", "postMessage", "WebSocket",
      "XMLHttpRequest", "EventSource", "sendBeacon", "import(", "http://", "https://", "window.open",
      "href", "img", "setAttribute", "location.assign", "createElementNS",
    ]) {
      assert.ok(!code.includes(forbidden), `${forbidden} in ${path}`);
    }
  }
  const page = source("./browser/reader.js");
  // One fetch call site, inside the client.
  assert.equal(page.match(/fetchFn\(/g).length, 1);
  assert.ok(!/[^.]\bfetch\(/.test(page), "no other fetch");
  assert.equal(source("./browser/main.js").trim(), 'import { mountReader } from "./reader.js";\n\nmountReader(window);');

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
  const texts = drawn.previews.children.flatMap((section) =>
    section.children.flatMap((block) => block.children.map((child) => child.textContent)),
  );
  assert.ok(texts.some((text) => text.includes(HOSTILE)), texts.join("|"));
  assert.ok(!tags(drawn.entries).includes("img"));
  assert.ok(!tags(drawn.previews).includes("img"));
});
