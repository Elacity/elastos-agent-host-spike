// The Documents surface against a fake fetch and a fake document.
// Run: node --test examples/docs-viewer/surface/reader.test.mjs
//
// The fake elements, document and responses are the capsule kit's
// (examples/capsule-kit/surface/test-kit.mjs).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  MAX_DOCUMENTS,
  PAGES_ROUTE,
  PAGES_SCHEMA,
  TOKEN_HEADER,
  launchToken,
  mountReader,
  readPages,
} from "./browser/reader.js";
import { MAX_BLOCKS } from "./browser/docs-render.js";
import { fakeDocument as kitDocument, response } from "../../capsule-kit/surface/test-kit.mjs";

const TOKEN = "launch-token-for-this-frame";
const HOSTILE = '<img src=x onerror="fetch(\'/api/apps/home/state\')">';
const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const bytes = (path) => readFileSync(new URL(path, import.meta.url));

const IDS = ["titles", "article", "status", "skipped", "skipped-title"];
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

const span = (text, style = "plain") => ({ style, text });

function pages(documents, skipped = []) {
  return { schema: PAGES_SCHEMA, shelf: "localhost://Users/self/.AppData/App/docs-viewer/shelf.json", documents, skipped };
}

function doc(order, blocks, extra = {}) {
  return {
    order,
    uri: `localhost://Users/self/Documents/${order}.md`,
    mime: "text/markdown",
    title: `Doc ${order}`,
    bytes: 10,
    blocks,
    ...extra,
  };
}

const ALL_KINDS = [
  { kind: "heading", level: 2, spans: [span("Title")] },
  { kind: "paragraph", spans: [span("a "), span("b", "strong"), span(" "), span("c", "em"), span("d", "code")] },
  { kind: "list", ordered: false, items: [[span("one")], [span("two")]] },
  { kind: "list", ordered: true, items: [[span("first")]] },
  { kind: "quote", spans: [span("q")] },
  { kind: "rule" },
  { kind: "code", text: "fn x() {}\n<b>not bold</b>" },
];

/** The tag and text tree of an element. */
function tree(node) {
  if (node.children.length === 0) return [node.tag, node.textContent];
  return [node.tag, node.children.map(tree)];
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

test("it draws each block kind as its element, with text only", async () => {
  const { view } = await mounted({ [PAGES_ROUTE]: response(200, pages([doc(0, ALL_KINDS)])) });
  assert.deepEqual(view.article.children.map(tree), [
    ["h2", [["span", "Title"]]],
    ["p", [["span", "a "], ["strong", "b"], ["span", " "], ["em", "c"], ["code", "d"]]],
    ["ul", [["li", [["span", "one"]]], ["li", [["span", "two"]]]]],
    ["ol", [["li", [["span", "first"]]]]],
    ["blockquote", [["span", "q"]]],
    ["hr", ""],
    ["pre", [["code", "fn x() {}\n<b>not bold</b>"]]],
  ]);
  assert.equal(view.status.textContent, "");
});

test("markup in a document stays text", async () => {
  const blocks = [{ kind: "paragraph", spans: [span(HOSTILE)] }, { kind: "code", text: HOSTILE }];
  const { view } = await mounted({
    [PAGES_ROUTE]: response(200, pages([doc(0, blocks, { title: HOSTILE })], [{ order: 1, message: HOSTILE }])),
  });
  assert.deepEqual(view.article.children.map(tree), [
    ["p", [["span", HOSTILE]]],
    ["pre", [["code", HOSTILE]]],
  ]);
  assert.equal(view.titles.children[0].children[0].textContent, HOSTILE);
  assert.equal(view.skipped.children[0].textContent, `Document 2: ${HOSTILE}`);
});

test("it never requests a path: the uri fields are dropped unread", async () => {
  const { requests, reader } = await mounted({
    [PAGES_ROUTE]: response(200, pages([doc(0, ALL_KINDS), doc(1, [{ kind: "rule" }])])),
  });
  assert.deepEqual(requests.map((request) => request.url), [PAGES_ROUTE]);
  for (const document of reader.state.documents) {
    assert.deepEqual(Object.keys(document).sort(), ["blocks", "order", "title"]);
  }
});

test("it makes one request, a GET with the launch token and nothing else", async () => {
  const { requests } = await mounted({ [PAGES_ROUTE]: response(200, pages([])) });
  assert.equal(requests.length, 1);
  const [{ url, options }] = requests;
  assert.equal(url, PAGES_ROUTE);
  assert.deepEqual(options, {
    method: "GET",
    headers: { [TOKEN_HEADER]: TOKEN },
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
  });
});

test("without a launch token it asks for nothing", async () => {
  const { requests, view } = await mounted({ [PAGES_ROUTE]: response(200, pages([])) }, { hash: "" });
  assert.equal(requests.length, 0);
  assert.equal(view.status.textContent, "Open Documents from Home.");
});

test("a refusal is shown as its text", async () => {
  const refused = await mounted({ [PAGES_ROUTE]: response(403, { error: "this launch is not bound to pages" }) });
  assert.equal(refused.view.status.textContent, "this launch is not bound to pages");
  const unreadable = await mounted({ [PAGES_ROUTE]: response(500, null) });
  assert.equal(unreadable.view.status.textContent, "Documents could not read this (500).");
  const long = await mounted({ [PAGES_ROUTE]: response(403, { error: "x".repeat(500) }) });
  assert.equal(long.view.status.textContent.length, 201);
});

test("pages that are not ones are refused", async () => {
  assert.throws(() => readPages(null), /not Documents pages/);
  assert.throws(() => readPages({ ...pages([]), schema: "elastos.photo-viewer.playlist/v1" }), /not Documents pages/);
  const many = pages(Array.from({ length: MAX_DOCUMENTS + 1 }, (_, n) => doc(n, [])));
  assert.throws(() => readPages(many), /more than 8 documents/);
  const shown = await mounted({ [PAGES_ROUTE]: response(200, { schema: "other" }) });
  assert.equal(shown.view.status.textContent, "These are not Documents pages.");
  assert.equal(shown.view.article.children.length, 0);
});

test("a document with a block it cannot read is not shown, and the rest are", () => {
  const { documents, skipped } = readPages(
    pages([
      doc(0, [{ kind: "script", text: "alert(1)" }]),
      doc(1, [{ kind: "paragraph", spans: "not a list" }]),
      doc(2, Array.from({ length: MAX_BLOCKS + 1 }, () => ({ kind: "rule" }))),
      doc(3, [{ kind: "list", items: [[span("a")], "x"] }]),
      doc(4, [{ kind: "rule" }]),
      doc(4, [{ kind: "rule" }]),
      doc(-1, []),
    ]),
  );
  assert.deepEqual(documents.map((document) => document.order), [4]);
  assert.deepEqual(
    skipped.map((skip) => skip.order),
    [0, 1, 2, 3, 4, null],
  );
});

test("an unknown style is plain and a heading level stays within 1 to 6", () => {
  const { documents } = readPages(
    pages([
      doc(0, [
        { kind: "heading", level: 9, spans: [span("deep")] },
        { kind: "heading", level: 0, spans: [span("top")] },
        { kind: "paragraph", spans: [{ style: "script", text: "x" }, { style: "link", text: "y" }] },
      ]),
    ]),
  );
  const [deep, top, paragraph] = documents[0].blocks;
  assert.equal(deep.level, 6);
  assert.equal(top.level, 1);
  assert.deepEqual(paragraph.spans.map((s) => s.tag), ["span", "span"]);
});

test("a style named after an inherited property is plain", () => {
  const names = ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf"];
  const { documents } = readPages(
    pages([doc(0, [{ kind: "paragraph", spans: names.map((style) => ({ style, text: style })) }])]),
  );
  const tags = documents[0].blocks[0].spans.map((s) => s.tag);
  assert.deepEqual(tags, names.map(() => "span"));
  // Each is a name the page can create an element from.
  for (const tag of tags) assert.equal(typeof tag, "string");
});

test("the titles and the arrow keys switch documents, in shelf order", async () => {
  const { reader, view, env } = await mounted({
    [PAGES_ROUTE]: response(
      200,
      pages([doc(2, [{ kind: "paragraph", spans: [span("third")] }]), doc(0, [{ kind: "paragraph", spans: [span("first")] }])]),
    ),
  });
  const text = () => view.article.children[0].children[0].textContent;
  assert.deepEqual(view.titles.children.map((li) => li.children[0].textContent), ["Doc 0", "Doc 2"]);
  assert.equal(text(), "first");
  assert.equal(view.titles.children[0].children[0].ariaCurrent, "page");
  view.titles.children[1].children[0].listeners.click();
  assert.equal(text(), "third");
  assert.equal(view.titles.children[0].children[0].ariaCurrent, null);
  const key = (name) => env.document.listeners.keydown({ key: name, preventDefault() {} });
  key("ArrowRight");
  assert.equal(text(), "first");
  key("ArrowLeft");
  assert.equal(text(), "third");
  assert.equal(reader.state.index, 1);
});

test("the shipped renderer matches the kit owner", () => {
  assert.deepEqual(bytes("./browser/docs-render.js"), bytes("../../capsule-kit/surface/docs-render.js"));
});

test("the page has no way to hold or reach anything else", () => {
  const page = source("./browser/reader.js");
  const renderer = source("./browser/docs-render.js");
  const main = source("./browser/main.js");
  for (const code of [page, renderer, main]) {
    for (const forbidden of [
      "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(",
      "localStorage", "sessionStorage", "indexedDB", "document.cookie", "postMessage", "WebSocket",
      "XMLHttpRequest", "EventSource", "sendBeacon", "import(", "http://", "https://", "window.open",
      "href", "src", "setAttribute", "location.assign", "createElementNS",
    ]) {
      assert.ok(!code.includes(forbidden), `${forbidden} in the page`);
    }
  }
  // One fetch call site, inside the client, across the whole page.
  assert.equal(page.match(/fetchFn\(/g).length, 1);
  for (const code of [page, renderer, main]) {
    assert.ok(!/\bfetch\s*\(/.test(code), "no fetch outside the client");
  }
  assert.equal(main.trim(), 'import { mountReader } from "./reader.js";\n\nmountReader(window);');

  const html = source("./browser/index.html");
  assert.ok(!/<script(?![^>]*\bsrc=)/.test(html), "no inline script");
  assert.ok(!/\son[a-z]+=/i.test(html), "no inline handler");
  assert.ok(!/<style/i.test(html), "no inline style");
  const loaded = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(loaded, ["./reader.css", "./main.js"]);

  const manifest = JSON.parse(source("./capsule.json"));
  assert.equal(manifest.name, "docs-reader");
  assert.equal(manifest.role, "viewer");
  assert.equal(manifest.execution, "web-projection");
  assert.deepEqual(manifest.capabilities ?? [], []);
  assert.deepEqual(manifest.permissions ?? {}, {});
  assert.deepEqual(manifest.requires ?? [], []);
});

test("it reads the pages the core writes, every block, and shows their markup as text", async () => {
  const written = JSON.parse(source("./fixtures/pages.json"));
  const { documents, skipped } = readPages(written);
  // Every document the core wrote is shown, and every one it skipped is listed.
  assert.deepEqual(documents.map((d) => d.order), written.documents.map((d) => d.order));
  assert.deepEqual(skipped.map((s) => s.order), written.skipped.map((s) => s.order));
  for (const [at, document] of documents.entries()) {
    assert.equal(document.blocks.length, written.documents[at].blocks.length, "no block was dropped");
  }
  const kinds = new Set(documents.flatMap((d) => d.blocks.map((b) => b.kind)));
  assert.deepEqual([...kinds].sort(), ["code", "heading", "list", "paragraph", "quote", "rule"]);

  const { view, reader } = await mounted({ [PAGES_ROUTE]: response(200, written) });
  const hostile = reader.state.documents.findIndex((d) => d.title.includes("onerror"));
  reader.next();
  reader.next();
  assert.equal(reader.state.index, hostile);
  const texts = view.article.children.flatMap((block) => block.children.map((child) => child.textContent));
  assert.ok(texts.some((text) => text.includes("<script>alert(1)</script>")), texts.join("|"));
  assert.ok(texts.some((text) => text.includes("the guide (javascript:")), texts.join("|"));
  assert.ok(texts.some((text) => text.includes("[image: a cat]")), texts.join("|"));
});
