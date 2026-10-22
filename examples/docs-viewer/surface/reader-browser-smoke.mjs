// The real Documents page in real Chromium, framed the way Home frames apps.
//
// The capsule kit's stand-in (examples/capsule-kit/surface/stand-in.mjs) plays
// Runtime and Home, as for the Photos page; here it serves the one Documents
// route. There is no Runtime seam for docs-reader (the one that exists serves
// image-viewer only), so this stand-in is the only server the page has run
// against.
//
// Run: node examples/docs-viewer/surface/reader-browser-smoke.mjs
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { inHome, standIn } from "../../capsule-kit/surface/stand-in.mjs";

const browserRoot = fileURLToPath(new URL("./browser/", import.meta.url));
const HOSTILE = '<img src=x onerror="fetch(\'/api/apps/home/state\')">';
const span = (text, style = "plain") => ({ style, text });
const PAGES = {
  schema: "elastos.docs-viewer.pages/v1",
  shelf: "localhost://Users/self/.AppData/App/docs-viewer/shelf.json",
  documents: [
    {
      order: 0,
      uri: "localhost://Users/self/Documents/notes.md",
      mime: "text/markdown",
      title: "Trip notes",
      bytes: 120,
      blocks: [
        { kind: "heading", level: 1, spans: [span("Trip notes")] },
        { kind: "paragraph", spans: [span("Pack "), span("boots", "strong"), span(" and "), span(HOSTILE, "code")] },
        { kind: "list", ordered: false, items: [[span("tent")], [span("stove")]] },
        { kind: "paragraph", spans: [span("the guide (javascript:fetch('/api/apps/home/state'))")] },
      ],
    },
    {
      order: 2,
      uri: "localhost://Users/self/Documents/todo.txt",
      mime: "text/plain",
      title: "Todo",
      bytes: 9,
      blocks: [{ kind: "paragraph", spans: [span("milk\nbread")] }],
    },
  ],
  skipped: [{ order: 1, uri: "localhost://Users/self/Documents/page.html", reason: "wrong_kind", message: HOSTILE }],
};

const { base, requests, close } = await standIn({
  app: "docs-reader",
  browserRoot,
  files: ["index.html", "main.js", "reader.js", "reader.css"],
  routes(method, path) {
    if (method === "GET" && path === "/api/viewers/docs-reader/pages") {
      return { type: "application/json", body: JSON.stringify(PAGES) };
    }
    return null;
  },
});
try {
  const problems = await inHome(base, async (frame) => {
    await frame.locator("#article h1").waitFor();
    assert.equal(await frame.locator("#article h1").textContent(), "Trip notes");
    assert.equal(await frame.locator("#article strong").textContent(), "boots");
    assert.deepEqual(await frame.locator("#article ul li").allTextContents(), ["tent", "stove"]);
    // Markup in a document and in a skipped message is text: nothing ran or loaded.
    assert.equal(await frame.locator("#article code").textContent(), HOSTILE);
    assert.equal(await frame.locator("#skipped li").textContent(), `Document 2: ${HOSTILE}`);
    assert.equal(await frame.locator("img, a, script:not([src]), iframe").count(), 0);
    assert.deepEqual(await frame.locator("#titles button").allTextContents(), ["Trip notes", "Todo"]);

    await frame.locator("#titles button", { hasText: "Todo" }).click();
    await frame.locator("#article p").filter({ hasText: "milk" }).waitFor();
    // A text document keeps its line breaks.
    assert.equal(await frame.locator("#article p").evaluate((p) => getComputedStyle(p).whiteSpace), "pre-wrap");

    // The frame is the opaque sandbox Home gives it: no storage, no cookies.
    const sandboxed = await frame.locator("body").evaluate(() => {
      try {
        window.localStorage.getItem("x");
        return false;
      } catch {
        return true;
      }
    });
    assert.equal(sandboxed, true);
  });
  const api = requests.filter((line) => line.includes(" /api/"));
  assert.deepEqual(
    api.filter((line) => line.startsWith("GET")),
    ["GET /api/viewers/docs-reader/pages"],
  );
  assert.ok(api.every((line) => /^(GET|OPTIONS) \/api\/viewers\/docs-reader\/pages$/.test(line)), api.join("\n"));
  assert.ok(!requests.some((line) => line.includes("/api/apps/home/state")), "markup in the pages ran");
  assert.deepEqual(problems, [], "console errors (CSP or script)");
  console.log("documents browser smoke: ok");
  console.log(requests.join("\n"));
} finally {
  close();
}
