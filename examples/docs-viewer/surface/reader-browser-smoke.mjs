// The real Documents page in real Chromium, framed the way Home frames apps.
//
// A local server stands in for Runtime. It serves the surface files with the
// headers Runtime sends for an app, answers the CORS preflight as the gateway
// front door does, and stands in for the one Documents route. The page is
// framed in Home's opaque sandbox (capsules/home-gui/browser/shell-windows.js).
//
// Copied from examples/photo-viewer/surface/photos-browser-smoke.mjs: the
// headers, the sandbox and the checks are the same; the routes and the content
// are the Documents ones. There is no Runtime seam for docs-reader (the one
// that exists serves image-viewer only), so this stand-in is the only server
// the page has run against.
//
// Run: node examples/docs-viewer/surface/reader-browser-smoke.mjs
import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "../../../scripts/system-uiux-fixture.mjs";

const browserRoot = fileURLToPath(new URL("./browser/", import.meta.url));
const TOKEN = "smoke-launch-token";
const SANDBOX = "allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts";
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

const requests = [];
const server = createServer(async (request, response) => {
  const origin = `http://${request.headers.host}`;
  const url = new URL(request.url, origin);
  requests.push(`${request.method} ${url.pathname}`);
  const opaque = request.headers.origin === "null";
  const cors = opaque ? { "access-control-allow-origin": "null", vary: "Origin" } : {};
  const isolation = { "cross-origin-opener-policy": "same-origin", "cross-origin-embedder-policy": "require-corp" };

  if (url.pathname === "/") {
    // Home: frames the app in an opaque sandbox.
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", ...isolation });
    response.end(
      `<!doctype html><title>Home</title><iframe id="app" sandbox="${SANDBOX}" ` +
        `src="/apps/docs-reader/?home_origin=${encodeURIComponent(origin)}#home_token=${TOKEN}" ` +
        `width="800" height="600"></iframe>`,
    );
    return;
  }
  if (url.pathname.startsWith("/apps/docs-reader/")) {
    const name = url.pathname.slice("/apps/docs-reader/".length) || "index.html";
    if (!["index.html", "main.js", "reader.js", "reader.css"].includes(name)) {
      response.writeHead(404).end();
      return;
    }
    const types = { html: "text/html; charset=utf-8", js: "application/javascript", css: "text/css" };
    const headers = {
      "content-type": types[name.split(".").pop()],
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "access-control-allow-origin": "null",
      "cross-origin-resource-policy": "cross-origin",
      "referrer-policy": "no-referrer",
      ...isolation,
    };
    if (name === "index.html") {
      // Runtime's app policy, as served (browser_capsules.rs).
      headers["content-security-policy"] =
        `sandbox allow-scripts allow-forms allow-downloads; default-src ${origin}; ` +
        `script-src 'self' 'wasm-unsafe-eval'; style-src ${origin} 'unsafe-inline'; ` +
        `img-src ${origin} blob: data:; connect-src ${origin} ws://${request.headers.host}; ` +
        `frame-src ${origin}; object-src 'none'; base-uri 'none'; form-action ${origin}`;
    }
    response.writeHead(200, headers);
    response.end(await readFile(join(browserRoot, name)));
    return;
  }
  if (url.pathname.startsWith("/api/") && request.method === "OPTIONS") {
    // As the gateway front door answers a preflight from an app frame.
    response.writeHead(204, {
      ...cors,
      "access-control-allow-methods": "GET, POST, PUT, DELETE, HEAD",
      "access-control-allow-headers": "content-type,x-elastos-home-token",
    });
    response.end();
    return;
  }
  if (request.headers["x-elastos-home-token"] !== TOKEN || !opaque) {
    response.writeHead(403, { "content-type": "application/json", ...cors });
    response.end(JSON.stringify({ error: "refused by the smoke server" }));
    return;
  }
  if (url.pathname === "/api/viewers/docs-reader/pages" && request.method === "GET") {
    response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store", ...cors });
    response.end(JSON.stringify(PAGES));
    return;
  }
  response.writeHead(404, cors).end();
});

server.listen(0, "127.0.0.1");
await once(server, "listening");
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  const problems = [];
  page.on("console", (message) => {
    if (message.type() === "error") problems.push(message.text());
  });
  page.on("pageerror", (error) => problems.push(String(error)));
  page.on("requestfailed", (request) => problems.push(`failed: ${request.url()} ${request.failure()?.errorText}`));
  await page.goto(`${base}/`);
  const frame = page.frameLocator("#app");

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
  await browser.close();
  server.close();
}
