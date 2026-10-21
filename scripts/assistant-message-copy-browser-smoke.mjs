#!/usr/bin/env node
// Copy on an Assistant message reaches the device clipboard through Home.
// The real Assistant capsule runs opaque-sandboxed inside an opaque Home GUI
// frame, as installed; the top document runs the real Home Clipboard host and
// prompt. Copy on a sent message writes the typed text, Copy on a reply writes
// its Markdown source, Copy on a code block writes the code, and a cancelled or
// oversized copy says so in the row instead of doing nothing.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "./system-uiux-fixture.mjs";

const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const homeToken = "assistant-copy-fixture";
const typed = "Why is the sky blue?  Keep <it> short & exact.";
const reply = [
  "**Rayleigh scattering**: shorter wavelengths scatter more.",
  "",
  "```js",
  "const answer = 42;",
  "```",
  "",
  "- blue scatters ~5.5× more than red",
].join("\n");
const oversized = `${"x".repeat(65_537)}`;
const workspace = {
  schema: "elastos.assistant.workspace/v2",
  revision: 1,
  document: {
    v: 1, activeSessionId: "copy-room", sessionMode: "chat", liveOfferId: "", selectedModelCid: null,
    composerDraft: { text: "", parts: [] }, projects: [], usageTurns: [],
    sessions: [{
      id: "copy-room", title: "Copy room", mode: "chat", composerDraft: { text: "", parts: [] },
      messages: [
        { role: "user", text: typed, modelText: typed },
        { role: "agent", text: reply },
        { role: "user", text: "And a long one?", modelText: "And a long one?" },
        { role: "agent", text: oversized },
      ],
    }],
  },
};

const errors = [];
const server = createServer(async (req, res) => {
  const url = new URL(req.url, "http://fixture");
  const origin = `http://127.0.0.1:${server.address().port}`;
  const headers = {
    "access-control-allow-origin": "null",
    "access-control-allow-headers": "content-type,x-elastos-home-token",
    "access-control-allow-methods": "GET,POST,PUT,OPTIONS",
    "cache-control": "no-store",
  };
  const send = (status, type, body) => { res.writeHead(status, { ...headers, "content-type": type }); res.end(body); };
  const json = (value, status = 200) => send(status, "application/json", JSON.stringify(value));
  try {
    if (req.method === "OPTIONS") { res.writeHead(204, headers); res.end(); return; }
    if (url.pathname === "/") {
      // Home: the trusted top document, its Clipboard prompt and host. App
      // frames bind on their first exact home:app-ready, as in Home.
      send(200, "text/html", `<!doctype html><style>html,body,iframe{width:100%;height:100%;margin:0;border:0}</style>
        <iframe id="gui" title="Home GUI" sandbox="allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts"
          src="/gui?home_origin=${encodeURIComponent(origin)}"></iframe>
        <section id="home-clipboard-prompt" role="dialog" aria-modal="true" aria-hidden="true" hidden
          style="position:fixed;inset:auto 0 0 0;background:#fff;padding:16px">
          <h1 id="home-clipboard-title">Clipboard request</h1><p id="home-clipboard-copy"></p>
          <button id="home-clipboard-allow" type="button">Continue</button>
          <button id="home-clipboard-cancel" type="button">Cancel</button>
        </section>
        <script type="module">
          import { createHomeClipboardFrameState, createHomeClipboardHost, createHomeClipboardPrompt } from "/apps/home/home-clipboard-host.js";
          const written = [];
          const prompt = createHomeClipboardPrompt({
            root: document.querySelector("#home-clipboard-prompt"),
            title: document.querySelector("#home-clipboard-title"),
            copy: document.querySelector("#home-clipboard-copy"),
            allowButton: document.querySelector("#home-clipboard-allow"),
            cancelButton: document.querySelector("#home-clipboard-cancel"),
          });
          const host = createHomeClipboardHost({
            clipboard: { readText: () => navigator.clipboard.readText(),
              async writeText(text) { written.push(text); return navigator.clipboard.writeText(text); } },
            prompt,
          });
          const app = { targetId: "assistant", homeToken: ${JSON.stringify(homeToken)}, origin: "null",
            parentOrigin: location.origin, source: null, clipboardState: createHomeClipboardFrameState() };
          window.__home = { written, bound: () => Boolean(app.source) };
          addEventListener("message", event => {
            const data = event.data;
            if (!data || typeof data !== "object" || data.homeToken !== app.homeToken || event.origin !== app.origin) return;
            const ready = data.type === "home:app-ready" && Object.keys(data).sort().join() === "homeToken,type";
            if (!app.source) { if (!ready) return; app.source = event.source; }
            if (app.source !== event.source) return;
            const context = { kind: "app-frame", ...app };
            if (ready) { host.resetFrame(app.clipboardState, context); return; }
            host.handle(event, context, data);
          });
        </script>`);
      return;
    }
    if (url.pathname === "/gui") {
      // Home GUI: hosts the Assistant frame and raises its room once ready.
      const homeOrigin = url.searchParams.get("home_origin");
      send(200, "text/html", `<!doctype html><style>html,body,iframe{width:100%;height:100%;margin:0;border:0}</style>
        <iframe title="Assistant" sandbox="allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts" allow="autoplay; fullscreen"
          src="/apps/assistant/?home_origin=${encodeURIComponent(homeOrigin)}#home_token=${homeToken}"></iframe>
        <script>addEventListener('message',event=>{if(event.data?.type==='home-agent:ready'){
          event.source.postMessage({type:'home-agent:open'},'*');
          event.source.postMessage({type:'home-agent:shelf-handover',on:true},'*');}});</script>`);
      return;
    }
    if (url.pathname.startsWith("/api/")) {
      assert.equal(req.headers["x-elastos-home-token"], homeToken);
      for await (const _chunk of req);
      if (url.pathname === "/api/apps/assistant/workspace-v2" && req.method === "GET") { json(workspace); return; }
      if (url.pathname === "/api/apps/assistant/workspace-v2") { json({ error: "fixture is read-only" }, 409); return; }
      if (url.pathname === "/api/provider/model/offers_list") { json({ offers: [] }); return; }
      if (url.pathname === "/api/capsules/catalog") {
        json({ schema: "elastos.capsules.catalog/v1", model_catalog_state: "verified", capsules: [] }); return;
      }
      throw new Error(`Unexpected API operation: ${req.method} ${url.pathname}`);
    }
    if (url.pathname === "/favicon.ico") { res.writeHead(204); res.end(); return; }
    const match = url.pathname.match(/^\/apps\/(assistant|home)\/(.*)$/);
    assert.ok(match, `Unexpected asset: ${url.pathname}`);
    const base = resolve(root, "capsules", match[1], "browser");
    const path = resolve(base, match[2] || "index.html");
    assert.ok(path.startsWith(`${base}/`));
    send(200, ({ ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css",
      ".svg": "image/svg+xml", ".woff2": "font/woff2" })[extname(path)] || "application/octet-stream", await readFile(path));
  } catch (error) { errors.push(String(error)); json({ error: "fixture failure" }, 500); }
});

let browser, stage = "launch";
const pageErrors = [];
try {
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true, ...(process.env.BRAVE_BIN ? { executablePath: process.env.BRAVE_BIN } : {}) });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin });
  const page = await context.newPage();
  page.on("pageerror", error => pageErrors.push(`${stage}: ${error}`));
  await page.goto(`${origin}/`);
  const frame = page.frameLocator("#gui").frameLocator("iframe");
  const rows = frame.locator(".agent-msg");
  await rows.nth(3).waitFor({ state: "attached" });
  const promptRoot = page.locator("#home-clipboard-prompt");
  const clipboard = () => page.evaluate(() => navigator.clipboard.readText());
  const status = row => row.locator(".agent-copy-status");

  async function copyThroughHome(row, button, expected, label) {
    stage = label;
    await page.evaluate(() => navigator.clipboard.writeText("clipboard before copy"));
    await row.hover();
    await button.click();
    await promptRoot.waitFor({ state: "visible", timeout: 3000 }).catch(() => {
      throw new Error(`${label}: Copy did not ask Home to write the clipboard`);
    });
    await page.locator("#home-clipboard-allow").click();
    await status(row).filter({ hasText: "Copied" }).waitFor({ timeout: 3000 });
    assert.equal(await clipboard(), expected, `${label}: the clipboard holds the exact text`);
  }

  const sent = rows.nth(0), received = rows.nth(1);
  assert.equal(await sent.getAttribute("data-role"), "user");
  assert.equal(await received.getAttribute("data-role"), "agent");
  await copyThroughHome(sent, sent.locator("[data-copy-message]"), typed, "sent message");
  await copyThroughHome(received, received.locator("[data-copy-message]"), reply, "received message");
  await copyThroughHome(received, received.locator(".agent-md-copy"), "const answer = 42;", "code block");

  stage = "cancelled copy";
  await page.evaluate(() => navigator.clipboard.writeText("clipboard before cancel"));
  await sent.hover();
  await sent.locator("[data-copy-message]").click();
  await promptRoot.waitFor({ state: "visible", timeout: 3000 });
  await page.locator("#home-clipboard-cancel").click();
  await status(sent).filter({ hasText: "Copy cancelled." }).waitFor({ timeout: 3000 });
  assert.equal(await clipboard(), "clipboard before cancel", "a cancelled copy leaves the clipboard alone");

  stage = "oversized copy";
  const long = rows.nth(3);
  await long.hover();
  await long.locator("[data-copy-message]").click();
  await status(long).filter({ hasText: "Too long to copy." }).waitFor({ timeout: 3000 });
  assert.equal(await promptRoot.isVisible(), false, "an oversized copy is refused before Home is asked");

  const written = await page.evaluate(() => window.__home.written);
  assert.deepEqual(written, [typed, reply, "const answer = 42;"], "Home wrote only what was confirmed");
  assert.deepEqual(errors, []);
  assert.deepEqual(pageErrors, []);
  console.log("PASS Assistant Copy: sent text, reply Markdown and code reach the clipboard through Home; cancelled and oversized copies say so");
} catch (error) {
  console.error(`Assistant message copy smoke failed at ${stage}`);
  console.error(JSON.stringify({ errors, pageErrors }, null, 1));
  throw error;
} finally {
  await browser?.close();
  server.close();
}
