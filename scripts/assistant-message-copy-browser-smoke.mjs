#!/usr/bin/env node
// Copy in the Assistant reaches the device clipboard through Home.
// The real Assistant capsule runs opaque-sandboxed inside an opaque Home GUI
// frame, as installed; the top document runs the real Home Clipboard host and
// prompt. Copy on a sent message writes the typed text, Copy on a reply writes
// its Markdown source (while it streams, the source received so far; once a
// stream ends without a confirmed outcome, the partial reply kept), Copy on a
// code block writes the code, and Copy in the pasted-text editor writes the
// pasted text. A cancelled or oversized copy says so instead of doing nothing,
// and under a Home page from before the update (its Clipboard does not know
// the message purpose yet) Copy says to reload Home.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "./system-uiux-fixture.mjs";
import { productSmokeLaunchOptions } from "./product-smoke-browser.mjs";

const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const schema = "elastos.assistant.workspace/v2";
const homeToken = "assistant-copy-fixture";
const textOffer = { id: "offer:text-fixture", title: "Text fixture", operation: "text.generate",
  input_modalities: ["text/plain"], output_modalities: ["text/plain"] };
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
const oversized = "x".repeat(65_537);
const streamed = ["**Streaming** reply, ", "first part."];
const pasted = `Pasted notes ${"π and ✓ ".repeat(1500)}END`;

const workspace = (session) => ({
  v: 1, activeSessionId: session.id, sessionMode: "chat", liveOfferId: textOffer.id, selectedModelCid: null,
  composerDraft: { text: "", parts: [] }, projects: [], usageTurns: [],
  sessions: [{ title: "Copy room", mode: "chat", composerDraft: { text: "", parts: [] }, ...session }],
});
const savedRoom = workspace({
  id: "copy-room",
  messages: [
    { role: "user", text: typed, modelText: typed },
    { role: "agent", text: reply },
    { role: "user", text: "And a long one?", modelText: "And a long one?" },
    { role: "agent", text: oversized },
  ],
});
// A turn still running when the room opens: the Assistant resumes it and
// streams the reply from the run's events.
const streamingRoom = workspace({
  id: "stream-room",
  messages: [{ role: "user", text: "Stream me something", modelText: "Stream me something" }],
  lastTurn: { turnId: "turn-stream", providerRunId: "run-stream", createRequestId: "request-stream",
    state: "streaming", startedAt: Date.now() - 1000 },
});

// `run` is open (text so far, no outcome) or unknown (the run ends with its
// outcome unknown, so the Assistant keeps the partial reply).
const fixture = { stored: null, run: "open" };
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
      // ?home=before-update loads Home's Clipboard as it was before Assistant
      // copied messages: a Home page not reloaded since the update.
      const homeAssets = url.searchParams.get("home") === "before-update" ? "/apps/home-before-update" : "/apps/home";
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
          import { createHomeClipboardFrameState, createHomeClipboardHost, createHomeClipboardPrompt } from "${homeAssets}/home-clipboard-host.js";
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
          window.__home = { written };
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
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks).toString("utf8");
      const input = body ? JSON.parse(body) : null;
      if (url.pathname === "/api/apps/assistant/workspace-v2") {
        if (req.method === "GET") { json(fixture.stored); return; }
        assert.equal(req.method, "PUT");
        if (input.if_revision !== fixture.stored.revision) { json({ error: "workspace revision conflict" }, 409); return; }
        fixture.stored = { schema, revision: fixture.stored.revision + 1, document: input.document };
        json(fixture.stored); return;
      }
      if (url.pathname === "/api/provider/model/offers_list") { json({ offers: [textOffer] }); return; }
      if (url.pathname === "/api/capsules/catalog") {
        json({ schema: "elastos.capsules.catalog/v1", model_catalog_state: "verified", capsules: [] }); return;
      }
      if (url.pathname === "/api/provider/model/runs_get") { json({ run_id: input.run_id }); return; }
      if (url.pathname === "/api/provider/model/runs_events") {
        assert.equal(input.run_id, "run-stream");
        const after = Number(input.after_sequence) || 0;
        const events = [
          { sequence: 1, kind: "text_delta", data: { text: streamed[0] } },
          { sequence: 2, kind: "text_delta", data: { text: streamed[1] } },
          ...(fixture.run === "unknown" ? [{ sequence: 3, kind: "settlement_unknown", data: {} }] : []),
        ].filter(event => event.sequence > after);
        json({ events, next_cursor: Math.max(after, ...events.map(event => event.sequence)), has_more: false });
        return;
      }
      throw new Error(`Unexpected API operation: ${req.method} ${url.pathname}`);
    }
    if (url.pathname === "/favicon.ico") { res.writeHead(204); res.end(); return; }
    const match = url.pathname.match(/^\/apps\/(assistant|home|home-before-update)\/(.*)$/);
    assert.ok(match, `Unexpected asset: ${url.pathname}`);
    const base = resolve(root, "capsules", match[1] === "assistant" ? "assistant" : "home", "browser");
    const path = resolve(base, match[2] || "index.html");
    assert.ok(path.startsWith(`${base}/`));
    let content = await readFile(path);
    if (match[1] === "home-before-update" && match[2] === "home-clipboard-protocol.js") {
      const current = content.toString("utf8");
      const before = current.replace(/\n {4}"message\.text": Object\.freeze\(\{[^}]*\}\),/, "");
      assert.notEqual(before, current, "the fixture removes the message purpose from Home's Clipboard");
      content = before;
    }
    send(200, ({ ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css",
      ".svg": "image/svg+xml", ".woff2": "font/woff2" })[extname(path)] || "application/octet-stream", content);
  } catch (error) { errors.push(String(error)); json({ error: "fixture failure" }, 500); }
});

let browser, page, stage = "launch";
const pageErrors = [];
try {
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true, ...productSmokeLaunchOptions() });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin });
  const open = async (document, query = "") => {
    fixture.stored = { schema, revision: 1, document: structuredClone(document) };
    await page?.close();
    page = await context.newPage();
    page.on("pageerror", error => pageErrors.push(`${stage}: ${error}`));
    await page.goto(`${origin}/${query}`);
    return page.frameLocator("#gui").frameLocator("iframe");
  };
  const clipboard = () => page.evaluate(() => navigator.clipboard.readText());
  const resetClipboard = text => page.evaluate(value => navigator.clipboard.writeText(value), text);
  const promptRoot = () => page.locator("#home-clipboard-prompt");
  const status = button => button.locator("xpath=following-sibling::*[contains(@class,'agent-copy-status')]");
  // The status waits below and the line that reports them share this number.
  const copyStatusTimeout = 3000;
  const factTimeout = 1000;

  // A copy status wait that, on timeout, adds what the page held at that
  // moment so the next failure says why. The wait keeps its own condition and
  // limit; a pass prints nothing new. Every read is bounded so a stalled frame
  // still ends in the original error, and a failed read never replaces it.
  async function waitForCopyStatus(label, expected, expectedClipboard, button, row, wait, since) {
    try {
      await wait();
    } catch (error) {
      const fact = async (name, read) => {
        let timer;
        try {
          const value = await Promise.race([
            read(),
            new Promise((_, reject) => {
              timer = setTimeout(() => reject(new Error("timed out")), factTimeout);
            }),
          ]);
          return `${name}: ${value}`;
        } catch (reason) {
          return `${name}: could not read: ${reason?.message || reason}`;
        } finally {
          clearTimeout(timer);
        }
      };
      const facts = await Promise.all([
        fact("statuses in the room frame", async () => JSON.stringify(
          await frame.locator(".agent-copy-status").evaluateAll(nodes => nodes.map(node => node.textContent)))),
        fact("clicked button data-copy-pending", async () => {
          const pending = await button.evaluate(node => node.getAttribute("data-copy-pending"), undefined,
            { timeout: factTimeout });
          return pending === null ? "absent" : `present, ${JSON.stringify(pending)}`;
        }),
        fact("buttons matching the clicked locator now", async () => String(await button.count())),
        fact("copy buttons in the target row", async () => row
          ? String(await row.locator("[data-copy-message]").count())
          : "none (the pasted-text editor is not a message row)"),
        fact("Home clipboard prompt", async () => await promptRoot().isVisible({ timeout: factTimeout }) ? "visible" : "hidden"),
        fact("written", async () => {
          const written = await page.evaluate(() => window.__home?.written ?? null);
          if (!Array.isArray(written)) return "absent";
          const last = written.at(-1);
          return `present, ${written.length} entries, last ${typeof last === "string" ? last.length : 0} chars`;
        }),
        // Lengths and equality only; the clipboard text is never printed.
        fact("clipboard vs the text this stage expects", async () => {
          const held = await page.evaluate(() => navigator.clipboard.readText());
          return held === expectedClipboard
            ? `equal, ${held.length} chars held, ${expectedClipboard.length} expected`
            : `different, ${held.length} chars held, ${expectedClipboard.length} expected`;
        }),
        `${since.label}: ${Date.now() - since.at} ms`,
      ]);
      const line = `copy status at "${label}" waited ${copyStatusTimeout} ms for "${expected}": ${facts.join("; ")}`;
      if (error && typeof error === "object") error.message = `${error.message}\n${line}`;
      // Node prints an uncaught error from its stack, so the line needs to be
      // printed here as well as appended to the message.
      console.error(line);
      throw error;
    }
  }

  async function copyThroughHome(button, expected, label, hover = null) {
    stage = label;
    await resetClipboard("clipboard before copy");
    await hover?.hover();
    await button.click();
    await promptRoot().waitFor({ state: "visible", timeout: 3000 }).catch(async () => {
      const said = await status(button).textContent({ timeout: 500 }).catch(() => "");
      throw new Error(`${label}: Copy did not ask Home to write the clipboard${said ? ` (it said "${said}")` : ""}`);
    });
    await page.locator("#home-clipboard-allow").click();
    const allowedAt = Date.now();
    await waitForCopyStatus(label, "Copied", expected, button, hover,
      () => status(button).filter({ hasText: "Copied" }).waitFor({ timeout: copyStatusTimeout }),
      { label: "click on Allow to timeout", at: allowedAt });
    assert.equal(await clipboard(), expected, `${label}: the clipboard holds the exact text`);
  }

  stage = "saved conversation";
  let frame = await open(savedRoom);
  let rows = frame.locator(".agent-msg");
  await rows.nth(3).waitFor({ state: "attached" });
  const sent = rows.nth(0), received = rows.nth(1);
  assert.equal(await sent.getAttribute("data-role"), "user");
  assert.equal(await received.getAttribute("data-role"), "agent");
  await copyThroughHome(sent.locator("[data-copy-message]"), typed, "sent message", sent);
  await copyThroughHome(received.locator("[data-copy-message]"), reply, "received message", received);
  await copyThroughHome(received.locator(".agent-md-copy"), "const answer = 42;", "code block", received);

  stage = "cancelled copy";
  await resetClipboard("clipboard before cancel");
  await sent.hover();
  await sent.locator("[data-copy-message]").click();
  await promptRoot().waitFor({ state: "visible", timeout: 3000 });
  await page.locator("#home-clipboard-cancel").click();
  const cancelledAt = Date.now();
  const sentCopy = sent.locator("[data-copy-message]");
  await waitForCopyStatus("cancelled copy", "Copy cancelled.", "clipboard before cancel", sentCopy, sent,
    () => status(sentCopy).filter({ hasText: "Copy cancelled." }).waitFor({ timeout: copyStatusTimeout }),
    { label: "click on Cancel to timeout", at: cancelledAt });
  assert.equal(await clipboard(), "clipboard before cancel", "a cancelled copy leaves the clipboard alone");

  stage = "oversized copy";
  const long = rows.nth(3);
  await long.hover();
  const longCopy = long.locator("[data-copy-message]");
  await longCopy.click();
  const oversizedAt = Date.now();
  await waitForCopyStatus("oversized copy", "Too long to copy.", "clipboard before cancel", longCopy, long,
    () => status(longCopy).filter({ hasText: "Too long to copy." }).waitFor({ timeout: copyStatusTimeout }),
    { label: "copy click to timeout", at: oversizedAt });
  assert.equal(await promptRoot().isVisible(), false, "an oversized copy is refused before Home is asked");

  stage = "pasted-text editor";
  await frame.locator("#agent-composer-input").evaluate((input, text) => {
    const data = new DataTransfer();
    data.setData("text/plain", text);
    input.focus();
    input.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
  }, pasted);
  // Headless Brave delivers no pointer events to the chip at the composer's
  // position in this nested fixture, so the editor is opened by a DOM click;
  // what is under test is its Copy, which is clicked for real below.
  await frame.locator("[data-attach-open]").evaluate(chip => chip.click());
  await copyThroughHome(frame.locator("[data-paste-copy]"), pasted, "pasted-text editor");
  assert.deepEqual(await page.evaluate(() => window.__home.written), [typed, reply, "const answer = 42;", pasted],
    "Home wrote only what was confirmed");

  stage = "streaming reply";
  fixture.run = "open";
  frame = await open(streamingRoom);
  const live = frame.locator(".agent-msg-agent.is-streaming");
  await live.filter({ hasText: "first part." }).waitFor({ timeout: 10000 });
  await copyThroughHome(live.locator("[data-copy-message]"), streamed.join(""), "streaming reply", live);

  stage = "partial reply kept after the stream ends";
  fixture.run = "unknown";
  const kept = frame.locator(".agent-msg-agent").last();
  await frame.locator(".agent-msg-agent.is-streaming").waitFor({ state: "detached", timeout: 10000 });
  await copyThroughHome(kept.locator("[data-copy-message]"), streamed.join(""), "partial reply", kept);

  const written = await page.evaluate(() => window.__home.written);
  assert.deepEqual(written, [streamed.join(""), streamed.join("")], "Home wrote only what was confirmed");

  stage = "Home page from before the update";
  frame = await open(savedRoom, "?home=before-update");
  rows = frame.locator(".agent-msg");
  await rows.nth(3).waitFor({ state: "attached" });
  const stale = rows.nth(1);
  await stale.hover();
  const staleCopy = stale.locator("[data-copy-message]");
  await staleCopy.click();
  const staleAt = Date.now();
  const staleStatus = status(staleCopy);
  // This wait has no text filter: it waits for any status to be visible, and
  // the old Home page leaves the clipboard holding the last text written.
  await waitForCopyStatus("Home page from before the update", "any status to be visible", streamed.join(""),
    staleCopy, stale,
    () => staleStatus.waitFor({ timeout: copyStatusTimeout }),
    { label: "copy click to timeout", at: staleAt });
  assert.equal(await staleStatus.textContent(), "Reload Home to copy.", "Copy under the old Home page says to reload Home");
  assert.equal(await promptRoot().isVisible(), false, "the old Home page asks nothing");
  assert.deepEqual(await page.evaluate(() => window.__home.written), [], "the old Home page writes nothing");
  assert.deepEqual(errors, []);
  assert.deepEqual(pageErrors, []);
  console.log("PASS Assistant Copy: sent text, reply Markdown (also mid-stream and a kept partial), code and pasted text reach the clipboard through Home; cancelled and oversized copies say so; under a Home page from before the update Copy says to reload Home");
} catch (error) {
  console.error(`Assistant message copy smoke failed at ${stage}`);
  console.error(JSON.stringify({ errors, pageErrors }, null, 1));
  throw error;
} finally {
  await browser?.close();
  server.close();
}
