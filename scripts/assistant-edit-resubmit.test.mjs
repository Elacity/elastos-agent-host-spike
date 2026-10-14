import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { chromium } from "./system-uiux-fixture.mjs";

// The real Assistant capsule in Chromium; only Runtime responses are fixtures.
const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const schema = "elastos.assistant.workspace/v2";
const offerId = "offer:edit-fixture";
const types = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml" };
const until = async (predicate, label) => {
  for (const deadline = Date.now() + 5000; !predicate();) {
    assert.ok(Date.now() < deadline, `Timed out: ${label}`);
    await new Promise(done => setTimeout(done, 25));
  }
};

test("Edit on a message sent in this view replaces that turn onward, then resubmits; Cancel restores", async () => {
  let stored = { schema, revision: 0, document: { v: 1, liveOfferId: offerId, sessions: [] } };
  const creates = [], errors = [];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://fixture");
    const headers = { "access-control-allow-origin": "null", "access-control-allow-headers": "content-type,x-elastos-home-token",
      "access-control-allow-methods": "GET,POST,PUT,OPTIONS", "cache-control": "no-store" };
    const json = value => { res.writeHead(200, { ...headers, "content-type": "application/json" }); res.end(JSON.stringify(value)); };
    try {
      if (req.method === "OPTIONS") { res.writeHead(204, headers); res.end(); return; }
      if (url.pathname === "/") {
        const origin = `http://127.0.0.1:${server.address().port}`;
        res.writeHead(200, { "content-type": "text/html" });
        res.end(`<!doctype html><style>html,body,iframe{width:100%;height:100%;margin:0;border:0}</style>
          <iframe sandbox="allow-scripts allow-forms allow-modals" src="/apps/assistant/?home_origin=${encodeURIComponent(origin)}#home_token=fixture"></iframe>
          <script>addEventListener('message',event=>{if(event.data?.type==='home-agent:ready'){
            event.source.postMessage({type:'home-agent:open'},'*');
            event.source.postMessage({type:'home-agent:shelf-handover',on:true},'*');}});</script>`);
        return;
      }
      if (url.pathname.startsWith("/api/")) {
        const chunks = []; for await (const chunk of req) chunks.push(chunk);
        const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : null;
        if (url.pathname === "/api/apps/assistant/workspace-v2") {
          if (req.method === "PUT") {
            assert.equal(body.if_revision, stored.revision);
            stored = { schema, revision: stored.revision + 1, document: body.document };
          }
          json(stored); return;
        }
        if (url.pathname === "/api/provider/model/offers_list") {
          json({ offers: [{ id: offerId, title: "Edit fixture", operation: "text.generate",
            context: { context_window_tokens: 8192, max_output_tokens: 1024 },
            input_modalities: ["text/plain"], output_modalities: ["text/plain"] }] }); return;
        }
        if (url.pathname === "/api/capsules/catalog") { json({ schema: "elastos.capsules.catalog/v1", capsules: [] }); return; }
        if (url.pathname === "/api/provider/model/runs_create") {
          creates.push(body);
          json({ status: "ok", data: { schema: "elastos.model.run/v1", run_id: `run:sha256:${String(creates.length).repeat(64)}`,
            offer_id: offerId, operation: "text.generate", status: "running", sequence_cursor: 0 } }); return;
        }
        if (url.pathname === "/api/provider/model/runs_events") {
          json({ status: "ok", data: { schema: "elastos.model.run-events/v1", run_id: body.run_id, next_cursor: 2, has_more: false,
            events: [{ sequence: 1, kind: "text_delta", data: { text: `Reply ${body.run_id.at(-1)}` } },
              { sequence: 2, kind: "completed", terminal: true, data: {} }] } }); return;
        }
        throw new Error(`Unexpected API operation: ${req.method} ${url.pathname}`);
      }
      const match = url.pathname.match(/^\/apps\/(assistant|home)\/(.*)$/);
      assert.ok(match, `Unexpected asset: ${url.pathname}`);
      const base = resolve(root, "capsules", match[1], "browser");
      const path = resolve(base, match[2] || "index.html");
      assert.ok(path.startsWith(`${base}/`));
      const bytes = await readFile(path);
      res.writeHead(200, { ...headers, "content-type": types[extname(path)] || "application/octet-stream" });
      res.end(bytes);
    } catch (error) { errors.push(String(error)); res.writeHead(500); res.end(); }
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
    page.on("pageerror", error => errors.push(String(error)));
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    const frame = page.frameLocator("iframe");
    const composer = frame.locator("#agent-composer-input");
    const userRows = frame.locator(".agent-msg-user");
    const userTexts = userRows.locator(".agent-msg-body");
    const replies = frame.locator(".agent-msg-agent .agent-msg-body");
    const forms = frame.locator("[data-edit-form]");
    // DOM text: rows use content-visibility:auto, so rendered text can be empty.
    const texts = async locator => (await locator.allTextContents()).map(text => text.trim());
    const startEdit = async index => {
      const row = userRows.nth(index);
      await row.hover();
      await row.getByRole("button", { name: "Edit and resubmit" }).click();
      await row.locator("[data-edit-form]").waitFor({ state: "visible", timeout: 5000 });
      return row.locator("[data-edit-form]");
    };

    await composer.waitFor({ state: "visible" });
    for (const [index, question] of ["First question", "Second question"].entries()) {
      await composer.fill(question);
      await composer.press("Enter");
      await replies.filter({ hasText: `Reply ${index + 1}` }).waitFor();
    }

    // Both rows were appended as sent; nothing re-rendered the transcript yet.
    assert.equal(await (await startEdit(0)).locator("textarea").inputValue(), "First question");
    const second = await startEdit(1);
    assert.equal(await second.locator("textarea").inputValue(), "Second question");
    await second.getByRole("button", { name: "Cancel" }).click();
    assert.equal(await forms.count(), 0, "Cancel closes the editors");
    assert.deepEqual(await texts(userTexts), ["First question", "Second question"]);
    assert.deepEqual(await texts(replies), ["Reply 1", "Reply 2"], "Cancel keeps the replies");
    assert.equal(creates.length, 2, "Cancel does not resubmit");

    const edit = await startEdit(1);
    await edit.locator("textarea").fill("Edited question");
    await edit.getByRole("button", { name: "Save & submit" }).click();
    await replies.filter({ hasText: "Reply 3" }).waitFor();
    assert.deepEqual(await texts(userTexts), ["First question", "Edited question"]);
    assert.deepEqual(await texts(replies), ["Reply 1", "Reply 3"], "the edited turn's reply is replaced");
    assert.equal(creates.length, 3, "Save & submit sends one new run");
    const prompt = creates[2].input.prompt;
    assert.ok(["First question", "Reply 1", "Edited question"].every(text => prompt.includes(text)), prompt);
    assert.ok(!/Second question|Reply 2/.test(prompt), "the resubmitted run does not carry the replaced turn");
    const expected = [["user", "First question"], ["agent", "Reply 1"], ["user", "Edited question"], ["agent", "Reply 3"]];
    const saved = () => JSON.stringify(stored.document.sessions?.[0]?.messages?.map(message => [message.role, message.text]));
    await until(() => saved() === JSON.stringify(expected), "the workspace keeps the edited transcript");
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
    server.closeAllConnections();
    await new Promise(done => server.close(done));
  }
});
