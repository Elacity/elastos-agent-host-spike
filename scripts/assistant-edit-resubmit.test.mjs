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

/** Run N answers "Reply N"; `firstReply` holds run 1's events until it resolves. */
async function openAssistant(t, { firstReply = null } = {}) {
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
          const run = body.run_id.at(-1);
          if (run === "1") await firstReply;
          json({ status: "ok", data: { schema: "elastos.model.run-events/v1", run_id: body.run_id, next_cursor: 2, has_more: false,
            events: [{ sequence: 1, kind: "text_delta", data: { text: `Reply ${run}` } },
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
  t.after(async () => {
    await browser.close();
    server.closeAllConnections();
    await new Promise(done => server.close(done));
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.on("pageerror", error => errors.push(String(error)));
  page.on("dialog", dialog => dialog.accept());
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const frame = page.frameLocator("iframe");
  const composer = frame.locator("#agent-composer-input");
  await composer.waitFor({ state: "visible" });
  const userRows = frame.locator(".agent-msg-user");
  const replies = frame.locator(".agent-msg-agent .agent-msg-body");
  // DOM text: rows use content-visibility:auto, so rendered text can be empty.
  const texts = async locator => (await locator.allTextContents()).map(text => text.trim());
  const saved = () => JSON.stringify(stored.document.sessions?.[0]?.messages?.map(message => [message.role, message.text]));
  return {
    page, frame, composer, userRows, replies, creates, errors,
    userTexts: () => texts(userRows.locator(".agent-msg-body")),
    replyTexts: () => texts(replies),
    send: async (question, reply) => {
      await composer.fill(question);
      await composer.press("Enter");
      if (reply) await replies.filter({ hasText: reply }).waitFor();
    },
    startEdit: async index => {
      const row = userRows.nth(index);
      await row.hover();
      await row.getByRole("button", { name: "Edit and resubmit" }).click();
      await row.locator("[data-edit-form]").waitFor({ state: "visible", timeout: 5000 });
      return row.locator("[data-edit-form]");
    },
    resubmit: async (form, text, reply) => {
      await form.locator("textarea").fill(text);
      await form.getByRole("button", { name: "Save & submit" }).click();
      await replies.filter({ hasText: reply }).waitFor();
    },
    savedTranscript: async expected => {
      await until(() => saved() === JSON.stringify(expected), "the workspace keeps the transcript");
    },
  };
}

test("Edit on a message sent in this view replaces that turn onward, then resubmits; Cancel and Delete keep indices right", async t => {
  const app = await openAssistant(t);
  await app.send("First question", "Reply 1");
  await app.send("Second question", "Reply 2");
  await app.send("Third question", "Reply 3");

  // The rows were appended as sent; nothing re-rendered the transcript yet.
  assert.equal(await (await app.startEdit(0)).locator("textarea").inputValue(), "First question");
  const second = await app.startEdit(1);
  assert.equal(await second.locator("textarea").inputValue(), "Second question");
  await second.getByRole("button", { name: "Cancel" }).click();
  assert.equal(await app.frame.locator("[data-edit-form]").count(), 0, "Cancel closes the editors");
  assert.deepEqual(await app.userTexts(), ["First question", "Second question", "Third question"]);
  assert.deepEqual(await app.replyTexts(), ["Reply 1", "Reply 2", "Reply 3"], "Cancel keeps the replies");
  assert.equal(app.creates.length, 3, "Cancel does not resubmit");

  // Editing an earlier turn drops it and every later turn and reply.
  await app.resubmit(await app.startEdit(1), "Edited question", "Reply 4");
  assert.deepEqual(await app.userTexts(), ["First question", "Edited question"]);
  assert.deepEqual(await app.replyTexts(), ["Reply 1", "Reply 4"]);
  assert.equal(app.creates.length, 4, "Save & submit sends one new run");
  let prompt = app.creates[3].input.prompt;
  assert.ok(["First question", "Reply 1", "Edited question"].every(text => prompt.includes(text)), prompt);
  assert.ok(!/Second question|Third question|Reply 2|Reply 3/.test(prompt), "the resubmitted run drops the replaced turns");
  await app.savedTranscript([["user", "First question"], ["agent", "Reply 1"], ["user", "Edited question"], ["agent", "Reply 4"]]);

  // Delete shifts the later messages; Edit then acts on the message shown.
  const firstReply = app.frame.locator(".agent-msg-agent").filter({ hasText: "Reply 1" });
  await firstReply.hover();
  await firstReply.getByRole("button", { name: "Delete" }).click();
  await app.savedTranscript([["user", "First question"], ["user", "Edited question"], ["agent", "Reply 4"]]);
  const edited = await app.startEdit(1);
  assert.equal(await edited.locator("textarea").inputValue(), "Edited question");
  await app.resubmit(edited, "Final question", "Reply 5");
  assert.deepEqual(await app.userTexts(), ["First question", "Final question"]);
  assert.deepEqual(await app.replyTexts(), ["Reply 5"]);
  prompt = app.creates[4].input.prompt;
  assert.ok(["First question", "Final question"].every(text => prompt.includes(text)), prompt);
  assert.ok(!/Edited question|Reply 1|Reply 4/.test(prompt), prompt);
  await app.savedTranscript([["user", "First question"], ["user", "Final question"], ["agent", "Reply 5"]]);
  assert.deepEqual(app.errors, []);
});

test("Edit on a queued follow-up sent in this view resubmits that message", async t => {
  let release;
  const app = await openAssistant(t, { firstReply: new Promise(done => { release = done; }) });
  t.after(() => release());
  await app.send("First question");
  await until(() => app.creates.length === 1, "first run created");
  // While a reply streams the composer's Enter is Stop, so the composer cannot
  // queue; queue through the capsule's own module instance instead.
  const capsule = app.page.frames().find(frame => frame.url().includes("/apps/assistant/"));
  await capsule.evaluate(async () => (await import("/apps/assistant/agent-stream.js"))
    .enqueueFollowUp("Second question", { displayText: "Second question" }));
  await app.frame.locator(".agent-queue-item-text").filter({ hasText: "Second question" }).waitFor();
  release();
  await app.replies.filter({ hasText: "Reply 2" }).waitFor();
  assert.deepEqual(await app.userTexts(), ["First question", "Second question"]);

  const queued = await app.startEdit(1);
  assert.equal(await queued.locator("textarea").inputValue(), "Second question");
  await app.resubmit(queued, "Edited follow-up", "Reply 3");
  assert.deepEqual(await app.userTexts(), ["First question", "Edited follow-up"]);
  assert.deepEqual(await app.replyTexts(), ["Reply 1", "Reply 3"]);
  assert.ok(!/Second question|Reply 2/.test(app.creates[2].input.prompt), app.creates[2].input.prompt);
  await app.savedTranscript([["user", "First question"], ["agent", "Reply 1"], ["user", "Edited follow-up"], ["agent", "Reply 3"]]);
  assert.deepEqual(app.errors, []);
});
