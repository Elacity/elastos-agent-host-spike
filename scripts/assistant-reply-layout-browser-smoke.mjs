#!/usr/bin/env node
// Replies stay readable at the edges of the Assistant room. The real
// Assistant capsule runs opaque-sandboxed inside an opaque Home GUI frame,
// as installed. Numbered lists of ten or more items keep every marker whole
// ("10.", "20."), in a saved reply and in one that streamed in, and while a
// turn runs its status line ("Working out the best approach…") and then the
// newest reply sit fully above the composer, not behind it. A reader at the
// end who sends a message follows its long reply to the end, while it
// streams and once it settles, without being offered Jump to latest.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "./system-uiux-fixture.mjs";

const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
const schema = "elastos.assistant.workspace/v2";
const homeToken = "assistant-layout-fixture";
const textOffer = { id: "offer:text-fixture", title: "Text fixture", operation: "text.generate",
  context: { context_window_tokens: 8192, max_output_tokens: 1024 },
  input_modalities: ["text/plain"], output_modalities: ["text/plain"] };
const numbered = (count, label) => Array.from({ length: count }, (_, i) => `${i + 1}. ${label} ${i + 1}`).join("\n");
const filler = "A sentence that fills the room so the transcript scrolls. ".repeat(12);
const savedList = `Here are twelve:\n\n${numbered(12, "Saved step")}`;
const streamedList = `Here are twenty-five:\n\n${numbered(25, "Streamed step")}`;
// A long Markdown reply like a hosted model's: taller than the room.
const gardenReply = [
  "Planning a garden goes best in a few **clear steps**.\n\n",
  ...Array.from({ length: 6 }, (_, i) => [
    `## Step ${i + 1}: ${["Choose the site", "Test the soil", "Pick the plants", "Draw the beds", "Set up water", "Plant and mulch"][i]}\n\n`,
    `${"Look at the light, the wind and the soil before deciding anything else. ".repeat(3)}\n\n`,
    "- **First:** note the sun hours\n- **Second:** note where water pools\n- Third: mark paths\n\n",
  ].join("")),
  "```text\nbed A: tomatoes, basil\nbed B: beans, lettuce\n```\n\n",
  "| Plant | Sun |\n| --- | --- |\n| Tomato | Full |\n| Lettuce | Part |\n\n",
  "That is the whole plan: the last line of the reply.\n",
].join("");

const history = [];
for (let i = 0; i < 4; i += 1) {
  history.push({ role: "user", text: `Question ${i + 1}`, modelText: `Question ${i + 1}` });
  history.push({ role: "agent", text: i === 3 ? savedList : filler });
}
history.push({ role: "user", text: "List twenty-five steps", modelText: "List twenty-five steps" });
// A turn still running when the room opens: the Assistant resumes it, shows
// its status while nothing has arrived, then streams the reply.
const busyRoom = {
  v: 1, activeSessionId: "layout-room", sessionMode: "chat", liveOfferId: textOffer.id, selectedModelCid: null,
  composerDraft: { text: "", parts: [] }, projects: [], usageTurns: [],
  sessions: [{ id: "layout-room", title: "Layout room", mode: "chat", composerDraft: { text: "", parts: [] },
    messages: history,
    lastTurn: { turnId: "turn-layout", providerRunId: "run-layout", createRequestId: "request-layout",
      state: "streaming", startedAt: Date.now() - 1000 } }],
};

const fixture = { stored: { schema, revision: 1, document: busyRoom }, events: [], runs: new Map() };
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
      send(200, "text/html", `<!doctype html><style>html,body,iframe{width:100%;height:100%;margin:0;border:0}</style>
        <iframe title="Home GUI" sandbox="allow-scripts" src="/gui?home_origin=${encodeURIComponent(origin)}"></iframe>`);
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
      if (url.pathname === "/api/provider/model/runs_create") {
        const runId = `run-sent-${fixture.runs.size + 1}`;
        fixture.runs.set(runId, []);
        json({ run_id: runId, status: "running", sequence_cursor: 0 }); return;
      }
      if (url.pathname === "/api/provider/model/runs_events") {
        const runEvents = input.run_id === "run-layout" ? fixture.events : fixture.runs.get(input.run_id);
        assert.ok(runEvents, `events of a known run: ${input.run_id}`);
        const after = Number(input.after_sequence) || 0;
        const events = runEvents.filter(event => event.sequence > after);
        json({ events, next_cursor: Math.max(after, ...events.map(event => event.sequence)), has_more: false });
        return;
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

/* Every marker of every numbered reply list, measured against the nearest
   box that clips it: an outside marker ends where its item's content starts
   and is as wide as its text ("25. "). */
function markerReport(selector) {
  const clipLeft = (el) => {
    let left = -Infinity;
    for (let node = el.parentElement; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      const contain = style.contain;
      if (style.overflowX !== "visible" || /paint|content|strict/.test(contain)) {
        left = Math.max(left, node.getBoundingClientRect().left + parseFloat(style.borderLeftWidth));
      }
    }
    return left;
  };
  const probe = document.createElement("span");
  probe.style.cssText = "position:absolute;visibility:hidden;white-space:pre";
  document.body.append(probe);
  const lists = [...document.querySelectorAll(selector)];
  const report = lists.map((list) => {
    const items = [...list.children].filter((item) => item.tagName === "LI");
    let worst = Infinity;
    items.forEach((item, index) => {
      const style = getComputedStyle(item, "::marker");
      probe.style.font = getComputedStyle(item).font;
      probe.style.fontVariantNumeric = style.fontVariantNumeric;
      probe.textContent = `${(Number(list.getAttribute("start")) || 1) + index}. `;
      const markerLeft = item.getBoundingClientRect().left - probe.getBoundingClientRect().width;
      worst = Math.min(worst, markerLeft - clipLeft(list));
    });
    return { items: items.length, worstRoomPx: Number(worst.toFixed(1)) };
  });
  probe.remove();
  return report;
}

/* How far the newest block in the transcript sits above the composer's top
   edge (negative: it is behind the composer). */
function newestClearance(selector) {
  const scroller = document.querySelector("#agent-harness-stream");
  const composer = document.querySelector(".taskbar.is-agent-face");
  const column = document.querySelector("#agent-harness-stream-column");
  const blocks = [...column.children].filter((el) => !el.hidden && el.getBoundingClientRect().height > 0);
  const newest = blocks.at(-1);
  return {
    newest: newest.matches(selector),
    text: newest.textContent.trim().slice(-40),
    abovePx: Math.round(composer.getBoundingClientRect().top - newest.getBoundingClientRect().bottom),
    atEnd: scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 1,
    follow: scroller.classList.contains("is-follow-bottom"),
    jump: Boolean(document.querySelector("[data-agent-jump-latest]")?.hidden === false),
  };
}

let browser, page, stage = "launch";
const pageErrors = [];
try {
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  browser = await chromium.launch({ headless: true, ...(process.env.BRAVE_BIN ? { executablePath: process.env.BRAVE_BIN } : {}) });
  page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  page.on("pageerror", error => pageErrors.push(`${stage}: ${error}`));
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const room = page.frameLocator("iframe").frameLocator("iframe");
  await room.locator(".agent-msg").nth(history.length - 1).waitFor({ state: "attached" });
  const frame = page.frames().find(candidate => candidate.url().includes("/apps/assistant/"));

  const input = room.locator("#agent-composer-input");
  // Waits for a page condition. The page function returns a state object with
  // an `ok` field, and a deadline failure names the condition and the state
  // that was still missing, so a loaded machine reports what never held.
  const waitForCondition = async (label, fn, arg = null, timeout = 20000) => {
    const deadline = Date.now() + timeout;
    let state = await frame.evaluate(fn, arg);
    while (!state.ok && Date.now() < deadline) {
      await page.waitForTimeout(50);
      state = await frame.evaluate(fn, arg);
    }
    assert.ok(state.ok, `${label}, within ${timeout} ms: ${JSON.stringify(state)}`);
  };
  // Polls until the newest block is at the end and fully above the composer;
  // then asserts on the last measurement. A finished reply reaches this state
  // through the page's own deferred render, so the bound has to cover that
  // work as well as the scroll that follows it.
  const expectNewestAboveComposer = async (selector, label, timeout = 15000) => {
    const deadline = Date.now() + timeout;
    let seen = await frame.evaluate(newestClearance, selector);
    while (!(seen.newest && seen.atEnd && seen.abovePx >= 0) && Date.now() < deadline) {
      await page.waitForTimeout(50);
      seen = await frame.evaluate(newestClearance, selector);
    }
    assert.ok(seen.newest && seen.atEnd,
      `${label} is the newest block, at the end, within ${timeout} ms: ${JSON.stringify(seen)}`);
    assert.ok(seen.abovePx >= 0,
      `${label} sits fully above the composer, within ${timeout} ms: ${JSON.stringify(seen)}`);
    return seen.abovePx;
  };
  // A long follow-up being typed grows the composer upwards; wait for the
  // growth so the next measurement cannot pass on the old composer.
  const composerHeight = () => frame.evaluate(() => document.querySelector(".taskbar.is-agent-face").getBoundingClientRect().height);
  const composerRestHeight = await composerHeight();
  const typeLongFollowUp = async () => {
    const before = await composerHeight();
    await input.fill(Array.from({ length: 6 }, (_, i) => `Follow-up line ${i + 1}`).join("\n"));
    await frame.waitForFunction((height) =>
      document.querySelector(".taskbar.is-agent-face").getBoundingClientRect().height > height, before, { timeout: 5000 });
  };
  // Clearing it shrinks the composer back. The room's clearance and its end
  // position move with that layout, so wait for the rest height before the
  // next reply is measured; otherwise the clearance can settle after the
  // reply's own end pin and leave the room short of the end.
  const clearFollowUp = async () => {
    await input.fill("");
    await waitForCondition("the composer returns to its resting height", (height) => {
      const now = document.querySelector(".taskbar.is-agent-face").getBoundingClientRect().height;
      return { ok: now <= height + 1, height: now, rest: height };
    }, composerRestHeight, 5000);
  };
  // The streaming reply's painted text. A reply grows in the DOM as its
  // flushes paint; waiting for that growth makes each pushed group land on
  // screen before the next is sent, so the reply grows across frames instead
  // of arriving in one events poll.
  const paintedChars = () => frame.evaluate(() =>
    document.querySelector(".agent-msg-agent.is-streaming .agent-msg-body")?.textContent.length ?? 0);
  const expectPaint = async (before, label) => {
    await waitForCondition(`${label}: the reply paints the text just sent`, (chars) => {
      const body = document.querySelector(".agent-msg-agent.is-streaming .agent-msg-body");
      const now = body?.textContent.length ?? 0;
      return { ok: now > chars, painted: now, before: chars };
    }, before, 15000);
  };
  const seen = {};

  stage = "status line of a running turn";
  await room.locator(".agent-progress:not([hidden])").filter({ hasText: "Working out the best approach" })
    .waitFor({ timeout: 10000 });
  seen.status = await expectNewestAboveComposer(".agent-progress", "the status line");
  await typeLongFollowUp();
  seen.statusTyping = await expectNewestAboveComposer(".agent-progress", "the status line, while a follow-up is typed");
  await clearFollowUp();

  stage = "streamed reply";
  fixture.events = [
    { sequence: 1, kind: "text_delta", data: { text: streamedList } },
    { sequence: 2, kind: "completed", data: {} },
  ];
  await room.locator(".agent-msg-agent.is-streaming").waitFor({ state: "detached", timeout: 15000 });
  await room.locator(".agent-msg-agent").last().filter({ hasText: "Streamed step 25" }).waitFor({ timeout: 5000 });
  // A finished reply gets its settled render after the stream closes, and
  // that render changes the reply's height. The position below is the
  // settled reply's, so wait for the phase, not for a fixed pause.
  await room.locator('.agent-msg-agent[data-stream-phase="presentation_done"]').last().waitFor({ timeout: 20000 });
  seen.reply = await expectNewestAboveComposer(".agent-msg-agent", "the newest reply");
  await typeLongFollowUp();
  seen.replyTyping = await expectNewestAboveComposer(".agent-msg-agent", "the newest reply, while a follow-up is typed");

  stage = "numbered list markers";
  // Both replies paint their numbered list from Markdown: the saved one with
  // the history render, the streamed one when it settles. Wait for both to
  // exist; the counts and marker widths are asserted next.
  await waitForCondition("the saved and the streamed reply each render a numbered list", () => {
    const lists = [...document.querySelectorAll(".agent-msg-agent ol.agent-md-list")];
    return { ok: lists.length >= 2, lists: lists.length, items: lists.map(list => list.children.length) };
  }, null, 15000);
  const markers = await frame.evaluate(markerReport, ".agent-msg-agent ol.agent-md-list");
  assert.deepEqual(markers.map(list => list.items), [12, 25], `saved and streamed lists render: ${JSON.stringify(markers)}`);
  for (const list of markers) {
    assert.ok(list.worstRoomPx >= 0, `every marker of a ${list.items}-item list is whole: ${JSON.stringify(markers)}`);
  }

  // The reader at the end sends a message. The status line shows, then a
  // fast hosted model's long reply streams in (taller than the room): the
  // status line giving way to the reply must not read as the reader
  // scrolling up. The room follows the reply while it streams and after it
  // settles into its history render.
  stage = "a sent message's long reply";
  await clearFollowUp();
  await frame.evaluate(() => {
    const scroller = document.querySelector("#agent-harness-stream");
    window.__follow = { on: true, samples: [] };
    const sample = () => {
      if (!window.__follow.on) return;
      try {
        const jump = document.querySelector("[data-agent-jump-latest]");
        window.__follow.samples.push({ t: performance.now(), jump: Boolean(jump && !jump.hidden),
          streaming: Boolean(document.querySelector(".agent-msg-agent.is-streaming")),
          follow: scroller.classList.contains("is-follow-bottom"),
          fromEnd: Math.round(scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight) });
      } catch (error) {
        window.__follow.error = String(error);
        return;
      }
      requestAnimationFrame(sample);
    };
    requestAnimationFrame(sample);
  });
  await input.fill("How do I plan a garden?");
  await input.press("Enter");
  await room.locator(".agent-progress:not([hidden])").last().filter({ hasText: "Working out the best approach" })
    .waitFor({ timeout: 10000 });
  // The room rests at the end with the status line showing, as it does before
  // a hosted model's first words; the sampler above then sees the reply row
  // appear and grow under a reader who never left the end. Ten consecutive
  // frames is a settled room at any frame rate.
  await frame.evaluate(() => {
    window.__rest = { stable: 0, frames: 0 };
    const step = () => {
      if (!window.__rest || window.__rest.stable >= 10) return;
      const scroller = document.querySelector("#agent-harness-stream");
      const progress = document.querySelector(".agent-progress:not([hidden])");
      const streaming = document.querySelector(".agent-msg-agent.is-streaming");
      const atEnd = scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 8;
      window.__rest.stable = progress && !streaming && atEnd ? window.__rest.stable + 1 : 0;
      window.__rest.frames += 1;
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
  await waitForCondition("the room rests at the end with the status line showing", () => ({
    ok: window.__rest.stable >= 10, stable: window.__rest.stable, frames: window.__rest.frames,
  }), null, 10000);
  const sent = fixture.runs.get("run-sent-1");
  assert.ok(sent, "the message started a run");
  const replyChunks = gardenReply.match(/[\s\S]{1,300}/g);
  let painted = 0;
  for (let index = 0; index < replyChunks.length; index += 3) {
    for (const text of replyChunks.slice(index, index + 3)) {
      sent.push({ sequence: sent.length + 1, kind: "text_delta", data: { text } });
    }
    await expectPaint(painted, "a sent message's long reply");
    painted = await paintedChars();
  }
  sent.push({ sequence: replyChunks.length + 1, kind: "completed", data: {} });
  await room.locator('.agent-msg-agent[data-stream-phase="presentation_done"]').filter({ hasText: "the last line of the reply" })
    .waitFor({ state: "attached", timeout: 10000 });
  seen.sentReply = await expectNewestAboveComposer(".agent-msg-agent", "a sent message's long reply, once settled");
  const follow = await frame.evaluate(() => {
    window.__follow.on = false;
    const streaming = window.__follow.samples.filter((sample) => sample.streaming);
    let behindMs = 0, since = null, behindFrames = 0, run = 0, maxGapMs = 0;
    streaming.forEach(({ t, fromEnd }, index) => {
      if (index) maxGapMs = Math.max(maxGapMs, t - streaming[index - 1].t);
      if (fromEnd > 8) {
        since ??= t;
        behindMs = Math.max(behindMs, t - since);
        run += 1;
        behindFrames = Math.max(behindFrames, run);
      } else { since = null; run = 0; }
    });
    const firstJump = streaming.find((sample) => sample.jump);
    return { behindFrames,
      jumpFrames: streaming.filter((sample) => sample.jump).length,
      samples: window.__follow.samples.length,
      ...(window.__follow.error ? { samplerError: window.__follow.error } : {}),
      streamingSamples: streaming.length,
      maxFromEnd: Math.round(Math.max(0, ...streaming.map((sample) => sample.fromEnd))),
      maxGapMs: Math.round(maxGapMs), behindMs: Math.round(behindMs),
      ...(firstJump ? { firstJump: { fromEnd: firstJump.fromEnd, follow: firstJump.follow } } : {}) };
  });
  // A following room is behind the end for at most the frame in which a
  // content flush paints before the follow lands. Frames are counted, not
  // milliseconds: a loaded machine paints fewer frames, and the gap between
  // two frames is not the room's fault. The settled position is asserted
  // separately below.
  assert.ok(follow.streamingSamples > 0, `the sampler saw the reply stream: ${JSON.stringify(follow)}`);
  assert.ok(follow.behindFrames <= 2, `the room follows the streaming reply: ${JSON.stringify(follow)}`);
  assert.equal(follow.jumpFrames, 0, `a reader who never left the end is not offered Jump to latest while the reply streams: ${JSON.stringify(follow)}`);
  // The reader is at the settled end, so the button is gone.
  await waitForCondition("Jump to latest is hidden at the settled end", () => {
    const jump = document.querySelector("[data-agent-jump-latest]");
    return { ok: Boolean(jump?.hidden), hidden: jump?.hidden };
  }, null, 5000);
  seen.sentReplyBehindFrames = follow.behindFrames;

  // A reader who moves up while a reply streams keeps their place, by any
  // amount and however they moved, while more of the reply keeps arriving:
  // small steps (ArrowUp, a 40 px wheel), a page (Shift+Space), or a scroll
  // position set directly, as a screen reader does. Then Jump to latest is
  // offered.
  const scrollState = () => frame.evaluate(() => {
    const scroller = document.querySelector("#agent-harness-stream");
    const jump = document.querySelector("[data-agent-jump-latest]");
    return { top: Math.round(scroller.scrollTop),
      fromEnd: Math.round(scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight),
      jump: Boolean(jump && !jump.hidden && jump.getBoundingClientRect().height > 0) };
  });
  const settled = () => frame.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))));
  const atEnd = () => frame.waitForFunction(() => {
    const scroller = document.querySelector("#agent-harness-stream");
    return scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight <= 8;
  }, null, { timeout: 5000 });
  // Beside the messages, inside the transcript (frame and page share
  // coordinates: both frames fill the page).
  const gutter = () => frame.evaluate(() => {
    const scroller = document.querySelector("#agent-harness-stream").getBoundingClientRect();
    const column = document.querySelector("#agent-harness-stream-column").getBoundingClientRect();
    return { x: Math.round((column.left + scroller.left) / 2), y: Math.round(scroller.top + scroller.height / 3) };
  });
  // The transcript takes the keyboard after a click a while ago: only the
  // keys that follow move the reader.
  const clickTranscriptAWhileAgo = async () => {
    const point = await gutter();
    assert.ok(point.x >= 8, `the transcript has room beside the messages: ${JSON.stringify(point)}`);
    await page.mouse.click(point.x, point.y);
    // Kept as a fixed wait because the time is the behavior: the page treats
    // a scroll up that follows pointer input within one second as the
    // reader's (READER_INPUT_MS), so this click must be older than that
    // window before the keys below may move the reader.
    await page.waitForTimeout(1500);
    await atEnd();
  };
  const readerMovesUp = async (label, move, prepare = async () => {}) => {
    stage = `a reader who moves up with ${label} while a reply streams`;
    const runId = `run-sent-${fixture.runs.size + 1}`;
    const marker = `End of the reply read with ${label}.`;
    await input.fill(`Plan another garden (${label})`);
    await input.press("Enter");
    for (const deadline = Date.now() + 10000; !fixture.runs.has(runId);) {
      assert.ok(Date.now() < deadline, `${label}: the message started a run`);
      await page.waitForTimeout(20);
    }
    const run = fixture.runs.get(runId);
    const chunks = `${gardenReply}\n${marker}\n`.match(/[\s\S]{1,120}/g);
    let sent = 0;
    const pushChunk = async () => {
      if (sent >= chunks.length) return;
      run.push({ sequence: sent + 1, kind: "text_delta", data: { text: chunks[sent] } });
      sent += 1;
      // Pacing between chunks of one group.
      await page.waitForTimeout(10);
    };
    // Two groups, each painted before the next is sent, so the reply is on
    // screen before the room's follow and the reader's first move are read.
    let painted = 0;
    const pushUntilPainted = async (target) => {
      while (sent < target) await pushChunk();
      await expectPaint(painted, `${label}: the reply paints the text just sent`);
      painted = await paintedChars();
    };
    await pushUntilPainted(4);
    await pushUntilPainted(8);
    await room.locator(".agent-msg-agent.is-streaming").filter({ hasText: chunks[sent - 1].trim().slice(-15) }).waitFor({ timeout: 5000 });
    // A new message makes the room shrink and grow again as its reply starts
    // (the scroll position clamps down): the room still follows to the end.
    await waitForCondition(`${label}: the room follows the start of the reply to the end`, () => {
      const scroller = document.querySelector("#agent-harness-stream");
      const fromEnd = Math.round(scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight);
      return { ok: fromEnd <= 8, fromEnd,
        follow: scroller.classList.contains("is-follow-bottom"),
        jump: Boolean(document.querySelector("[data-agent-jump-latest]")?.hidden === false) };
    }, null, 10000);
    await prepare();
    const before = await scrollState();
    // From the first move on, every frame: the reader is never pulled back
    // down (scrollTop only stays or goes up; the reply growing below the
    // reader does not move it).
    await frame.evaluate(() => {
      const scroller = document.querySelector("#agent-harness-stream");
      window.__reader = { on: true, tops: [] };
      const sample = () => {
        if (!window.__reader.on) return;
        window.__reader.tops.push(scroller.scrollTop);
        requestAnimationFrame(sample);
      };
      sample();
    });
    await move(pushChunk);
    while (sent < chunks.length) await pushChunk();
    run.push({ sequence: chunks.length + 1, kind: "completed", data: {} });
    await room.locator('.agent-msg-agent[data-stream-phase="presentation_done"]').filter({ hasText: marker })
      .waitFor({ state: "attached", timeout: 10000 });
    await settled();
    const end = await scrollState();
    const pulledBackPx = await frame.evaluate(() => {
      window.__reader.on = false;
      const { tops } = window.__reader;
      return Math.round(Math.max(0, ...tops.slice(1).map((top, i) => top - tops[i])));
    });
    assert.ok(pulledBackPx <= 2, `${label}: the reader is never pulled back toward the end (${pulledBackPx} px): ${JSON.stringify({ before, end })}`);
    assert.ok(end.top < before.top - 30 && end.fromEnd > 300,
      `${label}: the reader keeps their place above the end: ${JSON.stringify({ before, end })}`);
    assert.ok(end.jump, `${label}: Jump to latest is offered: ${JSON.stringify(end)}`);
    return end.top - before.top;
  };
  seen.smallStepsMovedPx = await readerMovesUp("ArrowUp and a 40 px wheel", async (pushChunk) => {
    for (let step = 0; step < 4; step += 1) {
      await page.keyboard.press("ArrowUp");
      await pushChunk();
      await page.mouse.wheel(0, -40);
      await pushChunk();
    }
  }, async () => {
    await clickTranscriptAWhileAgo();
    const point = await gutter();
    await page.mouse.move(point.x, point.y);
  });
  seen.shiftSpaceMovedPx = await readerMovesUp("Shift+Space", async (pushChunk) => {
    // More words arrive while the page-up scroll is still moving.
    await page.keyboard.press("Shift+Space");
    for (let i = 0; i < 4; i += 1) await pushChunk();
  }, clickTranscriptAWhileAgo);
  seen.setScrollMovedPx = await readerMovesUp("a set scroll position", async (pushChunk) => {
    await frame.evaluate(() => { document.querySelector("#agent-harness-stream").scrollTop -= 600; });
    for (let i = 0; i < 2; i += 1) await pushChunk();
  });

  assert.deepEqual(errors, []);
  assert.deepEqual(pageErrors, []);
  console.log(`PASS Assistant reply layout: px above the composer, longest ms behind a streaming reply ${JSON.stringify(seen)}; list markers whole (${markers.map(list => `${list.items} items, ${list.worstRoomPx}px spare`).join("; ")})`);
} catch (error) {
  console.error(`Assistant reply layout smoke failed at ${stage}`);
  console.error(JSON.stringify({ errors, pageErrors }, null, 1));
  throw error;
} finally {
  await browser?.close();
  server.close();
}
