#!/usr/bin/env node
// Import the real stream module in Chromium and, on macOS, system WKWebView.
// ASSISTANT_FOLLOW_REF serves a pinned module for fail-before evidence.
// ASSISTANT_FOLLOW_MATRIX=1 starts a live turn for develop/candidate comparison.
// ASSISTANT_FOLLOW_WEBKIT=1 also runs system WebKit with Accessibility access.
import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "./system-uiux-fixture.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = resolve(root, "output/assistant-follow-input");
const run = promisify(execFile);
const ref = process.env.ASSISTANT_FOLLOW_REF;
const matrix = process.env.ASSISTANT_FOLLOW_MATRIX === "1";
const native = process.env.ASSISTANT_FOLLOW_WEBKIT === "1";
const modes = process.env.ASSISTANT_FOLLOW_MODES
  ? process.env.ASSISTANT_FOLLOW_MODES.split(",").map(mode => mode === "normal" ? "" : mode)
  : native ? ["", "fallback", "swallow"] : ["", "fallback"];
assert.ok(modes.every(mode => ["", "fallback", "swallow"].includes(mode)), "known settlement modes");
const binary = resolve(output, "webkit");
const sourcePath = "capsules/assistant/browser/agent-stream.js";
const source = ref ? execFileSync("git", ["show", `${ref}:${sourcePath}`], { cwd: root }) : await readFile(resolve(root, sourcePath));
const sourceSha256 = createHash("sha256").update(source).digest("hex");
const reports = [];
const record = report => {
  report.sourceSha256 = sourceSha256;
  reports.push(report);
  console.log(JSON.stringify({ ref: ref || "worktree", ...report }));
};
const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url, "http://fixture").pathname;
    if (path === "/favicon.ico") { res.writeHead(204); res.end(); return; }
    const relative = path === "/" ? "scripts/fixtures/assistant-follow-input.html" : path.slice(1);
    assert.ok(relative.startsWith("capsules/assistant/browser/") || relative === "scripts/fixtures/assistant-follow-input.html");
    const file = resolve(root, relative);
    assert.ok(file.startsWith(root));
    const body = relative === sourcePath ? source : await readFile(file);
    res.writeHead(200, { "content-type": [".js", ".mjs"].includes(extname(file)) ? "text/javascript" : extname(file) === ".css" ? "text/css" : "text/html", "cache-control": "no-store" });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
let browser;
try {
  await mkdir(output, { recursive: true });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const url = `http://127.0.0.1:${server.address().port}/`;
  if (native) {
    assert.equal(process.platform, "darwin", "system WKWebView needs macOS");
    await run("swiftc", ["-O", "-module-cache-path", resolve(output, "module-cache"), "-o", binary,
      resolve(root, "scripts/fixtures/assistant-follow-input-webkit.swift")], { timeout: 60000 });
  }
  // Keep scrolling and its events on the main thread. With threaded scroll,
  // Chromium commits a scroll offset on the compositor, and a starved
  // compositor under four-core load held that commit for tens of seconds: the
  // module pinned the room and scrollTop still read the old offset, so the
  // queued-pin cases read fromEnd 100 with follow true and a native drag read
  // a position it had already left. The page's timers ran at their normal
  // rate the whole time. The check asserts main-thread follow state, not
  // compositor scheduling.
  browser = await chromium.launch({ headless: !native,
    args: native ? ["--force-renderer-accessibility"] : ["--disable-threaded-scrolling", "--disable-smooth-scrolling"],
    ignoreDefaultArgs: ["--hide-scrollbars"],
    ...(process.env.BRAVE_BIN ? { executablePath: process.env.BRAVE_BIN } : {}) });
  for (const mode of modes) {
    const page = await browser.newPage({ viewport: native ? null : { width: 800, height: 600 } });
    const browserSession = native ? await browser.newBrowserCDPSession() : null;
    const browserPid = native ? (await browserSession.send("SystemInfo.getProcessInfo")).processInfo.find(p => p.type === "browser").id : null;
    const driverErrors = [];
    const inputSteps = [];
    const step = async (label, work) => {
      const started = performance.now();
      await work();
      inputSteps.push({ label, ms: Math.round(performance.now() - started) });
    };
    page.on("console", message => { if (message.type() === "error") driverErrors.push(message.text()); });
    await page.exposeFunction("driveInput", async request => {
      const b = request.rect;
      if (native) {
        await run(binary, ["--input", String(browserPid), JSON.stringify(request)], { timeout: 5000 });
      } else if (request.phase === "wheel") {
        await step("wheel move", () => page.mouse.move(b.x + 120, b.y + 180));
        for (const delta of request.deltas) {
          await step(`wheel ${delta}`, () => page.mouse.wheel(0, delta));
          await page.waitForTimeout(request.gapMs || 20);
        }
      } else if (["hold", "release"].includes(request.phase)) {
        await step(`${request.phase} move`, () => page.mouse.move(b.x + b.width - (request.content ? 40 : 3), b.y + b.height - 14));
        await step(`${request.phase} ${request.phase === "hold" ? "down" : "up"}`,
          () => request.phase === "hold" ? page.mouse.down() : page.mouse.up());
      } else if (request.phase === "key") {
        await step(`key ${request.key}`, () => page.keyboard.press(request.key));
      } else {
        const selection = request.phase === "select";
        const back = request.phase === "drag-back";
        const x = selection ? b.x + 8 : b.x + b.width - 3;
        const y = selection ? b.y + b.height / 2 : b.y + (back ? 14 : b.height - 14);
        await step(`${request.phase} move`, () => page.mouse.move(x, y));
        await step(`${request.phase} down`, () => page.mouse.down());
        // Two moves make a drag, not a click. Each extra move costs a CDP
        // acknowledgement, and a starved browser charged 4.4 s for one during
        // a drag (70 s for sixteen): the gesture then finished after its
        // assertions had waited, and the drag itself was lost. The assertions
        // read the position and follow state after the gesture, so the number
        // of intermediate positions does not change what they test.
        await step(`${request.phase} drag`, () => page.mouse.move(selection ? b.x + b.width - 8 : x,
          selection ? y : b.y + (back ? b.height - 14 : 36), { steps: 2 }));
        await step(`${request.phase} up`, () => page.mouse.up());
      }
    });
    await page.addInitScript(() => {
      window.webkit = { messageHandlers: { probe: { postMessage: async text => {
        const request = JSON.parse(text);
        if (request.phase === "done") return;
        try { await window.driveInput(request); window.__continue(true); }
        catch (error) { console.error(error); window.__continue(false); }
      } } } };
    });
    await page.goto(`${url}?${mode}${matrix ? "&matrix" : ""}#home_token=follow-fixture`);
    // The fixture runs every case in the page, so this bound must sit above
    // the page's slowest run, not at its median: under a four-core load like
    // CI's the same page took 52-58 s, and a 55 s bound expired in 18 of 40
    // runs. 120 s leaves the same margin over that work for each mode, and
    // together with the runner's own per-run limit.
    // Poll on a timer. Playwright polls a waitForFunction on animation frames
    // by default, and a loaded renderer starves that loop: the report was set
    // but never read, which is how a run died at the bound.
    const reportTimeout = matrix ? 180000 : 120000;
    try {
      await page.waitForFunction(() => window.__report, null, { polling: 100, timeout: reportTimeout });
    } catch (error) {
      // Diagnosis only: a page that never writes its report must say where it
      // stopped and whether its clock and timers still advance. Bounded, so a
      // wedged renderer cannot hold this run past the runner's own limit.
      const diagnostics = await Promise.race([
        page.evaluate(() => ({
          report: Boolean(window.__report),
          phase: window.__fixture?.phase ?? null,
          case: window.__fixture?.case ?? null,
          step: window.__fixture?.step ?? null,
          lastCheck: window.__fixture?.lastCheck ?? null,
          lastWaitTimeout: window.__fixture?.waitTimeouts?.at(-1) ?? null,
          waitTimeoutCount: window.__fixture?.waitTimeouts?.length ?? 0,
          waitTimeouts: window.__fixture?.waitTimeouts ?? [],
          timingCount: window.__fixture?.timings?.length ?? 0,
          slowest: (window.__fixture?.timings ?? []).slice().sort((a, b) => b.ms - a.ms).slice(0, 12),
          lastTiming: (window.__fixture?.timings ?? []).slice(-6),
          visibilityState: document.visibilityState,
          hidden: document.hidden,
          dateNow: Date.now(),
          performanceNow: performance.now(),
          heartbeat: window.__heartbeat ?? null,
        })).catch(inner => ({ evaluateFailed: String(inner.message || inner) })),
        new Promise(done => setTimeout(() => done({ evaluate: "no answer within 10000 ms" }), 10000)),
      ]);
      console.error(`report wait timed out mode=${mode || "normal"} after ${reportTimeout} ms ` +
        JSON.stringify({ nodeDateNow: Date.now(), nodePerformanceNow: Math.round(performance.now()),
          driverSteps: inputSteps.slice(-14), slowDriverSteps: inputSteps.slice(-40).sort((a, b) => b.ms - a.ms).slice(0, 6),
          ...diagnostics }));
      throw error;
    }
    record({ engine: "Chromium", input: native ? "CGEvent" : "Playwright", driverErrors, ...await page.evaluate(() => window.__report) });
    await page.close();
  }
  await browser.close(); browser = null;
  if (native) {
    for (const mode of modes) {
      const { stdout } = await run(binary, [`${url}?${mode}${matrix ? "&matrix" : ""}#home_token=follow-fixture`], { timeout: matrix ? 190000 : 60000 });
      record({ engine: "system WebKit", input: "CGEvent", ...JSON.parse(stdout.trim()) });
    }
  }
  await writeFile(resolve(output, `${(ref || "worktree").replaceAll("/", "-")}${matrix ? "-matrix" : ""}.json`), JSON.stringify(reports, null, 2));
  if (matrix && process.env.ASSISTANT_FOLLOW_BASELINE) {
    const baseline = JSON.parse(await readFile(process.env.ASSISTANT_FOLLOW_BASELINE, "utf8"));
    assert.equal(reports.length, baseline.length, "same engine/mode coverage");
    for (const report of reports) {
      const prior = baseline.find(r => r.engine === report.engine && r.fallback === report.fallback && r.swallow === report.swallow);
      assert.ok(prior, "matching baseline engine/mode");
      assert.deepEqual(report.driverErrors || [], [], "native driver and page console are clean");
      assert.deepEqual(report.failures.filter(f => !Object.hasOwn(report.checks, f) || /driver available|trusted .* received/.test(f)), [],
        "shared failures cannot hide fixture or input errors");
      assert.deepEqual(Object.keys(report.checks), Object.keys(prior.checks), "same matrix checks");
      assert.deepEqual(report.failures.filter(f => !prior.failures.includes(f)), [], "candidate has no new failures");
      for (const label of ["1px then 220ms quiet then 80px and growth", "stationary scrollbar hold with 150px growth",
        "stream growth and completion without Jump flash"]) assert.equal(report.checks[label], true, label);
      console.log(JSON.stringify({ engine: report.engine, fallback: report.fallback, swallow: report.swallow,
        sharedFailures: report.failures }));
    }
  } else {
    assert.deepEqual(reports.flatMap(r => r.failures.map(f => `${r.engine} fallback=${r.fallback} swallow=${r.swallow}: ${f}`)), []);
  }
  console.log(`PASS Assistant follow input: ${reports.length} engine/settlement runs`);
} finally {
  await browser?.close();
  server.close();
}
