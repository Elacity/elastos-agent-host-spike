#!/usr/bin/env node
// Import the real stream module in Chromium and, on macOS, system WKWebView.
// ASSISTANT_FOLLOW_REF serves a pinned module for fail-before evidence.
// ASSISTANT_FOLLOW_WEBKIT=1 also runs system WebKit with Accessibility access.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { readFile, mkdir } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "./system-uiux-fixture.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = resolve(root, "output/assistant-follow-input");
const run = promisify(execFile);
const ref = process.env.ASSISTANT_FOLLOW_REF;
const native = process.env.ASSISTANT_FOLLOW_WEBKIT === "1";
const binary = resolve(output, "webkit");
const reports = [];
const record = report => {
  reports.push(report);
  console.log(JSON.stringify({ ref: ref || "worktree", ...report }));
};
const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url, "http://fixture").pathname;
    const relative = path === "/" ? "scripts/fixtures/assistant-follow-input.html" : path.slice(1);
    assert.ok(relative.startsWith("capsules/assistant/browser/") || relative === "scripts/fixtures/assistant-follow-input.html");
    const file = resolve(root, relative);
    assert.ok(file.startsWith(root));
    const body = ref && relative === "capsules/assistant/browser/agent-stream.js"
      ? execFileSync("git", ["show", `${ref}:${relative}`], { cwd: root }) : await readFile(file);
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
  browser = await chromium.launch({ headless: !native, args: native ? ["--force-renderer-accessibility"] : [], ignoreDefaultArgs: ["--hide-scrollbars"],
    ...(process.env.BRAVE_BIN ? { executablePath: process.env.BRAVE_BIN } : {}) });
  for (const mode of native ? ["", "fallback", "swallow"] : ["", "fallback"]) {
    const page = await browser.newPage({ viewport: native ? null : { width: 800, height: 600 } });
    const browserSession = native ? await browser.newBrowserCDPSession() : null;
    const browserPid = native ? (await browserSession.send("SystemInfo.getProcessInfo")).processInfo.find(p => p.type === "browser").id : null;
    const driverErrors = [];
    page.on("console", message => { if (message.type() === "error") driverErrors.push(message.text()); });
    await page.exposeFunction("driveInput", async request => {
      const b = request.rect;
      if (native) {
        await run(binary, ["--input", String(browserPid), JSON.stringify(request)], { timeout: 5000 });
      } else if (request.phase === "key") {
        await page.keyboard.press(request.key);
      } else {
        const selection = request.phase === "select";
        const back = request.phase === "drag-back";
        const x = selection ? b.x + 8 : b.x + b.width - 3;
        const y = selection ? b.y + b.height / 2 : b.y + (back ? 14 : b.height - 14);
        await page.mouse.move(x, y);
        await page.mouse.down();
        await page.mouse.move(selection ? b.x + b.width - 8 : x,
          selection ? y : b.y + (back ? b.height - 14 : 36), { steps: 16 });
        await page.mouse.up();
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
    await page.goto(`${url}?${mode}`);
    await page.waitForFunction(() => window.__report, null, { timeout: 45000 });
    record({ engine: "Chromium", input: native ? "CGEvent" : "Playwright", driverErrors, ...await page.evaluate(() => window.__report) });
    await page.close();
  }
  await browser.close(); browser = null;
  if (native) {
    for (const mode of ["", "fallback", "swallow"]) {
      const { stdout } = await run(binary, [`${url}?${mode}`], { timeout: 60000 });
      record({ engine: "system WebKit", input: "CGEvent", ...JSON.parse(stdout.trim()) });
    }
  }
  assert.deepEqual(reports.flatMap(r => r.failures.map(f => `${r.engine} fallback=${r.fallback} swallow=${r.swallow}: ${f}`)), []);
  console.log(`PASS Assistant follow input: ${reports.length} engine/settlement runs`);
} finally {
  await browser?.close();
  server.close();
}
