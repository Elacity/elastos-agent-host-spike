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
  browser = await chromium.launch({ headless: true, ignoreDefaultArgs: ["--hide-scrollbars"],
    ...(process.env.BRAVE_BIN ? { executablePath: process.env.BRAVE_BIN } : {}) });
  for (const fallback of [false, true]) {
    const page = await browser.newPage({ viewport: { width: 800, height: 600 } });
    await page.goto(`${url}${fallback ? "?fallback" : ""}`);
    await page.waitForFunction(() => window.__drag);
    const b = await page.evaluate(() => window.__drag);
    await page.mouse.move(b.x + b.width - 3, b.y + b.height - 14);
    await page.mouse.down();
    await page.mouse.move(b.x + b.width - 3, b.y + 36, { steps: 16 });
    await page.mouse.up();
    await page.evaluate(() => window.__continue(true));
    await page.waitForFunction(() => window.__report, null, { timeout: 20000 });
    record({ engine: "Chromium", ...await page.evaluate(() => window.__report) });
    await page.close();
  }
  await browser.close(); browser = null;
  if (process.env.ASSISTANT_FOLLOW_WEBKIT === "1") {
    assert.equal(process.platform, "darwin", "system WKWebView needs macOS");
    const binary = resolve(output, "webkit");
    await run("swiftc", ["-O", "-module-cache-path", resolve(output, "module-cache"), "-o", binary,
      resolve(root, "scripts/fixtures/assistant-follow-input-webkit.swift")], { timeout: 60000 });
    for (const fallback of [false, true]) {
      const { stdout } = await run(binary, [`${url}${fallback ? "?fallback" : ""}`], { timeout: 30000 });
      record({ engine: "system WebKit", ...JSON.parse(stdout.trim()) });
    }
  }
  assert.deepEqual(reports.flatMap(r => r.failures.map(f => `${r.engine} fallback=${r.fallback}: ${f}`)), []);
  console.log(`PASS Assistant follow input: ${reports.length} engine/settlement runs`);
} finally {
  await browser?.close();
  server.close();
}
