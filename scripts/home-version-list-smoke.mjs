#!/usr/bin/env node
// Opens the Home version list on a local fixture port and checks the screen.
// The installed Home on port 61180 is not touched.

import { createServer } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import assert from "node:assert/strict";
import {
  currentVersion,
  denyWithoutGrant,
  fileVersionsFromSummary,
  hostPath,
  proposeRestore,
  versionRows,
} from "../capsules/home-gui/browser/shell-version-list.js";

const savedVersionsText = readFileSync(
  new URL("../examples/agent-host/file-versions.json", import.meta.url),
  "utf8",
);
assert.equal(
  readFileSync(new URL("../capsules/home-gui/browser/file-versions.json", import.meta.url), "utf8"),
  savedVersionsText,
);
const savedVersions = JSON.parse(savedVersionsText);
const DEMO_PAGE = savedVersions.resource;
const DEMO_OBSERVATIONS = savedVersions.observations;

assert.deepEqual(
  versionRows(DEMO_PAGE, DEMO_OBSERVATIONS).map((row) => [row.version, row.text]),
  [
    [1, "<h1>demo</h1>"],
    [2, "<h1>next</h1>"],
  ],
);
assert.equal(currentVersion(DEMO_PAGE, DEMO_OBSERVATIONS), 1);
assert.equal(versionRows("/tmp/page.html", DEMO_OBSERVATIONS).length, 0);
assert.equal(versionRows("", DEMO_OBSERVATIONS).length, 0);
assert.equal(hostPath("localhost://Users/self/Projects/demo/../index.html"), true);

const current = proposeRestore(DEMO_PAGE, DEMO_OBSERVATIONS, 1);
assert.equal(current.error, null);
assert.equal(current.step.grant, null);
assert.equal(current.step.state, "prepared");
assert.equal(current.step.text, "<h1>demo</h1>");
assert.equal(proposeRestore(DEMO_PAGE, DEMO_OBSERVATIONS, 2).error, "stale");
assert.equal(proposeRestore(DEMO_PAGE, DEMO_OBSERVATIONS, 2).step, null);
assert.equal(denyWithoutGrant(current.step).state, "denied");
assert.equal(denyWithoutGrant(current.step).grant, null);
assert.deepEqual(fileVersionsFromSummary(undefined), { resource: "", observations: [] });
assert.equal(
  fileVersionsFromSummary({
    file_versions: { resource: "/tmp/page.html", observations: DEMO_OBSERVATIONS },
  }).resource,
  "/tmp/page.html",
);

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const browserRoot = join(repoRoot, "capsules/home-gui/browser");

function contentType(path) {
  return (
    {
      ".css": "text/css; charset=utf-8",
      ".html": "text/html; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".svg": "image/svg+xml",
    }[extname(path)] || "application/octet-stream"
  );
}

function staticPath(pathname) {
  const prefix = "/apps/home-gui/";
  if (!pathname.startsWith(prefix)) {
    return null;
  }
  const suffix = decodeURIComponent(pathname.slice(prefix.length)) || "index.html";
  const candidate = resolve(browserRoot, suffix);
  const escaped = relative(browserRoot, candidate);
  if (escaped.startsWith(`..${sep}`) || escaped === ".." || isAbsolute(escaped)) {
    return null;
  }
  return candidate;
}

function fixtureHostHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"></head>
<body style="margin:0">
<iframe id="home" title="Home" style="width:1100px;height:800px;border:0"></iframe>
<script>
const origin = location.origin;
const token = "fixture-home-gui-launch-token";
const summary = JSON.parse(decodeURIComponent(location.hash.slice(1) || "%7B%7D"));
const frame = document.getElementById("home");
frame.src = "/apps/home-gui/?home_origin=" + encodeURIComponent(origin) + "#home_token=" + encodeURIComponent(token);
window.addEventListener("message", (event) => {
  if (event.origin !== origin || event.source !== frame.contentWindow) return;
  const message = event.data;
  if (!message || typeof message !== "object") return;
  if (message.type === "home:shell-ready" || message.type === "home:refresh-summary") {
    frame.contentWindow.postMessage({ type: "home:shell-summary", summary }, origin);
  }
  if (typeof message.requestId === "string") {
    frame.contentWindow.postMessage({
      type: "home:shell-response",
      requestId: message.requestId,
      result: {},
    }, origin);
  }
});
</script>
</body>
</html>`;
}

const server = createServer((req, res) => {
  const url = new URL(req.url || "/", "http://127.0.0.1");
  if (url.pathname === "/fixture/home") {
    const html = Buffer.from(fixtureHostHtml());
    res.writeHead(200, {
      "cache-control": "no-store",
      "content-length": html.length,
      "content-type": "text/html; charset=utf-8",
    });
    res.end(html);
    return;
  }
  const path = staticPath(url.pathname);
  if (!path || !existsSync(path)) {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("not found");
    return;
  }
  const body = readFileSync(path);
  res.writeHead(200, {
    "cache-control": "no-store",
    "content-length": body.length,
    "content-type": contentType(path),
  });
  res.end(body);
});

await new Promise((resolveListen, rejectListen) => {
  server.once("error", rejectListen);
  server.listen(0, "127.0.0.1", resolveListen);
});
const address = server.address();
assert(address && typeof address === "object");
const origin = `http://127.0.0.1:${address.port}`;

function playwrightSpecifier() {
  const configured = process.env.ELASTOS_PLAYWRIGHT_MODULE || "";
  if (configured) {
    return configured.startsWith("file:") ? configured : pathToFileURL(resolve(configured)).href;
  }
  return pathToFileURL(
    join(repoRoot, "elastos/tools/browser-playwright-engine/node_modules/playwright/index.js"),
  ).href;
}

const imported = await import(playwrightSpecifier());
const { chromium } = imported.default || imported;
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1100, height: 800 } });
const pageErrors = [];
page.on("pageerror", (error) => pageErrors.push(String(error)));

try {
  await page.goto(`${origin}/apps/home-gui/version-list.html`, { waitUntil: "domcontentloaded" });
  await page.locator("[data-current-page]").waitFor();
  const currentPage = await page.locator("[data-current-page]").innerText();
  assert.equal(currentPage, "<h1>demo</h1>");
  const numbers = await page.locator("[data-version-row]").evaluateAll((nodes) =>
    nodes.map((node) => node.getAttribute("data-version-row")),
  );
  assert.deepEqual(numbers, ["1", "2"]);

  await page.getByRole("button", { name: "Restore version 2" }).click();
  await page.locator('[data-status="stale"]').waitFor();
  assert.equal(await page.locator("[data-proposal]").getAttribute("data-proposal"), "");
  assert.equal(await page.locator("[data-current-page]").innerText(), "<h1>demo</h1>");

  await page.getByRole("button", { name: "Restore version 1" }).click();
  await page.locator('[data-status="prepared"]').waitFor();
  assert.equal(await page.locator("[data-proposal]").getAttribute("data-proposal"), "prepared");
  assert.equal(await page.locator("[data-proposal]").getAttribute("data-grant"), "absent");
  assert.equal(await page.locator("[data-current-page]").innerText(), "<h1>demo</h1>");
  const preparedText = await page.locator("body").innerText();
  assert.equal(preparedText.includes("fixture-grant"), false);
  assert.equal(preparedText.includes("grant-id"), false);

  await page.screenshot({ path: "/tmp/home-version-list.png" });

  await page.getByRole("button", { name: "Send" }).click();
  await page.locator('[data-status="denied"]').waitFor();
  assert.equal(await page.locator("[data-proposal]").getAttribute("data-proposal"), "denied");
  assert.equal(await page.locator("[data-proposal]").getAttribute("data-grant"), "absent");
  assert.equal(await page.locator("[data-current-page]").innerText(), "<h1>demo</h1>");

  await page.goto(`${origin}/apps/home-gui/version-list.html?resource=/tmp/page.html`, {
    waitUntil: "domcontentloaded",
  });
  await page.locator('[data-status="empty"]').waitFor();
  assert.equal(await page.locator("[data-version-row]").count(), 0);
  assert.equal(await page.locator("[data-current-page]").innerText(), "");

  const demoHash = encodeURIComponent(JSON.stringify({
    authority: { signed_in: false },
    targets: [],
  }));
  await page.goto(`${origin}/fixture/home?load=demo#${demoHash}`, { waitUntil: "domcontentloaded" });
  const demoFrame = page.frameLocator("#home");
  await demoFrame.locator('body[data-home-status="ready"]').waitFor({ timeout: 20_000 });
  await demoFrame.locator("[data-target='demo']").waitFor({ state: "attached" });
  await demoFrame.locator("[data-target='demo']").evaluate((element) => element.click());
  await demoFrame.locator("#demo-app-window h1").waitFor();
  assert.equal(await demoFrame.locator("#demo-app-window h1").innerText(), "demo");
  await demoFrame.locator("#toolbar-home").evaluate((element) => element.click());
  await demoFrame.locator("#identity-menu-approval").evaluate((element) => element.click());
  await demoFrame.locator("#approval-sheet:not([hidden])").waitFor();
  const toolAnswers = await demoFrame.locator("[data-ask='tool'] button").allTextContents();
  const hostedAnswers = await demoFrame.locator("[data-ask='hosted'] button").allTextContents();
  assert.deepEqual(toolAnswers, ["Once", "This session", "Until I stop it"]);
  assert.deepEqual(hostedAnswers, toolAnswers);
  await demoFrame.locator("[data-ask='tool'] button").nth(0).click();
  await demoFrame.locator('[data-status="allow-once"]').waitFor();
  assert.equal(await demoFrame.locator("[data-status]").getAttribute("data-grant"), "absent");
  await demoFrame.locator("[data-ask='hosted'] button").nth(2).click();
  assert.equal(await demoFrame.locator("[data-ask='hosted']").getAttribute("data-grant"), "absent");
  assert.equal(await demoFrame.locator("[data-status]").innerText(), "Hosted model: Until I stop it. Not allowed.");

  async function openVersionsFromMenu(summary) {
    const hash = encodeURIComponent(JSON.stringify(summary));
    const load = encodeURIComponent(summary.file_versions?.resource || "none");
    await page.goto(`${origin}/fixture/home?load=${load}#${hash}`, { waitUntil: "domcontentloaded" });
    const frame = page.frameLocator("#home");
    await frame.locator('body[data-home-status="ready"]').waitFor({ timeout: 20_000 });
    await frame.locator("#toolbar-home").evaluate((element) => element.click());
    await frame.locator("#identity-menu-versions").waitFor();
    await frame.locator("#identity-menu-versions").evaluate((element) => element.click());
    await frame.locator("#version-list-sheet:not([hidden])").waitFor();
    return frame;
  }

  const menuFrame = await openVersionsFromMenu({
    authority: { signed_in: false },
    targets: [],
    file_versions: {
      resource: DEMO_PAGE,
      observations: DEMO_OBSERVATIONS.map((row) => ({ ...row, grant: "fixture-grant" })),
    },
  });
  assert.equal(await menuFrame.locator("[data-current-page]").innerText(), "<h1>demo</h1>");
  assert.deepEqual(
    await menuFrame.locator("[data-version-row]").evaluateAll((nodes) =>
      nodes.map((node) => node.getAttribute("data-version-row")),
    ),
    ["1", "2"],
  );
  await menuFrame.getByRole("button", { name: "Restore version 2" }).click();
  await menuFrame.locator('[data-status="stale"]').waitFor();
  assert.equal(await menuFrame.locator("[data-current-page]").innerText(), "<h1>demo</h1>");
  await menuFrame.getByRole("button", { name: "Restore version 1" }).click();
  await menuFrame.locator('[data-status="prepared"]').waitFor();
  assert.equal(await menuFrame.locator("[data-proposal]").getAttribute("data-grant"), "absent");
  const menuText = await menuFrame.locator("body").innerText();
  assert.equal(menuText.includes("fixture-grant"), false);
  await menuFrame.getByRole("button", { name: "Send" }).click();
  await menuFrame.locator('[data-status="denied"]').waitFor();
  assert.equal(await menuFrame.locator("[data-current-page]").innerText(), "<h1>demo</h1>");
  await menuFrame.locator("#toolbar-identity-menu").waitFor({ state: "hidden" });
  await page.screenshot({ path: "/tmp/home-version-list-menu.png" });

  const savedFrame = await openVersionsFromMenu({
    authority: { signed_in: false },
    targets: [],
  });
  assert.equal(await savedFrame.locator("[data-current-page]").innerText(), "<h1>demo</h1>");
  assert.deepEqual(
    await savedFrame.locator("[data-version-row]").evaluateAll((nodes) =>
      nodes.map((node) => node.getAttribute("data-version-row")),
    ),
    ["1", "2"],
  );

  const emptyFrame = await openVersionsFromMenu({
    authority: { signed_in: false },
    targets: [],
    file_versions: { resource: "/tmp/page.html", observations: DEMO_OBSERVATIONS },
  });
  await emptyFrame.locator('[data-status="empty"]').waitFor();
  assert.equal(await emptyFrame.locator("[data-version-row]").count(), 0);

  assert.deepEqual(pageErrors, []);
  console.log(`home version list smoke passed ${origin}`);
} finally {
  await browser.close();
  await new Promise((resolveClose) => server.close(resolveClose));
}
