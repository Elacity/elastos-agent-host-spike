import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import http from "node:http";
import test from "node:test";
import { returnInstalledHome } from "./ci-installed-home-navigation.mjs";
import { publicJourneyFailure } from "./ci-installed-home-failure.mjs";

const require = createRequire(new URL("../elastos/tools/browser-playwright-engine/package.json", import.meta.url));
const { chromium } = require("playwright");
const dockStyle = readFileSync(new URL("../capsules/home-gui/browser/style.css", import.meta.url));

test("installed recovery uses Assistant's visible Home control while Home's dock is hidden", async t => {
  // The fixture isolates navigation from model execution. Hosted installed CI
  // owns acceptance of the real Runtime, model and complete Home journey.
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, "http://localhost");
    response.setHeader("content-type", "text/html");
    if (url.pathname === "/dock.css") {
      response.setHeader("content-type", "text/css");
      response.end(dockStyle);
    } else if (url.pathname === "/shell") {
      response.end(`<!doctype html><link rel="stylesheet" href="/dock.css">
        <div id="desktop" hidden>Home desktop</div>
        <div id="assistant-space"><iframe id="assistant-space-frame" src="/assistant"></iframe></div>
        <div class="taskbar is-assistant-face"><div class="taskbar-primary">
          <button id="assistant-toggle">Assistant</button>
        </div></div>
        <script>
          addEventListener("message", event => {
            if (event.source !== document.querySelector("#assistant-space-frame").contentWindow ||
                event.data?.type !== "home-agent:close") return;
            if (new URLSearchParams(location.search).get("failure") !== "room_open") {
              document.querySelector("#assistant-space").hidden = true;
              document.querySelector("#desktop").hidden = false;
            }
          });
        </script>`);
    } else if (url.pathname === "/assistant") {
      response.end(`<!doctype html><button id="agent-shelf-flip-back" aria-label="Back to Home">Home</button>
        <script>
          document.querySelector("#agent-shelf-flip-back").addEventListener("click", () => {
            parent.postMessage({ type: "home-agent:close" }, location.origin);
          });
        </script>`);
    } else if (url.pathname === "/") {
      const failure = url.searchParams.get("failure") ?? "";
      response.end(`<!doctype html><body data-home-status="${failure === "home_unready" ? "loading" : "ready"}">
        <iframe id="active-shell-frame" src="/shell?failure=${failure}"></iframe>`);
    } else response.writeHead(404).end();
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    for (const failure of ["", "room_open", "home_unready"]) {
      await t.test(failure || "visible Home returns to ready desktop", async () => {
        const page = await browser.newPage();
        try {
          await page.goto(`http://127.0.0.1:${server.address().port}/?failure=${failure}`);
          const shell = page.frameLocator("#active-shell-frame");
          await shell.locator("#assistant-toggle").waitFor({ state: "hidden" });
          const assistantElement = await shell.locator("#assistant-space-frame").elementHandle();
          const assistant = await assistantElement.contentFrame();
          await assistant.locator("#agent-shelf-flip-back").waitFor({ state: "visible" });
          let screenshot;
          const takeScreenshot = page.screenshot.bind(page);
          page.screenshot = async options => {
            screenshot = options;
            const png = await takeScreenshot({ fullPage: options.fullPage });
            assert.equal(png.subarray(1, 4).toString(), "PNG");
          };
          if (failure) {
            const results = { memory_refusal: "passed" };
            let error;
            try { await returnInstalledHome(page, assistant, "/isolated-evidence", 3000); }
            catch (caught) { error = caught; }
            assert(error, "failed recovery keeps item 7 open");
            assert.equal(screenshot, undefined);
            const receipt = publicJourneyFailure(error, "finite_home_recovery");
            results[receipt.failure_stage] = "failed";
            assert.equal(results.memory_refusal, "passed");
            assert.equal(results.finite_home_recovery, "failed");
            assert.equal(receipt.failure, failure === "room_open" ? "timeout" : "assertion_failed");
          } else {
            await returnInstalledHome(page, assistant, "/isolated-evidence", 3000);
            assert.deepEqual(screenshot, { path: "/isolated-evidence/finite-home-recovery.png", fullPage: true });
            assert.equal(await shell.locator("#assistant-space").isVisible(), false);
            assert.equal(await shell.locator("#desktop").isVisible(), true);
          }
        } finally { await page.close(); }
      });
    }
  } finally {
    await browser?.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
