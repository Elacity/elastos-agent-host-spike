// The real Photos page in real Chromium, framed the way Home frames apps.
//
// A local server stands in for Runtime. It serves the surface files with the
// headers Runtime sends for an app (the CSP, CORS and isolation headers that
// gateway_tests/photos.rs runtime_serves_the_real_photos_surface_in_its_sandbox
// pins), answers the CORS preflight as the gateway front door does, and
// stands in for the two Photos routes. The page is framed in Home's opaque
// sandbox (capsules/home-gui/browser/shell-windows.js).
//
// Run: node examples/photo-viewer/surface/photos-browser-smoke.mjs
import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { crc32, deflateSync } from "node:zlib";

import { chromium } from "../../../scripts/system-uiux-fixture.mjs";

const browserRoot = fileURLToPath(new URL("./browser/", import.meta.url));
const TOKEN = "smoke-launch-token";
const SANDBOX = "allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts";
const HOSTILE = '<img src=x onerror="fetch(\'/api/apps/home/state\')">';

/** A real PNG of one colour. */
function png(width, height, [r, g, b]) {
  const chunk = (type, data) => {
    const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([length, body, crc]);
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header.set([8, 2, 0, 0, 0], 8);
  const row = Buffer.concat([Buffer.from([0]), Buffer.from(Array.from({ length: width }, () => [r, g, b]).flat())]);
  const pixels = Buffer.concat(Array.from({ length: height }, () => row));
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(pixels)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

const IMAGES = { 0: png(4, 3, [200, 30, 30]), 2: png(3, 5, [30, 30, 200]) };
const PLAYLIST = {
  schema: "elastos.photo-viewer.playlist/v1",
  album: "localhost://Users/self/Pictures/album.json",
  items: [
    { order: 0, uri: "localhost://Users/self/Pictures/a.png", mime: "image/png", width: 4, height: 3, duration_ms: 60000 },
    { order: 2, uri: "localhost://Users/self/Pictures/c.png", mime: "image/png", width: 3, height: 5, duration_ms: 60000 },
  ],
  skipped: [{ order: 1, uri: "localhost://Users/self/Pictures/b.gif", reason: "unsupported", message: HOSTILE }],
};

const requests = [];
const server = createServer(async (request, response) => {
  const origin = `http://${request.headers.host}`;
  const url = new URL(request.url, origin);
  requests.push(`${request.method} ${url.pathname}`);
  const opaque = request.headers.origin === "null";
  const cors = opaque ? { "access-control-allow-origin": "null", vary: "Origin" } : {};
  const isolation = { "cross-origin-opener-policy": "same-origin", "cross-origin-embedder-policy": "require-corp" };

  if (url.pathname === "/") {
    // Home: frames the app in an opaque sandbox.
    response.writeHead(200, { "content-type": "text/html; charset=utf-8", ...isolation });
    response.end(
      `<!doctype html><title>Home</title><iframe id="app" sandbox="${SANDBOX}" ` +
        `src="/apps/image-viewer/?home_origin=${encodeURIComponent(origin)}#home_token=${TOKEN}" ` +
        `width="800" height="600"></iframe>`,
    );
    return;
  }
  if (url.pathname.startsWith("/apps/image-viewer/")) {
    const name = url.pathname.slice("/apps/image-viewer/".length) || "index.html";
    if (!["index.html", "main.js", "photos.js", "photos.css"].includes(name)) {
      response.writeHead(404).end();
      return;
    }
    const types = { html: "text/html; charset=utf-8", js: "application/javascript", css: "text/css" };
    const headers = {
      "content-type": types[name.split(".").pop()],
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "access-control-allow-origin": "null",
      "cross-origin-resource-policy": "cross-origin",
      "referrer-policy": "no-referrer",
      ...isolation,
    };
    if (name === "index.html") {
      // Runtime's app policy, as served (browser_capsules.rs).
      headers["content-security-policy"] =
        `sandbox allow-scripts allow-forms allow-downloads; default-src ${origin}; ` +
        `script-src 'self' 'wasm-unsafe-eval'; style-src ${origin} 'unsafe-inline'; ` +
        `img-src ${origin} blob: data:; connect-src ${origin} ws://${request.headers.host}; ` +
        `frame-src ${origin}; object-src 'none'; base-uri 'none'; form-action ${origin}`;
    }
    response.writeHead(200, headers);
    response.end(await readFile(join(browserRoot, name)));
    return;
  }
  if (url.pathname.startsWith("/api/") && request.method === "OPTIONS") {
    // As the gateway front door answers a preflight from an app frame.
    response.writeHead(204, {
      ...cors,
      "access-control-allow-methods": "GET, POST, PUT, DELETE, HEAD",
      "access-control-allow-headers": "content-type,x-elastos-home-token",
    });
    response.end();
    return;
  }
  if (request.headers["x-elastos-home-token"] !== TOKEN || !opaque) {
    response.writeHead(403, { "content-type": "application/json", ...cors });
    response.end(JSON.stringify({ error: "refused by the smoke server" }));
    return;
  }
  if (url.pathname === "/api/viewers/image-viewer/playlist" && request.method === "GET") {
    response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store", ...cors });
    response.end(JSON.stringify(PLAYLIST));
    return;
  }
  const item = url.pathname.match(/^\/api\/viewers\/image-viewer\/playlist\/item\/(\d+)$/);
  if (item && request.method === "GET" && IMAGES[item[1]]) {
    response.writeHead(200, {
      "content-type": "application/octet-stream",
      "x-content-type-options": "nosniff",
      "cache-control": "no-store",
      ...cors,
    });
    response.end(IMAGES[item[1]]);
    return;
  }
  response.writeHead(404, cors).end();
});

server.listen(0, "127.0.0.1");
await once(server, "listening");
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  const problems = [];
  page.on("console", (message) => {
    if (message.type() === "error") problems.push(message.text());
  });
  page.on("pageerror", (error) => problems.push(String(error)));
  page.on("requestfailed", (request) => problems.push(`failed: ${request.url()} ${request.failure()?.errorText}`));
  await page.goto(`${base}/`);
  const frame = page.frameLocator("#app");

  const photo = frame.locator("#photo");
  await photo.evaluate((img) =>
    img.complete && img.naturalWidth ? null : new Promise((resolve) => img.addEventListener("load", resolve, { once: true })),
  );
  const first = await photo.evaluate((img) => ({ src: img.src, width: img.naturalWidth, height: img.naturalHeight }));
  assert.match(first.src, /^blob:/);
  assert.deepEqual([first.width, first.height], [4, 3]);
  assert.equal(await frame.locator("#caption").textContent(), "1 / 2 · 4 × 3");

  // The skipped entry is text: the markup in it did not run or load anything.
  assert.equal(await frame.locator("#skipped li").textContent(), `Photo 2: ${HOSTILE}`);
  assert.equal(await frame.locator("#skipped img").count(), 0);

  await frame.locator("#next").click();
  await frame.locator("#caption").filter({ hasText: "2 / 2" }).waitFor();
  const second = await photo.evaluate(async (img) => {
    if (!img.complete || !img.naturalWidth) await new Promise((resolve) => img.addEventListener("load", resolve, { once: true }));
    return { width: img.naturalWidth, height: img.naturalHeight };
  });
  assert.deepEqual([second.width, second.height], [3, 5]);

  // The frame is the opaque sandbox Home gives it: no storage, no cookies.
  const sandboxed = await frame.locator("body").evaluate(() => {
    try {
      window.localStorage.getItem("x");
      return false;
    } catch {
      return true;
    }
  });
  assert.equal(sandboxed, true);

  const api = requests.filter((line) => line.includes(" /api/"));
  assert.deepEqual(
    api.filter((line) => line.startsWith("GET")),
    [
      "GET /api/viewers/image-viewer/playlist",
      "GET /api/viewers/image-viewer/playlist/item/0",
      "GET /api/viewers/image-viewer/playlist/item/2",
    ],
  );
  assert.ok(api.every((line) => /^(GET|OPTIONS) \/api\/viewers\/image-viewer\/playlist(\/item\/\d+)?$/.test(line)), api.join("\n"));
  assert.ok(!requests.some((line) => line.includes("/api/apps/home/state")), "the skipped message ran");
  assert.deepEqual(problems, [], "console errors (CSP or script)");
  console.log("photos browser smoke: ok");
  console.log(requests.join("\n"));
} finally {
  await browser.close();
  server.close();
}
