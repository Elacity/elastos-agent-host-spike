// A stand-in for Runtime and Home, for a render-only page's browser smoke
// (capsule kit item A5). Moved here from
// examples/photo-viewer/surface/photos-browser-smoke.mjs.
//
// The server serves the page's files with the headers Runtime sends for an
// app (the CSP, CORS and isolation headers that elastos-server's
// gateway_tests/photos.rs runtime_serves_the_real_photos_surface_in_its_sandbox
// pins), answers the CORS preflight as the gateway front door does, refuses a
// request without the launch token or from outside the opaque frame, and
// serves the page's routes. Home frames the page in its opaque sandbox
// (capsules/home-gui/browser/shell-windows.js).
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { join } from "node:path";

import { chromium } from "../../../scripts/system-uiux-fixture.mjs";

export const TOKEN = "smoke-launch-token";
export const SANDBOX = "allow-downloads allow-forms allow-modals allow-pointer-lock allow-scripts";

/**
 * Starts the stand-in for the app `app`, serving `files` from `browserRoot`.
 * `routes(method, path)` returns `{ type, body, headers }` for a route the page
 * may read, or null. Returns the base URL, the requests seen, and `close`.
 */
export async function standIn({ app, browserRoot, files, routes }) {
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
          `src="/apps/${app}/?home_origin=${encodeURIComponent(origin)}#home_token=${TOKEN}" ` +
          `width="800" height="600"></iframe>`,
      );
      return;
    }
    if (url.pathname.startsWith(`/apps/${app}/`)) {
      const name = url.pathname.slice(`/apps/${app}/`.length) || "index.html";
      if (!files.includes(name)) {
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
    if (url.pathname === "/favicon.ico") {
      // A browser asks for it on its own; Home has none. A 403 here is a
      // console error, and the smoke fails on console errors.
      response.writeHead(204).end();
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
    const route = routes(request.method, url.pathname);
    if (route) {
      response.writeHead(200, { "content-type": route.type, "cache-control": "no-store", ...route.headers, ...cors });
      response.end(route.body);
      return;
    }
    response.writeHead(404, cors).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { base: `http://127.0.0.1:${server.address().port}`, requests, close: () => server.close() };
}

/**
 * Opens Home on the stand-in in real Chromium and runs `check(frame, page)` on
 * the framed app. Returns the console errors, page errors and failed requests
 * seen, for the caller to require none.
 */
export async function inHome(base, check) {
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
    await check(page.frameLocator("#app"), page);
    return problems;
  } finally {
    await browser.close();
  }
}
