// The Photos surface against a fake fetch and a fake document.
// Run: node --test examples/photo-viewer/surface/photos.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ITEM_ROUTE,
  MAX_DURATION_MS,
  MIN_DURATION_MS,
  PLAYLIST_ROUTE,
  PLAYLIST_SCHEMA,
  TOKEN_HEADER,
  launchToken,
  mountPhotos,
  readPlaylist,
} from "./browser/photos.js";

const TOKEN = "launch-token-for-this-frame";
const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

function element(tag = "div") {
  return {
    tag,
    textContent: "",
    hidden: false,
    src: undefined,
    alt: "",
    children: [],
    listeners: {},
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    addEventListener(type, listener) {
      this.listeners[type] = listener;
    },
  };
}

function fakeDocument() {
  const ids = ["photo", "caption", "status", "skipped", "skipped-title", "previous", "pause", "next"];
  const elements = Object.fromEntries(ids.map((id) => [id, element()]));
  return {
    elements,
    listeners: {},
    getElementById: (id) => elements[id] ?? null,
    createElement: (tag) => element(tag),
    addEventListener(type, listener) {
      this.listeners[type] = listener;
    },
  };
}

function playlist(items, skipped = []) {
  return { schema: PLAYLIST_SCHEMA, album: "localhost://Users/self/Pictures/album.json", items, skipped };
}

function item(order, extra = {}) {
  return {
    order,
    uri: `localhost://Users/self/Pictures/photo-${order}.png`,
    mime: "image/png",
    width: 640,
    height: 480,
    duration_ms: 5000,
    ...extra,
  };
}

function response(status, body, kind = "json") {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => (kind === "json" ? body : JSON.parse(body)),
    arrayBuffer: async () => body,
  };
}

/** A window with a fake fetch that serves `routes` and records each request. */
function world({ hash = `#home_token=${TOKEN}`, routes = {} } = {}) {
  const requests = [];
  const urls = { made: [], revoked: [] };
  const timers = [];
  const env = {
    document: fakeDocument(),
    location: { hash },
    fetch(url, options) {
      requests.push({ url, options, self: this });
      const route = routes[url];
      if (!route) return Promise.resolve(response(404, { error: "not a route here" }));
      return Promise.resolve(typeof route === "function" ? route() : route);
    },
    Blob: class {
      constructor(parts, options) {
        this.parts = parts;
        this.type = options.type;
      }
    },
    URL: {
      createObjectURL(blob) {
        const url = `blob:photos/${urls.made.length}`;
        urls.made.push({ url, blob });
        return url;
      },
      revokeObjectURL(url) {
        urls.revoked.push(url);
      },
    },
    setTimeout(callback, delay) {
      timers.push({ callback, delay, cleared: false });
      return timers.length - 1;
    },
    clearTimeout(id) {
      if (timers[id]) timers[id].cleared = true;
    },
  };
  return { env, requests, urls, timers };
}

const bytes = (label) => new TextEncoder().encode(`\x89PNG ${label}`).buffer;

function servingPlaylist(list, images = {}) {
  const routes = { [PLAYLIST_ROUTE]: response(200, list) };
  for (const [order, body] of Object.entries(images)) {
    routes[`${ITEM_ROUTE}${order}`] = response(200, body);
  }
  return routes;
}

test("the token comes from the fragment only", () => {
  assert.equal(launchToken(`#home_token=${TOKEN}`), TOKEN);
  assert.equal(launchToken("#other=1"), "");
  assert.equal(launchToken(""), "");
});

test("it renders only playlist items, in position order", async () => {
  const list = playlist([item(2), item(0)], [{ order: 1, uri: "x", reason: "too_large", message: "Too large." }]);
  const { env, requests, urls } = world({ routes: servingPlaylist(list, { 0: bytes("a"), 2: bytes("c") }) });
  const photos = mountPhotos(env);
  await photos.ready();
  assert.deepEqual(photos.state.slides.map((slide) => slide.order), [0, 2]);
  assert.equal(env.document.elements.photo.src, "blob:photos/0");
  assert.equal(urls.made[0].blob.type, "image/png");
  assert.equal(env.document.elements.caption.textContent, "1 / 2 · 640 × 480");
  await photos.next();
  assert.equal(env.document.elements.photo.src, "blob:photos/1");
  await photos.next();
  // Position 1 was skipped: it is never asked for.
  assert.deepEqual(
    requests.map((request) => request.url),
    [PLAYLIST_ROUTE, `${ITEM_ROUTE}0`, `${ITEM_ROUTE}2`, `${ITEM_ROUTE}0`],
  );
  assert.deepEqual(urls.revoked, ["blob:photos/0", "blob:photos/1"]);
});

test("it never requests a path: items are asked for by position, and their URIs are dropped", async () => {
  const list = playlist([
    item(0, { uri: "localhost://Users/self/Documents/secret.png" }),
    item(1, { uri: "../../../etc/passwd" }),
    { ...item(3), order: "4/../../secret" },
    { ...item(5), order: -1 },
    { ...item(6), order: 1.5 },
    item(0),
  ]);
  const { env, requests } = world({ routes: servingPlaylist(list, { 0: bytes("a"), 1: bytes("b") }) });
  const photos = mountPhotos(env);
  await photos.ready();
  await photos.next();
  assert.deepEqual(photos.state.slides.map((slide) => slide.order), [0, 1]);
  for (const slide of photos.state.slides) {
    assert.deepEqual(Object.keys(slide).sort(), ["durationMs", "height", "mime", "order", "width"]);
  }
  for (const { url } of requests) {
    assert.match(url, /^\/api\/viewers\/image-viewer\/playlist(\/item\/\d+)?$/);
    assert.ok(!url.includes("Users") && !url.includes(".."), url);
  }
  // Bad positions and the repeated 0 are listed as not shown, with no position.
  const lines = env.document.elements.skipped.children.map((line) => line.textContent);
  assert.equal(lines.filter((line) => line === "This entry could not be read.").length, 3);
  assert.ok(lines.includes("Photo 1: This entry could not be read."), lines.join("\n"));
});

test("it shows skipped items as text, never as markup", async () => {
  const hostile = '<img src=x onerror="fetch(\'/api/apps/home/state\')">';
  const list = playlist([item(0)], [
    { order: 1, uri: "localhost://Users/self/Pictures/b.png", reason: "too_large", message: hostile },
    { order: 2, uri: "localhost://Users/self/Pictures/c.gif", reason: "unsupported", message: "x".repeat(500) },
  ]);
  const { env, requests } = world({ routes: servingPlaylist(list, { 0: bytes("a") }) });
  await mountPhotos(env).ready();
  const lines = env.document.elements.skipped.children;
  assert.equal(lines.length, 2);
  assert.equal(lines[0].tag, "li");
  assert.equal(lines[0].textContent, `Photo 2: ${hostile}`);
  assert.equal(lines[1].textContent.length, "Photo 3: ".length + 201);
  assert.equal(env.document.elements["skipped-title"].hidden, false);
  assert.equal(requests.length, 2, "the message caused no request");
});

test("it makes no request other than the two routes, each a GET with the launch token and nothing else", async () => {
  const list = playlist([item(0), item(1)]);
  const { env, requests } = world({ routes: servingPlaylist(list, { 0: bytes("a"), 1: bytes("b") }) });
  const photos = mountPhotos(env);
  await photos.ready();
  await photos.next();
  await photos.previous();
  assert.equal(requests.length, 4);
  for (const { url, options, self } of requests) {
    assert.ok(url === PLAYLIST_ROUTE || url.startsWith(ITEM_ROUTE), url);
    assert.deepEqual(options, {
      method: "GET",
      headers: { [TOKEN_HEADER]: TOKEN },
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
    });
    assert.equal(self, env, "fetch keeps its window");
  }
});

test("without a launch token it asks for nothing", async () => {
  const { env, requests } = world({ hash: "" });
  await mountPhotos(env).ready();
  assert.equal(requests.length, 0);
  assert.equal(env.document.elements.status.textContent, "Open Photos from Home.");
});

test("a refusal is shown as its text", async () => {
  const routes = {
    [PLAYLIST_ROUTE]: response(200, playlist([item(0)])),
    [`${ITEM_ROUTE}0`]: response(409, { error: "the playlist changed during this launch (pinned sha256:ab)" }),
  };
  const { env } = world({ routes });
  await mountPhotos(env).ready();
  assert.equal(
    env.document.elements.status.textContent,
    "the playlist changed during this launch (pinned sha256:ab)",
  );
  assert.equal(env.document.elements.photo.src, undefined);

  const refused = world({ routes: { [PLAYLIST_ROUTE]: response(403, { error: "this Photos launch is not bound to a playlist" }) } });
  await mountPhotos(refused.env).ready();
  assert.equal(refused.env.document.elements.status.textContent, "this Photos launch is not bound to a playlist");
  assert.equal(refused.requests.length, 1);

  const unreadable = world({ routes: { [PLAYLIST_ROUTE]: { ok: false, status: 500, json: async () => { throw new Error("no json"); } } } });
  await mountPhotos(unreadable.env).ready();
  assert.equal(unreadable.env.document.elements.status.textContent, "Photos could not read this (500).");
});

test("a playlist that is not one is refused", () => {
  assert.throws(() => readPlaylist(null), /not a Photos playlist/);
  assert.throws(() => readPlaylist({ schema: "elastos.photo-viewer.playlist/v2", items: [] }), /not a Photos playlist/);
  assert.throws(
    () => readPlaylist(playlist(Array.from({ length: 65 }, (_, order) => item(order)))),
    /more than 64/,
  );
  const { slides, skipped } = readPlaylist(playlist([item(0, { mime: "image/svg+xml" }), item(1, { mime: "text/html" })]));
  assert.equal(slides.length, 0);
  assert.equal(skipped.length, 2);
});

test("a slow answer for an earlier choice does not replace a later one", async () => {
  let releaseFirst;
  const first = new Promise((resolve) => {
    releaseFirst = () => resolve(response(200, bytes("slow")));
  });
  const routes = {
    [PLAYLIST_ROUTE]: response(200, playlist([item(0), item(1)])),
    [`${ITEM_ROUTE}0`]: () => first,
    [`${ITEM_ROUTE}1`]: response(200, bytes("b")),
  };
  const { env, urls } = world({ routes });
  const photos = mountPhotos(env);
  await new Promise((resolve) => setImmediate(resolve));
  await photos.next();
  assert.equal(env.document.elements.photo.src, "blob:photos/0");
  releaseFirst();
  await photos.ready();
  assert.equal(env.document.elements.photo.src, "blob:photos/0", "the slow first photo was dropped");
  assert.equal(urls.made.length, 1);
});

test("each photo shows for its duration, kept within the core's bounds, and pause stops it", async () => {
  const list = playlist([item(0, { duration_ms: 10 }), item(1, { duration_ms: 10_000_000 }), item(2, { duration_ms: 2500 })]);
  const { env, timers } = world({ routes: servingPlaylist(list, { 0: bytes("a"), 1: bytes("b"), 2: bytes("c") }) });
  const photos = mountPhotos(env);
  await photos.ready();
  assert.equal(timers.at(-1).delay, MIN_DURATION_MS);
  await timers.at(-1).callback();
  assert.equal(photos.state.index, 1);
  assert.equal(timers.at(-1).delay, MAX_DURATION_MS);
  photos.togglePause();
  assert.equal(env.document.elements.pause.textContent, "Play");
  assert.ok(timers.every((timer) => timer.cleared), "paused: no timer left running");
  photos.togglePause();
  assert.equal(timers.at(-1).cleared, false);
  assert.equal(timers.at(-1).delay, MAX_DURATION_MS);
});

test("keys move and pause the slideshow", async () => {
  const list = playlist([item(0), item(1)]);
  const { env } = world({ routes: servingPlaylist(list, { 0: bytes("a"), 1: bytes("b") }) });
  const photos = mountPhotos(env);
  await photos.ready();
  const key = (name) => {
    let prevented = false;
    env.document.listeners.keydown({ key: name, preventDefault: () => (prevented = true) });
    return prevented;
  };
  assert.equal(key("ArrowRight"), true);
  assert.equal(photos.state.index, 1);
  assert.equal(key("ArrowLeft"), true);
  assert.equal(photos.state.index, 0);
  assert.equal(key(" "), true);
  assert.equal(photos.state.playing, false);
  assert.equal(key("a"), false);
});

test("the page has no way to hold or reach anything else", () => {
  const page = source("./browser/photos.js");
  const main = source("./browser/main.js");
  for (const code of [page, main]) {
    for (const forbidden of [
      "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "Function(",
      "localStorage", "sessionStorage", "indexedDB", "document.cookie", "postMessage", "WebSocket",
      "XMLHttpRequest", "EventSource", "sendBeacon", "import(", "http://", "https://", "window.open",
    ]) {
      assert.ok(!code.includes(forbidden), `${forbidden} in the page`);
    }
  }
  // One fetch call site, inside the client.
  assert.equal(page.match(/fetchFn\(/g).length, 1);
  assert.ok(!/[^.]\bfetch\(/.test(page), "no other fetch");
  assert.equal(main.trim(), 'import { mountPhotos } from "./photos.js";\n\nmountPhotos(window);');

  const html = source("./browser/index.html");
  assert.ok(!/<script(?![^>]*\bsrc=)/.test(html), "no inline script");
  assert.ok(!/\son[a-z]+=/i.test(html), "no inline handler");
  assert.ok(!/<style/i.test(html), "no inline style");
  const loaded = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(loaded, ["./photos.css", "./main.js"]);

  const manifest = JSON.parse(source("./capsule.json"));
  assert.equal(manifest.name, "image-viewer");
  assert.equal(manifest.role, "viewer");
  assert.equal(manifest.execution, "web-projection");
  assert.deepEqual(manifest.capabilities ?? [], []);
  assert.deepEqual(manifest.permissions ?? {}, {});
  assert.deepEqual(manifest.requires ?? [], []);
});
