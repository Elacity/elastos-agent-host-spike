// The real Archive page in real Chromium, framed the way Home frames apps.
//
// The capsule kit's stand-in (examples/capsule-kit/surface/stand-in.mjs) plays
// Runtime and Home, as for the Documents page; here it serves the one Archive
// route and the page's own files, including the shared renderer it ships as
// ./docs-render.js. There is no Runtime seam for archive-reader (the one that
// exists serves image-viewer only), so this stand-in is the only server the
// page has run against.
//
// Run: node examples/archive-viewer/surface/reader-browser-smoke.mjs
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { inHome, standIn } from "../../capsule-kit/surface/stand-in.mjs";

const browserRoot = fileURLToPath(new URL("./browser/", import.meta.url));
const HOSTILE = '<img src=x onerror="fetch(\'/api/apps/home/state\')">';
const span = (text, style = "plain") => ({ style, text });
const ENTRY = (index, extra = {}) => ({
  compressed_size: 10,
  index,
  kind: "file",
  method: 0,
  path: `entry-${index}.txt`,
  status: "listed",
  uncompressed_size: 10,
  ...extra,
});
const VIEW = {
  archive: { size: 4096, uri: "localhost://Users/self/Downloads/trip.zip" },
  entries: [
    ENTRY(0, { compressed_size: 30, path: "notes.txt", uncompressed_size: 30 }),
    ENTRY(1, { compressed_size: 0, kind: "directory", path: "photos/", uncompressed_size: 0 }),
    ENTRY(2, { path: HOSTILE, reason: "control_character", status: "blocked" }),
    ENTRY(3, { compressed_size: 90, kind: "file", method: 8, path: "photos/cat.png", uncompressed_size: 4000 }),
    ENTRY(4, { kind: "archive", path: "inner.zip" }),
  ],
  previews: [
    {
      blocks: [
        { kind: "heading", level: 1, spans: [span("Trip notes")] },
        { kind: "paragraph", spans: [span("Pack "), span("boots", "strong"), span(" and read "), span(HOSTILE, "code")] },
        { kind: "list", ordered: false, items: [[span("tent")], [span("stove")]] },
      ],
      index: 0,
    },
  ],
  schema: "elastos.archive-viewer.view/v1",
  skipped: [{ index: 2, message: "The entry is blocked by the path rules.", reason: "control_character" }],
};

const { base, requests, close } = await standIn({
  app: "archive-reader",
  browserRoot,
  files: ["index.html", "main.js", "reader.js", "docs-render.js", "reader.css"],
  routes(method, path) {
    if (method === "GET" && path === "/api/viewers/archive-reader/view") {
      return { type: "application/json", body: JSON.stringify(VIEW) };
    }
    return null;
  },
});
try {
  const problems = await inHome(base, async (frame) => {
    await frame.locator("#previews h1").waitFor();
    // The listing shows every entry, and a hostile path is text.
    assert.equal(await frame.locator("#archive").textContent(), "localhost://Users/self/Downloads/trip.zip (4096 bytes)");
    assert.equal(await frame.locator("#entries li").count(), 5);
    assert.equal(await frame.locator("#entries li").nth(0).locator("span").first().textContent(), "notes.txt");
    assert.equal(await frame.locator("#entries li").nth(2).locator("span").first().textContent(), HOSTILE);
    assert.equal(
      await frame.locator("#entries li").nth(3).locator("span").last().textContent(),
      "File; method 8; declared 90 compressed, 4000 uncompressed; listed",
    );
    // The text preview is drawn by the shared documents renderer.
    assert.deepEqual(await frame.locator("#previews h3").allTextContents(), ["notes.txt"]);
    assert.equal(await frame.locator("#previews h1").textContent(), "Trip notes");
    assert.equal(await frame.locator("#previews strong").textContent(), "boots");
    assert.deepEqual(await frame.locator("#previews ul li").allTextContents(), ["tent", "stove"]);
    // Markup in a path and in a preview is text: nothing ran or loaded.
    assert.equal(await frame.locator("#previews code").textContent(), HOSTILE);
    assert.equal(await frame.locator("#skipped li").textContent(), "Entry 3: The entry is blocked by the path rules. (control_character)");
    assert.equal(await frame.locator("img, a, script:not([src]), iframe").count(), 0);
    assert.equal(await frame.locator("#status").textContent(), "");

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
  });
  const api = requests.filter((line) => line.includes(" /api/"));
  assert.deepEqual(
    api.filter((line) => line.startsWith("GET")),
    ["GET /api/viewers/archive-reader/view"],
  );
  assert.ok(api.every((line) => /^(GET|OPTIONS) \/api\/viewers\/archive-reader\/view$/.test(line)), api.join("\n"));
  assert.ok(!requests.some((line) => line.includes("/api/apps/home/state")), "markup in the view ran");
  assert.deepEqual(problems, [], "console errors (CSP or script)");
  console.log("archive browser smoke: ok");
  console.log(requests.join("\n"));
} finally {
  close();
}
