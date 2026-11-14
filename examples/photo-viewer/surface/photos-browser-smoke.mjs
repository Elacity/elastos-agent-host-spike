// The real Photos page in real Chromium, framed the way Home frames apps.
//
// The capsule kit's stand-in (examples/capsule-kit/surface/stand-in.mjs) plays
// Runtime: the app headers Runtime sends, the front door's CORS preflight, and
// here the page's two reads of its content launch (the launch's output and its
// content by path). The page is framed in Home's opaque sandbox.
//
// Run: node examples/photo-viewer/surface/photos-browser-smoke.mjs
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { crc32, deflateSync } from "node:zlib";

import { inHome, standIn } from "../../capsule-kit/surface/stand-in.mjs";

const browserRoot = fileURLToPath(new URL("./browser/", import.meta.url));
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

const IMAGES = { "images/a.png": png(4, 3, [200, 30, 30]), "images/c d.png": png(3, 5, [30, 30, 200]) };
const PLAYLIST = {
  schema: "elastos.photo-viewer.playlist/v1",
  album: "elastos://launch/content/",
  items: [
    { order: 0, uri: "elastos://launch/content/images/a.png", mime: "image/png", width: 4, height: 3, duration_ms: 60000 },
    { order: 2, uri: "elastos://launch/content/images/c d.png", mime: "image/png", width: 3, height: 5, duration_ms: 60000 },
    { order: 3, uri: "localhost://Users/self/Pictures/secret.png", mime: "image/png", width: 3, height: 5, duration_ms: 60000 },
  ],
  skipped: [{ order: 1, uri: "elastos://launch/content/images/b.gif", reason: "unsupported", message: HOSTILE }],
};
const OUTPUT = "/api/viewers/image-viewer/launch/output/playlist.json";
const CONTENT = "/api/viewers/image-viewer/launch/content/";

const { base, requests, close } = await standIn({
  app: "image-viewer",
  browserRoot,
  files: ["index.html", "main.js", "photos.js", "photos.css"],
  routes(method, path) {
    if (method !== "GET") return null;
    if (path === OUTPUT) {
      return { type: "application/octet-stream", body: JSON.stringify(PLAYLIST) };
    }
    const image = path.startsWith(CONTENT) && IMAGES[decodeURIComponent(path.slice(CONTENT.length))];
    if (image) {
      return { type: "application/octet-stream", headers: { "x-content-type-options": "nosniff" }, body: image };
    }
    return null;
  },
});
try {
  const problems = await inHome(base, async (frame) => {
    const photo = frame.locator("#photo");
    await photo.evaluate((img) =>
      img.complete && img.naturalWidth ? null : new Promise((resolve) => img.addEventListener("load", resolve, { once: true })),
    );
    const first = await photo.evaluate((img) => ({ src: img.src, width: img.naturalWidth, height: img.naturalHeight }));
    assert.match(first.src, /^blob:/);
    assert.deepEqual([first.width, first.height], [4, 3]);
    assert.equal(await frame.locator("#caption").textContent(), "1 / 2 · 4 × 3");

    // The skipped entry is text: the markup in it did not run or load anything.
    // The entry outside the launched set is listed, never asked for.
    const lines = await frame.locator("#skipped li").allTextContents();
    assert.deepEqual(lines, [
      `Photo 2: ${HOSTILE}`,
      "Photo 4: This entry is not in the photo set this page was opened with.",
    ]);
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
  });
  const api = requests.filter((line) => line.includes(" /api/"));
  assert.deepEqual(
    api.filter((line) => line.startsWith("GET")),
    [`GET ${OUTPUT}`, `GET ${CONTENT}images/a.png`, `GET ${CONTENT}images/c%20d.png`],
  );
  assert.ok(api.every((line) => /^(GET|OPTIONS) \/api\/viewers\/image-viewer\/launch\/(output|content)\//.test(line)), api.join("\n"));
  assert.ok(!requests.some((line) => line.includes("Users")), "nothing outside the set asked for");
  assert.ok(!requests.some((line) => line.includes("/api/apps/home/state")), "the skipped message ran");
  assert.deepEqual(problems, [], "console errors (CSP or script)");
  console.log("photos browser smoke: ok");
  console.log(requests.join("\n"));
} finally {
  close();
}
