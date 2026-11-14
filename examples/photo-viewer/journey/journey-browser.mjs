#!/usr/bin/env node
// The browser step of the photo viewer's journey (run by run-journey.sh): in headless Chromium with a virtual
// passkey, a person registers in Home and is signed in; from Home's own page they open the photo set by its CID
// (`POST /api/home/launch/content`), load the page's address with the page's token in its fragment, and see the
// three pictures in order; then the set whose bytes no longer match its CID, and a CID never staged, are each
// refused by name, with no page token. Prints one JSON line of results; exit 0 only if every check holds.
import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const env = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};
const BASE = env("BASE").replace(/\/+$/, "");
const [SET, CHANGED, NEVER] = [env("SET_CID"), env("CHANGED_CID"), env("NEVER_CID")];
const EVIDENCE = env("EVIDENCE");
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.ELASTOS_PLAYWRIGHT_MODULE || env("PLAYWRIGHT_FALLBACK"));

const results = {};
const failures = [];
function check(name, ok, detail) {
  results[name] = ok ? "passed" : { failed: detail };
  if (!ok) failures.push(name);
  console.log(`${ok ? "ok" : "FAILED"}: ${name}${ok ? "" : ` (${JSON.stringify(detail)})`}`);
}

// The open, asked from Home's own page as Home asks it: same origin, Home's session cookie.
async function open(page, cid) {
  return page.evaluate(async (cid) => {
    const answer = await fetch("/api/home/launch/content", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ cid }),
    });
    return { status: answer.status, text: await answer.text() };
  }, cid);
}

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1280, height: 860 } });
  const home = await context.newPage();
  const cdp = await context.newCDPSession(home);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });

  // 1. Sign in: a new person registers a passkey in Home.
  const front = await home.goto(`${BASE}/home/`, { waitUntil: "domcontentloaded" });
  check("Home's page is served", front.ok(), front.status());
  await home.locator("#home-unlock-name").waitFor({ state: "visible", timeout: 60000 });
  await home.locator("#home-unlock-name").fill("Photo journey");
  const registered = home.waitForResponse((r) => r.url().endsWith("/api/auth/passkey/register/complete"), { timeout: 60000 });
  await home.locator("#home-unlock-primary").click();
  const completion = await registered;
  check("a person registers a passkey and is signed in to Home", completion.ok(),
    { status: completion.status(), text: completion.ok() ? undefined : (await completion.text().catch(() => "")).slice(0, 300) });

  // 2. The set, opened by its CID.
  const opened = await open(home, SET);
  let answer = {};
  try { answer = JSON.parse(opened.text); } catch { /* checked below */ }
  check("Home opens the set by its CID", opened.status === 200 && answer.page === "image-viewer"
    && /^\/launch\/[0-9a-f]{32}\/page\/browser\/index\.html$/.test(answer.page_url || "") && typeof answer.token === "string",
    { status: opened.status, page: answer.page, page_url: answer.page_url, text: opened.status === 200 ? undefined : opened.text.slice(0, 200) });

  // 3. The page, loaded at its address with its token in the fragment; the three pictures, in order.
  if (opened.status === 200) {
    const viewer = await context.newPage();
    const asked = [];
    viewer.on("request", (request) => {
      const url = new URL(request.url());
      if (url.pathname.startsWith("/api/")) asked.push(url.pathname);
    });
    // JOURNEY_PLANT=token-dropped (falsify-journey.sh only): the page loaded without its token.
    const fragment = process.env.JOURNEY_PLANT === "token-dropped" ? "" : `#home_token=${encodeURIComponent(answer.token)}`;
    await viewer.goto(`${BASE}${answer.page_url}${fragment}`, { waitUntil: "domcontentloaded" });
    await viewer.locator("#pause").click({ timeout: 30000 }).catch(() => {});
    const shown = [];
    for (let n = 1; n <= 3; n += 1) {
      await viewer.waitForFunction((n) => {
        const caption = document.getElementById("caption").textContent;
        const photo = document.getElementById("photo");
        return caption.startsWith(`${n} / 3`) && photo.complete && photo.naturalWidth > 0;
      }, n, { timeout: 30000 }).catch(() => {});
      const state = await viewer.evaluate(() => {
        const photo = document.getElementById("photo");
        // The colour the picture shows, read back from its pixels: the fixture's three are solid colours.
        let rgb = null;
        if (photo.naturalWidth > 0) {
          const canvas = document.createElement("canvas");
          canvas.width = photo.naturalWidth; canvas.height = photo.naturalHeight;
          const context = canvas.getContext("2d");
          context.drawImage(photo, 0, 0);
          rgb = Array.from(context.getImageData(1, 1, 1, 1).data.slice(0, 3));
        }
        return { caption: document.getElementById("caption").textContent, width: photo.naturalWidth,
                 height: photo.naturalHeight, rgb, status: document.getElementById("status").textContent };
      });
      shown.push(state);
      await viewer.screenshot({ path: join(EVIDENCE, `picture-${n}.png`) });
      if (n < 3) await viewer.locator("#next").click();
    }
    // 01.png is red, 02.jpg green, 03.webp blue (the fixture's README): the strongest channel of each picture shown.
    const strongest = (rgb) => (rgb ? ["red", "green", "blue"][rgb.indexOf(Math.max(...rgb))] : null);
    const inOrder = shown.every((s, i) => s.caption.startsWith(`${i + 1} / 3`))
      && JSON.stringify(shown.map((s) => strongest(s.rgb))) === JSON.stringify(["red", "green", "blue"]);
    const realSizes = shown.every((s) => s.width > 0 && s.caption.includes(`${s.width} × ${s.height}`));
    check("the three pictures are shown, in order (red 01.png, green 02.jpg, blue 03.webp)", inOrder && shown.every((s) => s.width > 0), shown);
    check("each picture decodes at the size the photo core read from its bytes", realSizes, shown);
    const reads = [...new Set(asked)];
    const expected = ["/api/viewers/image-viewer/launch/output/playlist.json",
      "/api/viewers/image-viewer/launch/content/images/01.png",
      "/api/viewers/image-viewer/launch/content/images/02.jpg",
      "/api/viewers/image-viewer/launch/content/images/03.webp"];
    check("the page asked only for the playlist and the three pictures", JSON.stringify(reads.sort()) === JSON.stringify(expected.sort()), reads);
    results.shown = shown;
    results.reads = reads;
  }

  // 4. The refusals, by name, with no page token.
  const changed = await open(home, CHANGED);
  check("a set whose bytes no longer match its CID is refused by name",
    changed.status === 400 && changed.text.startsWith("bundle_cid_mismatch") && !changed.text.includes("token"),
    { status: changed.status, text: changed.text.slice(0, 200) });
  const never = await open(home, NEVER);
  check("a CID never staged is refused by name",
    never.status === 400 && never.text.startsWith("bundle_missing") && !never.text.includes("token"),
    { status: never.status, text: never.text.slice(0, 200) });
  results.refusals = { changed: changed.text.slice(0, 200), never: never.text.slice(0, 200) };
} catch (error) {
  check("the journey ran to its end", false, String(error && error.message || error).slice(0, 300));
} finally {
  await browser.close();
}
writeFileSync(join(EVIDENCE, "journey-results.json"), JSON.stringify(results, null, 2));
console.log(JSON.stringify({ failures }));
process.exit(failures.length === 0 ? 0 : 1);
