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
// The page token is a bearer credential: it must never reach stdout, journey-results.json or the failure files.
// Playwright puts navigation URLs (with the fragment) in its error call logs, so every recorded text is redacted.
let pageToken = null;
function redact(text) {
  let out = String(text).replace(/home_token=[^\s"'&#)\]\\]*/g, "home_token=<redacted>")
    // A token field in any answer text, even one that does not parse (so before pageToken is known): a quoted
    // value up to its closing quote OR the end of the text (an unclosed string), or an unquoted value.
    .replace(/("token"\s*:\s*)(?:"(?:[^"\\]|\\.)*(?:"|$)|[^,}\s]*)/g, '$1"<redacted>"');
  if (pageToken) {
    for (const form of [pageToken, encodeURIComponent(pageToken)]) out = out.split(form).join("<redacted>");
  }
  return out;
}
// Redact every string inside a recorded value, keeping its shape (no JSON text round-trip, which an escaped
// quote next to a redacted token could break).
function redactValue(value) {
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value && typeof value === "object") {
    // Keys too: a parsed answer can carry the token as a key.
    return Object.fromEntries(Object.entries(value).map(([key, inner]) => [redact(key), redactValue(inner)]));
  }
  return value;
}
// The failure files show the page of the FIRST failed check or error, not wherever the journey went next.
let currentPage = null;
let failurePage = null;
function check(name, ok, detail) {
  const safe = redactValue(detail);
  results[name] = ok ? "passed" : { failed: safe };
  if (!ok) { failures.push(name); if (!failurePage) failurePage = currentPage; }
  console.log(`${ok ? "ok" : "FAILED"}: ${name}${ok ? "" : ` (${JSON.stringify(safe)})`}`);
}

// What a journey records of a server answer: only which of the refusal names the checks expect it starts with,
// and its length, never its raw text. Raw answer text is where a token could hide in a shape no redactor
// anticipates (an unclosed string, a key, an encoding); a fixed allowlist of names cannot carry one.
const KNOWN_REFUSALS = ["bundle_cid_mismatch", "bundle_missing"];
function answerName(text) {
  const t = String(text);
  const name = KNOWN_REFUSALS.find((known) => t === known || t.startsWith(`${known}:`));
  return `${name || "<not an expected refusal name>"} (${t.length} chars)`;
}
// A parsed answer's page and page_url are recorded only in the shapes the check expects.
const recordedPage = (page) => (typeof page === "string" && /^[a-z0-9-]{1,64}$/.test(page) ? page : "<not a page name>");
const PAGE_URL = /^\/launch\/[0-9a-f]{32}\/page\/browser\/index\.html$/;
const recordedPageUrl = (url) => (typeof url === "string" && PAGE_URL.test(url) ? url : "<not the expected page address>");

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
// The failure record: the page of the first failed check or error, saved (redacted) in the evidence folder
// run-journey.sh gives this step.
// A check that fails without throwing (a plant) also lands here, so the red is inspectable.
let failureSaved = false;
async function saveFailureEvidence() {
  if (failureSaved) return;
  failureSaved = true;
  const page = failurePage || currentPage;
  if (!page) {
    console.error("no page to save failure evidence from");
    return;
  }
  for (const [name, write] of [
    ["failure.png", () => page.screenshot({ path: join(EVIDENCE, "failure.png"), fullPage: true })],
    ["failure.html", async () => writeFileSync(join(EVIDENCE, "failure.html"), redact(await page.content()))],
  ]) {
    try { await write(); } catch (error) {
      console.error(`could not write ${name}: ${redact(String(error && error.message || error)).slice(0, 300)}`);
    }
  }
}
try {
  const context = await browser.newContext({ viewport: { width: 1280, height: 860 } });
  const home = await context.newPage();
  currentPage = home;
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
  // The sign-in click has timed out on the Linux ROG after the button had resolved. Wait on the condition
  // first, with one 60 s deadline, and name the condition that was not met, with the button as read.
  let signInState = null;
  const signInDeadline = Date.now() + 60000;
  const readState = () => home.evaluate(() => {
      const button = document.querySelector("#home-unlock-primary");
      if (!button) return { present: false };
      const style = getComputedStyle(button);
      const rect = button.getBoundingClientRect();
      return { present: true, text: button.textContent, disabled: Boolean(button.disabled),
               visible: style.visibility !== "hidden" && style.display !== "none" && rect.width > 0 && rect.height > 0 };
    });
  for (;;) {
    // Each read is bounded by what is left of the one deadline, so a stalled page cannot carry the wait past it.
    const left = signInDeadline - Date.now();
    signInState = left <= 0 ? { present: false, stalled: true } : await Promise.race([
      readState(),
      new Promise((resolve) => setTimeout(() => resolve({ present: false, stalled: true }), left)),
    ]);
    if (signInState.present && signInState.visible && !signInState.disabled && Date.now() < signInDeadline) break;
    if (Date.now() >= signInDeadline) {
      const unmet = [];
      if (!signInState.present || !signInState.visible) unmet.push("not visible");
      if (signInState.disabled) unmet.push("disabled");
      const state = signInState.stalled ? "the page did not answer the read before the deadline"
        : signInState.present
        ? `text ${JSON.stringify(signInState.text)}, disabled ${signInState.disabled}, visible ${signInState.visible}`
        : "no #home-unlock-primary in the page";
      throw new Error(`sign-in button not ready within 60 s: ${unmet.join(" and ")}; ${state}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  // Visible and enabled is not all a click needs: Playwright also waits for the button to be stable and to
  // receive the pointer (no overlay). A trial click checks those, inside the same deadline, without clicking,
  // and a failure is named as such, with Playwright's call log (redacted when recorded).
  try {
    await home.locator("#home-unlock-primary").click({ trial: true, timeout: Math.max(1, signInDeadline - Date.now()) });
  } catch (error) {
    throw new Error(`sign-in button visible and enabled but not clickable within 60 s (not stable, or another element takes the pointer): ${String(error && error.message || error)}`);
  }
  const registered = home.waitForResponse((r) => r.url().endsWith("/api/auth/passkey/register/complete"), { timeout: 60000 });
  // A click that throws leaves this wait pending; closing the browser then rejects it. Handle that rejection
  // so the failure record and journey-results.json are still written.
  registered.catch(() => {});
  await home.locator("#home-unlock-primary").click();
  const completion = await registered;
  check("a person registers a passkey and is signed in to Home", completion.ok(),
    { status: completion.status(), answer: completion.ok() ? undefined : answerName(await completion.text().catch(() => "")) });

  // 2. The set, opened by its CID.
  currentPage = home;
  const opened = await open(home, SET);
  let answer = {};
  try { answer = JSON.parse(opened.text); } catch { /* checked below */ }
  if (typeof answer.token === "string" && answer.token) pageToken = answer.token;
  check("Home opens the set by its CID", opened.status === 200 && answer.page === "image-viewer"
    && PAGE_URL.test(answer.page_url || "") && typeof answer.token === "string",
    { status: opened.status, page: recordedPage(answer.page), page_url: recordedPageUrl(answer.page_url),
      answer: opened.status === 200 ? undefined : answerName(opened.text) });

  // 3. The page, loaded at its address with its token in the fragment; the three pictures, in order.
  if (opened.status === 200) {
    const viewer = await context.newPage();
    currentPage = viewer;
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
  currentPage = home;
  const changed = await open(home, CHANGED);
  check("a set whose bytes no longer match its CID is refused by name",
    changed.status === 400 && changed.text.startsWith("bundle_cid_mismatch") && !changed.text.includes("token"),
    { status: changed.status, answer: answerName(changed.text) });
  const never = await open(home, NEVER);
  check("a CID never staged is refused by name",
    never.status === 400 && never.text.startsWith("bundle_missing") && !never.text.includes("token"),
    { status: never.status, answer: answerName(never.text) });
  results.refusals = { changed: answerName(changed.text), never: answerName(never.text) };
} catch (error) {
  // The full Playwright message carries its call log, which names the condition it waited on; the old 300-char
  // cut ended inside that log. This is the detail the result records and prints.
  // Redacted BEFORE the cut, so a cut cannot leave part of a token behind.
  const full = redact(String(error && error.message || error)).slice(0, 1500);
  check("the journey ran to its end", false, full);
  await saveFailureEvidence();
} finally {
  if (failures.length > 0) await saveFailureEvidence();
  await browser.close();
}
// Every recorded value (results.shown, results.reads, results.refusals too) is redacted before it is written.
writeFileSync(join(EVIDENCE, "journey-results.json"), JSON.stringify(redactValue(results), null, 2));
console.log(JSON.stringify({ failures }));
process.exit(failures.length === 0 ? 0 : 1);
