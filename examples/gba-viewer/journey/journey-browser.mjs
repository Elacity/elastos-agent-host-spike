#!/usr/bin/env node
// The browser step of the GBA viewer's journey (run by run-journey.sh): in headless Chromium with a virtual
// passkey, a person registers in Home and is signed in; from Home's own page they open the game by its content
// CID (`POST /api/home/launch/content`; the page CID is the one that content's manifest pins), load the page's
// address with the page's token in its fragment, and pass only if the page boots the game (#status hidden and
// empty, #power-led on) and the mGBA main loop renders at least 30 frames in a window measured from the page's
// own clock (the second sample must land within 2500 ms of the first). Prints one JSON line of results; exit 0
// only if every check holds.
//
// Frames are counted by a wrapper installed with page.addInitScript before the page's own scripts: the census of
// this page found exactly two callers of window.requestAnimationFrame, mGBA's `MainLoop_runner` (the engine's
// rendering loop) and the page's input poller `pollInput`, so only `MainLoop_runner` calls are counted.
import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const env = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};
const BASE = env("BASE").replace(/\/+$/, "");
const CONTENT = env("CONTENT_CID");
const PAGE = env("PAGE_CID");
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
// anticipates; a fixed allowlist of names cannot carry one. The list is every `BundleRefusal::code()` value
// (bundle_admission.rs and bundle-identity), so a wrong number names the production code it saw.
const KNOWN_REFUSALS = [
  "bundle_unsigned", "bundle_trust_set_empty", "bundle_signature_unparsed",
  "bundle_signature_names_another_cid", "bundle_signature_not_accepted", "bundle_slot_differs",
  "bundle_store_io", "bundle_cid_form_invalid", "bundle_missing", "bundle_cid_mismatch",
  "bundle_manifest_field_refused", "bundle_manifest_invalid", "bundle_not_a_component",
  "bundle_start_failed", "bundle_requirement_name_invalid", "bundle_requirement_unpinned",
  "bundle_requirement_mismatch", "bundle_ask_too_wide", "bundle_content_not_passive",
  "bundle_content_requires_invalid", "bundle_viewer_core_invalid", "bundle_member_kind_refused",
  "bundle_content_listing_too_long", "bundle_closure_too_deep", "bundle_closure_too_many",
  "bundle_walk_bad_path_part", "bundle_walk_changed", "bundle_walk_directory_over_block_limit",
  "bundle_walk_duplicate_path", "bundle_walk_file_and_directory", "bundle_walk_file_over_chunk_limit",
  "bundle_walk_file_over_leaf_limit", "bundle_walk_manifest_invalid", "bundle_walk_manifest_unparsed",
  "bundle_walk_name_mismatch", "bundle_walk_no_manifest", "bundle_walk_not_a_cid",
  "bundle_walk_not_regular_file", "bundle_walk_over_budget", "bundle_walk_pin_refused",
  "bundle_walk_unreadable",
];
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
  await home.locator("#home-unlock-name").fill("GBA journey");
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
  // receive the pointer (no overlay). A trial click checks those, inside the same deadline, without clicking.
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

  // 2. The game, opened by its content CID. The answer's page is the product page's name, and the page CID this
  // run staged is the one the content's manifest pins (run-journey.sh derived and checked that edge).
  currentPage = home;
  const opened = await open(home, CONTENT);
  let answer = {};
  try { answer = JSON.parse(opened.text); } catch { /* checked below */ }
  if (typeof answer.token === "string" && answer.token) pageToken = answer.token;
  const tokenField = /"token"\s*:/.test(opened.text);
  check("Home opens the game by its CID", opened.status === 200 && answer.page === "gba-emulator"
    && PAGE_URL.test(answer.page_url || "") && typeof answer.token === "string",
    { status: opened.status, non_2xx: opened.status !== 200,
      answer: opened.status === 200 ? undefined : answerName(opened.text),
      token_field: tokenField ? "present" : "none",
      page: recordedPage(answer.page), page_url: recordedPageUrl(answer.page_url),
      page_cid: PAGE });

  // 3. The page, loaded at its address with its token in the fragment; the real ROM boots and frames advance.
  if (opened.status === 200) {
    const viewer = await context.newPage();
    currentPage = viewer;
    // Counted before the page's own scripts: the census found mGBA's MainLoop_runner and the page's pollInput.
    await viewer.addInitScript(() => {
      const counts = { total: 0, byCallback: {} };
      window.__gbaRaf = counts;
      const original = window.requestAnimationFrame;
      window.requestAnimationFrame = function (callback) {
        const label = typeof callback === "function" ? (callback.name || "<anonymous>") : "<not a function>";
        counts.total += 1;
        counts.byCallback[label] = (counts.byCallback[label] || 0) + 1;
        return original.call(window, callback);
      };
    });
    // JOURNEY_PLANT=token-dropped (falsify-journey.sh only): the page loaded without its token.
    const fragment = process.env.JOURNEY_PLANT === "token-dropped" ? "" : `#home_token=${encodeURIComponent(answer.token)}`;
    await viewer.goto(`${BASE}${answer.page_url}${fragment}`, { waitUntil: "domcontentloaded" });
    // Wait until the page either booted the game or showed an error status; "Starting game" is neither.
    await viewer.waitForFunction(() => {
      const status = document.getElementById("status");
      const led = document.getElementById("power-led");
      if (!status || !led) return false;
      const booted = status.hidden && status.textContent === "" && !led.classList.contains("off");
      const failed = !status.hidden && status.textContent !== "" && status.classList.contains("error");
      return booted || failed;
    }, null, { timeout: 30000 }).catch(() => {});
    const boot = await viewer.evaluate(() => {
      const status = document.getElementById("status");
      const led = document.getElementById("power-led");
      const canvas = document.getElementById("canvas");
      return {
        status_text: status ? status.textContent : "<no #status>",
        status_hidden: status ? status.hidden : null,
        led_off: led ? led.classList.contains("off") : null,
        title: document.title,
        canvas_width: canvas ? canvas.width : null,
        canvas_height: canvas ? canvas.height : null,
      };
    });
    check("the page boots the game (#status hidden and empty, #power-led on)",
      boot.status_hidden === true && boot.status_text === "" && boot.led_off === false, boot);
    results.boot = boot;

    // The two samples, ~2 s apart, each stamped with the page's own clock. The window is a measured deadline:
    // the check passes only if the second sample lands within 2500 ms of the first (the 2 s sleep plus the
    // screenshots), so a late timer cannot let frames produced after two seconds pass. The canvas screenshots
    // are information only, not a pass condition.
    const readRaf = () => viewer.evaluate(() => {
      const counts = window.__gbaRaf || { total: 0, byCallback: {} };
      return { at_ms: performance.now(), total: counts.total, byCallback: { ...counts.byCallback } };
    });
    const first = await readRaf();
    await viewer.locator("#canvas").screenshot({ path: join(EVIDENCE, "canvas-sample-1.png") })
      .catch((error) => console.error(`could not write canvas-sample-1.png: ${redact(String(error && error.message || error)).slice(0, 300)}`));
    await new Promise((resolve) => setTimeout(resolve, 2000));
    const second = await readRaf();
    await viewer.locator("#canvas").screenshot({ path: join(EVIDENCE, "canvas-sample-2.png") })
      .catch((error) => console.error(`could not write canvas-sample-2.png: ${redact(String(error && error.message || error)).slice(0, 300)}`));
    const frames = (sample) => sample.byCallback.MainLoop_runner || 0;
    const delta = frames(second) - frames(first);
    // Compare the raw measured window with the literal BEFORE any rounding: 2500.4 ms is an overrun.
    const rawElapsedMs = second.at_ms - first.at_ms;
    const elapsedMs = Math.round(rawElapsedMs);
    const callers = [...new Set([...Object.keys(first.byCallback), ...Object.keys(second.byCallback)])];
    const withinWindow = rawElapsedMs <= 2500;
    check("frames advance (mGBA's MainLoop_runner renders at least 30 frames in 2 s)",
      delta >= 30 && withinWindow,
      { first, second, delta, elapsed_ms: elapsedMs, callers,
        ...(withinWindow ? {} : { overran: `frame window overran: ${rawElapsedMs.toFixed(1)} ms` }) });
    results.samples = { first, second };
    results.frames = delta;
    results.elapsed_ms = elapsedMs;
    results.raf_callers = callers;
  }
} catch (error) {
  // The full Playwright message carries its call log, which names the condition it waited on.
  // Redacted BEFORE the cut, so a cut cannot leave part of a token behind.
  const full = redact(String(error && error.message || error)).slice(0, 1500);
  check("the journey ran to its end", false, full);
  await saveFailureEvidence();
} finally {
  if (failures.length > 0) await saveFailureEvidence();
  await browser.close();
}
// Every recorded value is redacted before it is written.
results.content_cid = CONTENT;
results.page_cid = PAGE;
writeFileSync(join(EVIDENCE, "journey-results.json"), JSON.stringify(redactValue(results), null, 2));
console.log(JSON.stringify({ failures }));
process.exit(failures.length === 0 ? 0 : 1);
