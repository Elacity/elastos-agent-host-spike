// The GBA page's launch branch, driven through the real emulator.js: a launch
// address reads the core's record and the recorded ROM, refuses bytes that do
// not match the record, and keeps the installed by-name page unchanged.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

const source = readFileSync(
  new URL("../capsules/gba-emulator/browser/emulator.js", import.meta.url),
  "utf8",
).replace(/^import .*\n/gm, "").split("async function loadInstalledGames()")[0];

// Fixture literals: 18 bytes of ASCII and its sha256, computed independently of
// the page (node:crypto), not read back from any page value.
const ROM_TEXT = "GBA-LAUNCH-FIXTURE";
const ROM_BYTES = new Uint8Array(Buffer.from(ROM_TEXT, "utf8"));
const ROM_SIZE = 18;
const ROM_SHA256 = "ba6cb8a0dde6318d338e16be66b5f63621c2222c7432e455f79202e48320daaf";
const RECORDED_PATH = "u-city.gba";
const LAUNCH_ADDRESS = "/launch/0123456789abcdef0123456789abcdef/page/browser/index.html";
const RECORD_URL = "/api/viewers/gba-emulator/launch/output/rom.json";
const RECORDED_CONTENT_URL = "/api/viewers/gba-emulator/launch/content/u-city.gba";
const BY_NAME_CONTENT_URL = "/api/viewers/gba-emulator/content/ucity";

function element() {
  const child = { textContent: "" };
  return {
    dataset: {},
    classList: { toggle() {}, remove() {}, add() {} },
    hidden: false,
    disabled: false,
    value: "100",
    title: "",
    textContent: "",
    querySelector() { return child; },
    setAttribute() {},
    focus() {},
    addEventListener() {},
    closest() { return { hidden: false }; },
    append() {},
  };
}

// The Runtime's answers, stubbed at the page's fetch: launch routes answer with
// the record/ROM this scenario gives, by-name content with the ROM, and storage
// with the status the scenario gives (an installed page sees 404 for a save).
function server({ rom = ROM_BYTES, record = null, recordStatus = record ? 200 : 404, recordBody = null, storageStatus = 404 } = {}) {
  const requests = [];
  const fetch = async (url, options = {}) => {
    requests.push({ url, headers: options.headers || {} });
    if (url.includes("/launch/output/")) {
      if (recordStatus !== 200) return new Response(null, { status: recordStatus });
      return new Response(recordBody ?? JSON.stringify(record), { status: 200 });
    }
    if (url.includes("/launch/content/")) return new Response(rom, { status: 200 });
    if (url.includes("/storage/")) return new Response(null, { status: storageStatus });
    if (url.includes("/content/")) return new Response(rom, { status: 200 });
    return new Response(null, { status: 401 });
  };
  return { fetch, requests };
}

function page({ pathname = LAUNCH_ADDRESS, search = "", hash = "#home_token=launch-token" } = {}) {
  const timers = new Map();
  let timerId = 0;
  const children = new Map();
  const game = {
    loads: [],
    states: new Map(),
    getSave() { return new Uint8Array([1]); },
    pauseGame() {},
    resumeGame() {},
    setVolume() {},
    setFastForwardMultiplier() {},
    loadGame(path) { this.loads.push(path); return true; },
    saveState() { return true; },
    loadState() { return true; },
  };
  game.FS = {
    writeFile: (path, bytes) => game.states.set(path, new Uint8Array(bytes)),
    readFile: (path) => game.states.get(path),
    unlink: (path) => game.states.delete(path),
    analyzePath: () => ({ exists: false }),
  };
  const top = { postMessage() {} };
  const window = {
    location: { pathname, search, hash },
    setInterval(fn) { timers.set(++timerId, fn); return timerId; },
    clearInterval(id) { timers.delete(id); },
    setTimeout,
    clearTimeout,
    confirm: () => false,
  };
  window.self = pathname.startsWith("/launch/") ? window : {};
  window.top = pathname.startsWith("/launch/") ? window : top;
  const queries = [];
  const document = {
    body: { dataset: {} },
    title: "",
    getElementById(id) {
      if (!children.has(id)) children.set(id, element());
      return children.get(id);
    },
  };
  const context = vm.createContext({
    window,
    document,
    createHomeNavigationClient: () => ({ setQuery: (query) => queries.push(query) }),
    URLSearchParams,
    Uint8Array,
    crypto: webcrypto,
    console,
    game,
  });
  vm.runInContext(`${source}
    loadEngine = async () => (engine = game);
    startInputLoop = () => {};
    globalThis.api = { openGame, requestedGame, readGame, readLaunchRecord, readLaunchGame, persistSave };
  `, context);
  return { ...context.api, context, game, queries, timers, window };
}

test("s1: the installed embedded page with #home_token reads its ROM and its save the old way", async () => {
  // The installed token is not launch-bound: a launch route answers it 401.
  const store = server({ recordStatus: 401 });
  const app = page({
    pathname: "/apps/gba-emulator/",
    search: "?capsule=ucity&home_origin=https%3A%2F%2Fhome.example",
    hash: "#home_token=embedded-token",
  });
  app.context.fetch = (...args) => store.fetch(...args);
  let failure = null;
  await app.openGame(app.requestedGame()).catch((error) => { failure = error; });
  assert.equal(failure, null, `openGame failed: ${failure?.message}`);
  assert.equal(store.requests[0].url, BY_NAME_CONTENT_URL);
  assert.ok(
    store.requests.some((item) => item.url === `/api/viewers/gba-emulator/storage/ucity/save/${ROM_SHA256}.sav`),
    "the installed page still reads its save by name",
  );
  assert.equal(store.requests.some((item) => item.url.includes("/launch/")), false);
  assert.equal(app.game.loads[0], `/data/games/${ROM_SHA256}.gba`);
  assert.equal(vm.runInContext("saveSession.save.url", app.context),
    `/api/viewers/gba-emulator/storage/ucity/save/${ROM_SHA256}.sav`);
  assert.equal(app.queries[0].capsule, "ucity");
});

test("s2: a launch-address page reads the record and fetches exactly the recorded path", async () => {
  const store = server({ record: { path: RECORDED_PATH, size: ROM_SIZE, sha256: ROM_SHA256 } });
  const app = page();
  app.context.fetch = (...args) => store.fetch(...args);
  const request = app.requestedGame();
  assert.equal(request.launch, true);
  await app.openGame(request);
  assert.equal(store.requests[0].url, RECORD_URL);
  assert.equal(store.requests[1].url, RECORDED_CONTENT_URL);
  assert.equal(app.game.loads[0], `/data/games/${ROM_SHA256}.gba`);
  assert.equal(vm.runInContext("gameLoaded", app.context), true);
});

test("s3: bytes that differ from the record are refused by name and the emulator is not started", async () => {
  const store = server({ record: { path: RECORDED_PATH, size: ROM_SIZE, sha256: "0".repeat(64) } });
  const app = page();
  app.context.fetch = (...args) => store.fetch(...args);
  await assert.rejects(app.openGame(app.requestedGame()), (error) => {
    assert.equal(error.message,
      `gba_launch_rom_hash_mismatch: record ${"0".repeat(64)}, fetched ${ROM_SHA256}`);
    return true;
  });
  assert.deepEqual(app.game.loads, []);
  assert.equal(vm.runInContext("gameLoaded", app.context), false);
});

test("s4: launch mode makes no saved-game read", async () => {
  const store = server({ record: { path: RECORDED_PATH, size: ROM_SIZE, sha256: ROM_SHA256 } });
  const app = page();
  app.context.fetch = (...args) => store.fetch(...args);
  await app.openGame(app.requestedGame());
  assert.deepEqual(store.requests.filter((item) => item.url.includes("/save/")), []);
  assert.equal(vm.runInContext("saveSession.save", app.context), null);
  assert.deepEqual(app.timers.size, 1);
});

test("s5: a missing or malformed record is refused by name before any ROM fetch", async () => {
  const missing = server({ recordStatus: 404 });
  const first = page();
  first.context.fetch = (...args) => missing.fetch(...args);
  await assert.rejects(first.openGame(first.requestedGame()), {
    message: "gba_launch_record_missing: 404",
  });
  assert.equal(missing.requests.some((item) => item.url.includes("/launch/content/")), false);
  assert.deepEqual(first.game.loads, []);

  const malformed = server({ recordStatus: 200, recordBody: JSON.stringify({ path: RECORDED_PATH, size: ROM_SIZE }) });
  const second = page();
  second.context.fetch = (...args) => malformed.fetch(...args);
  await assert.rejects(second.openGame(second.requestedGame()), {
    message: "gba_launch_record_invalid: path, size and sha256 are required",
  });
  assert.equal(malformed.requests.some((item) => item.url.includes("/launch/content/")), false);
  assert.deepEqual(second.game.loads, []);

  const extraKey = server({ recordStatus: 200, recordBody: JSON.stringify({
    path: RECORDED_PATH, size: ROM_SIZE, sha256: ROM_SHA256, extra: 1 }) });
  const third = page();
  third.context.fetch = (...args) => extraKey.fetch(...args);
  await assert.rejects(third.openGame(third.requestedGame()), {
    message: "gba_launch_record_invalid: path, size and sha256 are required",
  });
  assert.deepEqual(third.game.loads, []);
});
