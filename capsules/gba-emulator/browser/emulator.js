import { BUTTON_BITS, gamepadMask as readGamepadMask } from "./gba-input.js";
import { createHomeNavigationClient } from "/apps/home/home-navigation-client.js";

const VIEWER_ID = "gba-emulator";
// A fetch sanity bound only. The launch core owns the 64 MiB rule.
const MAX_ROM_BYTES = 64 * 1024 * 1024;
const LAUNCH_RECORD_NAME = "rom.json";
const query = new URLSearchParams(window.location.search);
const homeToken = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("home_token") || "";
// A by-CID launch serves this page at the Runtime's own address,
// /launch/<id>/page/<entrypoint>. Its token and the installed app's
// #home_token look alike, so the address decides: the id is 32 ASCII hex
// digits in either case and the entrypoint a plain content path, with no
// encoded slash standing for a segment break.
const LAUNCH_ADDRESS = /^\/launch\/([0-9a-fA-F]{32})\/page\/(.+)$/;
const launchMode = launchAddress(window.location.pathname) !== null;
const homeParentOrigin = query.get("home_origin") || "";
const homeNavigation = createHomeNavigationClient({ homeToken, homeOrigin: homeParentOrigin });
if (homeToken && homeParentOrigin && window.top !== window) {
  window.top.postMessage({ type: "home:app-ready", homeToken }, homeParentOrigin);
}
const hostMode = window.self === window.top ? "standalone" : "embedded";
document.body.dataset.emulatorAccessMode = homeToken ? "shell" : "gateway";
document.body.dataset.emulatorHostMode = hostMode;
document.body.dataset.shellWindowFit = hostMode === "embedded" ? "fixed" : "auto";
const canvas = document.getElementById("canvas");
const emptyState = document.getElementById("drop-zone");
const installedGames = document.getElementById("rom-library-list");
const status = document.getElementById("status");
const saveRecoveryButton = document.getElementById("btn-save-recovery");
const pauseButton = document.getElementById("btn-pause");
const fastForwardButton = document.getElementById("btn-ff");
const volume = document.getElementById("volume-slider");
const fullscreenButton = document.getElementById("btn-fullscreen");
const screenBezel = document.getElementById("screen-bezel");
const powerLed = document.getElementById("power-led");

const KEY_BUTTONS = {
  KeyX: "a",
  KeyZ: "b",
  Backspace: "select",
  Enter: "start",
  ArrowRight: "right",
  ArrowLeft: "left",
  ArrowUp: "up",
  ArrowDown: "down",
  KeyS: "r",
  KeyA: "l",
};

let enginePromise = null;
let engine = null;
let gameLoaded = false;
let paused = false;
let fastForward = false;
let soundEnabled = false;
let keyboardMask = 0;
let gamepadMask = 0;
let appliedInputMask = 0;
let inputFrame = 0;
let saveTimer = 0;
let activeSaveName = "";
let activeRomId = "";
let activeStorageCapsule = VIEWER_ID;
let saveSession = null;
let openSequence = 0;
const touchPointers = new Map();

function launchHeaders() {
  return homeToken ? { "x-elastos-home-token": homeToken } : {};
}

function showStatus(message, error = false) {
  status.textContent = message;
  status.classList.toggle("error", error);
  status.hidden = !message;
}

function setIconButton(button, glyph, label) {
  button.querySelector(".icon-glyph").textContent = glyph;
  button.setAttribute("aria-label", label);
  button.title = label;
}

function syncPauseButton() {
  setIconButton(pauseButton, paused ? "▶" : "❚❚", paused ? "Resume" : "Pause");
  pauseButton.setAttribute("aria-pressed", String(paused));
}

function syncFullscreenButton() {
  const active = Boolean(document.fullscreenElement);
  setIconButton(fullscreenButton, active ? "⤡" : "⤢", active ? "Exit fullscreen" : "Fullscreen");
  fullscreenButton.setAttribute("aria-pressed", String(active));
}

function setSlotState(slot, saved) {
  const loadButton = document.getElementById(`btn-load${slot}`);
  const slotStatus = document.getElementById(`slot-status${slot}`);
  loadButton.dataset.saved = String(saved);
  loadButton.title = saved ? `Load state ${slot}` : `State ${slot} is empty`;
  loadButton.disabled = launchMode || !gameLoaded || !saved;
  slotStatus.textContent = saved ? "Saved" : "Empty";
  slotStatus.dataset.slotState = saved ? "saved" : "empty";
}

function setGameControlsEnabled(enabled) {
  pauseButton.disabled = !enabled;
  fastForwardButton.disabled = !enabled;
  for (let slot = 1; slot <= 3; slot += 1) {
    // A by-CID launch keeps no save state, so its state controls never turn on.
    document.getElementById(`btn-save${slot}`).disabled = launchMode || !enabled;
    const loadButton = document.getElementById(`btn-load${slot}`);
    loadButton.disabled = launchMode || !enabled || loadButton.dataset.saved !== "true";
  }
}

function withTimeout(promise, timeoutMs, message) {
  let timer = 0;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = window.setTimeout(() => reject(new Error(message)), timeoutMs);
    }),
  ]).finally(() => window.clearTimeout(timer));
}

function assertPortableEngineSupport() {
  if (typeof WebAssembly !== "object") {
    throw new Error("This browser cannot run the GBA engine.");
  }
}

function ensureDirectory(path) {
  if (!engine.FS.analyzePath(path).exists) engine.FS.mkdir(path);
}

async function loadEngine() {
  if (!enginePromise) {
    enginePromise = (async () => {
      assertPortableEngineSupport();
      const { default: createMgba } = await import("./mgba.js");
      engine = await withTimeout(
        createMgba({ canvas }),
        15_000,
        "The GBA engine did not start.",
      );
      ensureDirectory("/data");
      ensureDirectory("/data/games");
      ensureDirectory("/data/saves");
      ensureDirectory("/data/states");
      ensureDirectory("/data/cheats");
      ensureDirectory("/autosave");
      engine.setVolume(0);
      return engine;
    })().catch((error) => {
      enginePromise = null;
      engine = null;
      throw error;
    });
  }
  return enginePromise;
}

function launchAddress(pathname) {
  const match = LAUNCH_ADDRESS.exec(pathname);
  if (!match) return null;
  const entrypoint = match[2];
  // A percent-encoded slash would stand for a segment break here while the
  // Runtime joins it as one part, so no encoded slash is a launch address.
  if (/%(?:2f|5c)/i.test(entrypoint)) return null;
  let decoded;
  try {
    decoded = decodeURIComponent(entrypoint);
  } catch {
    // An escape the Runtime could not decode is not this page's address.
    return null;
  }
  return plainLaunchContentPath(decoded) ? decoded : null;
}

function requestedGame() {
  if (launchMode) return { launch: true };
  const capsule = query.get("capsule");
  if (capsule) return { capsule };
  const objectUri = query.get("objectUri") || query.get("uri");
  return objectUri ? { objectUri } : null;
}

function fileNameFromUri(uri) {
  const segment = String(uri).split("/").filter(Boolean).pop() || "game.gba";
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

async function fetchBytes(path) {
  const response = await fetch(path, { headers: launchHeaders() });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(detail || `Game data is unavailable (${response.status}).`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (!bytes.length || bytes.length > MAX_ROM_BYTES) {
    throw new Error("The selected file is not a valid GBA game.");
  }
  return bytes;
}

async function readGame(request) {
  if (request.launch) return readLaunchGame();
  if (request.capsule) {
    return {
      bytes: await fetchBytes(
        `/api/viewers/${VIEWER_ID}/content/${encodeURIComponent(request.capsule)}`,
      ),
      fileName: `${request.capsule}.gba`,
    };
  }
  if (request.objectUri) {
    const search = new URLSearchParams({ uri: request.objectUri, raw: "true" });
    return {
      bytes: await fetchBytes(`/api/viewers/${VIEWER_ID}/library-object?${search}`),
      fileName: fileNameFromUri(request.objectUri),
    };
  }
  throw new Error("Choose a GBA game from Library.");
}

// A content path the launch route can address, as the Runtime's
// `plain_content_path` requires (`page_launch.rs:118`): one or more plain parts
// joined by `/`, not empty, no `\`, no control character (`char::is_control` is
// the Unicode Cc category: C0, DEL and C1), no empty, `.` or `..` part. The
// Runtime rule has no byte bound, so none is invented here. A lone UTF-16
// surrogate is refused here too: Rust strings cannot hold one, and
// `encodeURIComponent` would throw an unnamed error on it.
function hasLoneSurrogate(text) {
  for (let index = 0; index < text.length; index += 1) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function plainLaunchContentPath(path) {
  return (
    typeof path === "string" &&
    path.length > 0 &&
    !path.includes("\\") &&
    !/\p{Cc}/u.test(path) &&
    !hasLoneSurrogate(path) &&
    path.split("/").every((part) => part !== "" && part !== "." && part !== "..")
  );
}

// The core writes this one record under elastos://launch/output/; the page reads
// it at the same name and trusts only the three keys it names.
async function readLaunchRecord() {
  const response = await fetch(
    `/api/viewers/${VIEWER_ID}/launch/output/${LAUNCH_RECORD_NAME}`,
    { headers: launchHeaders() },
  );
  if (!response.ok) throw new Error(`gba_launch_record_missing: ${response.status}`);
  let record;
  try {
    record = await response.json();
  } catch {
    throw new Error("gba_launch_record_invalid: not JSON");
  }
  if (
    !record ||
    typeof record !== "object" ||
    Object.keys(record).sort().join(",") !== "path,sha256,size" ||
    !plainLaunchContentPath(record.path) ||
    !Number.isSafeInteger(record.size) ||
    record.size <= 0 ||
    typeof record.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(record.sha256)
  ) {
    throw new Error("gba_launch_record_invalid: path, size and sha256 are required");
  }
  return record;
}

// The launch boots the ROM the core recorded, at the recorded path, and refuses
// bytes that do not match the record. A by-CID launch is play-only: no save.
async function readLaunchGame() {
  const record = await readLaunchRecord();
  const path = record.path.split("/").map(encodeURIComponent).join("/");
  const bytes = await fetchBytes(`/api/viewers/${VIEWER_ID}/launch/content/${path}`);
  if (bytes.length !== record.size) {
    console.warn(`gba_launch_rom_size_mismatch: record ${record.size}, fetched ${bytes.length}`);
    throw new Error("gba_launch_rom_size_mismatch: the ROM size differs from the launch record");
  }
  const sha256 = await sha256Hex(bytes);
  if (sha256 !== record.sha256) {
    console.warn(`gba_launch_rom_hash_mismatch: record ${record.sha256}, fetched ${sha256}`);
    throw new Error("gba_launch_rom_hash_mismatch: the ROM differs from the launch record");
  }
  return { bytes, fileName: record.path.split("/").pop() };
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function storageCapsuleForRequest(request) {
  return request?.capsule || VIEWER_ID;
}

function saveUrl(name, capsule = activeStorageCapsule) {
  return `/api/viewers/${VIEWER_ID}/storage/${encodeURIComponent(capsule)}/save/${encodeURIComponent(name)}`;
}

function stateName(slot) {
  return activeRomId ? `${activeRomId}.ss${slot}` : "";
}

function stateUrl(slot) {
  return `/api/viewers/${VIEWER_ID}/storage/${encodeURIComponent(activeStorageCapsule)}/state/${encodeURIComponent(stateName(slot))}`;
}

function statePath(slot) {
  return `/data/states/${stateName(slot)}`;
}

function responseRevision(response) {
  const revision = response.headers.get("etag");
  if (!/^"[0-9a-f]{64}"$/.test(revision || "")) throw new Error("Saved data has no valid revision.");
  return revision;
}

// A by-CID launch is play-only: the Runtime keeps no save, save state or
// library for it, so the page asks no storage route under its token.
function assertStorageAllowed() {
  if (launchMode) throw new Error("A launch keeps no saved data.");
}

async function readStoredData(url) {
  assertStorageAllowed();
  const response = await fetch(url, { headers: launchHeaders() });
  if (response.status === 404) return { url, revision: null, bytes: null };
  if (!response.ok) throw new Error("Saved data is unavailable. Keep the current game open.");
  const revision = responseRevision(response);
  return { url, revision, bytes: new Uint8Array(await response.arrayBuffer()) };
}

function assertSaveSession(session) {
  if (!session || session !== saveSession) throw new Error("The game changed before saving finished.");
  if (session.blocked) throw new Error(session.blocked);
}

function stopSaving(session, message) {
  session.blocked = message;
  if (session === saveSession) {
    window.clearInterval(saveTimer);
    showStatus(message, true);
    saveRecoveryButton.hidden = false;
    saveRecoveryButton.textContent = "Check saved data";
  }
  return new Error(message);
}

// One in-flight operation per live game; revisions belong to its captured paths.
function withSaveSession(session, operation) {
  const result = session.pending.then(() => {
    assertSaveSession(session);
    return operation();
  });
  session.pending = result.catch(() => {});
  return result;
}

async function writeStoredData(session, record, bytes, keepalive = false) {
  assertStorageAllowed();
  assertSaveSession(session);
  if (!record) throw new Error("Read this save successfully before saving. The live game is unchanged.");
  session.failedWrite = { record, bytes, uncertain: true };
  let response;
  try {
    response = await fetch(record.url, {
      method: "PUT",
      headers: { ...launchHeaders(), ...(record.revision === null
        ? { "If-None-Match": "*" } : { "If-Match": record.revision }) },
      body: bytes,
      keepalive,
    });
  } catch {
    throw stopSaving(session, "Save result is uncertain. Keep this game open; automatic saving stopped.");
  }
  if (response.status === 412) {
    session.failedWrite.uncertain = false;
    throw stopSaving(session, "Saved data changed in another window. This game is still running; automatic saving stopped.");
  }
  if (!response.ok) throw stopSaving(session, "Save was not confirmed. Keep this game open; automatic saving stopped.");
  try {
    const revision = responseRevision(response);
    assertSaveSession(session);
    record.revision = revision;
    record.bytes = bytes;
    session.failedWrite = null;
  } catch {
    throw stopSaving(session, "Save result is uncertain. Keep this game open; automatic saving stopped.");
  }
}

function sameSavedBytes(left, right) {
  return left?.length === right?.length && left?.every((byte, index) => byte === right[index]);
}

async function recoverSave() {
  const session = saveSession;
  const failed = session?.failedWrite;
  if (!failed || saveRecoveryButton.disabled) return;
  saveRecoveryButton.disabled = true;
  try {
    await session.pending;
    const current = await readStoredData(failed.record.url);
    if (session !== saveSession || session.failedWrite !== failed) return;
    if (failed.uncertain && sameSavedBytes(current.bytes, failed.bytes)) {
      Object.assign(failed.record, current);
    } else if (failed.uncertain && current.revision === failed.record.revision) {
      // The exact pre-write version remains. A conditional retry is safe and uses current live progress.
      Object.assign(failed.record, current);
    } else {
      if (!current.bytes?.length) throw new Error("Saved data is unavailable. Your current game is unchanged.");
      if (!window.confirm("Saved data differs from this game. Discard current progress and load the stored save?")) return;
      // Read again after the user decision; the same game/path still owns this action.
      const selected = await readStoredData(failed.record.url);
      if (session !== saveSession || session.failedWrite !== failed) return;
      if (!selected.bytes?.length) throw new Error("Saved data is unavailable. Your current game is unchanged.");
      if (failed.record === session.save) {
        session.engine.FS.writeFile(session.savePath, selected.bytes);
        if (!session.engine.loadGame(session.romPath, session.savePath)) throw new Error("The stored game could not be loaded.");
      } else {
        const slot = [1, 2, 3].find((value) => session.states[value] === failed.record);
        if (!slot) return;
        session.engine.FS.writeFile(session.statePaths[slot], selected.bytes);
        if (!session.engine.loadState(slot)) throw new Error("The stored state could not be loaded.");
      }
      Object.assign(failed.record, selected);
      if (!paused) session.engine.resumeGame();
    }
    session.failedWrite = null;
    session.blocked = "";
    saveRecoveryButton.hidden = true;
    showStatus("Saved data checked. Automatic saving resumed.");
    startSaveLifecycle();
  } catch (error) {
    if (session === saveSession) showStatus(error.message, true);
  } finally {
    if (session === saveSession) saveRecoveryButton.disabled = false;
  }
}

async function persistSave(keepalive = false) {
  const session = saveSession;
  if (launchMode || !session || !session.save || !gameLoaded) return;
  return withSaveSession(session, async () => {
    const bytes = session.engine.getSave();
    if (bytes?.length) await writeStoredData(session, session.save, new Uint8Array(bytes), keepalive);
  });
}

async function waitForState(session, slot) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    assertSaveSession(session);
    try {
      const bytes = session.engine.FS.readFile(session.statePaths[slot]);
      if (bytes?.length) return bytes;
    } catch {
      // mGBA creates the state file asynchronously.
    }
    await new Promise((resolve) => window.setTimeout(resolve, 50));
  }
  throw new Error(`State ${slot} was not created.`);
}

async function saveState(slot) {
  assertStorageAllowed();
  const session = saveSession;
  assertSaveSession(session);
  return withSaveSession(session, async () => {
    if (!session.states[slot]) throw new Error(`State ${slot} could not be read. Saving is unavailable.`);
    try { session.engine.FS.unlink(session.statePaths[slot]); } catch { /* A new slot has no local file. */ }
    if (!session.engine.saveState(slot)) throw new Error(`State ${slot} could not be saved.`);
    await writeStoredData(session, session.states[slot], new Uint8Array(await waitForState(session, slot)));
    assertSaveSession(session);
    setSlotState(slot, true);
    showStatus(`State ${slot} saved`);
  });
}

async function loadState(slot) {
  assertStorageAllowed();
  const session = saveSession;
  assertSaveSession(session);
  return withSaveSession(session, async () => {
    const record = await readStoredData(session.stateUrls[slot]);
    assertSaveSession(session);
    if (!record.bytes?.length) {
      setSlotState(slot, false);
      throw new Error(`State ${slot} is empty.`);
    }
    session.engine.FS.writeFile(session.statePaths[slot], record.bytes);
    if (!session.engine.loadState(slot)) throw new Error(`State ${slot} could not be loaded.`);
    session.states[slot] = record;
    setSlotState(slot, true);
    showStatus(`State ${slot} loaded`);
  });
}

async function refreshStateSlots(session = saveSession) {
  await Promise.all(
    [1, 2, 3].map(async (slot) => {
      try {
        const record = await readStoredData(session.stateUrls[slot]);
        assertSaveSession(session);
        session.states[slot] = record;
        setSlotState(slot, Boolean(record.bytes?.length));
      } catch {
        if (session === saveSession) {
          setSlotState(slot, false);
          document.getElementById(`slot-status${slot}`).textContent = "Unavailable";
          document.getElementById(`btn-save${slot}`).disabled = true;
        }
      }
    }),
  );
}

function startSaveLifecycle() {
  window.clearInterval(saveTimer);
  saveTimer = window.setInterval(() => persistSave().catch(console.warn), 10_000);
}

async function openGame(request, title = "GBA Emulator") {
  if (!homeToken) throw new Error("Open GBA from Home or Library.");
  const sequence = ++openSequence;
  const previous = saveSession;
  if (previous) assertSaveSession(previous);
  showStatus("Starting game");

  const [{ bytes, fileName }, module] = await Promise.all([readGame(request), loadEngine()]);
  const romId = await sha256Hex(bytes);
  const romPath = `/data/games/${romId}.gba`;
  const saveName = `${romId}.sav`;
  const savePath = `/data/saves/${saveName}`;
  const storageCapsule = storageCapsuleForRequest(request);
  // A launch has no save route; asking under a launch token only gets a 401.
  let saved = request.launch ? null : await readStoredData(saveUrl(saveName, storageCapsule));
  if (sequence !== openSequence) return;
  // Preserve the live game when the final save is refused or uncertain.
  if (previous) {
    previous.engine.pauseGame();
    try { await persistSave(); } catch (error) {
      if (!paused) previous.engine.resumeGame();
      throw error;
    }
  }
  if (sequence !== openSequence) {
    if (previous === saveSession && previous && !paused) previous.engine.resumeGame();
    return;
  }
  if (previous && saved?.url === previous.save.url) saved = { ...previous.save };
  if (saved?.bytes?.length) module.FS.writeFile(savePath, saved.bytes);
  else { try { module.FS.unlink(savePath); } catch { /* First save has no local file. */ } }
  module.FS.writeFile(romPath, bytes);
  if (!module.loadGame(romPath, savePath)) {
    if (previous === saveSession && previous && !paused) previous.engine.resumeGame();
    throw new Error("The GBA engine rejected this game.");
  }

  activeSaveName = saveName;
  activeRomId = romId;
  activeStorageCapsule = storageCapsule;
  saveSession = { engine: module, romPath, savePath, save: saved, states: {}, statePaths: {}, stateUrls: {}, pending: Promise.resolve(), blocked: "", failedWrite: null };
  saveRecoveryButton.hidden = true;
  for (let slot = 1; slot <= 3; slot += 1) {
    saveSession.statePaths[slot] = statePath(slot);
    saveSession.stateUrls[slot] = stateUrl(slot);
  }
  gameLoaded = true;
  paused = false;
  fastForward = false;
  soundEnabled = false;
  module.setVolume(0);
  module.setFastForwardMultiplier(1);
  module.resumeGame();
  if (!request.launch) {
    homeNavigation.setQuery(request.capsule ? { capsule: request.capsule } : { objectUri: request.objectUri });
  }
  emptyState.hidden = true;
  powerLed.classList.remove("off");
  setGameControlsEnabled(true);
  syncPauseButton();
  fastForwardButton.classList.remove("active");
  document.title = request.launch ? "GBA Emulator - ElastOS" : `${title || fileName} - GBA Emulator - ElastOS`;
  showStatus("");
  if (!request.launch) {
    const session = saveSession;
    await refreshStateSlots(session);
    if (session !== saveSession || sequence !== openSequence) return;
    startSaveLifecycle();
  }
  startInputLoop();
  canvas.focus({ preventScroll: true });
}

async function loadInstalledGames() {
  if (!homeToken) return;
  const response = await fetch(`/api/viewers/${VIEWER_ID}/library`, {
    headers: launchHeaders(),
  });
  if (!response.ok) return;
  const payload = await response.json();
  for (const item of Array.isArray(payload.items) ? payload.items : []) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "rom-library-item";
    button.textContent = item.title || item.capsule;
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      openGame({ capsule: item.capsule }, item.title || item.capsule).catch((error) => {
        showStatus(error.message || String(error), true);
      });
    });
    installedGames.append(button);
    installedGames.closest("#rom-library").hidden = false;
  }
}

function currentTouchMask() {
  let mask = 0;
  for (const button of touchPointers.values()) mask |= BUTTON_BITS[button] || 0;
  return mask;
}

function syncInput() {
  if (!engine || !gameLoaded) return;
  const nextMask = keyboardMask | currentTouchMask() | gamepadMask;
  for (const [button, bit] of Object.entries(BUTTON_BITS)) {
    const wasPressed = Boolean(appliedInputMask & bit);
    const isPressed = Boolean(nextMask & bit);
    if (wasPressed !== isPressed) {
      engine[isPressed ? "buttonPress" : "buttonUnpress"](button);
      document.querySelector(`[data-key="${button}"]`)?.classList.toggle("pressed", isPressed);
    }
  }
  appliedInputMask = nextMask;
}

function pollInput() {
  gamepadMask = readGamepadMask(navigator.getGamepads?.()?.find(Boolean));
  syncInput();
  inputFrame = requestAnimationFrame(pollInput);
}

function startInputLoop() {
  cancelAnimationFrame(inputFrame);
  inputFrame = requestAnimationFrame(pollInput);
}

function clearInput() {
  keyboardMask = 0;
  gamepadMask = 0;
  touchPointers.clear();
  syncInput();
}

function bindInput() {
  window.addEventListener("keydown", (event) => {
    if (event.target === saveRecoveryButton) return;
    const stateShortcut = {
      F1: [saveState, 1],
      F2: [saveState, 2],
      F3: [saveState, 3],
      F5: [loadState, 1],
      F6: [loadState, 2],
      F7: [loadState, 3],
    }[event.code];
    if (gameLoaded && !launchMode && stateShortcut) {
      event.preventDefault();
      stateShortcut[0](stateShortcut[1]).catch((error) => showStatus(error.message, true));
      return;
    }
    const button = KEY_BUTTONS[event.code];
    if (!button || event.repeat) return;
    event.preventDefault();
    keyboardMask |= BUTTON_BITS[button];
    syncInput();
    enableSound().catch(() => {});
  });
  window.addEventListener("keyup", (event) => {
    if (event.target === saveRecoveryButton) return;
    const button = KEY_BUTTONS[event.code];
    if (!button) return;
    event.preventDefault();
    keyboardMask &= ~BUTTON_BITS[button];
    syncInput();
  });
  window.addEventListener("blur", clearInput);
  document.querySelectorAll("[data-key]").forEach((element) => {
    const button = element.dataset.key;
    const release = (event) => {
      event.preventDefault();
      touchPointers.delete(event.pointerId);
      syncInput();
    };
    element.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      element.setPointerCapture?.(event.pointerId);
      touchPointers.set(event.pointerId, button);
      syncInput();
      enableSound().catch(() => {});
    });
    element.addEventListener("pointerup", release);
    element.addEventListener("pointercancel", release);
    element.addEventListener("lostpointercapture", release);
  });
}

async function enableSound() {
  if (!engine || !gameLoaded || soundEnabled) return;
  engine.setVolume(Number(volume.value) / 100);
  soundEnabled = true;
}

function openLibrary() {
  if (homeParentOrigin && window.top && window.top !== window) {
    window.top.postMessage(
      { type: "home:open-target", target: "library", homeToken },
      homeParentOrigin,
    );
    return;
  }
  window.location.href = "/apps/home/";
}

pauseButton.addEventListener("click", () => {
  if (!engine || !gameLoaded) return;
  enableSound().catch(() => {});
  paused = !paused;
  engine[paused ? "pauseGame" : "resumeGame"]();
  syncPauseButton();
  if (paused) persistSave().catch((error) => showStatus(error.message, true));
});
saveRecoveryButton.addEventListener("click", () => { recoverSave().catch(() => {}); });
fastForwardButton.addEventListener("click", () => {
  if (!engine || !gameLoaded) return;
  enableSound().catch(() => {});
  fastForward = !fastForward;
  engine.setFastForwardMultiplier(fastForward ? 4 : 1);
  fastForwardButton.classList.toggle("active", fastForward);
});
volume.addEventListener("input", () => {
  enableSound().catch(() => {});
  if (engine) engine.setVolume(Number(volume.value) / 100);
});
fullscreenButton.addEventListener("click", () => {
  const action = document.fullscreenElement
    ? document.exitFullscreen()
    : screenBezel.requestFullscreen();
  action?.catch(() => {});
});
document.addEventListener("fullscreenchange", () => {
  syncFullscreenButton();
  canvas.focus({ preventScroll: true });
});
emptyState.addEventListener("click", openLibrary);
emptyState.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  event.preventDefault();
  openLibrary();
});
for (let slot = 1; slot <= 3; slot += 1) {
  document.getElementById(`btn-save${slot}`).addEventListener("click", () => {
    saveState(slot).catch((error) => showStatus(error.message, true));
  });
  document.getElementById(`btn-load${slot}`).addEventListener("click", () => {
    loadState(slot).catch((error) => showStatus(error.message, true));
  });
}
document.addEventListener("visibilitychange", () => {
  if (document.hidden) persistSave().catch(console.warn);
});
window.addEventListener("pagehide", () => {
  window.clearInterval(saveTimer);
  cancelAnimationFrame(inputFrame);
  clearInput();
  persistSave(true).catch(() => {});
});

syncPauseButton();
syncFullscreenButton();
bindInput();
if (!launchMode) loadInstalledGames().catch(() => {});
const launch = requestedGame();
if (launch) {
  const title = launchMode ? "" : query.get("name") || query.get("capsule") || fileNameFromUri(launch.objectUri);
  openGame(launch, title).catch((error) => showStatus(error.message || String(error), true));
} else {
  homeNavigation.setQuery({});
}
