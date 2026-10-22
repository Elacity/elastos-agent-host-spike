import assert from "node:assert/strict";
import test from "node:test";

import {
  bindBrowserInputSurface,
  plainTextFromClipboardEvent,
} from "./browser-input-surface.js";
import { selkiesMessagesForInput } from "./browser-input.js";

function clipboardEvent(types, values = {}) {
  return {
    clipboardData: {
      types,
      getData(type) {
        return values[type] ?? "";
      },
    },
  };
}

test("explicit ClipboardEvent accepts only text/plain", () => {
  assert.equal(
    plainTextFromClipboardEvent(
      clipboardEvent(["text/plain"], { "text/plain": "paste me" }),
    ),
    "paste me",
  );
  assert.equal(
    plainTextFromClipboardEvent(
      clipboardEvent(["text/html"], { "text/html": "<b>no</b>" }),
    ),
    "",
  );
  assert.equal(
    plainTextFromClipboardEvent(
      clipboardEvent(["text"], { text: "alias is not accepted" }),
    ),
    "",
  );
});

test("missing or malformed ClipboardEvent data is rejected", () => {
  assert.equal(plainTextFromClipboardEvent(null), "");
  assert.equal(plainTextFromClipboardEvent({ clipboardData: {} }), "");
  assert.equal(
    plainTextFromClipboardEvent({
      clipboardData: {
        types: ["text/plain"],
        getData() {
          return null;
        },
      },
    }),
    "",
  );
});

function fakeTarget(extra = {}) {
  const listeners = new Map();
  return {
    ...extra,
    addEventListener(type, listener) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(listener);
    },
    fire(type, init = {}) {
      const event = {
        type,
        defaultPrevented: false,
        preventDefault() { this.defaultPrevented = true; },
        stopPropagation() {},
        getModifierState: () => false,
        target: this,
        ...init,
      };
      for (const listener of listeners.get(type) || []) listener(event);
      return event;
    },
  };
}

function surface({ datachannel = true } = {}) {
  globalThis.document ??= fakeTarget();
  globalThis.window ??= fakeTarget({ setTimeout, clearTimeout });
  const inputs = [];
  const frames = [];
  const captured = new Set();
  const remoteVideo = fakeTarget({
    hidden: false,
    videoWidth: 1280,
    videoHeight: 720,
    contains: () => false,
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 1280, height: 720 }),
  });
  const renderPanel = fakeTarget({
    focus() {},
    setPointerCapture: (id) => captured.add(id),
    hasPointerCapture: (id) => captured.has(id),
    releasePointerCapture: (id) => captured.delete(id),
  });
  bindBrowserInputSurface({
    copyRemoteClipboardToHost: async () => inputs.push({ type: "copy" }),
    friendlyOpenError: (error) => String(error),
    getCurrentPage: () => ({ page_id: "page:1" }),
    getCurrentView: () => ({ width: 1280, height: 720 }),
    keyboardCapture: null,
    pasteHostClipboardIntoRemote: async () => {},
    readHostClipboardText: async () => "",
    remoteVideo,
    renderPanel,
    sendBrowserInput: async (event) => inputs.push(event),
    showStatus: () => {},
    streamsPointerDrag: () => datachannel,
    unlockRemoteAudioFromGesture: () => {},
    requestAnimationFrameFn: (callback) => frames.push(callback),
    cancelAnimationFrameFn: () => {},
  });
  const flushFrames = () => frames.splice(0).forEach((callback) => callback());
  const mouse = (type, clientX, clientY, extra = {}) =>
    renderPanel.fire(type, { pointerType: "mouse", pointerId: 1, button: 0, clientX, clientY, ...extra });
  return { inputs, renderPanel, remoteVideo, mouse, flushFrames, captured };
}

test("mouse event encodes as one Selkies held-button or release message", () => {
  assert.deepEqual(selkiesMessagesForInput({ type: "mouse", x: 10.4, y: 20.6, buttons: 1 }), ["m,10,21,1,0"]);
  assert.deepEqual(selkiesMessagesForInput({ type: "mouse", x: 30, y: 40, buttons: 0 }), ["m,30,40,0,0"]);
});

test("datachannel mouse drag sends press, frame-throttled moves, release, and no click", () => {
  const { inputs, renderPanel, mouse, flushFrames, captured } = surface();
  mouse("pointerdown", 100, 100);
  mouse("pointermove", 102, 101);
  assert.deepEqual(inputs, [], "movement under 4 px is not a drag");
  mouse("pointermove", 110, 100);
  mouse("pointermove", 150, 100);
  assert.ok(captured.has(1), "drag captures the pointer");
  flushFrames();
  mouse("pointermove", 200, 120);
  mouse("pointerup", 210, 120);
  flushFrames();
  renderPanel.fire("click", { clientX: 210, clientY: 120 });
  assert.deepEqual(inputs, [
    { type: "mouse", x: 100, y: 100, buttons: 1 },
    { type: "mouse", x: 150, y: 100, buttons: 1 },
    { type: "mouse", x: 210, y: 120, buttons: 0 },
  ]);
  assert.equal(captured.size, 0, "release drops pointer capture");
});

test("a press without movement keeps the Runtime click", () => {
  const { inputs, renderPanel, mouse } = surface();
  mouse("pointerdown", 100, 100);
  mouse("pointermove", 103, 100);
  mouse("pointerup", 103, 100);
  renderPanel.fire("click", { clientX: 103, clientY: 100 });
  assert.deepEqual(inputs, [{ type: "click", x: 103, y: 100 }]);
});

test("pointercancel during a drag sends the release", () => {
  const { inputs, mouse, flushFrames } = surface();
  mouse("pointerdown", 100, 100);
  mouse("pointermove", 120, 100);
  mouse("pointercancel", 0, 0);
  flushFrames();
  assert.deepEqual(inputs, [
    { type: "mouse", x: 100, y: 100, buttons: 1 },
    { type: "mouse", x: 120, y: 100, buttons: 0 },
  ]);
});

test("Runtime-route input falls back to today's click without drag messages", () => {
  const { inputs, renderPanel, mouse, flushFrames } = surface({ datachannel: false });
  mouse("pointerdown", 100, 100);
  mouse("pointermove", 200, 100);
  mouse("pointerup", 200, 100);
  flushFrames();
  renderPanel.fire("click", { clientX: 200, clientY: 100 });
  assert.deepEqual(inputs, [{ type: "click", x: 200, y: 100 }]);
});

test("touch pan and non-primary buttons do not start a mouse drag", () => {
  const { inputs, mouse, flushFrames } = surface();
  mouse("pointerdown", 100, 100, { button: 2 });
  mouse("pointermove", 200, 100);
  flushFrames();
  assert.deepEqual(inputs, []);
});

test("Cmd+A and Ctrl+A send the guest Ctrl+A select-all", () => {
  const { inputs, renderPanel } = surface();
  const meta = renderPanel.fire("keydown", { key: "a", metaKey: true });
  renderPanel.fire("keydown", { key: "A", ctrlKey: true, shiftKey: true });
  renderPanel.fire("keydown", { key: "a", metaKey: true, altKey: true });
  assert.ok(meta.defaultPrevented);
  assert.deepEqual(inputs, [
    { type: "key_combo", keysyms: [65507, 97] },
    { type: "key_combo", keysyms: [65507, 97] },
  ]);
});
