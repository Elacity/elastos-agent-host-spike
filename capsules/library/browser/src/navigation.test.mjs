import assert from "node:assert/strict";
import test from "node:test";

import { createLibraryNavigation } from "./navigation.js";

// One embedded Library frame: its slice of the joint session history, the
// messages it posts to the shell, and the shell's layout attribute.
function embeddedLibrary() {
  const entries = [{ state: null }];
  let index = 0;
  const posted = [];
  const observers = [];
  const dataset = {};
  let nav = null;
  const history = {
    get state() {
      return entries[index].state;
    },
    pushState(state) {
      entries.splice(index + 1, entries.length, { state });
      index += 1;
    },
    replaceState(state) {
      entries[index] = { state };
    },
    go(delta) {
      queueMicrotask(() => {
        index = Math.max(0, Math.min(entries.length - 1, index + delta));
        void nav.handleBrowserPopState({ state: entries[index].state });
      });
    },
    back() {
      this.go(-1);
    },
    forward() {
      this.go(1);
    },
  };
  const parent = { postMessage: (message) => posted.push(message) };
  globalThis.window = { parent, history, location: { href: "https://library.invalid/" } };
  globalThis.document = { documentElement: { dataset } };
  globalThis.MutationObserver = class {
    constructor(callback) {
      this.callback = callback;
      observers.push(this);
    }
    observe() {}
  };
  const state = {
    backStack: [],
    forwardStack: [],
    historyEntries: [],
    historyIndex: -1,
    historyKeyCounter: 0,
    currentUri: "home://files",
    query: "",
  };
  const button = () => ({ disabled: false });
  nav = createLibraryNavigation({
    backButton: button(),
    forwardButton: button(),
    loadCurrentFolder: async () => {},
    parentUri: (uri) => uri.split("/").slice(0, -1).join("/"),
    rootForUri: () => ({ uri: "home://files" }),
    searchInput: { value: "" },
    setStatus: () => {},
    state,
    upButton: button(),
  });
  const setStage = (factor) => {
    dataset.elFormFactor = factor;
    for (const observer of observers) observer.callback([]);
  };
  const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
  return { nav, state, posted, setStage, settle, depth: () => index, entries };
}

test("a phone stage reset drops the Library's own entries and tells the shell; a desktop one reinstalls them", async () => {
  const library = embeddedLibrary();
  library.nav.installBrowserHistory();
  assert.equal(library.depth(), 0, "an embedded Library waits for the shell to name the stage");

  library.setStage("desktop");
  assert.deepEqual(library.posted.at(-1), { type: "elastos:app-history", held: true });
  await library.nav.navigate("home://files/photos");
  assert.equal(library.depth(), 2, "guard, root, folder");

  library.setStage("phone");
  await library.settle();
  assert.equal(library.depth(), 0, "every entry the Library pushed is behind it");
  assert.deepEqual(library.posted.at(-1), { type: "elastos:app-history", held: false });
  assert.equal(library.state.historyIndex, -1);
  assert.deepEqual(library.state.backStack, ["home://files"], "the in-app Back keeps its stack");
  assert.equal(library.state.currentUri, "home://files/photos", "the folder on screen stays");

  // On the phone the shell owns Back: a traversal that reaches this frame
  // never navigates it, and folder changes push nothing.
  await library.nav.handleBrowserPopState({ state: library.entries[1].state });
  assert.equal(library.state.currentUri, "home://files/photos");
  await library.nav.navigate("home://files/photos/2026");
  assert.equal(library.depth(), 0);
  await library.nav.navigateBack();
  assert.equal(library.state.currentUri, "home://files/photos");

  library.setStage("desktop");
  assert.equal(library.depth(), 1, "a desktop stage reinstalls guard and current folder");
  assert.deepEqual(library.posted.at(-1), { type: "elastos:app-history", held: true });
});
