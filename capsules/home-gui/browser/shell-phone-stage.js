/* Phone stage: the system back gesture and the title-bar swipe.

   Back: the shell keeps at most one history entry of its own (model in
   shell-phone-stage-history.js). It is pushed when the first layer (a window
   on the stage or any registered Back layer: sheets, rails, menus, About,
   Mission Control, the Assistant room) opens on a phone and consumed again
   when the last layer closes, so the bare desktop never traps back — the host
   page's own history is left alone. popstate closes exactly one layer: the
   open layer that paints on top (one stacking order over every registered
   layer), through the close it registered, and that layer stops counting at
   once while its hide animates. With no layer open, the window that is
   actually on this Space goes home (minimise; the capsule keeps running). A
   window parked on another Space is not that window. Layers register next to
   their own close (registerStageLayer in shell-popovers.js); the phone smoke
   fails on a Home host surface that has none.

   Swipe: a downward drag on the title bar opens Mission Control as the app
   switcher. It starts on the title bar only — capsule frames own their own
   touches — and cancels on horizontal drift. Presentation only. */

import { HOME_GUI_HOST_SELECTORS, shellState } from "./shell-core.js?v=home-20260813a";
import {
  STAGE_HISTORY_STATE,
  createStageHistory,
  isStageHistoryState,
} from "./shell-phone-stage-history.js?v=home-20260813a";
import { isPhone } from "./shell-form-factor.js?v=home-20260813a";
import { minimizeWindow } from "./shell-windows.js?v=home-20260813a";
import { isExposeOpen, openExpose } from "./shell-expose.js?v=home-20260813a";
import { registeredStageLayers } from "./shell-popovers.js?v=home-20260813a";

// A title-bar drag this far down opens the switcher…
export const TITLE_SWIPE_DOWN_PX = 48;
// …unless it drifted this far sideways first (a scroll or a slip).
export const TITLE_SWIPE_DRIFT_PX = 32;

// Always on screen, so never a layer. The notification toast is a passing
// notice that dismisses itself, not something Back has to close. Every other
// host surface must be a registered layer.
const STAGE_CHROME = Object.freeze([
  ".desktop-backdrop",
  ".toolbar",
  ".desktop-workspace",
  ".taskbar",
  "#home-notification-toast",
]);
export const LAYER_HOST_SELECTORS = Object.freeze(
  HOME_GUI_HOST_SELECTORS.filter((selector) => !STAGE_CHROME.includes(selector)),
);
// A close that never lands stops holding its layer after this long.
export const LAYER_CLOSE_TIMEOUT_MS = 2000;

// On the stage: not minimised, and still in the Space the Dock is showing.
export function windowOnStage(entry) {
  const node = entry?.node;
  return Boolean(node && !node.classList.contains("hidden") && node.dataset.spaceVisible !== "false");
}

export function visibleWindowCount(windows = shellState.windows) {
  let count = 0;
  for (const entry of windows.values()) {
    if (windowOnStage(entry)) {
      count += 1;
    }
  }
  return count;
}

function shown(node) {
  return Boolean(node && !node.hidden && node.getClientRects().length > 0);
}

function layerNode(layer, doc) {
  return doc.querySelector(layer.selector);
}

function layerOpen(layer, doc) {
  return layer.isOpen ? layer.isOpen() === true : shown(layerNode(layer, doc));
}

// Layers whose close is in flight: one Back already took them.
const closing = new Set();
let onLayerSettled = () => {};

// z-indexed ancestors of a node, outermost first.
function stackingPath(node, view) {
  const path = [];
  for (let el = node; el && el.nodeType === 1; el = el.parentElement) {
    const z = Number.parseInt(view.getComputedStyle(el).zIndex, 10);
    if (Number.isFinite(z)) {
      path.unshift({ el, z });
    }
  }
  return path;
}

function documentOrder(a, b) {
  return a.compareDocumentPosition(b) & 4 ? -1 : 1;
}

// Negative when `a` paints below `b`. Walks both stacking paths to the first
// context they do not share: a higher z wins there, then the later element in
// the document; inside one context the nested surface is on top.
export function compareStacking(a, b, view) {
  if (!a || !b) {
    return a ? 1 : b ? -1 : 0;
  }
  const pa = stackingPath(a, view);
  const pb = stackingPath(b, view);
  for (let index = 0; index < Math.min(pa.length, pb.length); index += 1) {
    if (pa[index].el === pb[index].el) {
      continue;
    }
    return pa[index].z !== pb[index].z ? pa[index].z - pb[index].z : documentOrder(pa[index].el, pb[index].el);
  }
  if (pa.length !== pb.length) {
    return pa.length - pb.length;
  }
  return a === b ? 0 : documentOrder(a, b);
}

// Open layers that Back has not taken yet, top-most last.
export function openStageLayers(doc = document) {
  const view = doc.defaultView;
  return registeredStageLayers()
    .filter((layer) => !closing.has(layer.id) && layerOpen(layer, doc))
    .map((layer) => ({ layer, node: layerNode(layer, doc) }))
    .sort((a, b) => compareStacking(a.node, b.node, view))
    .map(({ layer }) => layer);
}

export function openSheetCount(doc = document) {
  return openStageLayers(doc).length;
}

export function stageLayerCount(doc = document) {
  return visibleWindowCount() + openSheetCount(doc);
}

// Runs the layer's own close and resolves once it is really gone (its hide
// animation included), or after LAYER_CLOSE_TIMEOUT_MS if it never goes.
export function closeStageLayer(layer, doc = document) {
  const view = doc.defaultView;
  closing.add(layer.id);
  const started = Date.now();
  return new Promise((resolve) => {
    const check = () => {
      if (layerOpen(layer, doc) && Date.now() - started < LAYER_CLOSE_TIMEOUT_MS) {
        view.setTimeout(check, 32);
        return;
      }
      closing.delete(layer.id);
      onLayerSettled();
      resolve();
    };
    try {
      layer.close();
    } catch (_error) {
      // A close that throws leaves the layer open; the timeout releases it.
    }
    check();
  });
}

// Closes exactly one layer, the top-most, and reports how many remain.
export function closeTopStageLayer(doc = document) {
  const top = openStageLayers(doc).at(-1);
  if (top) {
    void closeStageLayer(top, doc);
    return stageLayerCount(doc);
  }
  const active = shellState.windows.get(shellState.activeWindowId);
  const visible = [...shellState.windows.values()].find(windowOnStage);
  const chosen = windowOnStage(active) ? active : visible;
  if (chosen?.id) {
    minimizeWindow(chosen.id);
  }
  return stageLayerCount(doc);
}

// The swipe ends with a click on the title bar, which is now a Mission
// Control card; letting it through would activate the card and undo the open.
// Window capture runs before Mission Control's document-capture handlers.
function suppressGestureClick(doc) {
  const view = doc.defaultView;
  const swallow = (event) => {
    event.preventDefault();
    event.stopPropagation();
  };
  view.addEventListener("click", swallow, { capture: true, once: true });
  view.setTimeout(() => view.removeEventListener("click", swallow, { capture: true }), 500);
}

function bindTitleSwipe(doc) {
  let gesture = null;
  doc.addEventListener(
    "pointerdown",
    (event) => {
      if (!isPhone() || isExposeOpen()) {
        return;
      }
      const head = event.target.closest?.(".window-head");
      if (!head || event.target.closest("button")) {
        return;
      }
      gesture = { startX: event.clientX, startY: event.clientY, pointerId: event.pointerId };
      // The window body is an iframe; without capture the pointer's moves
      // would land in that document once the swipe leaves the title bar.
      try {
        head.setPointerCapture(event.pointerId);
      } catch (_error) {
        // Capture is a nicety; the gesture still works when the moves stay on the head.
      }
    },
    { passive: true },
  );
  doc.addEventListener(
    "pointermove",
    (event) => {
      if (!gesture || event.pointerId !== gesture.pointerId) {
        return;
      }
      const dx = Math.abs(event.clientX - gesture.startX);
      const dy = event.clientY - gesture.startY;
      if (dx >= TITLE_SWIPE_DRIFT_PX) {
        gesture = null;
        return;
      }
      if (dy >= TITLE_SWIPE_DOWN_PX) {
        gesture = null;
        suppressGestureClick(doc);
        openExpose();
      }
    },
    { passive: true },
  );
  const end = () => {
    gesture = null;
  };
  doc.addEventListener("pointerup", end, { passive: true });
  doc.addEventListener("pointercancel", end, { passive: true });
}

// WebKit (Safari, every iOS browser) records nested frame loads as joint
// session steps and, seen from the shell frame, one history.back() after a
// pushState took the shell frame itself to about:blank (phone smoke,
// 2026-09-23). Buttons and the title swipe cover every function, so on
// WebKit the stage history stays off. Chromium and Gecko follow the spec.
export function stageHistorySupported(view = window) {
  const agent = String(view.navigator?.userAgent || "");
  const webkit = /AppleWebKit\//.test(agent) && !/(Chrome|Chromium|Edg)\//.test(agent);
  return !webkit;
}

export function bindPhoneStage(doc = document, view = window) {
  bindTitleSwipe(doc);
  if (!stageHistorySupported(view)) {
    doc.body.dataset.stageHistory = "buttons";
    return null;
  }
  doc.body.dataset.stageHistory = "history";
  const stageHistory = createStageHistory({
    onOurEntry: () => isStageHistoryState(view.history.state),
    layerCount: () => (isPhone(view) ? stageLayerCount(doc) : 0),
    pushState: () => view.history.pushState(STAGE_HISTORY_STATE, ""),
    back: () => view.history.back(),
    onBack: () => closeTopStageLayer(doc),
  });
  let scheduled = false;
  const sync = () => {
    scheduled = false;
    stageHistory.sync();
  };
  const schedule = () => {
    if (!scheduled) {
      scheduled = true;
      view.queueMicrotask ? view.queueMicrotask(sync) : Promise.resolve().then(sync);
    }
  };
  // A layer whose close timed out counts again; let the history catch up.
  onLayerSettled = schedule;
  new view.MutationObserver(schedule).observe(doc.body, {
    attributes: true,
    attributeFilter: ["class", "hidden"],
    childList: true,
    subtree: true,
  });
  view.addEventListener("popstate", () => {
    stageHistory.handlePopState();
  });
  view.addEventListener("resize", schedule);
  return stageHistory;
}
