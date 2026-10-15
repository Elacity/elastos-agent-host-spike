/* Phone stage: the system back gesture and the title-bar swipe.

   Back: the shell keeps at most one history entry of its own (model in
   shell-phone-stage-history.js). It is pushed when the first layer (a window
   on the stage, Mission Control, the Assistant room, or any visible Home
   surface other than the bar, Dock and desktop) opens on a phone and consumed
   again when the last layer closes, so the bare desktop never traps back —
   the host page's own history is left alone. popstate closes the top layer:
   the top-most open surface gets the Escape a keyboard user would press there
   (or the shell's ordered Escape stack, if the surface has no Escape of its
   own), then Mission Control, then the window that is actually on this Space
   goes home (minimise; the capsule keeps running). A window parked on another
   Space is not that window. The surfaces come from HOME_GUI_HOST_SELECTORS,
   so a new Home surface is a Back layer without a second list.

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
import { closeExpose, isExposeOpen, openExpose } from "./shell-expose.js?v=home-20260813a";
import { dispatchStageBackEscape } from "./shell-popovers.js?v=home-20260813a";
import { assistantFaceActive, dismissAssistantForBack } from "./shell-assistant-face.js?v=home-20260813a";

// A title-bar drag this far down opens the switcher…
export const TITLE_SWIPE_DOWN_PX = 48;
// …unless it drifted this far sideways first (a scroll or a slip).
export const TITLE_SWIPE_DRIFT_PX = 32;

// Always on screen, so never a layer. The notification toast is a passing
// notice that dismisses itself, not something Back has to close.
const STAGE_CHROME = Object.freeze([
  ".desktop-backdrop",
  ".toolbar",
  ".desktop-workspace",
  ".taskbar",
  "#home-notification-toast",
]);
export const LAYER_SELECTORS = Object.freeze(
  HOME_GUI_HOST_SELECTORS.filter((selector) => !STAGE_CHROME.includes(selector)),
);
// The Assistant room lives outside the host surfaces (it is its own frame).
const ASSISTANT_ROOM = "#assistant-space";

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

function assistantOpen(doc) {
  return shown(doc.querySelector(ASSISTANT_ROOM)) || assistantFaceActive();
}

// Open layers as { node, close } with the top-most last: by z-index, then by
// document order (a later sibling paints above an earlier one).
export function openStageLayers(doc = document) {
  const layers = LAYER_SELECTORS.map((selector) => doc.querySelector(selector))
    .filter(shown)
    .map((node) => ({ node, close: () => closeSurface(doc, node) }));
  if (assistantOpen(doc)) {
    const node = doc.querySelector(ASSISTANT_ROOM);
    layers.push({ node, close: () => dismissAssistantForBack() });
  }
  const view = doc.defaultView;
  const z = (node) => {
    const value = node && view ? Number.parseInt(view.getComputedStyle(node).zIndex, 10) : 0;
    return Number.isFinite(value) ? value : 0;
  };
  return layers.sort((a, b) => {
    const byZ = z(a.node) - z(b.node);
    if (byZ !== 0 || !a.node || !b.node) {
      return byZ;
    }
    return a.node.compareDocumentPosition(b.node) & 4 ? -1 : 1;
  });
}

export function openSheetCount(doc = document) {
  return openStageLayers(doc).length;
}

export function stageLayerCount(doc = document) {
  return visibleWindowCount() + openSheetCount(doc) + (isExposeOpen() ? 1 : 0);
}

// The surface's own Escape first. A surface that only answers the shell's
// ordered Escape stack (Quick Look, the window switcher) neither claims that
// key nor closes, so it gets a plain Escape.
function closeSurface(doc, node) {
  const claimed = dispatchStageBackEscape(node);
  if (!claimed && shown(node)) {
    doc.body.dispatchEvent(new doc.defaultView.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
  }
}

// Closes the top layer and reports how many remain.
export function closeTopStageLayer(doc = document) {
  const top = openStageLayers(doc).at(-1);
  if (top) {
    top.close();
    return stageLayerCount(doc);
  }
  if (isExposeOpen()) {
    closeExpose();
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
