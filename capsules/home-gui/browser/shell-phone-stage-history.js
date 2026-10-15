/* One-entry history model for the phone stage; pure so node:test can drive
   it. The shell pushes one entry when its first layer opens and consumes it
   when the last layer closes, so back on the bare desktop leaves Home.

   history.state is the source of truth, not a flag: capsule frames add joint
   session entries of their own above ours and traversal is asynchronous, so
   counting pushes and pops drifts (WebKit delivered pops to the wrong step).
   Reading which entry we landed on cannot drift.

   Leaving calls back() once per close cycle and never retries: a second
   back() before the traversal lands could walk out of the host's own
   history. The leave stays in flight until its popstate lands (or, if that
   back() only popped a capsule step and no popstate reaches this document,
   until LEAVE_SETTLE_MS pass); layers opened and closed meanwhile neither push
   nor call back() again. The landing pop is our own leave, never a user's
   back: it only re-arms if a layer opened meanwhile. A leftover entry of ours
   is consumed by the next close or the user's next back — one extra back
   press, never a navigation away. */

export const STAGE_HISTORY_STATE = Object.freeze({ elastosStage: true });

// A same-document traversal lands within a frame or two; this is the bound
// after which a leave whose pop never reached us counts as landed.
export const LEAVE_SETTLE_MS = 1000;

export function isStageHistoryState(state) {
  return Boolean(state && typeof state === "object" && state.elastosStage === true);
}

/**
 * @param {object} io
 * @param {() => boolean} io.onOurEntry — is history.state ours right now
 * @param {() => number} io.layerCount — windows + open Back layers
 * @param {() => void} io.pushState — push STAGE_HISTORY_STATE
 * @param {() => void} io.back — history.back()
 * @param {() => number} io.onBack — close the top layer; returns layers left
 * @param {(fn: () => void) => void} [io.defer] — run fn after LEAVE_SETTLE_MS
 */
export function createStageHistory({
  onOurEntry,
  layerCount,
  pushState,
  back,
  onBack,
  defer = (fn) => setTimeout(fn, LEAVE_SETTLE_MS),
}) {
  let leaving = false;
  let leaveToken = 0;

  // The leave landed: re-arm for a layer that opened while it was in flight.
  const landed = () => {
    leaving = false;
    leaveToken += 1;
    if (layerCount() > 0 && !onOurEntry()) {
      pushState();
    }
  };

  const leave = () => {
    if (leaving) {
      return;
    }
    leaving = true;
    const token = ++leaveToken;
    back();
    defer(() => {
      if (leaving && token === leaveToken) {
        landed();
      }
    });
  };

  return {
    get leaving() {
      return leaving;
    },
    // Called whenever the layer count may have changed.
    sync() {
      if (leaving) {
        // The traversal is in flight; its landing re-syncs.
        return;
      }
      const layers = layerCount();
      const ours = onOurEntry();
      if (layers > 0) {
        if (!ours) {
          pushState();
        }
        return;
      }
      if (ours) {
        leave();
      }
    },
    // A history traversal landed on this document. Returns whether the shell
    // handled it as a user's back.
    handlePopState() {
      if (leaving) {
        landed();
        return false;
      }
      const layers = layerCount();
      const ours = onOurEntry();
      if (layers === 0) {
        // A leftover entry of ours surfaced with nothing open: the user is on
        // the way out.
        if (ours) {
          leave();
        }
        return false;
      }
      // Something is open and the user went back: from above our entry (a
      // capsule step was popped) or off it (we sit beneath it now).
      const remaining = onBack();
      if (remaining > 0 && !ours) {
        pushState();
      } else if (remaining === 0 && ours) {
        leave();
      }
      return true;
    },
  };
}
