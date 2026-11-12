import assert from "node:assert/strict";
import test from "node:test";
import { pointerOnTopPageControl, pressTopPageControl } from "./home-top-page-press.mjs";

// A control whose page sees the pointer only from the `reachedOnMove`-th move
// on, as when the browser has not yet drawn the control over a frame.
function control(reachedOnMove) {
  const node = {
    listeners: [],
    addEventListener(type, listener) { this.listeners.push({ type, listener }); },
  };
  const calls = { moves: 0, presses: 0 };
  return {
    calls,
    toString: () => "locator('#allow')",
    evaluate: async (read) => read(node),
    async hover() {
      calls.moves += 1;
      if (calls.moves < reachedOnMove) return;
      for (const { type, listener } of node.listeners.splice(0)) if (type === "mousemove") listener();
    },
    async click() { calls.presses += 1; },
  };
}

test("the pointer is moved until Home's page reports it, then the control is pressed once", async () => {
  const late = control(3);
  await pressTopPageControl(late);
  assert.deepEqual(late.calls, { moves: 3, presses: 1 });
});

test("a control whose page never reports the pointer is not pressed, and the error names it", async () => {
  const never = control(Infinity);
  let clock = 0;
  await assert.rejects(
    pressTopPageControl(never, { label: "sent message", timeout: 3000, now: () => (clock += 1000) }),
    /^Error: sent message: the pointer did not reach this control of Home's page within 3000 ms$/,
  );
  assert.equal(never.calls.presses, 0);
  await assert.rejects(pointerOnTopPageControl(control(Infinity), { now: () => (clock += 1000) }), /locator\('#allow'\)/);
});

test("putting the pointer on a control does not press it", async () => {
  const first = control(1);
  await pointerOnTopPageControl(first);
  assert.deepEqual(first.calls, { moves: 1, presses: 0 });
});
