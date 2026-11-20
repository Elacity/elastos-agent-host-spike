// A press on a control of Home's top page that is drawn over a capsule frame.
//
// Home's top page and the frames under it run in different processes, and the
// browser sends a pointer event to the page it last drew at that spot. Until
// it has drawn a prompt, sheet or bar that Home has just shown, a press on it
// goes to the frame underneath and Home never hears of it; the driver still
// reports the press as done. A pointer move goes the same way as a press, so
// the pointer is put on the control until Home's own page reports a move
// there. From then on a press at that spot reaches Home.
//
// Only the move is repeated, never the press, and nothing here sleeps.

export const POINTER_REACH_TIMEOUT_MS = 3000;

// Puts the pointer on `control`, a locator in Home's top page, and returns
// once that page has seen the pointer move on it.
export async function pointerOnTopPageControl(control, {
  label = String(control),
  timeout = POINTER_REACH_TIMEOUT_MS,
  now = Date.now,
} = {}) {
  await control.evaluate((node) => {
    node.__pointerReached = false;
    node.addEventListener("mousemove", () => { node.__pointerReached = true; }, { once: true });
  });
  const deadline = now() + timeout;
  do {
    if (now() > deadline) {
      throw new Error(`${label}: the pointer did not reach this control of Home's page within ${timeout} ms`);
    }
    await control.hover({ timeout });
  } while (!(await control.evaluate((node) => node.__pointerReached === true)));
}

// The same, then one press.
export async function pressTopPageControl(control, options = {}) {
  await pointerOnTopPageControl(control, options);
  await control.click();
}
