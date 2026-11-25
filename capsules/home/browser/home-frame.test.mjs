import assert from "node:assert/strict";
import test from "node:test";
import { paintFrame, startHomeFrame } from "./home-frame.js";

function root() {
  const children = [];
  return {
    children,
    ownerDocument: {
      createElement() {
        return { textContent: "", children: [] };
      },
    },
    replaceChildren() {
      children.length = 0;
    },
    appendChild(child) {
      children.push(child);
    },
    setAttribute() {},
    removeAttribute() {},
  };
}

test("a script-shaped text is text", () => {
  const panel = root();
  paintFrame(panel, {
    nodes: [
      { kind: "text", text: "<script>alert(1)</script>" },
      { kind: "image", resource: "localhost://photo" },
    ],
  });
  assert.equal(panel.children.length, 2);
  assert.equal(panel.children[0].textContent, "<script>alert(1)</script>");
  assert.equal(panel.children[0].children.length, 0);
  assert.equal(panel.children[1].textContent, "localhost://photo");
  paintFrame(panel, { nodes: [] });
  assert.equal(panel.children.length, 0);
});

test("a slow read does not overlap the next poll", async () => {
  const panel = root();
  let open = 0;
  let peak = 0;
  const timer = startHomeFrame(
    panel,
    () =>
      new Promise((resolve) => {
        open += 1;
        peak = Math.max(peak, open);
        setTimeout(() => {
          open -= 1;
          resolve({ nodes: [] });
        }, 60);
      }),
    20,
  );
  await new Promise((resolve) => setTimeout(resolve, 90));
  clearInterval(timer);
  assert.equal(peak, 1);
});

test("a hidden page does not poll", async () => {
  let calls = 0;
  const timer = startHomeFrame(
    root(),
    async () => {
      calls += 1;
      return { nodes: [] };
    },
    20,
    { hidden: () => true },
  );
  await new Promise((resolve) => setTimeout(resolve, 70));
  clearInterval(timer);
  assert.equal(calls, 0);
});

test("two failed polls clear the panel and the first failure keeps it", async () => {
  const panel = root();
  let calls = 0;
  const timer = startHomeFrame(
    panel,
    () => {
      calls += 1;
      if (calls === 1) {
        return Promise.resolve({ nodes: [{ kind: "text", text: "live" }] });
      }
      return Promise.reject(new Error("down"));
    },
    20,
    { deadlineMs: 200 },
  );
  const until = async (done) => {
    const start = Date.now();
    while (!done()) {
      if (Date.now() - start > 1000) throw new Error("the poll did not arrive");
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  };
  try {
    await until(() => calls >= 1 && panel.children[0] && panel.children[0].textContent === "live");
    await until(() => calls >= 2);
    assert.equal(panel.children[0].textContent, "live");
    await until(() => panel.children.length === 0);
    assert.ok(calls >= 3);
  } finally {
    clearInterval(timer);
  }
});

test("a deadline aborts the fetch", async () => {
  const panel = root();
  let signal;
  const timer = startHomeFrame(
    panel,
    (abort) => {
      signal = abort;
      return new Promise((_, reject) => {
        if (abort) abort.addEventListener("abort", () => reject(new Error("aborted")));
      });
    },
    1000,
    { deadlineMs: 30 },
  );
  try {
    await new Promise((resolve) => setTimeout(resolve, 80));
    assert.equal(signal.aborted, true);
  } finally {
    clearInterval(timer);
  }
});
