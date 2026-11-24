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
