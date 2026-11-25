import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { bindV2App, clearV2App, paintFrame, startHomeFrame } from "./home-frame.js";

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

test("a component launch paints above the shell and an iframe launch leaves it", () => {
  const page = fs.readFileSync(new URL("./index.html", import.meta.url), "utf8");
  const host = fs.readFileSync(new URL("./home-shell-host.js", import.meta.url), "utf8");
  const css = fs.readFileSync(new URL("./style.css", import.meta.url), "utf8");
  assert.match(page, /id="home-v2-frame"/);
  assert.match(css, /\.active-shell-root\s*\{[^}]*z-index:\s*190000/);
  assert.match(css, /#home-v2-frame:not\(\[hidden\]\)\s*\{[^}]*z-index:\s*200000/);
  assert.match(css, /#home-v2-frame:not\(\[hidden\]\)\s*\{[^}]*position:\s*fixed/);
  assert.match(
    host,
    /if \(launched\?\.attach_kind === "component" && capsuleId\) showV2App\(capsuleId\);/,
  );
  assert.equal((host.match(/showV2App\(capsuleId\)/g) || []).length, 1);
});

test("the running app is the only frame requested", async () => {
  const page = fs.readFileSync(new URL("./index.html", import.meta.url), "utf8");
  const host = fs.readFileSync(new URL("./home-shell-host.js", import.meta.url), "utf8");
  assert.match(page, /id="home-v2-frame"/);
  assert.match(host, /bindV2App\(homeV2Frame/);
  assert.match(host, /clearV2App\(homeV2Frame/);
  assert.match(host, /launched\?\.capsule_id/);
  const panel = root();
  panel.dataset = {};
  const asked = [];
  bindV2App(panel, "app-a");
  const timer = startHomeFrame(
    panel,
    () => {
      const app = panel.dataset.app || "";
      asked.push(app);
      if (!app) return Promise.resolve({ nodes: [] });
      return Promise.resolve({ nodes: [{ kind: "text", text: app }] });
    },
    15,
    { deadlineMs: 200 },
  );
  try {
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.ok(asked.includes("app-a"));
    assert.ok(asked.every((id) => id === "app-a"));
    asked.length = 0;
    bindV2App(panel, "app-b");
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.ok(asked.includes("app-b"));
    assert.ok(!asked.includes("app-a"), "another app's frame was requested");
    asked.length = 0;
    clearV2App(panel);
    await new Promise((resolve) => setTimeout(resolve, 40));
    assert.equal(panel.dataset.app, undefined);
    assert.equal(panel.children.length, 0);
    assert.ok(asked.every((id) => id === ""));
    assert.ok(!asked.includes("app-b"));
  } finally {
    clearInterval(timer);
  }
});

function pageFrame(tag) {
  const children = [];
  const attrs = new Map();
  if (tag.includes("hidden")) attrs.set("hidden", "");
  return {
    id: "home-v2-frame",
    dataset: {},
    children,
    get hidden() {
      return attrs.has("hidden");
    },
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
    setAttribute(name, value) {
      attrs.set(name, String(value));
    },
    removeAttribute(name) {
      attrs.delete(name);
    },
  };
}

test("the real page shows a fixture then the next app", async () => {
  const page = fs.readFileSync(new URL("./index.html", import.meta.url), "utf8");
  const host = fs.readFileSync(new URL("./home-shell-host.js", import.meta.url), "utf8");
  const tag = page.match(/<section id="home-v2-frame"[^>]*>/);
  assert.ok(tag, "index.html has #home-v2-frame");
  const homeV2Frame = pageFrame(tag[0]);
  const showSrc = host.slice(
    host.indexOf("function showV2App("),
    host.indexOf("function retireLaunchedAppContext("),
  );
  const showV2App = new Function(
    "bindV2App",
    "clearV2App",
    "homeV2Frame",
    `let shownV2App = "";\n${showSrc}\nreturn showV2App;`,
  )(bindV2App, clearV2App, homeV2Frame);
  const callAt = host.indexOf("startHomeFrame(homeV2Frame, (signal) => {");
  const fetchLine = "encodeURIComponent(app), { signal });";
  const afterFetch = host.indexOf(fetchLine, callAt) + fetchLine.length;
  const callbackSrc = host.slice(
    callAt + "startHomeFrame(homeV2Frame, ".length,
    host.indexOf("}", afterFetch) + 1,
  );
  const asked = [];
  const frames = {
    "component-one": { nodes: [{ kind: "text", text: "fixture-one" }] },
    "component-two": { nodes: [{ kind: "text", text: "fixture-two" }] },
  };
  const fetchJson = (url) => {
    asked.push(url);
    const app = new URL(url, "http://home.invalid").searchParams.get("app");
    return Promise.resolve(frames[app] || { nodes: [] });
  };
  const readFrame = new Function("fetchJson", "homeV2Frame", `return ${callbackSrc};`)(
    fetchJson,
    homeV2Frame,
  );
  const timer = startHomeFrame(homeV2Frame, readFrame, 15, {
    deadlineMs: 200,
    hidden: () => false,
  });
  const until = async (done) => {
    const start = Date.now();
    while (!done()) {
      if (Date.now() - start > 1000) throw new Error("the frame did not update");
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  };
  try {
    showV2App("component-one");
    await until(() => homeV2Frame.children[0]?.textContent === "fixture-one");
    assert.equal(homeV2Frame.hidden, false);
    assert.ok(asked.includes("/api/apps/home/frame?app=component-one"));
    showV2App("component-two");
    await until(() => homeV2Frame.children[0]?.textContent === "fixture-two");
    assert.ok(homeV2Frame.children.every((child) => child.textContent !== "fixture-one"));
  } finally {
    clearInterval(timer);
  }
});
