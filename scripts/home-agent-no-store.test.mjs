import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";

// While third-party admission is closed (#217), Assistant is not a store.
// It may ask Home to open Marketplace. It does not buy, install, or publish.
const assistant = new URL("../capsules/assistant/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("capsule.json", assistant), "utf8"));
const browser = new URL("browser/", assistant);
const sources = readdirSync(browser)
  .filter((name) => name.endsWith(".js"))
  .map((name) => readFileSync(new URL(name, browser), "utf8"));

test("the Assistant manifest grants no store operation", () => {
  assert.equal(manifest.role, "app");
  for (const key of ["capabilities", "providers", "permissions", "provides"]) {
    assert.equal(manifest[key], undefined, key);
  }
  assert.deepEqual(
    manifest.interfaces.map((entry) => entry.id),
    ["elastos.assistant.model"],
  );
  assert.deepEqual(
    manifest.interfaces[0].methods.map((method) => method.id),
    ["offers.list", "run.create", "run.get", "run.events", "run.cancel", "content.retention", "content.reclaim"],
  );
});

test("the Assistant page only asks Home to open Marketplace", () => {
  const routes = new Set();
  const invokes = new Set();
  const messages = new Set();
  for (const text of sources) {
    for (const match of text.matchAll(/\/api\/[a-z0-9_/-]+/g)) routes.add(match[0]);
    for (const match of text.matchAll(/interface: "([^"]+)", method: "([^"]+)"/g)) {
      invokes.add(`${match[1]} ${match[2]}`);
    }
    for (const match of text.matchAll(/postMessage\(\{ type: "([^"]+)"/g)) messages.add(match[1]);
  }
  for (const route of routes) {
    assert.match(
      route,
      /^\/api\/(provider\/model\/[a-z_]*|capsules\/catalog|capsules\/interfaces\/invoke|apps\/(assistant|home-agent)\/[a-z0-9-]+)$/,
      route,
    );
  }
  assert.deepEqual([...invokes], ["elastos.assistant.model content.retention"]);
  assert.deepEqual([...messages].sort(), ["home:app-ready", "home:open-target"]);
});
