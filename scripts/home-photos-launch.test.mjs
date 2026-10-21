// Home asks Runtime to bind the Photos playlist only when Photos is opened as
// an app. Runtime checks the request (viewer_gateway.rs photos_launch_binding).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const host = readFileSync(new URL("../capsules/home/browser/home-shell-host.js", import.meta.url), "utf8");
const PLAYLIST = "localhost://Users/self/.AppData/App/photo-viewer/playlist.json";

function launchHomeTargetSource() {
  const start = host.search(/async function launchHomeTarget\(/);
  assert(start >= 0, "launchHomeTarget");
  return host.slice(start, host.indexOf("\n}", start) + 2);
}

async function issuedBody(target, query) {
  let issued;
  const sandbox = vm.createContext({
    window: { location: { origin: "https://home.test" } },
    launchedAppContexts: new Map(),
    fetchJson: async (url, options) => {
      assert.equal(url, "/api/apps/home/launch");
      issued = JSON.parse(options.body);
      return { target, attach_kind: "window", route: "fixture" };
    },
  });
  vm.runInContext(launchHomeTargetSource(), sandbox);
  await sandbox.launchHomeTarget(target, query);
  return issued;
}

test("Photos opened as an app asks to bind its playlist", async () => {
  const body = await issuedBody("image-viewer", {});
  assert.deepEqual(body, {
    target: "image-viewer",
    query: { home_origin: "https://home.test" },
    selected_resource: PLAYLIST,
  });
});

test("Photos opened from the Library for one image binds nothing", async () => {
  const body = await issuedBody("image-viewer", { objectUri: "localhost://Users/self/Pictures/a.png" });
  assert.equal("selected_resource" in body, false);
});

test("other targets never ask to bind a resource", async () => {
  for (const target of ["documents", "library", "photo-viewer", "image-viewer-x"]) {
    const body = await issuedBody(target, {});
    assert.equal("selected_resource" in body, false, target);
  }
});
