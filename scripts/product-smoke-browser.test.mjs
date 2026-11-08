import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  behaviourInputsDir,
  playwrightCoreDir,
  productSmokeLaunchOptions,
} from "./product-smoke-browser.mjs";

test("behaviour cache paths follow test-behaviour.sh", () => {
  assert.equal(
    behaviourInputsDir({ HOME: "/home/tester" }),
    "/home/tester/.cache/elastos-runtime/behaviour",
  );
  assert.equal(
    behaviourInputsDir({ HOME: "/home/tester", RUNNER_TEMP: "/runner" }),
    "/runner/behaviour",
  );
  assert.equal(
    behaviourInputsDir({ BEHAVIOUR_INPUTS: "/inputs", RUNNER_TEMP: "/runner", HOME: "/home/tester" }),
    "/inputs",
  );
  assert.equal(
    playwrightCoreDir({ BEHAVIOUR_INPUTS: "/inputs" }),
    "/inputs/core/node_modules/playwright-core",
  );
  assert.equal(
    playwrightCoreDir({ BROWSER_OPERATOR_PLAYWRIGHT_CORE: "/core", BEHAVIOUR_INPUTS: "/inputs" }),
    "/core",
  );
});

test("BRAVE_BIN is the product smoke executable", () => {
  let called = false;
  const options = productSmokeLaunchOptions({ BRAVE_BIN: "/opt/brave" }, () => {
    called = true;
    return "/chromium";
  });
  assert.deepEqual(options, { executablePath: "/opt/brave" });
  assert.equal(called, false);
});

test("an empty BRAVE_BIN is not an explicit browser", () => {
  const dir = mkdtempSync(join(tmpdir(), "product-smoke-browser-"));
  const executablePath = join(dir, "chromium");
  writeFileSync(executablePath, "");
  try {
    assert.deepEqual(
      productSmokeLaunchOptions({ BRAVE_BIN: "" }, () => executablePath),
      { executablePath },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a missing Playwright Chromium leaves the executable unset", () => {
  assert.deepEqual(
    productSmokeLaunchOptions({}, () => join(tmpdir(), "missing-chromium-560")),
    {},
  );
});

test("a missing behaviour cache leaves the executable unset", () => {
  const error = new Error("Cannot find module");
  error.code = "MODULE_NOT_FOUND";
  assert.deepEqual(productSmokeLaunchOptions({}, () => { throw error; }), {});
});

test("a Playwright lookup failure other than a missing module is reported", () => {
  assert.throws(
    () => productSmokeLaunchOptions({}, () => { throw new Error("broken registry"); }),
    /broken registry/,
  );
});

test("unset BRAVE_BIN uses the installed behaviour-cache Chromium", () => {
  const env = {};
  for (const key of ["HOME", "RUNNER_TEMP", "BEHAVIOUR_INPUTS", "BROWSER_OPERATOR_PLAYWRIGHT_CORE"]) {
    if (process.env[key]) env[key] = process.env[key];
  }
  const core = playwrightCoreDir(env);
  const packageJson = join(core, "package.json");
  const options = productSmokeLaunchOptions(env);
  if (!existsSync(packageJson)) {
    assert.deepEqual(options, {});
    return;
  }
  const { chromium } = createRequire(packageJson)(core);
  const executablePath = chromium.executablePath();
  if (existsSync(executablePath)) {
    assert.deepEqual(options, { executablePath });
    assert.equal(executablePath.includes("Brave Browser.app"), false);
  } else {
    assert.deepEqual(options, {});
  }
});

test("product smokes do not default to the Brave application", () => {
  const dir = fileURLToPath(new URL(".", import.meta.url));
  const bravePath = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
  const hits = readdirSync(dir)
    .filter((name) => name.endsWith(".mjs") || name.endsWith(".sh"))
    .filter((name) => name !== "product-smoke-browser.test.mjs")
    .filter((name) => readFileSync(join(dir, name), "utf8").includes(bravePath))
    .sort();
  assert.deepEqual(hits, [
    "gba-opaque-frame-browser-smoke.sh",
    "home-browser-context-opaque-frame-smoke.sh",
    "home-gui-sign-out-opaque-frame-smoke.sh",
  ]);
});
