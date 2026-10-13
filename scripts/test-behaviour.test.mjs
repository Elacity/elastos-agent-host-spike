import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./test-behaviour.sh", import.meta.url));

function fixture(t, ci = "") {
  const root = mkdtempSync(join(tmpdir(), "behaviour-inputs-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const inputs = join(root, "inputs");
  const log = join(root, "commands.jsonl");
  const installer = `const fs = require("node:fs"), path = require("node:path");
    fs.appendFileSync(process.env.INPUTS_LOG, JSON.stringify({
      revision: __BUILD__, args: process.argv.slice(2),
      cache: process.env.PLAYWRIGHT_BROWSERS_PATH, gc: process.env.PLAYWRIGHT_SKIP_BROWSER_GC,
    }) + "\\n");
    if (process.env.FAIL_REVISION === String(__BUILD__)) process.exit(73);
    fs.mkdirSync(path.join(process.env.PLAYWRIGHT_BROWSERS_PATH, "shell-" + __BUILD__), { recursive: true });
  `;
  for (const [prefix, name, version, revision] of [
    ["browser", "playwright", "1.60.0", 1223],
    ["core", "playwright-core", "1.59.1", 1217],
  ]) {
    const packageRoot = join(inputs, prefix, "node_modules", name);
    mkdirSync(packageRoot, { recursive: true });
    writeFileSync(join(packageRoot, "package.json"), JSON.stringify({ version }));
    writeFileSync(join(packageRoot, "cli.js"), installer.replaceAll("__BUILD__", String(revision)));
    if (name === "playwright") {
      const bin = join(inputs, prefix, "node_modules", ".bin");
      mkdirSync(bin);
      writeFileSync(join(bin, "playwright"), `#!/usr/bin/env node\n${installer.replaceAll("__BUILD__", String(revision))}`, { mode: 0o755 });
    }
  }
  const env = { ...process.env, CI: ci, BEHAVIOUR_INPUTS: inputs, INPUTS_LOG: log,
    PLAYWRIGHT_BROWSERS_PATH: join(root, "cache"), PLAYWRIGHT_SKIP_BROWSER_GC: "0" };
  delete env.FAIL_REVISION;
  return { env, log, run: () => spawnSync("bash", [script, "inputs"], { env, encoding: "utf8", timeout: 10_000 }) };
}

for (const ci of ["", "true"]) {
  test(`behaviour inputs install both pinned browser builds${ci ? " in CI" : ""}`, t => {
    const { env, log, run } = fixture(t, ci);
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = run();
      assert.equal(result.status, 0, result.stderr);
      const commands = readFileSync(log, "utf8").trim().split("\n").map(JSON.parse).slice(attempt * 2);
      assert.deepEqual(commands, [
        { revision: 1223, args: ["install", "chromium", "--only-shell", ...(ci ? ["--with-deps"] : [])], cache: env.PLAYWRIGHT_BROWSERS_PATH, gc: "1" },
        { revision: 1217, args: ["install", "chromium-headless-shell"], cache: env.PLAYWRIGHT_BROWSERS_PATH, gc: "1" },
      ]);
      assert.deepEqual(readdirSync(env.PLAYWRIGHT_BROWSERS_PATH).sort(), ["shell-1217", "shell-1223"]);
    }
  });
}

test("behaviour inputs fail when the older browser build cannot install", t => {
  const { env, run } = fixture(t);
  env.FAIL_REVISION = "1217";
  assert.equal(run().status, 73);
});
