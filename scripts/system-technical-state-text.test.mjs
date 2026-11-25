import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../capsules/system/browser/system.js", import.meta.url), "utf8");

function functionBody(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, name);
  let depth = 0;
  let seen = false;
  for (let index = source.indexOf("{", start); index < source.length; index += 1) {
    const char = source[index];
    if (char === "{") {
      depth += 1;
      seen = true;
    } else if (char === "}") {
      depth -= 1;
      if (seen && depth === 0) {
        return source.slice(start, index + 1);
      }
    }
  }
  throw new Error(`unclosed ${name}`);
}

const context = vm.createContext({});
vm.runInContext(
  [functionBody("readText"), functionBody("humanizeName"), functionBody("technicalStateText")].join("\n"),
  context,
);

function shown(state) {
  return vm.runInContext(`technicalStateText(${JSON.stringify(state)})`, context);
}

const sentence = "Users/note.bin is not readable. Make it readable or move it out of the folder, then restart.";

test("a refusal sentence stays the System state text", () => {
  assert.equal(shown(sentence), sentence);
  assert.equal(shown(`  ${sentence}  `), sentence);
});

test("a short state name is still a label", () => {
  assert.equal(shown("running"), "Running");
});
