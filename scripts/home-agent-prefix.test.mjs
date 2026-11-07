import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { measurePrefixHit, packStablePrefix } from "../capsules/assistant/browser/agent-context.js";

const head = "You are the ElastOS agent host.";

test("the head stays put when a note changes", () => {
  const first = packStablePrefix({
    head,
    notes: ["prefer short answers"],
    excerpts: ["the page says demo"],
  });
  const second = packStablePrefix({
    head,
    notes: ["prefer long answers"],
    excerpts: ["the page says next"],
  });
  assert.equal(first[0].role, "system");
  assert.equal(first[0].content, head);
  assert.equal(second[0].content, first[0].content);
  assert.deepEqual(
    first.map((message) => message.role),
    ["system", "user", "user"],
  );
  assert.equal(first[1].content, "prefer short answers");
  assert.equal(first[2].content, "the page says demo");
  assert.equal(second[1].content, "prefer long answers");
  assert.notEqual(second[1].content, first[1].content);
  assert.equal(measurePrefixHit(first, second), Buffer.byteLength(head));
  const moved = packStablePrefix({
    head: "A different head.",
    notes: ["prefer short answers"],
    excerpts: ["the page says demo"],
  });
  assert.equal(measurePrefixHit(first, moved), 0);
});

test("the prompt cache stays off", () => {
  const source = readFileSync(
    new URL("../capsules/model-provider/src/local_llama.rs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /Admission covers the live context only, without cached prompts\.\n\s*"--cache-ram"\.into\(\),\n\s*"0"\.into\(\),/,
  );
});
