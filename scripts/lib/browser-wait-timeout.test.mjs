import assert from "node:assert/strict";
import test from "node:test";
import { browserWaitTimeoutMs, CI_WAIT_TIMEOUT_MS, LOCAL_WAIT_TIMEOUT_MS } from "./browser-wait-timeout.mjs";

test("the wait timeout is 5 s locally and 15 s on a CI runner", () => {
  assert.equal(LOCAL_WAIT_TIMEOUT_MS, 5000);
  assert.equal(CI_WAIT_TIMEOUT_MS, 15000);
  assert.equal(browserWaitTimeoutMs({}), 5000);
  assert.equal(browserWaitTimeoutMs({ CI: "true" }), 15000);
  assert.equal(browserWaitTimeoutMs({ CI: "" }), 5000);
});

test("ELASTOS_BROWSER_TIMEOUT_MS names the time and outranks CI", () => {
  assert.equal(browserWaitTimeoutMs({ ELASTOS_BROWSER_TIMEOUT_MS: "20000" }), 20000);
  assert.equal(browserWaitTimeoutMs({ ELASTOS_BROWSER_TIMEOUT_MS: "20000", CI: "true" }), 20000);
  assert.equal(browserWaitTimeoutMs({ ELASTOS_BROWSER_TIMEOUT_MS: "1500.4" }), 1500);
  assert.equal(browserWaitTimeoutMs({ ELASTOS_BROWSER_TIMEOUT_MS: " ", CI: "true" }), 15000);
  for (const bad of ["0", "-1", "soon", "5000ms"]) {
    assert.throws(() => browserWaitTimeoutMs({ ELASTOS_BROWSER_TIMEOUT_MS: bad }), /ELASTOS_BROWSER_TIMEOUT_MS/, bad);
  }
});
