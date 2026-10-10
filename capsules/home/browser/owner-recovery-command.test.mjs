import assert from "node:assert/strict";
import test from "node:test";

import { ownerRecoveryCommand } from "./owner-recovery-command.js";

test("recovery command names this page's origin and rp id", () => {
  const url = new URL("http://localhost:8090/home/");
  assert.equal(
    ownerRecoveryCommand(url),
    "elastos identity arm-owner-recovery --origin http://localhost:8090 --rp-id localhost",
  );
  assert.equal(
    ownerRecoveryCommand(new URL("https://home.example:8443/")),
    "elastos identity arm-owner-recovery --origin https://home.example:8443 --rp-id home.example",
  );
});
