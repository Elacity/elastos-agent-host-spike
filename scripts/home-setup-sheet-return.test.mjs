import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const setup = read("capsules/home-gui/browser/shell-setup-sheet.js");
function functionSource(source, name) {
  const start = source.search(new RegExp(`(?:export )?(?:async )?function ${name}\\(`));
  assert(start >= 0, name);
  return source.slice(start, source.indexOf("\n}", start) + 2).replace(/^export /, "");
}

function fixture() {
  const classes = new Set();
  const sheet = { hidden: false, inert: false, setAttribute() {},
    classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c), contains: (c) => classes.has(c) } };
  const summary = { authority: { signed_in: true }, identity: {
    profile_readiness: { schema: "elastos.profile.readiness/v1", status: "ready" },
    recovery_readiness: { schema: "elastos.recovery.readiness/v1", status: "setup_required" },
  } };
  const f = { classes, sheet, summary, opened: [], saveResult: true };
  f.context = vm.createContext({
    PROFILE_READINESS_SCHEMA: "elastos.profile.readiness/v1",
    RECOVERY_READINESS_SCHEMA: "elastos.recovery.readiness/v1",
    SETUP_REMINDER_ID: "setup",
    shellState: { currentSummary: summary, shellLayoutState: {} },
    sheet, card: null, recoveryBody: { textContent: "" }, recoveryButton: { disabled: false, focus() { f.focused = "recovery"; } },
    closeButton: { focus() { f.focused = "close"; } },
    recoveryActBusy: false, waitingForSystemClose: false, dismissedThisSession: false, drag: null,
    targetById: () => ({ id: "system" }), setTimeout, queueMicrotask,
    renderSetupSheet() { f.context.recoveryButton.disabled = f.context.setupFinished(summary); }, forgetChromeNotification() {}, rememberChromeNotification() {}, showSetupSheet() {},
    openTarget: (id, options) => f.opened.push([id, options]),
    openSystemRecoverySave: async () => {
      assert(classes.has("is-yielded"), "System is in front while it saves");
      if (f.saveResult) summary.identity.recovery_readiness.status = "ready";
      return f.saveResult;
    },
  });
  vm.runInContext(["typedReadinessStatus", "homeSetupStatus", "homeRecoveryStatus", "setupFinished",
    "homeSetupNeedsAct", "setupSheetOpen", "yieldSetupSheet", "restoreSetupSheetOverlay", "openRecoveryAct",
    "syncSetupSheet", "setupSheetWindowClosed", "returnSetupSheet", "hideSetupSheet", "rememberSetupReminder"]
    .map((name) => functionSource(setup, name)).join("\n"), f.context);
  f.shown = () => !sheet.hidden && !classes.has("is-yielded");
  return f;
}

test("Save Recovery Kit brings the onboarding sheet back, done or for Retry", async () => {
  const f = fixture();
  f.saveResult = false;
  await f.context.openRecoveryAct();
  assert(f.shown(), "failed save brings the sheet back for Retry");
  assert.match(f.context.recoveryBody.textContent, /not saved/);
  assert.equal(f.focused, "recovery", "Retry has keyboard focus");
  f.saveResult = true;
  await f.context.openRecoveryAct();
  assert(f.shown(), "saved kit brings the sheet back");
  assert.equal(f.focused, "close", "focus leaves System for the enabled sheet control");
  f.context.syncSetupSheet(null, f.summary);
  await new Promise((resolve) => setTimeout(resolve, 1500));
  assert(f.shown(), "step 1 done keeps the sheet open with the next steps");
});

test("Closing System after the settings step brings the onboarding sheet back", async () => {
  const f = fixture();
  f.summary.identity.profile_readiness.status = "setup_required";
  await f.context.openRecoveryAct();
  assert.deepEqual(JSON.parse(JSON.stringify(f.opened)), [["system", { query: { settings: "security" } }]]);
  assert(f.classes.has("is-yielded"), "System settings is in front");
  f.focused = "system";
  f.context.setupSheetWindowClosed("wallet");
  await null;
  assert(f.classes.has("is-yielded"), "another window closing leaves System in front");
  f.context.setupSheetWindowClosed("system");
  f.focused = "next window";
  await null;
  assert(f.shown(), "closing System brings the sheet back");
  assert.equal(f.focused, "recovery", "the returned sheet holds keyboard focus");
  assert(read("capsules/home-gui/browser/home-gui.js").includes("windowClosed: setupSheetWindowClosed,"));
  assert(read("capsules/home-gui/browser/shell-windows.js").includes("windowHooks?.windowClosed?.(entry.targetId);"));
});
