import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../capsules/system/browser/system.js", import.meta.url), "utf8");
const controller = source.slice(
  source.indexOf("const RECOVERY_ROOT_CHECKED_SENTENCE"),
  source.indexOf("async function onRecoveryDownload("),
);

function render(status) {
  const shown = {};
  const context = vm.createContext({
    recoveryProfileStatus: "ready",
    recoveryProfileRequired: false,
    readText: value => typeof value === "string" ? value.trim() : "",
    showRecoveryStatus: (text, tone) => { shown.status = text; shown.statusTone = tone; },
    showRecoveryNote: (text, tone) => { shown.note = text; shown.noteTone = tone; },
    setRecoveryButton: (label, disabled) => { shown.button = label; shown.disabled = disabled; },
  });
  vm.runInContext(`${controller}\nsetRecoveryStatus(${JSON.stringify(status)});`, context);
  return shown;
}

const ready = { recovery_configured: true, recovery_download_available: true, protection_configured: true, required_actions: [] };
const checked = "No unencrypted file was found in your protected Home folders, and each file there is labelled for this Home's current key. Each file's contents are checked when you open it.";

test("an encrypted root states what start checked, and nothing more", () => {
  const shown = render({ ...ready, root_encrypted: true });
  assert.equal(shown.status, "");
  assert.ok(shown.note.startsWith(`${checked} Saves your Profile`), shown.note);
  assert.doesNotMatch(shown.note, /verified|authenticated|intact/);
  assert.equal(shown.button, "Download Recovery Kit");
  assert.ok(!render({ ...ready, root_encrypted: false }).note.includes(checked));
});

test("damaged files are named once with their action", () => {
  const action = "Documents/a.bin does not carry the label this Home writes on encrypted files.";
  const shown = render({
    ...ready,
    root_encrypted: true,
    objects_needing_attention: [{ path: "Documents/a.bin", problem: "label_unreadable", action }],
    objects_needing_attention_count: 3,
  });
  assert.equal(shown.status, "Needs attention");
  assert.equal(shown.note, `3 file(s) in your protected Home folders need attention: ${action} And 2 more.`);
  assert.equal(shown.button, "Download Recovery Kit");
  const one = render({
    ...ready,
    objects_needing_attention: [{ path: "Documents/a.bin", problem: "label_unreadable", action }],
    objects_needing_attention_count: 1,
  });
  assert.equal(one.note, `1 file(s) in your protected Home folders need attention: ${action}`);
});

test("a pending encryption step is explained", () => {
  const shown = render({ ...ready, root_encrypted: false, required_actions: ["finish_interrupted_principal_root_migration"] });
  assert.equal(shown.status, "Needs attention");
  assert.equal(shown.note, "An earlier encryption step did not finish. Home will not start again until it is finished or undone; reinstalling ElastOS does that, and your files are kept.");
});

test("plaintext that arrived while Home runs is explained", () => {
  const encrypts = "Saving your Recovery Kit encrypts files of up to 16 MiB after you approve with your passkey; a larger file is named so you can move it out of your protected folders (Library takes uploads up to 100 MiB).";
  const shown = render({ ...ready, root_encrypted: false, required_actions: ["migrate_declared_plaintext_objects"] });
  assert.equal(shown.status, "Needs attention");
  assert.equal(shown.note, `Some files in your protected Home folders are not encrypted yet; until they are, Home will not start again. ${encrypts}`);
  assert.equal(shown.button, "Download Recovery Kit");
  // An unprotected root reports the same action; the start sentence is for protected roots only.
  const unprotected = render({ required_actions: ["migrate_declared_plaintext_objects"], protection_configured: false });
  assert.equal(unprotected.note, `Some files in your protected Home folders are not encrypted yet. ${encrypts}`);
});

const STAY = "Agents and their data stay on the Home where you created them; this bundle does not carry them.";
const recoverySource = source.slice(
  source.indexOf("const AGENTS_STAY_ON_THIS_HOME"),
  source.indexOf("function recoveryImportIsComplete"),
);
const pendingSource = source.slice(
  source.indexOf("function showRecoveryPending"),
  source.indexOf("function showWalletRestorePending"),
);

function recoveryPage(agentsBuilt) {
  const shown = {};
  const pending = { hidden: true, textContent: "" };
  const note = { hidden: true, textContent: "", dataset: {} };
  const button = { textContent: "", disabled: false };
  const context = vm.createContext({
    readText: (value) => (typeof value === "string" ? value.trim() : ""),
    shortText: (value) => (typeof value === "string" ? value.trim() : ""),
    recoveryPendingNode: pending,
    recoveryPendingTextNode: pending,
    recoveryNoteNode: note,
    recoveryAttachButton: button,
    hasShellAccess: () => true,
    showRecoveryNote: (text) => {
      note.textContent = text;
    },
    fetchJson: () => Promise.resolve({ agents: [] }),
    shellHeaders: () => ({}),
  });
  vm.runInContext(`${recoverySource}\n${pendingSource}`, context);
  return {
    pendingText: (plan) => {
      context.showRecoveryPending(plan, agentsBuilt);
      return pending.textContent;
    },
    success: (response) => context.recoveryImportSuccessMessage(response, agentsBuilt),
    refusal: (error) => context.recoveryRefusal(error),
    builds: (fetchJson) => {
      context.fetchJson = fetchJson;
      return context.runtimeBuildsAgents();
    },
  };
}

test("recovery text says agents stay on the Home where they were created", async () => {
  const on = recoveryPage(true);
  const off = recoveryPage(false);
  const plan = { kitRoot: "localhost://Users/ab" };
  assert.equal(on.pendingText(plan).endsWith(STAY), true);
  assert.equal(off.pendingText(plan).includes(STAY), false);
  assert.equal(on.success({}).endsWith(STAY), true);
  assert.equal(off.success({}), "Recovery Kit imported.");
  const sentence = "1 agent on this Home would stop opening. Retire that agent first, or import on another Home.";
  assert.equal(on.refusal({ message: `request failed: 409 ${sentence}` }), sentence);
  const orphan = "1 agent on this Home would belong to nobody. This recovery changes the owner id its record names.";
  assert.equal(on.refusal({ message: `request failed: 409 ${orphan}` }), orphan);
  const orphans = "2 agents on this Home would belong to nobody. This recovery changes the owner id their records name.";
  assert.equal(on.refusal({ message: `request failed: 409 ${orphans}` }), orphans);
  assert.equal(await on.builds(() => Promise.resolve({ agents: [] })), true);
  assert.equal(
    await off.builds(() => Promise.reject(new Error("request failed: 409 agents are not built into this Runtime"))),
    false,
  );
  const rust = readFileSync(new URL("../elastos/crates/elastos-server/src/api/auth_gateway.rs", import.meta.url), "utf8");
  assert.equal(rust.includes(`const AGENTS_STAY_ON_THIS_HOME: &str = "${STAY}";`), true);
});

test("the agents sentence is shown only for a confirmed agents answer", async () => {
  const page = recoveryPage(false);
  const plan = { kitRoot: "localhost://Users/ab" };
  const failures = [
    () => Promise.reject(new Error("request failed: 409 agents are not built into this Runtime")),
    () => Promise.reject(new Error("request failed: 401")),
    () => Promise.reject(new Error("network")),
    () => Promise.resolve({}),
    () => Promise.resolve(null),
  ];
  for (const failure of failures) {
    assert.equal(await page.builds(failure), false);
  }
  assert.equal(page.pendingText(plan).includes(STAY), false);
  assert.equal(page.success({}).includes(STAY), false);
  const confirmed = recoveryPage(true);
  assert.equal(await confirmed.builds(() => Promise.resolve({ agents: [] })), true);
  assert.equal(confirmed.pendingText(plan).endsWith(STAY), true);
  assert.equal(confirmed.success({}).endsWith(STAY), true);
});

test("a Home whose Profile needs backup still sees files needing attention", () => {
  const action = "Documents/a.bin does not carry the label this Home writes on encrypted files.";
  const shown = render({
    ...ready,
    required_actions: ["download_recovery_kit_with_profile"],
    objects_needing_attention: [{ path: "Documents/a.bin", problem: "label_unreadable", action }],
    objects_needing_attention_count: 1,
  });
  assert.equal(shown.status, "Profile needs backup");
  assert.equal(shown.note, `Save a new kit that includes your Profile. 1 file(s) in your protected Home folders need attention: ${action}`);
  assert.equal(shown.button, "Save complete Recovery Kit");
  assert.equal(render({ ...ready, required_actions: ["download_recovery_kit_with_profile"] }).note, "Save a new kit that includes your Profile.");
});
