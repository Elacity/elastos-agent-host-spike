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
  const onHome = "1 agent on this Home would stop opening. Retire that agent on this Home, or import on another Home.";
  const otherRuntime = "1 agent on this Home would stop opening. Retire that agent in a Runtime that includes agents, or import on another Home.";
  assert.equal(on.refusal({ message: `request failed: 409 ${onHome}` }), onHome);
  assert.equal(on.refusal({ message: `request failed: 409 ${otherRuntime}` }), otherRuntime);
  const orphan = "1 agent on this Home would belong to nobody. This recovery changes the owner id its record names.";
  assert.equal(on.refusal({ message: `request failed: 409 ${orphan}` }), orphan);
  const orphans = "2 agents on this Home would belong to nobody. This recovery changes the owner id their records name.";
  assert.equal(on.refusal({ message: `request failed: 409 ${orphans}` }), orphans);
  const unreadable = "This Home has an agents file this build cannot read, so a root-key change is refused.";
  assert.equal(on.refusal({ message: `request failed: 409 ${unreadable}` }), unreadable);
  const wrap = "This Home cannot open the key that wraps an agent's data, so a root-key change is refused.";
  assert.equal(on.refusal({ message: `request failed: 409 ${wrap}` }), wrap);
  const rust = readFileSync(new URL("../elastos/crates/elastos-server/src/api/auth_gateway.rs", import.meta.url), "utf8");
  assert.equal(rust.includes(`const AGENTS_STAY_ON_THIS_HOME: &str = "${STAY}";`), true);
});

test("the agents sentence is shown only for a confirmed agents answer", async () => {
  const plan = { kitRoot: "localhost://Users/ab" };
  assert.equal(recoveryPage(false).pendingText(plan).includes(STAY), false);
  assert.equal(recoveryPage(false).success({}).includes(STAY), false);
  assert.equal(recoveryPage(true).pendingText(plan).endsWith(STAY), true);
  assert.equal(recoveryPage(true).success({}).endsWith(STAY), true);
  for (const fetchJson of [
    async () => {
      throw new Error("request failed: 409 agents are not built into this Runtime");
    },
    async () => {
      throw new Error("network");
    },
    async () => ({}),
    async () => null,
  ]) {
    const hidden = recoveryFlow({ fetchJson });
    await hidden.context.submitRecoveryImport({
      schema: "elastos.full-recovery-bundle.import.request/v1",
    });
    assert.equal(hidden.note.textContent.includes(STAY), false);
  }
  const shown = recoveryFlow({ agentsBuilt: true });
  await shown.context.submitRecoveryImport({
    schema: "elastos.full-recovery-bundle.import.request/v1",
  });
  assert.equal(shown.note.textContent.endsWith(STAY), true);
});

const flowSource = source.slice(
  source.indexOf("async function onRecoveryImport("),
  source.indexOf("async function refreshChainNetworks("),
);
const FEATURE_OFF = "request failed: 409 agents are not built into this Runtime";

function recoveryFlow(options = {}) {
  const calls = [];
  const pending = { hidden: true, textContent: "" };
  const note = { hidden: true, textContent: "", dataset: {} };
  const statusNode = {
    hidden: true,
    textContent: "",
    dataset: {},
    classList: { toggle() {} },
  };
  const button = { textContent: "", disabled: false };
  const agentsError = options.agentsError || FEATURE_OFF;
  const context = vm.createContext({
    hasShellAccess: () => true,
    fetchJson: async (url) => {
      calls.push(String(url));
      if (String(url).includes("/api/apps/system/agents")) {
        throw new Error(agentsError);
      }
      if (String(url).includes("/api/auth/recovery/status")) {
        if (options.fetchJson) {
          return options.fetchJson(url);
        }
        return {
          principal_id: "person:current",
          localhost_root: "localhost://Users/current",
          agents_built: options.agentsBuilt === true,
        };
      }
      if (String(url).includes("/api/auth/recovery/full-import")) {
        return {
          schema: "elastos.full-recovery-bundle.import.response/v2",
          status: "imported",
          wallet_restore: { status: "complete", imported_count: 0 },
          runtime_audit: { status: "complete" },
        };
      }
      throw new Error(`unexpected ${url}`);
    },
    shellHeaders: () => ({}),
    readText: (value) => (typeof value === "string" ? value.trim() : ""),
    shortText: (value) => (typeof value === "string" ? value.trim() : ""),
    publicSystemError: (value) => String((value && value.message) || value || ""),
    pendingRecoveryImport: null,
    recoveryImportInput: { value: "" },
    recoveryPasswordInput: { value: "" },
    recoveryPendingNode: pending,
    recoveryPendingTextNode: pending,
    recoveryNoteNode: note,
    recoveryStatusNode: statusNode,
    recoveryAttachButton: button,
    recoveryDownloadButton: null,
    recoveryExportBusy: false,
    setRecoveryStatus: () => {},
    focusRequestedSettingsAction: () => {},
    refreshSystemSummary: async () => {},
    refreshAccountList: async () => {},
    notifyHomeSummaryChanged: () => {},
  });
  const refreshSource = source.slice(
    source.indexOf("async function refreshRecoveryStatus("),
    source.indexOf("const RECOVERY_ROOT_CHECKED_SENTENCE"),
  );
  vm.runInContext(`${refreshSource}\n${flowSource}`, context);
  return { context, calls, pending, note };
}

function kitFile(principalId, root) {
  return {
    text: async () => JSON.stringify({
      schema: "elastos.full-recovery-bundle/v1",
      principal_id: principalId,
      localhost_root: root,
    }),
  };
}

test("onRecoveryImport reads agents_built and does not decide from a 409", async () => {
  const hidden = recoveryFlow();
  await hidden.context.onRecoveryImport({
    target: { files: [kitFile("person:other", "localhost://Users/other")] },
  });
  assert.equal(hidden.calls.includes("/api/apps/system/agents"), false);
  assert.equal(hidden.pending.textContent.includes(STAY), false);
  assert.equal(hidden.pending.textContent.includes("another Home account"), true);

  const shown = recoveryFlow({
    agentsBuilt: true,
    agentsError: "request failed: 409 agents are not turned on for this Home",
  });
  await shown.context.onRecoveryImport({
    target: { files: [kitFile("person:other", "localhost://Users/other")] },
  });
  assert.equal(shown.calls.includes("/api/apps/system/agents"), false);
  assert.equal(shown.calls.filter((url) => String(url).includes("/api/auth/recovery/status")).length, 1);
  assert.equal(shown.pending.textContent.includes(STAY), true);
});

test("submitRecoveryImport reads agents_built and does not decide from a 403", async () => {
  const hidden = recoveryFlow();
  await hidden.context.submitRecoveryImport({
    schema: "elastos.full-recovery-bundle.import.request/v1",
  });
  assert.equal(hidden.calls.includes("/api/apps/system/agents"), false);
  assert.equal(hidden.note.textContent.includes(STAY), false);
  assert.equal(hidden.note.textContent, "Recovery Kit imported.");

  const shown = recoveryFlow({
    agentsBuilt: true,
    agentsError: "request failed: 403 admin passkey required",
  });
  await shown.context.submitRecoveryImport({
    schema: "elastos.full-recovery-bundle.import.request/v1",
  });
  assert.equal(shown.calls.includes("/api/apps/system/agents"), false);
  assert.equal(shown.calls.filter((url) => String(url).includes("/api/auth/recovery/status")).length, 1);
  assert.equal(shown.note.textContent.endsWith(STAY), true);
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
