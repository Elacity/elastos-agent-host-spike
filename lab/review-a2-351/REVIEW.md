# Independent adversarial review of draft PR #351

```text
PR:        #351 A2 e2e resume after a real Runtime process restart
Head:      a97a6373181f526af2eba17fe95d2898201ab63d
Base:      cursor/a2-journal-load-b1e8 (#341)
Reviewer:  Cursor Grok (GPT-family)
Date:      26 Oct 2026
Machine:   Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Guest:     sha256:b234ac47ca4f52de27b17ff999ec2af6b9694135e53bf059e49c16897df058e4
           (one rebuild this session; same as the PR claim)
Verdict:   A2 cannot be counted
```

Do not merge #351. This folder is the review only. #351 files were not edited.

Rule used: a complete journey, refusal evidence, and the required reviews. A skip is not a pass. Every claim needs a falsifier.

Raw plants: `experiments.py` and `experiments.log`.

## Claims

| # | Claim | Verdict |
| --- | --- | --- |
| 1 | Driver uses the same component resource bridge as the guest. The two new public hooks are test-only, do not widen product API or authority, and cannot mask a real failure. | **FALSIFIED** |
| 2 | The two processes are genuinely separate (separate PIDs, no shared in-memory state). The store persists on disk. | **HOLDS** |
| 3 | Every row PASS is derived from real output. A hardcoded PASS and a skipped step fail. | **FALSIFIED** |
| 4 | Extra falsifiers: second-process stale write; older journal; store wipe; guest hash change. | **WEAK** |
| 5 | The +8760-line PR has no vendored or generated bulk that should stay out of git. | **WEAK** |
| — | A2 can be counted under complete journey + refusal evidence + required reviews. | **No** |

## 1. Bridge and the two public hooks — FALSIFIED

The guest path is real for WRITE and RESUME.

`Runtime::set_provider_registry` installs a hostcall that calls `handle_component_resource_request`. The first and second processes launch the guest with `run_local_with_principal`. The guest `run()` asks for journal grants and calls `open_task_journal`. That is the same function the ignored e2e uses.

STALE and WRITE2 do not go through the guest. They call the new public `handle_component_resource_request` with a token the driver mints itself (`capability_manager.grant`). The guest after resume never writes. WRITE2 therefore cannot fail if the guest cannot write after a load. That masks a real resume-write failure.

The driver's `BridgeContext` also builds a new empty `ProviderRegistry`. For this journal the write still hits `protected_principal_root_resource_response` before `send_raw`, so the empty registry does not change the bytes. The shortcut is the skipped guest, not a second store.

### `handle_component_resource_request`

Was `pub(crate)`. Now `pub`. No new HTTP or CLI route. Product launch still goes through `set_provider_registry`. Any crate that depends on `elastos-server` can now invoke the bridge with a constructed `BridgeContext` and a minted token. That is a crate-API widen, not a Home HTTP widen.

### `store_test_principal_root_protection`

This is not test-only.

Was `#[cfg(test)] pub(crate)`. Now `pub`, compiled into the product library. It writes principal-root protection using a fixed recovery phrase already used by server tests. Product Home still creates protection through init and recovery. The function is now a public helper on the shipping crate. That is a library authority surface, not an HTTP grant.

The first process creates this protection if it is missing. A missing real Home init still lets WRITE pass. The second process refuses if protection is absent. That part is honest.

Security finding, details for Sasha: a public helper on `elastos-server` can write principal-root protection with a known test recovery phrase. No HTTP path was added. No exploit steps here.

## 2. Two processes and the on-disk store — HOLDS

This session:

```text
PROCESS first pid=13387   exit 0
PROCESS second pid=13397  exit 0
same_printed_pid=False
```

The harness runs two `subprocess.run` calls. The first process is gone before the second starts. Each process builds its own `Runtime`, `CapabilityManager`, and `PendingRequestStore`. Grants do not persist. That is a real process restart.

The journal is on disk after the first process exits:

```text
lab/review-a2-351/scratch/two-proc/runtime-data/Users/79613eeee49541fb21e31909/.AppData/Agents/agent-host/tasks/demo/journal
```

`read_journal` compares the bridge read with `read_principal_root_object` on that path. The sidecar `a2-resume-state.json` holds revision, sha256, and `first_pid`. This lab does not start `elastos serve`. The PR already says that.

START is only the banner `PROCESS second`. That line is printed before `setup`. A wiped store still prints it. See claim 4.

## 3. PASS derivation — FALSIFIED

WRITE, STALE, RESUME, and WRITE2 are taken from driver `ROW` lines. The harness does not re-read the journal. If the driver prints `ROW WRITE PASS` with no store, WRITE is PASS.

Plants this session:

| Plant | Result | Meaning |
| --- | --- | --- |
| `Proof.row` six hardcoded PASSes | **MISSED** | `A2_counted=True` with no driver and no store |
| Driver prints WRITE/STALE PASS and returns | **MISSED** | WRITE=PASS, no journal on disk |
| Skip `stale_write` (no STALE row) | **CAUGHT** | STALE=NOT RUN, later rows not started |
| NOT RUN then PASS | **CAUGHT** | `Proof.row` refuses the upgrade |
| First process exits 1 after WRITE+STALE | **MISSED** | STOP=PASS because the check is `returncode is not None` |

`subprocess.run` always sets `returncode`. STOP is therefore PASS whenever WRITE is PASS, including exit 1. The evidence line can say "exited 0" while the rule does not require 0.

A skipped step fails. A hardcoded PASS does not.

The three PR plants (F-A2-CREATE-ONLY, F-A2-SKIP-LOAD, F-A2-REVISION) look like real unique edits. This session did not re-run them. They rebuild the guest or the driver and edit #351 files. The review plants above are enough to refuse the "every PASS is real output" claim.

## 4. Extra falsifiers — WEAK

These were not in #351. They were planted here against the published driver and harness.

| Id | Plant | Lab result | Notes |
| --- | --- | --- | --- |
| F-REV-SECOND-STALE-WRITE | Second process writes with `if_revision=stale-not-current` | **CAUGHT** | WRITE2 FAIL. The check exists. #351 does not run it. |
| F-REV-OLDER-JOURNAL | State names a different journal than the store | **CAUGHT** | RESUME FAIL. The check exists. #351 does not run it. |
| F-REV-STORE-WIPE | Store removed between processes | **CAUGHT** for RESUME/WRITE2 | Second process prints `PROCESS second`, then `DRIVER_ERROR`. Harness would still mark START PASS. |
| F-REV-GUEST-HASH | Last byte of the guest wasm flipped | **MISSED** | Harness logs the hash and never compares it. Mutated guest still WRITE PASS, STALE PASS, exit 0. Guest restored to `b234ac47…`. |

Refusal evidence for a stale write exists on the first process only, and that write is the driver hook, not the guest. A second-process stale write would fail WRITE2 if someone planted it. The published runner does not plant it. A guest-hash change is not a row and does not fail the journey.

## 5. The +8760-line diff — WEAK

```text
15 files, +8760 / -3
lab/a2-e2e-resume/Cargo.lock  7558 lines, 181 KiB
```

The lockfile is generated. Other labs also commit `Cargo.lock`. This one is large because the crate depends on `elastos-server`. It is not vendored source, not a wasm, and not a secret. It is most of the advertised size.

`evidence.txt` is 46 lines of proof log. That is small and fine. `*.component.wasm` is gitignored. No large binary is in the commit.

## Final verdict

**A2 cannot be counted.**

The complete journey is not the guest journey. WRITE and RESUME go through the guest and the real hostcall. STALE and WRITE2 go through the new public hook with a driver-minted token. A guest that loads and then cannot write would still WRITE2 PASS.

Refusal evidence is incomplete. A first-process stale write through the hook is checked. A second-process stale write, a wiped store, an older journal, and a guest-hash change are not in the published falsifier list. The first three would fail later rows if planted. The hash change would not.

PASS is not always real output. The harness believes a `ROW … PASS` line. STOP PASSes on any finished process. START PASSes on a banner printed before the store is opened. A hardcoded six-row PASS counts A2.

The required review does not pass. `store_test_principal_root_protection` is no longer `#[cfg(test)]`. It is a public product-crate helper.

What still holds: two OS processes, a journal file on disk, guest WRITE/RESUME on the same hostcall, a skipped STALE row becomes NOT RUN, this machine's guest hash matches the PR.

## What is next

Keep #351 draft. Do not count A2. Do not merge.

Before A2 can be counted:

1. WRITE2 (and STALE if it is part of the guest journey) must go through the guest, or the row must say it is a driver hook and not count as guest resume-write.
2. Put `store_test_principal_root_protection` back behind a test-only gate, or a lab-only crate feature that the product binary does not compile.
3. STOP must require exit 0. START must require the second process opened the same store, not only a printed banner.
4. The harness must not treat a `ROW PASS` as proof unless it also sees the store bytes, or a planted hardcoded PASS must fail.
5. Add the four review plants to the published falsifier list. Guest hash must be pinned and compared.

This review does not edit those files.
