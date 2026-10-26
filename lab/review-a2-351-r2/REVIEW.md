# Independent adversarial review r2 of draft PR #351

```text
PR:        #351 A2 e2e resume after a real Runtime process restart
Head:      9e7a85d631aec12de8c1da4fc4958bce18252d21 (measured)
Report:    4c024265b5655a222c4b6cd7d19c1f3068507379
Base:      cursor/a2-journal-load-b1e8 (#341)
Prior:     #368 FALSIFIED A2 at a97a6373
Reviewer:  Cursor Grok (GPT-family)
Date:      26 Oct 2026
Machine:   Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
Guest:     sha256:0e868fc1b7565f317c06b514992c90e1d75bdeeb1c0e92d2172e4dd4d41cbace
           (clean rebuild this session; same as the PR pin)
Verdict:   A2 can be counted on this Linux machine
```

This folder is the r2 review only. #351 files were not edited. This
branch was not pushed to `cursor/a2-e2e-resume-27c8`. Do not merge
this review PR or #351.

Rule used (Anders): a complete journey, refusal evidence, and the
required reviews. A skip is not a pass. Every claim needs a falsifier.

Raw plants: `experiments.py` and `experiments.log`.

## Plain English

#368 said A2 could not be counted. STALE and WRITE2 skipped the guest.
A public helper on `elastos-server` could write principal-root
protection with a known recovery phrase. The harness believed a
hardcoded PASS. STOP passed on exit 1.

Those holes are closed on the measured head.

This session reran `lab/a2-e2e-resume/run.sh` from a clean tree.
WRITE, STALE, STOP, START, RESUME, and WRITE2 were computed PASS on
two OS processes (pids 13524 then 13534). The journal hashes matched
the author's run. The author's ten falsifiers were CAUGHT. This
review then replanted every #368 attack on its own. They were CAUGHT
again.

The second process is a new pid. The first pid is gone before START.
The store is on disk. The driver writes only the sidecar JSON. The
journal write is the in-process Runtime after the guest hostcall.
`guest.sha256` is the file Wasmtime loads. STALE is a Runtime
`revision_conflict` on the guest write, not a guest-printed word.

Default release `elastos` and the default `libelastos_server.rlib`
do not contain the recovery phrase. A probe crate without
`lab-protection` cannot see the helper (`error[E0425]`, cfg-gated).
No workspace member, CI job, or `just` recipe turns the feature on.

A2 counts on Linux under Anders's rule. Mac still has to rebuild the
guest, re-pin the hash, and rerun the same script. This lab still
does not start `elastos serve`.

## Claims

| # | Claim | Verdict |
| --- | --- | --- |
| 1 | STALE and WRITE2 go through the guest `providers.invoke` hostcall. The driver does not mint a write token or call `handle_component_resource_request`. | **HOLDS** |
| 2 | `store_test_principal_root_protection` is `pub(crate)` under `cfg(test)`, or public only with off-by-default `lab-protection`. Default / workspace / CI / release builds do not enable it. | **HOLDS** (one residual) |
| 3 | Every row is computed. `Proof.row` refuses PASS. STOP requires exit 0. WRITE checks `guest.sha256`. | **HOLDS** |
| 4 | Two real OS processes; store reopened from disk; first process gone before START. | **HOLDS** |
| 5 | STALE proves the Runtime refused, not the guest printing "conflict". | **HOLDS** |
| 6 | `guest.sha256` is the file Wasmtime loads. | **HOLDS** |
| — | A2 can be counted under Anders's rule. | **Yes, on Linux** |

## Clean journey this session

`lab/a2-e2e-resume/run.sh` at 2026-10-26T22:47:04Z, exit 0.

| Step | Result | Evidence |
| --- | --- | --- |
| WRITE | PASS | first pid 13524; format-2 journal sha256 `fca6e299…931d30`; `write:ok`; guest `0e868fc1…cbace` |
| STALE | PASS | guest `write:conflict`; stored sha256 unchanged |
| STOP | PASS | first process exited 0; store `lab/a2-e2e-resume/homes/store-3076` |
| START | PASS | second pid 13534 on the same store |
| RESUME | PASS | guest read then write on the stored journal |
| WRITE2 | PASS | new revision `eba4e7eb…271d6f`; journal sha256 `fe13e4b9…e33ea` |
| A2_counted | yes | every row computed PASS; skipped none |

Both pids were gone after the harness waited. The on-disk journal is
encrypted at rest (`ef8fbd71…`). The plaintext hash is what the
bridge reports.

A second independent driver pair (pids 21887 then 22035) also
computed 6/6 PASS with the same journal hashes.

## #368 plants, replanted here

| Id | #368 | r2 | Notes |
| --- | --- | --- | --- |
| F-REV-HARDCODED-HARNESS-PASS | MISSED | **CAUGHT** | `Proof.row` refuses PASS |
| F-REV-NOT-RUN-UPGRADE | CAUGHT | **CAUGHT** | NOT RUN cannot become PASS |
| F-REV-HARDCODED-DRIVER-PASS | MISSED | **CAUGHT** | WRITE FAIL; no journal |
| F-REV-SKIPPED-STALE | CAUGHT | **CAUGHT** | STALE NOT RUN |
| F-REV-STOP-NONZERO | MISSED | **CAUGHT** | first exit 1; STOP FAIL |
| F-REV-SECOND-STALE-WRITE | CAUGHT | **CAUGHT** | WRITE2 FAIL; RESUME PASS |
| F-REV-OLDER-JOURNAL | CAUGHT | **CAUGHT** | RESUME FAIL |
| F-REV-STORE-WIPE | CAUGHT* | **CAUGHT** | START FAIL; no PROCESS second |
| F-REV-GUEST-HASH | MISSED | **CAUGHT** | WRITE FAIL (`0e868fc1…` → `07236439…`) |

The author's `falsify.py` also CAUGHT F-A2-CREATE-ONLY, F-A2-SKIP-LOAD,
and F-A2-REVISION. 10 of 10 on `run.sh`. The old driver strings
`stale_write(&host, …)` and `bridge_write(host, …)` are gone. The
only remaining `handle_component_resource_request` text in the driver
is a comment.

#368 said START still passed on a wiped store. It no longer does.

## New hunts

### `lab-protection` unification — HOLD

The only enabler is `lab/a2-e2e-resume/Cargo.toml`. That crate is not
an `elastos` workspace member. `elastos-server` default features are
empty. No CI workflow, `justfile`, or `scripts/` path uses
`--all-features`. `cargo test --workspace` does not pass
`--all-features`. Shared `target-build` does not unify features
across separate cargo graphs. `cargo tree -p elastos-server -e
features` shows no `lab-protection` edge.

Residual: do not add the lab crate to the elastos workspace. If you
do, one workspace build would turn the feature on for every member
that depends on `elastos-server`.
`cargo build -p elastos-server --features lab-protection` compiles
the phrase into that rlib. Nobody in CI or release scripts does that.

### Release artifacts — HOLD

Default `cargo build -p elastos-server --release` exit 0.

| Artifact | Phrase | Helper |
| --- | --- | --- |
| `elastos` binary (117,865,312 bytes) | absent | absent |
| default `libelastos_server.rlib` | absent | name only in rustdoc / compile_fail example; `nm` has no text symbol |
| probe crate, no feature | — | `error[E0425]`; rustc names both cfg gates |
| `--features lab-protection` rlib | **present** | `nm` shows `T` symbol |
| featured `elastos` binary | absent (nothing calls it) | absent |
| lab `a2-resume-driver` | present | present |

The shipping binary and the default rlib lack the recovery phrase.
The helper is not a compiled symbol unless `lab-protection` is on.

### Process isolation — HOLD

First pid 13524, then 24581 in a later pair. After
`subprocess.run` returns, `/proc/<first>` is gone. Second pid
differs. Grants live in that process only. The second process
refuses if principal-root protection is missing on disk. No shared
fd or env is required for resume. The marker env
`A2_REVIEW_MARKER` is unused.

### Driver writes — HOLD

`strace -f -e openat,open,write` on the first process:

- tokio worker 25663: `journal` `O_RDONLY` → ENOENT, then
  `O_WRONLY|O_CREAT|O_EXCL` (the guest create_only write through
  the Runtime), then `O_RDONLY` rereads.
- driver thread 25660: reads `guest.sha256`, later reads the
  journal, writes `a2-resume-state.json` only.
- no token file write.

The driver source has no `write_principal_root_object` and no
`handle_component_resource_request(` call. It still grants the two
pending journal asks. That is Home's role, not the #368 bypass.

### `guest.sha256` vs loaded bytes — HOLD

`capsule.json` entrypoint is `agent-host.component.wasm`.
`ComponentProvider::load` does `Component::from_file` on
`path.join(&manifest.entrypoint)`. The pin, the driver hash, and
the harness hash are that file. This session: live = pin =
`0e868fc1…`. The check is a hash of the file just before launch,
not a hash after Wasmtime decode. Same path.

### STALE is a Runtime refusal — HOLD

`probe_stale_write` sends `if_revision=stale-not-current` through
`bus.invoke(..., "write", ...)` and accepts only
`revision_conflict`. The host maps that code to audited
`write:conflict`. The guest cannot write the audit log.

First-process invokes (newest first):
`write:conflict,read:ok,write:ok,read:error`.

A second `create_only` write would also audit as `write:conflict`.
On the published guest, STALE is the stale `if_revision` probe.
The harness does not read the write body. F-A2-REVISION and
F-REV-SKIPPED-STALE still catch a fake or missing refusal.

## Anders's rule

Complete journey: six computed rows, two OS processes, one on-disk
store, guest hostcall on WRITE, STALE, RESUME, and WRITE2.

Refusal evidence: stale `if_revision` is `revision_conflict`;
create_only without load fails resume; flipped guest fails WRITE;
exit 1 fails STOP; wiped store fails START.

Required review: this GPT-family adversarial review of the measured
head. **VERDICT: PASS.**

This lab still does not start `elastos serve`. That limit was
already in the A2 report. It does not stop the A2 count the author
asked for (restart of the in-process Runtime + real bridge).

## What must still run on macOS

The guest hash is per machine. The pin `0e868fc1…` is Linux x86_64.
A Mac run must rebuild the guest, write a new `guest.sha256`, and
rerun `lab/a2-e2e-resume/run.sh`. This review did not do that.

## What is next

Keep #351 draft. A2 may be counted on Linux. Do not merge until
Sasha wants it. Mac still has to run the same script after a
re-pin.
