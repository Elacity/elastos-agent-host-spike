# Independent adversarial review of #284 (A15) at cb102ed1

Reviewer: Cursor Grok 4.6 (Grok family). #284 was authored by Claude. This is the first independent review of that PR.

Reviewed head: `cb102ed13b9e93e7e99a820d63195cf931bee22a`  
Worktree: `/tmp/a15-review/cb102ed1` (detached at that commit)  
Review branch: `cursor/review-a15-284-6e0e` from `origin/spike/agent-host` at `e70f6e7c75f582e542d436d82ef928d4b98e1121`  
Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28)  
Date: 26 Oct 2026

**Bookability for A15: not bookable. A15 stays open.**

The complete journey as worded is preview, explicit approval, then execute exactly the approved plan. The journal write stays BLOCKED. The notes read stays BLOCKED. Lab evidence for Runtime-side rows stays evidence. Rows that need the Runtime and do not have it stay BLOCKED. This review records FIX items. It is not a PASS that books the check.

Related Runtime asks RA-4 and RA-5 live in draft PR #309. They stay asks.

This folder is the only change on this branch. #284's branch was not pushed. Nothing was merged.

## Verdict by claim

| Claim | Source | Grade |
| --- | --- | --- |
| A plan runs only after the person approves it | `ab337a01` | **WEAK** |
| The falsifier selects each approval test | `ed8faec6` | **HOLDS** |
| Approved journal steps are sent over the bus bridge, partly against the real Runtime | `cb102ed1` | **WEAK** |

No claim is FALSIFIED in the sense that the README invents a stored journal. The README's BLOCKED rows match the code. The weakness is that the Host gate is incomplete, the "real Runtime" path is an in-process library call, and several guards can be removed without the PR's own tests failing.

## Anders's counting rule, applied

A check counts only when the complete journey as worded passes, each refusal carries a reason plus a CAUGHT falsifier, and the required reviews exist. Lab evidence for a Runtime-side property stays evidence until the Runtime half passes. Rows that need the Runtime and do not have it must say BLOCKED, not PASS.

| Journey part | What I saw | Counts? |
| --- | --- | --- |
| Preview | `preview()` lists both steps and records no grant. Lab. | Lab evidence only |
| Explicit approval | `Host::review(..., Choice::Approve)` is a function argument. There is no person channel, session id, or signed approval object. | Lab evidence only |
| Execute exactly the approved plan | `Host::execute` binds canonical bytes and the step list. The journal step records BLOCKED. The notes step records BLOCKED without a Runtime call. Nothing is stored. | BLOCKED |
| Refusal + reason | Reject, altered plan, extra step, and spent grant return named reasons. Cross-host replay returns `the bus bridge did not answer`, which is the lab mapping for a validate failure, after the notes effect is already recorded. | Partial |
| CAUGHT falsifier | One plant removes all of `approval_check`. The five named tests fail. Per-guard mutants M3, M5, M6, M7, M8 survive those five tests. | Partial |
| Required reviews | None on #284 before this file. This review is FIX, not PASS. | Missing PASS |

**A15 is not bookable.**

## What I rebuilt and reran

First `cargo clippy` / `cargo test` with `--locked --offline` failed: `no matching package named tokio`. I ran `cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml` (exit 0), then the PR commands again.

```bash
export RUST_TEST_THREADS=2
cd /tmp/a15-review/cb102ed1
cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check
cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture
```

| Command | Exit | Result |
| --- | --- | --- |
| `cargo fmt -- --check` | 0 | no diff |
| `cargo clippy ... -D warnings` | 0 | clean for `intent-planner` |
| `cargo test ... -- --nocapture` | 0 | `13 passed; 0 failed; 0 ignored` in 105.43s |

The plant runner printed:

```text
plant F-A15-approval caught test approved_plan_executes_with_the_approved_grants ... FAILED
plant F-A15-approval caught test rejected_plan_executes_nothing ... FAILED
plant F-A15-approval caught test plan_altered_after_approval_is_refused ... FAILED
plant F-A15-approval caught test extra_step_injected_at_run_time_is_refused ... FAILED
plant F-A15-approval caught test approved_grant_runs_once ... FAILED
```

After that run, `src/lib.rs` still had one `approval_check` body and no `open-{index}` text. SHA-256 of `lab/intent-planner/src/lib.rs` at the reviewed head, and again after every restore: `d96a2079c805bdae534db92dc4b0aa34d85afd7aea8193a1126011fc25d218af`.

Clippy of `elastos-server` printed two `AsyncFd::new` deprecation warnings. They are in the dependency, not in `intent-planner`.

## Rows: lab, Runtime evidence, or BLOCKED

| Row | Where the call actually goes | Class |
| --- | --- | --- |
| Preview of the two-step plan | `preview()` in this crate | lab |
| Notes step BLOCKED (`UsersAI` alias) | `runtime_gap()` string, no Runtime call | BLOCKED (STATIC) |
| Reject / altered plan / extra step / spent grant | `Host::approval_check` | lab |
| Unapproved journal step `missing_token` | `handle_remote_request_with_audit_dir` in this process | evidence (library), not a Runtime process |
| Altered resource `wrong resource` | lab `CapabilityManager::validate` | evidence (library) |
| Same altered resource on the public bus | same public function; returns `principal_context_required` first | BLOCKED |
| First use of the allow-once grant | lab `CapabilityManager::validate` | evidence (library) |
| Second use `use limit exceeded` | lab `CapabilityManager::validate` | evidence (library) |
| Second use on the public bus | public function; storage refusal first | BLOCKED |
| Approved journal write stored | public function; nothing is stored | BLOCKED |

`invoke_journal` calls `elastos_server::resource_bridge::handle_remote_request_with_audit_dir` with `audit_data_dir: None` and `api_url: "http://127.0.0.1:9"`. For a principal-root write the function returns `principal_context_required` / `principal-root storage requires an in-runtime protected storage bridge` before it validates the token and before it opens HTTP. I compared `/proc/*/comm` before and after that call: the elastos-named process list was unchanged. `pgrep -a elastos` was empty after the suite. **No row reaches a Runtime process.**

`CapabilityManager::new` generates a fresh signing key. Tokens minted by one `Host` do not validate on another `Host`. That is why a Review moved to a second Host returns `Refuse::Bridge`.

The test name `approved_plan_executes_with_the_approved_grants` passes while both steps are BLOCKED. The body is honest. The name reads like a completed execute.

## Break attempts

I ran 15 extra probes against the public Host API (worktree-only; see `attacks.rs`). After documenting the two cross-host leaks, all 15 passed.

| Probe | Result |
| --- | --- |
| Reorder the two steps after approval | refused `OutsidePlan`; empty effects |
| Edit operation `write` → `append` | refused `OutsidePlan`; empty effects |
| Edit action `Write` → `Read` | refused `OutsidePlan`; empty effects |
| Approve `ada`, execute `bea`'s plan | refused `PlanAltered`; empty effects |
| Partial steps (journal only) | refused `OutsidePlan`; empty effects |
| Empty constructed plan, then approve | `Ok`, zero grants, zero effects |
| Construct a write step the planner never emitted, then approve | one grant, one BLOCKED journal effect |
| Replay a used Review on a second `Host` | `Refuse::Bridge`; **one notes effect already recorded** |
| Unused Review on a second `Host` | `Refuse::Bridge`; **one notes effect already recorded** |
| Forged token string on `invoke_journal` | same `principal_context_required` as a real token |
| Stolen approval token on `invoke_journal` without `execute` | same storage BLOCKED; Host effects stay empty |
| `Grants::mint` + `invoke_journal` with no preview and no `review` | same storage BLOCKED |
| Preview only | no grant, no effects |
| `/proc` comm during `invoke_journal` | no new `elastos` process |
| Scoped journal path | launching person is `person:local:intent-planner`; agent name is only the `.AppData/Agents/<id>/` segment |

The Host gate holds for reorder, argument edit, extra step, and another principal **when the caller goes through `Host::execute`**. The same crate also exposes `Grants::mint_journal_write` and `invoke_journal`. Those skip preview and approval.

`execute` pushes the notes BLOCKED effect, then can return `Refuse::Bridge` on the journal step. Effects are not rolled back. The error text says the bus did not answer. The failure I saw was `CapabilityManager::validate` rejecting another Host's token.

## Per-guard mutants

Each mutant was applied to `src/lib.rs` (or `plant.rs` for M9), then the five Host tests from the PR plant were rerun with `--exact`. `src/lib.rs` was restored to `d96a2079…` after every mutant.

| Id | Guard removed | PR Host tests | Grade |
| --- | --- | --- | --- |
| M1 | `choice != Approve` | `rejected_plan_executes_nothing` FAIL | CAUGHT |
| M2 | canonical byte check | `plan_altered_after_approval_is_refused` FAIL | CAUGHT |
| M3 | step zip equality; length kept | all five PASS | **SURVIVED** |
| M4 | `used` token list | `approved_grant_runs_once` FAIL (`Bridge` vs `GrantSpent`) | CAUGHT |
| M5 | `grant.covers`; take first grant | all five PASS | **SURVIVED** |
| M6 | `validate_journal_write` before the bridge | all five PASS | **SURVIVED** |
| M7 | skip `invoke_journal`; hardcode the known BLOCKED effect | all five PASS | **SURVIVED** |
| M8 | drop `principal` from `canonical()` | all five PASS | **SURVIVED** |
| M9 | plant runner: treat a non-FAILED cargo run as caught | current plants still print FAILED | honesty hole, unexercised |

M3 is live: with only the length check, `review_m3_reorder_probe` called `execute` on swapped steps and got `Ok` with two effects. Exit 0.

M6 is live: with validate removed, `review_m6_cross_host_probe` ran an unused Review on a second Host and got `Ok` with two effects. Exit 0. The public bridge does not check the token for this write, so the lab-side validate is the only Host-to-token bind.

M7 means the five Host tests do not prove a bus call. The dedicated `runtime_*` and `public_bridge_*` tests still call `invoke_journal` themselves. They stay green if `execute` never reaches the bridge.

M4 is caught, but the second use fails as `Refuse::Bridge` (`use limit exceeded` mapped to "the bus bridge did not answer"), not as `GrantSpent`. The `used` list is the only Host-level replay bind. The Runtime use counter lives on the lab manager, and the public bridge never sees it.

The PR plant `F-A15-approval` removes the whole of `approval_check` at once. That is why the five named tests fail together. It does not pin each guard.

Timeouts: `plant.rs` requires a line `test <name> ... FAILED` and a process exit code. A signal-killed cargo run is refused. I did not see a timeout counted as CAUGHT. The suite has no test timeout.

Hardcoded PASS: none of the 13 tests return `Ok` without assertions. `approved_plan_executes_with_the_approved_grants` asserts the two BLOCKED effects. That is a tripwire for today's gap, not a PASS of a stored journal.

## Claim notes

### ab337a01 — plan runs only after approval — WEAK

`Host::execute` does refuse `Choice::Reject` (M1 caught). The person is the caller of `review()`. A caller who can call `review(..., Approve)` is the approver. A caller who can call `invoke_journal` skips the Host.

`Review` is a cloneable value. It is not bound to the `Host` that minted it. `used` is per-Host. A second Host accepts the Review through `approval_check`, records the notes step, then fails validate.

`Plan` fields are public. `Host::review` accepts a constructed plan the table never emitted.

### ed8faec6 — falsifier selects each approval test — HOLDS

`--exact` is used. I reran the plant. Each of the five names printed `FAILED`. `src/lib.rs` was restored. That is what the commit claims.

The plant still removes every Host guard in one edit. Per-guard survival (M3, M5, M6, M7, M8) is outside that claim, and it is why the approval claim stays WEAK.

### cb102ed1 — bus bridge, partly real Runtime — WEAK

`execute` does call `invoke_journal` today. That function is the public bus entry. RA-4 is right: `handle_component_resource_request` is `pub(crate)`, and the public path refuses principal-root storage first.

"Partly against the real Runtime" means linked crate code in the test process. It does not mean an `elastos` process, a data directory, or a stored journal. The allow-once and wrong-resource rows are the lab manager. The public-bridge rows that need those checks stay BLOCKED, as the README says.

M7 shows the Host tests still pass if `execute` never calls the bridge and hardcodes the BLOCKED strings.

## Principles

- 3 No ambient authority. The Host gate is real for `execute`. `mint` and `invoke_journal` stay callable without it.
- 7 One authority model. Approval is a `Choice` enum, not a person grant the Runtime minted.
- 10 One canonical path. The README names `approval_check` and `handle_remote_request_with_audit_dir`. Direct `invoke_journal` is a second path.
- 11 Fail closed, then explain. Cross-host failure says the bus did not answer. Effects already recorded are kept.
- 12 Docs, code, and tests agree on BLOCKED storage. They disagree on "executes" in the passing test name, and on "real Runtime" vs in-process library.
- 16 UI is not authority. The preview records no grant. That part holds.
- 18 Isolated instances. There is no session or instance id on `Review`.
- 19 Consequences, not transports. The public bridge refusal is a transport/entry refusal. It is labeled BLOCKED. That part holds.

DeepSeek: none. I did not change Runtime source.

## Ranked fixes for #284

1. Bind a `Review` to the `Host` (or session) that minted it. Refuse another Host with a named reason. Roll back effects when `execute` returns an error.
2. Pin that `execute` calls the bus. A Host-path test must fail if `invoke_journal` is skipped or the BLOCKED strings are hardcoded (closes M7).
3. Add Host tests for reorder, grant-to-step `covers`, and principal-in-canonical (closes M3, M5, M8).
4. Split `F-A15-approval` into one plant per guard. Keep `--exact`.
5. Rename `approved_plan_executes_with_the_approved_grants` so a BLOCKED journey is not read as a completed write.
6. Keep RA-4 / RA-5 as the Runtime half. Until those land and a stored journal is asserted, A15 stays BLOCKED.
7. Keep `mint` / `invoke_journal` as test-only, or make them go through the same approval bind.
8. Map a validate failure to its own reason. Stop calling it `Refuse::Bridge`.

## Bookability sentence

A15 is a lab model of preview and a Host approval bind, plus honest BLOCKED rows for UsersAI (RA-5) and protected storage (RA-4). It does not complete the journey. It has surviving mutants. It had no independent PASS. **Do not book A15.**

## Next

#284 authors fix the Host bind and the surviving mutants, or accept them as lab limits in the README. RA-4 and RA-5 stay with Anders after 0.8.0. This review PR stays draft. Do not merge #284 on the strength of this file.
