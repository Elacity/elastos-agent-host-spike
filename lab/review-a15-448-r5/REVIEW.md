# Independent adversarial review r5 of #448 (A15) at 3417741a

Reviewer: Cursor Grok 4.6 (Grok family). #448 was authored by Claude as the
r4 lab-half fix for #284. r1 was PR #399 at `cb102ed1`. r2 was PR #414 at
`4f17e482`. r3 was PR #428 at `d169f90`. r4 was PR #445 at `36049b90`.
This is the fifth independent review of the A15 Host gate, and the first
review of draft #448. I read `lab/review-a15-284-r4/REVIEW.md` first.

Reviewed head: `3417741a9d6ca5eccde06eae5f07baa6e7879c03`  
Code commit: `89c1cdc7556bc7db86dc5b20d913e0382428df8d`  
Base: `cursor/a15-r4-fail-closed-c89c` on #284 at `36049b90b6102b3dff937bf761f1a03029ce24e1`  
Review branch: `cursor/review-a15-448-r5-70f1` from that head  
Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28)  
Date: 27 Oct 2026

**Bookability for A15: still open. The journal write stays BLOCKED.**

The r4 survivors are dead. The author's 42/0 count is real. I replanted
all 39 plants myself. Every named-error guard is reachable: deleting it
fails its pin test. Constructed Unicode, percent, trailing slash, empty
segment, absolute, symlink, and public-API TOCTOU / replay probes stop
before a bus call.

Three new holes still get a grant or a bus call through without a matching
approval:

1. A two-journal execute spends the first grant when the second validate
   fails. Retry makes two more bus calls. This breaks the written
   "failed execute leaves the grant unused" rule.
2. Approving a write under `Agents/.../secrets` mints a journal token
   and calls the bus with the secrets URI.
3. Rewriting `Review.host_id` to the victim Host's id makes that Host
   invoke the bus. It never minted the token.

This folder is the only change on this branch. #448 and #284 were left
alone. Nothing was merged. Elacity/elastos-runtime was left alone.

## Verdict

**VERDICT: FIX**

Lab half only. The r4 plants are CAUGHT. The Host gate still spends a
grant on a failed multi-step execute, still mints a journal token for a
non-journal path, and still treats `host_id` as a rewriteable label.

A15 stays open while the journal write is BLOCKED (RA-4), UsersAI notes
are BLOCKED (RA-5), and a spawned `elastos` over the bus is NEEDS RUNTIME.

## Anders's counting rule, applied

A check counts when the complete journey as worded passes, each refusal
carries a reason plus a CAUGHT falsifier, and the required reviews exist.
Lab evidence for a Runtime-side property stays evidence. Rows that need
the Runtime stay BLOCKED.

| Journey part | What I saw | Counts? |
| --- | --- | --- |
| Preview | `preview()` lists both steps and records no grant. Lab. | Lab evidence |
| Explicit approval | `Host::review(..., Choice::Approve)` is a function argument. There is still no person channel, session id, or signed approval object. | Lab evidence |
| Execute exactly the approved plan | r4 constructed `_ada` / empty plan / `[journal, journal]` / `.` `..` `a..b` `...` host_id / `notes/foo/..` are now refused. A failed two-journal execute still spends the first grant. A secrets path still mints a journal token. A rewritten `host_id` still reaches the bus. | BLOCKED for the product journey. Lab Host-gate is incomplete for multi-step spend and mint scope. |
| Refusal + reason | Each named `Refuse` is reachable and pinned. Partial-spend returns `Bridge` with a spent grant and no reason that the first grant is gone. | Partial |
| CAUGHT falsifier | Author plants F-A15-approval, M1–M8, M6-host, N1–N10, R3-1..R3-12, and R4-1..R4-7 are CAUGHT. New plants R5-7a, R5-11, and R5-6d survive the author's 41 Host/library tests. | Partial |
| Required reviews | r1–r4 of #284 were FIX. This r5 of #448 is FIX. | Missing PASS |

**A15 is not bookable.**

## What I rebuilt and reran

Worktree at `3417741a`. First command was `cargo fetch --locked`.

```bash
export RUST_TEST_THREADS=2
cargo fetch --locked --manifest-path lab/intent-planner/Cargo.toml
cargo fmt --manifest-path lab/intent-planner/Cargo.toml -- --check
cargo clippy --manifest-path lab/intent-planner/Cargo.toml --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml -- --nocapture --skip model_planted_bugs_are_caught
cargo test --locked --offline --manifest-path lab/intent-planner/Cargo.toml --lib model_planted_bugs_are_caught -- --exact --nocapture
```

| Command | Exit | Result |
| --- | --- | --- |
| `cargo fetch --locked` | 0 | lock file resolved |
| `cargo fmt -- --check` | 0 | no diff |
| `cargo clippy ... -D warnings` | 0 | clean for `intent-planner` |
| `cargo test ... --skip model_planted_bugs_are_caught` | 0 | `41 passed; 0 failed; 0 ignored` in 1.35s |
| `cargo test ... model_planted_bugs_are_caught` | 0 | `1 passed` in 221.94s; every named plant line printed `FAILED` |

Together that is the author's **42/0**. `pgrep -a elastos` was empty
after the suite. Clippy of `elastos-server` printed two `AsyncFd::new`
deprecation warnings. They are in the dependency.

SHA-256 of `lab/intent-planner/src/lib.rs` at the reviewed head, after
the author runner, after my independent replant, after every named-error
deletion restore, and after the r5 probes:  
`7a30fda81a2a12e5ea80428cfc69355b5fcb5f1a14cfdaed73785e909bb05ca3`.

SHA-256 of `lab/intent-planner/src/runtime_bridge.rs`:  
`b5a35da21f95b989ac473a03ea5f3ca2a1e3a064cdcd07de62ffc6f250c31932`.

Those are the hashes the author named in `reports/A15-r4-fail-closed.md`.

## Author plants, rerun by me

I ran `model_planted_bugs_are_caught`. That applies each `plants/*.txt`
once, requires the named `--exact` test line to end `FAILED`, then writes
the original bytes back. Named-test lines below are exact.

| Plant | Named tests FAILED | Grade |
| --- | --- | --- |
| F-A15-approval | 5/5 (`approved_plan_records_blocked_in_process_bridge_effects`, `rejected_plan_executes_nothing`, `plan_altered_after_approval_is_refused`, `extra_step_injected_at_run_time_is_refused`, `approved_grant_runs_once`) | CAUGHT |
| M1 | 1/1 `rejected_plan_executes_nothing` | CAUGHT |
| M2 | 1/1 `plan_altered_after_approval_is_refused` | CAUGHT |
| M3 | 1/1 `reordered_approved_steps_are_refused` | CAUGHT |
| M4 | 1/1 `approved_grant_runs_once` | CAUGHT |
| M5 | 1/1 `grant_lookup_uses_covers_for_the_exact_resource` | CAUGHT |
| M6 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | CAUGHT |
| M6-host | 1/1 `unused_review_does_not_run_on_a_second_host` | CAUGHT |
| M7 | 1/1 `blocked_journal_effect_comes_from_an_in_process_library_call` | CAUGHT |
| M8 | 1/1 `approval_for_one_principal_does_not_execute_for_another` | CAUGHT |
| N1 | 1/1 `newline_fields_do_not_collide` | CAUGHT |
| N2 | 1/1 `plan_altered_after_approval_is_refused` | CAUGHT |
| N3 | 1/1 `trailing_space_principal_is_a_different_plan` | CAUGHT |
| N4 | 1/1 `prefix_resource_does_not_cover_a_child_journal` | CAUGHT |
| N5 | 1/1 `grant_lookup_uses_covers_for_the_exact_resource` | CAUGHT |
| N6 | 1/1 `approved_plan_refuses_a_stored_bus_reply` | CAUGHT |
| N7 | 1/1 `prefix_host_id_stays_foreign` | CAUGHT |
| N8 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | CAUGHT |
| N9 | 1/1 `execute_spends_the_allow_once_grant_at_the_lab_manager` | CAUGHT |
| N10 | 1/1 `failed_execute_does_not_spend_the_grant` | CAUGHT |
| R3-1 | 1/1 `nfc_nfd_principals_do_not_collide` | CAUGHT |
| R3-2 | 1/1 `cyrillic_confusable_principal_is_a_different_plan` | CAUGHT |
| R3-3 | 1/1 `over_length_field_is_not_truncated` | CAUGHT |
| R3-4 | 1/1 `dotdot_path_does_not_cover_journal` | CAUGHT |
| R3-5 | 1/1 `trailing_slash_path_does_not_cover_journal` | CAUGHT |
| R3-6 | 1/1 `ascii_case_path_does_not_cover_journal` | CAUGHT |
| R3-7 | 1/1 `blocked_reply_is_a_whole_token` | CAUGHT |
| R3-8 | 1/1 `empty_or_nul_host_id_is_foreign` | CAUGHT |
| R3-9 | 1/1 `approved_step_order_is_bound` | CAUGHT |
| R3-10 | 1/1 `percent_encoded_path_does_not_cover_journal` | CAUGHT |
| R3-11 | 1/1 `failed_execute_does_not_spend_the_grant` | CAUGHT |
| R3-12 | 1/1 `unused_review_does_not_run_on_a_second_host` | CAUGHT |
| R4-1 | 1/1 `dot_or_dotdot_host_id_is_foreign` | CAUGHT |
| R4-2 | 1/1 `dotdot_notes_path_is_refused_at_execute` | CAUGHT |
| R4-3 | 1/1 `constructed_plain_principal_is_refused_at_execute` | CAUGHT |
| R4-4 | 1/1 `empty_plan_cannot_be_approved` | CAUGHT |
| R4-5 | 1/1 `duplicate_journal_steps_are_refused` | CAUGHT |
| R4-6 | 1/1 `embedded_dotdot_host_id_is_foreign` | CAUGHT |
| R4-7 | 1/1 `nul_intent_is_refused_at_execute` | CAUGHT |

The author claim "42/0, all 39 plants CAUGHT, lib.rs sha `7a30fda8…`" holds.
The r4 holes are pinned in code, not only in docs.

## Named errors: each guard is reachable

I deleted each named-error guard once, ran its pin test with `--exact`,
then wrote the original bytes back. Source restored to `7a30fda8…`.

| Error | Guard deleted | Pin test | Grade |
| --- | --- | --- | --- |
| `BadPrincipal` | `plain_principal` at `execute` | `constructed_plain_principal_is_refused_at_execute` | FAILED (pinned) |
| `UnknownIntent` | `_ => Err(Refuse::UnknownIntent)` | `unknown_intent_and_bad_principal_are_refused` | FAILED (pinned) |
| `BadIntent` | `plain_intent` at `execute` | `nul_intent_is_refused_at_execute` | FAILED (pinned) |
| `EmptyPlan` | `steps.is_empty()` | `empty_plan_cannot_be_approved` | FAILED (pinned) |
| `DuplicateStep` | `has_duplicate_steps` | `duplicate_journal_steps_are_refused` | FAILED (pinned) |
| `NotApproved` | `review.choice != Approve` | `rejected_plan_executes_nothing` | FAILED (pinned) |
| `PlanAltered` | `review.canonical != plan.canonical()` | `plan_altered_after_approval_is_refused` | FAILED (pinned) |
| `OutsidePlan` | `steps != plan.steps` | `extra_step_injected_at_run_time_is_refused` | FAILED (pinned) |
| `GrantSpent` | `self.used.contains` | `approved_grant_runs_once` | FAILED (pinned) |
| `ForeignHost` | `review.host_id != self.id` | `unused_review_does_not_run_on_a_second_host` | FAILED (pinned) |
| `Bridge` | `classify` Other/Unapproved → `Bridge` | `approved_plan_refuses_a_stored_bus_reply` | FAILED (pinned) |

Script output (every line `named_failed=True`, then restore):

```text
GUARD BadPrincipal test=constructed_plain_principal_is_refused_at_execute compile_ok=True named_failed=True
GUARD UnknownIntent test=unknown_intent_and_bad_principal_are_refused compile_ok=True named_failed=True
GUARD BadIntent test=nul_intent_is_refused_at_execute compile_ok=True named_failed=True
GUARD EmptyPlan test=empty_plan_cannot_be_approved compile_ok=True named_failed=True
GUARD DuplicateStep test=duplicate_journal_steps_are_refused compile_ok=True named_failed=True
GUARD NotApproved test=rejected_plan_executes_nothing compile_ok=True named_failed=True
GUARD PlanAltered test=plan_altered_after_approval_is_refused compile_ok=True named_failed=True
GUARD OutsidePlan test=extra_step_injected_at_run_time_is_refused compile_ok=True named_failed=True
GUARD GrantSpent test=approved_grant_runs_once compile_ok=True named_failed=True
GUARD ForeignHost test=unused_review_does_not_run_on_a_second_host compile_ok=True named_failed=True
GUARD Bridge test=approved_plan_refuses_a_stored_bus_reply compile_ok=True named_failed=True
RESTORED sha256=7a30fda81a2a12e5ea80428cfc69355b5fcb5f1a14cfdaed73785e909bb05ca3
```

`UnknownIntent` is reachable from `plan()` only. `execute` never returns it.
A constructed plan with intent `delete my notes` still runs (R5-12). That
is a table split, not a missing pin of the `plan()` arm.

## New attacks (reviewer-owned)

Each probe ran against the clean tree at `3417741a`. Source restored to
`7a30fda8…` after the temporary probe function was removed.

### Unicode lookalikes — CAUGHT

| Probe | Clean tree | Grade |
| --- | --- | --- |
| journal path with Cyrillic `аda` | `OutsidePlan`, audit empty. Review still minted the journal grant. | CAUGHT at execute |
| `/` replaced by U+FF0F | `OutsidePlan`, 0 grants | CAUGHT |
| principal `ada` + U+200B | `BadPrincipal`, audit empty. Review minted one grant. | CAUGHT at execute |
| matching `host_id` `host` + U+2011 + `1` | `ForeignHost`, audit empty | CAUGHT |

`validated_path` requires ASCII. `validated_name` refuses the hyphen and
the zero-width space. No bus call.

### Percent-encoding, trailing slash, empty segments, absolute paths — CAUGHT

| Probe | Clean tree | Grade |
| --- | --- | --- |
| `journa%6c` | `OutsidePlan`, 1 grant minted, audit 0 | CAUGHT at execute |
| `journal/` | `OutsidePlan`, 1 grant minted, audit 0 | CAUGHT at execute |
| `//journal` empty segment | `OutsidePlan`, 1 grant minted, audit 0 | CAUGHT at execute |
| `/Users/self/.AppData/Agents/ada/.../journal` | `OutsidePlan`, 0 grants | CAUGHT |
| `file:///etc/passwd` | `OutsidePlan`, 0 grants | CAUGHT |
| `journal/%2e%2e` | `OutsidePlan`, 1 grant minted, audit 0 | CAUGHT at execute |

`contains('%')`, `ends_with('/')`, and empty segments fail `validated_path`
before `invoke_journal`. Review still mints when `runtime_gap` is None.

### Symlinked segments — CAUGHT

A real symlink `link-journal -> real-journal` as the step resource was
`OutsidePlan`, 0 grants, audit 0. The lab compares URI strings. It does
not walk the filesystem. Symlink resolution stays NEEDS RUNTIME / RA-4.

### Step-id collision where resources differ — mixed

README says two steps may share an id when their resources differ.
`has_duplicate_steps` compares the raw resource string.

| Probe | Clean tree | Grade |
| --- | --- | --- |
| same id, `ada` journal + `bea` journal | `Ok`, 2 grants, 2 effects, 4 audit records | allowed by the r4 rule |
| same id, journal + `journal/.` | `OutsidePlan`, 2 grants minted, audit 0 | CAUGHT at execute |
| same id, journal + `journal/foo/..` | `OutsidePlan`, 2 grants minted, audit 0 | CAUGHT at execute |
| ids 1 and 2, journal + `journal/` | `OutsidePlan`, 2 grants minted, audit 0 | CAUGHT at execute |

The execute path loop stops the bus. Review still mints two journal
tokens for a pair that would be the same path after a fold. The design
is refuse-not-fold, so execute is fail-closed. The extra mint is a
leftover, not a bus bypass.

### Plan changed between approval and execute (TOCTOU) — CAUGHT

| Probe | Clean tree | Grade |
| --- | --- | --- |
| mutate `plan.steps[1].resource` after `review` | `PlanAltered`, audit 0 | CAUGHT |
| pass a different `steps` slice, original `plan` | `OutsidePlan`, audit 0 | CAUGHT |
| mutate `plan.principal` after `review` | `PlanAltered`, audit 0 | CAUGHT |

`canonical()` is recomputed at execute. There is no interior mutability
on `Plan`. Public-API TOCTOU is the r4 `PlanAltered` / `OutsidePlan` pair.

### Replaying an approval against a different plan — mixed

| Probe | Clean tree | Grade |
| --- | --- | --- |
| `ada` review executed as `plan("bea")` | `PlanAltered`, audit 0 | CAUGHT |
| forge `review.canonical` to bea's bind, bea's steps | `OutsidePlan` (`covers` fails), audit 0 | CAUGHT |
| forge `review.canonical` to a `bea` label that still lists ada's steps | `Ok`, 2 effects, 2 audit records | **LIVE execute** (Review field rewrite) |
| clone `ada` review, set `host_id` to host B, execute on B | `Bridge`, effects 0, **audit_b=2** | **SURVIVED** (bus call) |

The crate already mutates `Review.host_id` in
`empty_or_nul_host_id_is_foreign`. Field rewrite is in the lab model.

R5-6c only relabels the principal. The bus still writes ada's journal,
which that review minted. Weak.

R5-6d is a bus call on a Host that did not mint the token. `approval_check`
compares the `host_id` string and then `covers` on step fields. The token
is not bound to the minting Host. `validate_journal_write` on B fails
after the invoke, so effects stay empty and A's grant stays unused.

Exact probe output:

```text
R5PROBE R5-6d forged-host-id-transplant execute=Err(Bridge) effects_b=0 audit_b=2 audit_a=0
```

### Error path that leaves a partial grant — SURVIVED

README: "A failed execute leaves the grant unused, so a retry is not
`GrantSpent`." `failed_execute_does_not_spend_the_grant` pins a single
journal step whose bus call fails before `validate`.

Two journal steps (`ada`, `bea`), Approve, then pre-spend only bea's
token at the lab manager:

```text
R5PROBE R5-7a partial-spend execute=Err(Bridge) ada_after=Err("use limit exceeded: 1 >= 1") retry=Err(Bridge) effects=0 audit=8
```

`execute` invokes both journals, classifies both as storage-BLOCKED,
then `validate`s ada (spends), then `validate`s bea (fails). It returns
`Bridge` without updating `self.used` or `self.effects`. Ada's grant is
spent. Retry is `Bridge` again and adds four more audit records.

A forced fail on the first invoke leaves ada unused (R5-7b). That is
the N10 path. The hole is the validate loop after two successful
invokes.

The author's 41 Host/library tests do not build this case.

### Constructed `host_id` with a leading or trailing dot — LIVE execute

`plain_principal` refuses a name that starts with `.` or ends with `.`.
`host_id` uses `validated_name` only. Matching `host_id` values
`.host-1`, `host-1.`, and `host.` each returned `Ok`, 2 effects, 2 audit
records.

This is the leftover of r4's "one name grammar". It does not transplant
a foreign review. Rank below R5-7a / R5-11 / R5-6d.

### Review still mints for a name `execute` refuses — residual

Constructed `_ada`: `review.choice == Approve`, `grants.len() == 1`,
then `execute` is `BadPrincipal`. R4-3 asserts that mint. The r4 ranked
fix asked for the grammar at `review` as well. #448 applied it at
`execute` only.

### Secrets path under Agents — SURVIVED

```text
R5PROBE R5-11 secrets-under-agents execute=Ok(()) grants=1 effects=1 audit=2
```

`runtime_gap` is None for any `localhost://Users/self/.AppData/Agents/`
write. `mint` always calls `mint_journal_write(plan_agent(resource))`.
The person approved `.../secrets`. The token resource is the journal.
The bus URI is `.../secrets`.

That is a journal grant without a journal approval, and a bus call for
a URI the token does not name. After RA-4 the public entry would check
the token and fail closed. The Host gate already minted the wrong grant.

### Unknown intent at `execute` — residual

`plan("ada", "delete my notes")` is `UnknownIntent`. A constructed `Plan`
with that intent and the table journal steps returned `Ok`, 1 grant,
2 effects. The person approved those steps in `review`. The table is
only a `plan()` front door.

## Plant table (new)

| Plant | What it tries | Grade |
| --- | --- | --- |
| R5-1a..d | Unicode lookalikes in path / principal / host_id | CAUGHT |
| R5-2a..f | Percent, trailing slash, empty segment, absolute, `file://`, `%2e%2e` | CAUGHT |
| R5-3 | Symlinked host path as resource | CAUGHT |
| R5-4a | Same step id, ada + bea journals | CAUGHT (allowed) |
| R5-4b..d | Same / paired resources that would fold to the journal | CAUGHT at execute |
| R5-5a..c | Public-API TOCTOU | CAUGHT |
| R5-6a..b | Replay / forged bind onto a different resource | CAUGHT |
| R5-6c | Forged canonical, same steps, other principal label | LIVE execute (relabel) |
| R5-6d | Forged `host_id` onto a second Host | **SURVIVED** (bus call) |
| R5-7a | Second grant pre-spent; first grant spent on `Bridge` | **SURVIVED** |
| R5-7b | First invoke forced fail | CAUGHT |
| R5-8 | `host_id` `.host-1` / `host-1.` / `host.` | LIVE execute (grammar leftover) |
| R5-9 | Review mints for `_ada` | residual (R4-3 asserts it) |
| R5-10a | Notes-only plan | CAUGHT (RA-5 BLOCKED, no grant) |
| R5-10b | Both step ids 0 | LIVE execute of an approved plan |
| R5-11 | Approve `.../secrets`, mint journal token, bus secrets | **SURVIVED** |
| R5-12 | Constructed unknown intent | residual (`plan()` only) |

## Survivors: minimal patches

### R5-7a — do not leave a spent grant on a failed execute

`execute` invokes every journal step, then validates every grant. A
later `validate` error drops `recorded` and `used`, and keeps the
earlier manager spend.

Pin: two journal steps, pre-spend the second token, assert execute fails,
assert the first token still validates, assert retry is not a second
pair of bus calls.

```rust
// Before any invoke, refuse if a grant is already spent at this Host
// or at this Host's manager. On any later failure, record every token
// that this execute already spent into self.used so retry is GrantSpent.
for grant in &allowed {
    if self.used.contains(&grant.token) {
        return Err(Refuse::GrantSpent);
    }
}
```

Smallest fail-closed change that matches the README: validate each
grant only after its own invoke, and on error push the tokens already
spent into `self.used` before returning `Bridge`. Add
`failed_two_step_execute_does_not_spend_the_first_grant`.

### R5-11 — mint only the approved journal resource

`runtime_gap` currently treats every Agents write as nameable.

```rust
pub fn runtime_gap(step: &Step) -> Option<&'static str> {
    if step.resource == runtime_bridge::guest_journal(plan_agent(&step.resource))
        && step.capability.action == Action::Write
        && step.capability.operation == "write"
    {
        None
    } else if step.resource.starts_with("localhost://UsersAI/") {
        Some(runtime_bridge::USERS_AI_GAP)
    } else {
        Some("resource is outside the journal bridge")
    }
}
```

Pin: approve `.../secrets`, assert `review.grants()` is empty, assert
execute records BLOCKED with no token and no `component.invoke` audit.

### R5-6d — bind the token to the minting Host before invoke

```rust
// on Grant
host_id: String,

// in approval_check, before invoke
if grant.host_id != self.id {
    return Err(Refuse::ForeignHost);
}
```

Set `host_id` in `mint`. A rewritten `Review.host_id` then fails
`covers` / this check before `invoke_journal`. Pin: clone a review,
set `host_id` to host B, execute on B, assert `ForeignHost` and an
empty audit dir on B.

### R5-8 (optional, same grammar)

Apply the `plain_principal` start/end rules to `host_id`, or write in
the README that `validated_name` allows `.host` and `host.`.

## RA-4, RA-5, and NEEDS RUNTIME

They stay as stated. I reran the tests that name those rows.

| Row | Evidence I reran | Class |
| --- | --- | --- |
| Notes step BLOCKED (`UsersAI`) | `planner_lists_capability_and_resource_for_each_step` still records `USERS_AI_GAP`. R5-10a notes-only: `Ok`, 0 grants, 1 BLOCKED effect, audit 0. | BLOCKED (STATIC). Needs RA-5 |
| Approved journal write stored | `approved_plan_records_blocked_in_process_bridge_effects` and `public_bridge_blocks_journal_storage_before_token_checks` still assert `principal_context_required` / `STORAGE_BRIDGE_GAP`. Nothing is stored. | BLOCKED. Needs RA-4 |
| Altered resource / second use on the public entry | Same public-entry test: storage refusal first, not `capability_denied`. | BLOCKED. Needs RA-4 |
| Spawned `elastos` over the bus | `pgrep -a elastos` empty after the suite. This crate links `handle_remote_request_with_audit_dir`. | NEEDS RUNTIME |

`README.md` and `RUNTIME-ASK.md` still name RA-4, RA-5, and NEEDS RUNTIME
in those words. #448 did not close them. A15 stays open.

## Rows: what counts

| Row | Where the call goes | Class | Counts as |
| --- | --- | --- | --- |
| Preview of the two-step plan | `preview()` | lab | Lab evidence |
| Notes step BLOCKED (`UsersAI`) | `runtime_gap()`, no bus | BLOCKED (STATIC), RA-5 | BLOCKED |
| Reject / altered resource / extra step / reorder / spent grant / other principal / empty plan / duplicate resource / `_ada` / NUL intent / `.` `..` `a..b` `...` host_id / `notes/foo/..` | `Host::approval_check` + execute grammar | lab Host-gate | Lab evidence for those pairs. Multi-step partial spend, secrets-path mint, and rewritten `host_id` are unpinned. |
| Review from another `Host::new()` | `host_id` inequality + `validated_name` | lab Host-gate | Lab evidence for consecutive ids, `host-1`/`host-10`, empty, NUL, `.`, `..`, `a..b`, `...`. A rewritten matching `host_id` still invokes. |
| Unapproved journal `missing_token` | in-process `handle_remote_request_with_audit_dir` | library | Library evidence |
| Altered resource / allow-once / second use | lab `CapabilityManager::validate` | library | Library evidence |
| Same checks on the public bus entry | in-process public function | BLOCKED, RA-4 | BLOCKED |
| Approved journal write stored | in-process public function | BLOCKED, RA-4 | BLOCKED |
| BLOCKED journal effect from an in-process library call | `execute` → `invoke_journal` + audit dir | library | Library evidence |
| Spawned `elastos` over the bus | absent | NEEDS RUNTIME | NEEDS RUNTIME |

## Principles

- 3 No ambient authority. The Host gate holds for the r4 constructed
  pairs. A secrets path still mints a journal token. A rewritten
  `host_id` still reaches the bus. `mint` and `invoke_journal` stay
  callable without `review`.
- 7 One authority model. Approval is still a `Choice` enum.
- 10 One canonical path. README names `approval_check` and the
  in-process public entry. Direct `invoke_journal` is a second path,
  and the README says so.
- 11 Fail closed, then explain. Unicode / percent / slash / `..` fail
  closed at execute. A failed two-journal execute spends the first
  grant and returns `Bridge`.
- 12 Docs, code, and tests agree on BLOCKED storage, on "in-process",
  and on the r4 binds. They stretch on "failed execute leaves the
  grant unused" and on "one token for the scoped journal resource".
- 16 UI is not authority. The preview records no grant.
- 18 Isolated instances. `Review` carries `host_id`. The minted token
  does not. Rewriting the label bypasses the Host compare.
- 19 Consequences, not transports. The public entry refusal is labeled
  BLOCKED. That part holds.

DeepSeek: none. I did not change Runtime source.

## Ranked fixes for #448

1. Pin R5-7a. A failed execute must leave every grant unused, including
   a two-journal plan (closes partial spend and the extra retry bus).
2. Pin R5-11. `runtime_gap` / `mint` only for the exact guest journal
   (closes a journal token for `.../secrets`).
3. Pin R5-6d. Carry the minting `host_id` on `Grant` and refuse before
   invoke (closes the transplanted bus call).
4. Optional: apply `plain_principal` start/end rules to `host_id`, and
   stop minting at `review` for a plan `execute` will refuse.
5. Keep RA-4 / RA-5 as the Runtime half. Until a stored journal is
   asserted, A15 stays open.

## Bookability sentence

A15 is a lab model of preview and a Host approval bind, plus honest
BLOCKED rows for UsersAI (RA-5) and protected storage (RA-4). The r4
mutants are dead. A failed two-journal execute still spends the first
grant, a secrets path still mints a journal token, and a rewritten
`host_id` still reaches the bus.
**Do not book A15. The journal write stays BLOCKED.**

## Next

#448 authors pin R5-7a, R5-11, and R5-6d, or write those limits into
the README as lab limits. RA-4 and RA-5 stay with Anders after 0.8.0.
This review PR stays draft. Do not merge #448 or #284 on the strength
of this file.
