# Independent adversarial review r4 of #284 (A15) at 36049b90

Reviewer: Cursor Grok 4.6 (Grok family). #284 was authored by Claude. r1 was
PR #399 at `cb102ed1`. r2 was PR #414 at `4f17e482`. r3 was PR #428 at
`d169f90`. This is the fourth independent review. I read
`lab/review-a15-284-r3/REVIEW.md` first.

Reviewed head: `36049b90b6102b3dff937bf761f1a03029ce24e1`  
Code commit: `c2e7936e13f6be5dcfda372c0d2de9d1596337cd`  
Worktree: `/tmp/a15-review-r4/36049b90` (detached at that commit)  
Review branch: `cursor/review-a15-284-r4-2898` from `origin/spike/agent-host` at `970abb4ca83baa2ec6b94c3bc7e3d2f5fe55209a`  
Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28)  
Date: 27 Oct 2026

**Bookability for A15: still open. The journal write stays BLOCKED.**

The r3 surviving mutants are dead. The author's 35/0 count is real. I
replanted all 20 author plants and R3-1..R3-12 myself. The Host gate still
executes constructed plans the suite never builds: a principal `plan()`
would refuse, an empty plan, a two-journal plan, and a host id of `a..b`
or `...`. Two r3-era checks (exact `.` / `..` on a name, and path grammar
on a BLOCKED notes step) exist in the source and are unpinned.

This folder is the only change on this branch. #284's branch was left
alone. Nothing was merged. Elacity/elastos-runtime was left alone.

## Verdict

**VERDICT: FIX**

Lab half only. The r3 plants are CAUGHT. The Host gate is still open for
constructed plans the suite never builds.

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
| Execute exactly the approved plan | Table-plan reject, reorder, extra step, altered plan, other principal, spent grant, second `Host::new()`, newline split, trailing space, parent-path covers, `host-1`/`host-10`, NFC/NFD, confusable, over-length, `..` / trailing slash / ASCII case / percent covers, exact BLOCKED token, empty or NUL `host_id`, and ordered `canonical()` are pinned. Constructed `_ada` / `ada.` / `.ada`, an empty plan, and `[journal, journal]` still execute. | BLOCKED for the product journey. Lab Host-gate is incomplete for constructed plans. |
| Refusal + reason | r3 refusals now have named reasons. Empty-plan success has no reason. A principal `plan()` would refuse still returns `Ok`. | Partial |
| CAUGHT falsifier | Author plants F-A15-approval, M1–M8, M6-host, N1–N10, and R3-1..R3-12 are CAUGHT. New plants R4-1 and R4-2 survive the author's 34 Host/library tests. | Partial |
| Required reviews | r1 was FIX. r2 was FIX. r3 was FIX. This r4 is FIX. | Missing PASS |

**A15 is not bookable.**

## What I rebuilt and reran

Detached worktree only. First command was `cargo fetch --locked`.

```bash
export RUST_TEST_THREADS=2
cd /tmp/a15-review-r4/36049b90
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
| `cargo test ... --skip model_planted_bugs_are_caught` | 0 | `34 passed; 0 failed; 0 ignored` in 1.30s |
| `cargo test ... model_planted_bugs_are_caught` | 0 | `1 passed` in 131.04s; every named plant line printed `FAILED` |

Together that is the author's **35/0**. `pgrep -a elastos` was empty
after the suite. Clippy of `elastos-server` printed two `AsyncFd::new`
deprecation warnings. They are in the dependency.

SHA-256 of `lab/intent-planner/src/lib.rs` at the reviewed head, after
the author runner, after my independent replant, and after every restore
I made: `443ea480cf2775e583b4e376b1b7687fa0e8655c2c321e6c15fe1f498164e2cb`.

SHA-256 of `lab/intent-planner/src/runtime_bridge.rs`:
`b5a35da21f95b989ac473a03ea5f3ca2a1e3a064cdcd07de62ffc6f250c31932`.

Those are the hashes the author named in `reports/A15-r3-surviving-plants.md`.

## Author plants, rerun by me

I applied each plant file myself (a script that reads `plants/*.txt`,
replaces once, runs the named `--exact` test, then writes the original
bytes back). Named-test lines below are exact. Source restored to
`443ea480…` after every plant.

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

The author claim "all 20 author plants + R3-1..R3-12 CAUGHT, 35/0, lib.rs
sha `443ea480…`" holds. The r3 holes are pinned in code, not only in docs.

## New attacks (reviewer-owned)

Each probe ran against the clean tree at `36049b90` unless a plant is
named. Source restored to `443ea480…` after every plant.

### Grammar on one field but not another — SURVIVED (LIVE execute)

`plan()` uses `plain_principal`: `[a-z0-9][a-z0-9._-]*` and it does not
end in `.`. `Host::execute` uses `validated_name` on the principal:
`[a-z0-9._-]`, and only the whole string `.` or `..` is refused.
`intent` and `step.id` have no grammar. `host_id` uses `validated_name`.
`resource` uses `validated_path` (ASCII letters in either case).

| Probe | Clean tree | Grade |
| --- | --- | --- |
| `plan("_ada")` is `BadPrincipal`; `review`+`execute` of constructed `_ada` | `Ok`, one journal grant, effects recorded | **LIVE execute** |
| constructed `ada.` | `Ok` | **LIVE execute** |
| constructed `.ada` | `Ok` | **LIVE execute** |
| constructed intent `INTENT + NUL + extra` | `Ok` | **LIVE execute** |
| constructed `step.id = 0` on the table plan | `Ok` | **LIVE execute** |
| matching `host_id = "a..b"` | `Ok`, journal invoke ran | **LIVE execute** |
| matching `host_id = "..."` | `Ok`, journal invoke ran | **LIVE execute** |
| `validated_path` keeps `Users` / `AppData` / `Agents`; `validated_name` refuses those tokens | as written | CAUGHT (alphabet split is intended) |

`Host::review` still accepts any constructed `Plan`. The bind is
byte-exact, so `_ada` does not collide with `ada`. The hole is
admission: the Host runs a name `plan()` would refuse.

Exact pin (apply the planner rule at execute, and at review):

```rust
if !plain_principal(&plan.principal) {
    return Err(Refuse::BadPrincipal);
}
```

### Mixed-case Runtime prefixes — CAUGHT

A grant for `localhost://Users/self/.AppData/Agents/ada/...` does not
cover `users/`, `.appdata/`, or `/agents/`. `covers` stayed false.
`runtime_gap` does not mint a journal grant for `users/`. Execute of a
`users/` plan returned `Ok` with one BLOCKED "outside the journal
bridge" effect and an empty token. That is fail-closed for the grant.

No plant. R3-6 already pins ASCII case on the agent segment.

### Separators other than `/` — CAUGHT

Grant for `.../journal` did not cover:

- `...\journal` (backslash)
- `...` + U+2215 + `journal`
- `...` + U+FF0F + `journal`

`approve`+`execute` of a backslash journal was `OutsidePlan`.
U+2215 and U+FF0F fail `validated_path` (`!raw.is_ascii()`).
Backslash fails `valid_path_segment`.

### Length in chars vs bytes — CAUGHT

`NAME_MAX` and `RESOURCE_MAX` use `str::len()` (bytes). Names and paths
must be ASCII, so a passing value has `chars == bytes`.

| Input | Result |
| --- | --- |
| 255-byte ASCII path | `validated_path` Some |
| 256-byte ASCII path | None |
| 200 × `é` (200 chars, 400 bytes) | None (`!is_ascii`, and bytes > 255) |
| 64-byte `a` name | Some |
| 65-byte `a` name | None |

A plant that switched `raw.len()` to `raw.chars().count()` would still
refuse the UTF-8 cases at the ASCII check. No live execute.

### Empty or zero-step plan — SURVIVED (LIVE execute)

```rust
let empty = Plan { principal: "ada".into(), intent: INTENT.into(), steps: vec![] };
host.review(&empty, Choice::Approve); // grants empty
host.execute(&review, &empty, &empty.steps); // Ok, effects=0
```

There is no guard to remove. The suite never builds an empty plan.

Exact pin:

```rust
if plan.steps.is_empty() || steps.is_empty() {
    return Err(Refuse::OutsidePlan);
}
```

A notes-only plan (one BLOCKED UsersAI step, no grant) returned `Ok`
with one BLOCKED effect. That matches the table-plan notes row. It is
not an empty plan.

### Duplicate steps — mixed

| Probe | Clean tree | Grade |
| --- | --- | --- |
| approve `[journal]` execute `[journal, journal]` | `OutsidePlan` | **CAUGHT** (`steps != plan.steps`) |
| approve `[journal, journal]` ids 1 and 2 | `Ok`, 2 grants, 2 effects, 2 bus calls | **LIVE execute** |
| approve `[journal, journal]` same id 1 | `Bridge` (second `validate` hits use limit; effects stay 0) | CAUGHT (fail-closed) |

The extra-step test only adds a step the plan does not list. The suite
never builds two journal writes in one plan.

Exact pin: refuse a repeated `step.id` or a repeated journal resource
at `review` and at `approval_check`.

### JSON / serde duplicate keys or unknown fields — CAUGHT (no surface)

`Review` and `Plan` are `#[derive(Debug, Clone, PartialEq, Eq)]`. No
`Serialize`, no `Deserialize`. Approval is an in-process Rust struct.
`serde_json` is used only to build the outbound bus line in
`invoke_journal`. There is no approval JSON to confuse.

### Integer overflow in step indices — CAUGHT

`step.id` is a `u32`. `canonical()` writes `to_string()`. `covers`
compares with `==`. There is no addition of attacker-controlled ids.
`plan()` uses `u32::try_from(index + 1)` on a 2-row table.

Both table steps set to `u32::MAX` still ran as the table plan (notes
BLOCKED + journal BLOCKED). Ids `u32::MAX` and `0` stayed distinct.
No wrap, no crash.

### Validation after hashing — CAUGHT (no live execute)

`review()` stores `plan.canonical()` of the raw fields. `approval_check`
compares those raw bytes, then `execute` runs `validated_name` /
`validated_path`. Validation is identity-or-refuse. It does not fold.

| Probe | Clean tree |
| --- | --- |
| approve+execute NFC `café` (same raw) | `BadPrincipal` |
| approve+execute 256-byte principal | `BadPrincipal` |
| approve+execute journal with a trailing `/` | review still minted a grant; execute `OutsidePlan` (`covers` is false) |

The author's "validated before compare" sentence is true for `host_id`.
It is false for principal and resource: those are compared first, then
refused. That order does not create a collision while validation refuses
instead of folding.

### BLOCKED token with trailing NUL — CAUGHT

Forced reply `principal_context_required\0` / exact gap → `Bridge`.
Exact code / gap + `\0` → `Bridge`. Exact token after those probes
still ran. `classify` concatenates code, `'\n'`, and message with no
trim.

### host_id `.` or `..` — CAUGHT on the clean tree, unpinned

Matching `host_id = "."` and matching `host_id = ".."` are
`ForeignHost` before any bus call. Audit dirs stayed empty.

The suite never builds those two strings. `empty_or_nul_host_id_is_foreign`
pins empty and NUL only. Plant R4-1 (below) removes the two comparisons
and the author's 34 tests still pass. Under that plant, `host_id = "."`
returned `Ok`, 2 effects, and 2 `component.invoke` audit records.

Embedded `a..b` and `...` already execute on the clean tree (see
grammar). Path segments use the same rule: a segment may contain `.`
and may be `a..b`; only the whole segment `.` or `..` is refused.

## New plants that survived the author's suite

| Id | Guard removed | Author suite | Probe | Grade |
| --- | --- | --- | --- | --- |
| R4-1 | `validated_name` drops `raw == "." \|\| raw == ".."` | 34/0 SURVIVED | matching `host_id = "."` returned `Ok`, 2 effects, 2 audit records. Clean tree: `ForeignHost`, audit empty. | **LIVE execute under plant** |
| R4-2 | delete the `validated_path` loop in `execute` | 34/0 SURVIVED | constructed notes resource `.../notes/foo/..` returned `Ok`, 2 effects. Clean tree: `OutsidePlan`. | **LIVE execute under plant** |

### R4-1 exact patch

```text
--- old
    if raw.is_empty()
        || raw.len() > NAME_MAX
        || raw.contains('\0')
        || raw.contains('%')
        || raw == "."
        || raw == ".."
    {
--- new
    if raw.is_empty()
        || raw.len() > NAME_MAX
        || raw.contains('\0')
        || raw.contains('%')
    {
```

### R4-2 exact patch

```text
--- old
        if steps
            .iter()
            .any(|step| validated_path(&step.resource).is_none())
        {
            return Err(Refuse::OutsidePlan);
        }
--- new
        (deleted)
```

R4-2 is the grammar-mismatch plant for a BLOCKED step: `covers`
validates a journal path; a UsersAI notes step never calls `covers`.
The only grammar on that step is the unpinned `execute` loop.

## Rows: what counts

| Row | Where the call goes | Class | Counts as |
| --- | --- | --- | --- |
| Preview of the two-step plan | `preview()` | lab | Lab evidence |
| Notes step BLOCKED (`UsersAI`) | `runtime_gap()`, no bus | BLOCKED (STATIC), RA-5 | BLOCKED |
| Reject / altered resource / extra step / reorder / spent grant / other principal / newline / trailing space / NFC / confusable / over-length / ordered plan object | `Host::approval_check` | lab Host-gate | Lab evidence for the table plan. Constructed `_ada`, empty plan, and `[journal, journal]` are unpinned. |
| Review from another `Host::new()` | `host_id` inequality + `validated_name` | lab Host-gate | Lab evidence for consecutive ids, `host-1`/`host-10`, empty, and NUL. Exact `.` / `..` exist in source and are unpinned. `a..b` and `...` execute. |
| Unapproved journal `missing_token` | in-process `handle_remote_request_with_audit_dir` | library | Library evidence |
| Altered resource / allow-once / second use | lab `CapabilityManager::validate` | library | Library evidence |
| Same checks on the public bus entry | in-process public function | BLOCKED, RA-4 | BLOCKED |
| Approved journal write stored | in-process public function | BLOCKED, RA-4 | BLOCKED |
| BLOCKED journal effect from an in-process library call | `execute` → `invoke_journal` + audit dir | library | Library evidence. Exact BLOCKED bytes, trailing space, case, extra text, and trailing NUL are pinned. |
| Spawned `elastos` over the bus | absent | NEEDS RUNTIME | NEEDS RUNTIME |

## README and row-label check

Honest now, and kept:

- In-process `handle_remote_request_with_audit_dir`.
- Spawned `elastos` is NEEDS RUNTIME.
- UsersAI notes BLOCKED (RA-5). Stored journal BLOCKED (RA-4).
- Grammar before compare for names and paths, refuse, never fold or
  truncate: true for the pairs the suite builds. `canonical()` keeps
  step order. BLOCKED reply is a whole token. Empty and NUL `host_id`
  are `ForeignHost` before invoke.
- Runtime alphabet `Users`, `AppData`, `Agents` is kept as written.

Stretch that remains:

- README "names and paths are validated by grammar". `plan()` and
  `execute` use two name grammars. `intent` and `step.id` have none.
- README does not say an empty plan is refused. It executes.
- README does not say a plan may list the journal once. Two distinct
  journal step ids execute twice.
- "validated before compare" is true for `host_id` only.

## Principles

- 3 No ambient authority. The Host gate holds for the table plan and
  for the r3 constructed pairs. A constructed `_ada` plan, an empty
  plan, and a two-journal plan still execute. `mint` and
  `invoke_journal` stay callable without `review`.
- 7 One authority model. Approval is still a `Choice` enum.
- 10 One canonical path. README names `approval_check` and the
  in-process public entry. Direct `invoke_journal` is a second path,
  and the README says so.
- 11 Fail closed, then explain. Invalid NFC / over-length / trailing
  slash fail closed after the raw bind. An empty approved plan returns
  `Ok`. A principal `plan()` would refuse also returns `Ok`.
- 12 Docs, code, and tests agree on BLOCKED storage, on "in-process",
  and on the r3 binds. They stretch on one name grammar and on empty
  or duplicate plans.
- 16 UI is not authority. The preview records no grant.
- 18 Isolated instances. `Review` carries `host_id`. Empty, NUL,
  `host-1`/`host-10` are pinned. `.` and `..` are unpinned. `a..b`
  and `...` execute.
- 19 Consequences, not transports. The public entry refusal is labeled
  BLOCKED. That part holds.

DeepSeek: none. I did not change Runtime source.

## Ranked fixes for #284

1. Use one name grammar at `plan()`, `review`, and `execute`. Refuse
   `_ada`, `ada.`, and `.ada` (closes the plan/execute split).
2. Refuse an empty step list at `review` and at `approval_check`
   (closes empty-plan `Ok`).
3. Refuse a repeated `step.id` or a repeated journal resource (closes
   `[journal, journal]` ids 1 and 2).
4. Pin `host_id` `.` and `..` with a named test (closes R4-1). Keep
   `a..b` as a legal segment, or refuse embedded `..` in the name
   grammar and say so.
5. Pin the `execute` path loop with a notes `.../foo/..` case (closes
   R4-2).
6. Keep RA-4 / RA-5 as the Runtime half. Until a stored journal is
   asserted, A15 stays open.

## Bookability sentence

A15 is a lab model of preview and a Host approval bind, plus honest
BLOCKED rows for UsersAI (RA-5) and protected storage (RA-4). The r3
mutants are dead. Constructed principals `plan()` would refuse, an
empty plan, a two-journal plan, and an unpinned `.` / `..` host-id
check still survive the author's tests.
**Do not book A15. The journal write stays BLOCKED.**

## Next

#284 authors pin the empty plan, the `plain_principal` execute rule,
duplicate journal steps, and R4-1 / R4-2, or write those limits into
the README as lab limits. RA-4 and RA-5 stay with Anders after 0.8.0.
This review PR stays draft. Do not merge #284 on the strength of this
file.
