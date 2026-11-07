# M1 evidence red team

Independent adversarial review of the evidence behind the M1 checks that the
recently merged PRs carry. Every verdict below comes from a test or script in
this folder that ran on the machine named here. The draft PR holds the code.

- Target: `spike/agent-host` at `b5069b992dac29d1457576efabd5700e34ea05e7`
  (merge of #277). Scratch clones check out this branch's head, whose bytes
  outside `lab/redteam-m1/` equal `b5069b99`.
- Machine: Linux x86_64 (cloud VM, 4 cores), `rustc 1.91.0`, Python 3.12.
  Not present: `sandbox-exec`, `wasmtime`, `wasmer`, KVM.
- Scope: PRs #248 to #277, plus #179, #201, #213 and #219 (#265 and #275 are
  inside the range).
- Rule: every mutation happens in a scratch clone outside this repository
  (`git clone --shared` of this checkout). No lane folder, no `BACKLOG.md`,
  no `lane.env`, no `scripts/` and no Runtime source in this repository
  changes. Runtime test modules live in `rust/` here and are copied into a
  scratch clone only.

## Check wording

The text of the M1 checks lives in the orchestrator's `milestones.json`. It is
not in this repository, and this machine cannot read it. The merged lanes name
some checks themselves, and this review uses those names:

- A6: "process-isolation lab half of A3, A6 and A9" (#201).
- A8: "M1 A8, one fake host-file route" (#179).
- A10: "cancel at the pending-request point, lab half of A10 (A12 census)" (#213).
- A11: "kill-worker settlement, lab half of A11 (A12 census)" (#219, #249).
- A12: "cleanup census, lab half of A10/A11/A12" (#187, carried by #213,
  #219, #249); #187's title is "Cleanup census: a run leaves no process,
  socket, temp file or grant".

No file, commit message or PR body names A1, A2 or C1 to C8. A draft note for
Sash (bot store, "M1 working session with Anders", 26 Oct) gives M1 as 15/30
and lists the open checks (A3, A4, A5, A7, B1 to B4, C9, D1). The 15 passed
checks are then A1, A2, A6, A8, A10, A11, A12 and C1 to C8. This review
attacks each PR's own stated claim and records the check it most plausibly
feeds; those mappings say "inferred". C1 to C8 are mapped to the confine,
cc-model-confine and wasm-capsule-lab PRs. A1 and A2 most plausibly sit on
older agent-conformance rows (`probe_imports_only_the_bus`,
`ungranted_effect_is_refused`) outside this PR range, so they were not
attacked. Correct the mappings against `milestones.json` before reading a
verdict as a statement about a numbered check.

## Verdict table

Verdicts: **holds** = the claim survived the attack; **weak** = the evidence
is narrower than the claim, or a check passes something it says it refuses
while a working guard sits elsewhere; **falsified** = a reproducible test here
shows the claim, as worded, does not hold.

| PR | Check claimed | Verdict | Evidence | Suggested fix |
| --- | --- | --- | --- | --- |
| #201 cx-agent-conformance 023 | A6, lab half (with A3 and A9): `instance_grant_does_not_authorise_sibling` | **falsified** as evidence that the Runtime keeps a grant inside its instance; holds for "each instance is served by its own session grant" | FM-A6 (Linux port): both A6 rows pass on the merged bytes (Runtime `6aad2790…`). With F-ac3b (the fixture grants the sibling) the row fails, as the lane says. With the Runtime's per-session token check removed (`validate` step 4, `token.capsule != caller_capsule_id`; rebuilt by the lane's own build step as Runtime `6f0bc07d…`) **both rows still pass**. FM-A6 (Runtime handler test): `request_capability` sends every request to pending ("For now, all requests go to pending"); a session that holds a live session grant gets `"pending"` again, so the sibling's "new pending request" is the answer to every request, and the fixture's deny is what refuses the sibling. A control shows step 4 does refuse a token from another session; no A6 journey presents one. FM-AX: its falsifiers edit only lab files. | Add a journey where instance 2 presents instance 1's grant to the provider and the Runtime must refuse it; until then count only "two concurrent instances, each served by its own session grant". |
| #179 cx-agent-conformance 017 | A8, lab half: "one fake host-file route" | **weak** (the row is literally true; its evidence is generic) | FM-A8 (Linux port): the journey passes on the merged bytes, and it still passes when the fake host key is replaced by `localhost://Public/an-ordinary-undeclared-file.txt`; both runs print the same outcome, `exit:Some(1) matched:0 granted:0 denied:0 marker_absent:true unchanged:true provider_traversal_refusal:false`. FM-A8 (Runtime handler test): for both resources the Runtime returns the identical `{"code":"manifest_capability_denied","message":"capsule manifest does not declare authority for <resource>"}`. The host-file protection itself (the provider's `Path traversal not allowed`) is reached only under the manual falsifier F-ac8a, the only caught falsifier that names this row (it edits the fixture grants and the probe manifest). | Declare and grant the probe's resource (or its parent) so the refusal under test is the provider's containment check; add symlink and encoded-path routes; keep the manifest-bound refusal as its own row. |
| #213 cx-agent-conformance 026 | A10, lab half | **weak** | FM-A10: the "cancel" is `self.deny(request, CANCEL_REASON)`, the same `POST /api/capability/deny` the fixture uses for every refusal; only the reason text differs, and it works only while the instance waits on a pending capability request. GAPS: "Resident cancellation stays RT4". Linux port: the journey passes and prints `reason:fixture cancel: instance-1 cancelled mid-run`. FM-AX: its falsifiers edit the controller only. The PR title ("Cancel one instance mid-run") claims more than the row label ("cancel at the pending-request point"). | Count A10 when a Runtime-owned cancel or stop exists (RT4); add a journey that tries to cancel a computing instance (the `runaway` probe) to show the gap. |
| #219, #249 cx-agent-conformance 027, 035 | A11, lab half: "settlement recorded, no silent retry" | **weak** | FM-A11: the killed worker's pending request is settled by the fixture (`settle_orphan` calls `self.deny`; AC-027-ORPHAN is open). Linux port: the journey passes and prints `orphan_before:1 orphan_after:0; settled by the fixture`: the Runtime left the dead client's request pending. The only retry the row can catch is one the lab harness starts (F-kill-retry edits `tests/effects.rs`); the Runtime has no restart path for `run` clients. | Count A11 when the Runtime settles a dead client's requests (AC-027-ORPHAN) and records that in its audit log; keep the fixture settlement as a measured gap row. |
| #187 (carried by #213, #219, #249) | A12, cleanup census | **falsified** against #187's wording; holds for the narrower row label | FM-A12 (Linux port, two runs): `granted_read_succeeds` passes with `cleanup census: root checks PASS; ... outside-root:BLOCKED(AC-006-STORAGE); pending:0 grants:BLOCKED(AC-021-GRANTS)`, and the run creates `/tmp/elastos/storage` (absent before, an empty directory after) outside the throwaway root. FM-A12 (static): GAPS says Unix-socket absence under the root "remains unmeasured"; `run_leaves_no_live_grant` is ignored (AC-021-GRANTS). So socket, grant and outside-root leftovers, three of the title's four nouns, are unmeasured. The lane's own LOG (task 032, #256) records a real `run.sh` exit 1 with `cleanup_census_refuses_each_leftover` FAIL ("process leftover; processes:3"), treated as transient, and a "known kill-worker cleanup flake" (034, 035). | Word A12 as "no process, API port or TMPDIR entry under the root"; close AC-006 (derive `run` storage from the Home) and AC-021 before counting the rest; add a socket selector with a bound-socket control. |
| #248 cx-agent-conformance 034 | Report grading (supports every A row) | **holds** | The six new grader tests pass on Linux (13 of the 19 report tests run here; the other 6 need a macOS Home). | Bind each receipt to the merged commit (see cross-cutting 3). |
| #256 cx-agent-conformance 032 | P7 gap row (A5 groundwork) | **holds** | `p7_gap_row_is_blocked_with_label` passes on Linux; the row stays BLOCKED by design. | None. |
| #253, #259, #265, #267, #275 (shared contract check) | Profiles meet the contract: no `(allow default)`, no network allow, one exec allow (C-series, inferred) | **falsified** for the source checks | FM-C1: appending `(if #t (allow default))`, `(begin (allow network*))`, `(begin (allow process-exec))` and `(import "bsd.sb")` to the did profile passes all four Linux-runnable checks (contract, trace, removal, did's `profile_denies_network`); a top-level `(allow default)` fails them (control). The checks read only top-level forms that start with `(allow `. Not run here: whether macOS `sandbox-exec` applies the nested rules (Apple's profiles grant inside `(if ...)`); on the Mac the behavioural sandbox tests remain the guard. | Refuse every top-level form except `version`, `deny` and `allow` (no `if`, `begin`, `define`, `import`, macros), or walk nested forms. |
| #253 confine 068, #259 confine 069 | did/wallet operations tables cite each right and its test (C-series, inferred) | **weak** | FM-C4: with `fn outside_read_denied()` renamed and its old text left in a comment, `every_operations_table_cites_existing_tests` passes; without the comment it fails (control). The check is `source.contains("fn NAME(")`. | Match citations against `cargo test -- --list` output or parsed `#[test] fn` items. |
| #265 confine 070 | did/wallet allow rules trace to declared rights (C-series, inferred) | **weak** | FM-C2: `(allow file-read* (subpath "/"))` added to the did profile and to the `storage` right passes the trace check and the contract check; undeclared, it fails (control). The declared-rights file copies the profile's own rules, so the check proves the two files agree, not that a right bounds its rules. | Pin each right id to the rule forms it may claim inside the check (for `storage`, only the two `STORAGE_*` param rules). |
| #267 confine 071 | did storage rows prove both sides of their right (C-series, inferred) | **weak** | The cited proofs are sandbox tests; on Linux all 10 did sandbox tests skip and count as passed (FM-C5), and the only Linux-run check is the citation check (FM-C4). Mac-only evidence. | As FM-C4 and FM-C5. |
| #275 confine 073 | Declared rights share one shape; platform baseline is justified (C-series, inferred) | **weak** | FM-C3: both justifications set to `macOS did-provider executable bound as PROVIDER_EXECUTABLE: x` pass; `x` alone fails (control). The check tests a prefix. The PR also replaces "observed startup needs, not approved rights; Anders decides" with "Runtime platform baseline ... not approved rights", which drops the open decision from the label. | Keep "Anders decides" until he decides; compare each justification with a fixed text per baseline id (as the model crate does). |
| did, wallet and model confine suites | Sandbox tests prove the macOS profiles | **weak** (documented) | FM-C5: on this host 10 of 43 wallet, 10 of 15 did and 11 of 24 model `--test confine` results reported "ok" are tests that printed a skip line and ran nothing (each named in the test output). | `#[ignore]` them off macOS, or fail without `sandbox-exec`, so a skip never counts as a pass. |
| #260 cc-model-confine 033 | Model allow rules trace to declared rights (C-series, inferred) | **weak** | FM-C6: the model crate keeps its own line-based copy of the trace check. `(allow\n    file-read* (subpath "/"))` passes it; only the wallet crate's shared check refuses it (`model-provider allow rule has no declared right ...`). FM-C1 and FM-C2 apply as well. Its justification check is exact text, which is stronger than the shared one. | One trace check (P10): call the shared form parser and check from the model crate, or delete the copy. |
| #266 cc-model-confine 031 | Model operations table cites real tests (C-series, inferred) | **weak** | FM-C6: the check reads only backticked spans that start with `model_`. With `allow_rules_trace_to_declared_rights` (cited in the section) renamed, it still passes. | Check every cited test name against the parsed test list. |
| #250 cc-model-confine 029, #252 032 | None ("counts toward no M1 check") | **holds** as labelled | `bound_executable_digest_mismatch_refuses_start` runs on Linux (it is not in the skip list) and passes. | None. |
| #268 cc-model-confine 034 | Path-binding show fails if the profile did not apply | **holds**, Mac-only | `byte_different_file_at_bound_path_starts` is one of the 11 model tests that skip here; not reproduced. | None beyond FM-C5. |
| #254 wasm-capsule-lab 027, #262 028 | Memory cap from the declared manifest size; receipt records it per engine (C-series, inferred) | **weak** | FM-W2: `run` accepts a bundle that declares 64 MB and starts wasmer with no cap ("run accepted the bundle (ok: true) and started wasmer with no memory cap (started: true)"); the receipt line says SKIPPED. Flint's C0 refusal ("never run it uncapped") is not built. FM-W1: with no engine on PATH, 7 of 7 real-engine tests (the four cap tests among them) print SKIPPED and are reported "ok". On wasmtime the cap tests assert the exact trap text, so the Mac evidence holds there. | Refuse to start an engine that cannot apply the declared cap; make real-engine tests `#[ignore]` or fail without the engine. |
| #269 wasm-capsule-lab 029 | Runner entries for two held-back falsifiers | **holds** | Replay on Linux: `summary: 2 CAUGHT of 2` (F-WC3-LANE-FILES-QUOTED, F-WC9-RUN-DROPS-GRANTS). | None. |
| #273 wasm-capsule-lab 030 | Discovery: each engine applies the module's own memory maximum | **holds** as discovery (Mac CLI facts; no engines here) | Its own answer (d) says `capsule.wasm` declares no maximum, so C0 still needs a reader of the module's maximum. | None. |
| #255 cu-bus-v2-proposal 001 | Citation check for the core-calls draft | **weak** | FM-B1: `check.problems` accepts an in-range line that does not support the sentence, and `fn NAME(` inside a comment for a `::NAME` citation. A heuristic scan of the draft's 75 line citations flagged 11; on reading, all 11 are accurate (for example `capsules/model-provider/src/state.rs:609` is the concurrency comparison). | Say "path and line exist" in the docstring, or check a quoted token on the cited line. |
| #258, #261, #264, #270, #272, #276 cu-bus-v2-proposal 002 to 007 | None (design input; "leaves those checks open") | **holds** | Citations hold on the scan above; the draft claims no check. | None. |
| #251 provider 030 | None (proof of runner verdicts) | **holds** | Replay of its 35 ids on Linux at `f92fe859`: `summary: 35 CAUGHT of 35`. | None. |
| #257 provider 031 | None ("books no M1 check") | **holds** | All 69 explicit `path:line` citations exist at `ce62fa9`; the 5 table rows name the exact test functions and `#[ignore]` lines; spot checks (`lib.rs:10161`, `:13262`, `adapters.rs:1081`, `execution.rs:4349`) say what the report says. | None. |
| #263, #271, #274, #277 grant-binding 001 to 004 | None ("counts toward no M1 check"); models A5, A7 (`F-A7-*`), B2 | **holds** as labelled; **weak** as an A5/A7 model | FM-GB1: one ceiling and one outstanding total for the whole verifier; agent-2's first reserve is refused with `OverCeiling { ceiling: 5, held: 5, asked: 1 }` after agent-1 reserves 5. FM-GB2: `use_path` returns `Ok(())` for `UsersAI/agent-1/notes/page.md` when `page.md` is a real symlink out of the root. FM-GB3: agents `agent-1` and `AGENT-1` both bind `UsersAI/<name>/notes`, one directory on a case-insensitive file system. Also: `child_journal` is stored and never checked; `operate` takes no path. | Ledger per grant or principal; rename `SymlinkShaped` or move the check to the provider; canonicalise principal names (case, Unicode) before comparing. |

## Cross-cutting findings

1. **Falsifiers edit only the lab.** Every caught falsifier that names an
   A6, A8, A10, A11 or A12 row edits files under `lab/agent-conformance/`
   (FM-AX). None mutates Runtime code. The one Runtime mutation tried here
   (FM-A6) survives both A6 rows.
2. **A skip counts as a pass** on hosts without the tool: 31 confine tests
   (FM-C5) and 7 wasm real-engine tests (FM-W1) report "ok" here having run
   nothing. A test count from such a host is not evidence.
3. **Evidence is bound to dirty Mac trees.** The agent-conformance LOG for
   034 and 035 records results from "the dirty candidate, rather than a
   committed change", with receipts uncommitted on the Mac. The Linux re-run
   here is the first run of these journeys on the merged commit that the
   repository can point to.
4. **One check, two copies.** The model crate keeps its own trace and
   citation checks, with different parsers and different gaps (FM-C6); did
   keeps its own profile parser for `profile_denies_network`.
5. **Positive result.** On Linux, with three scratch-only shims, all six
   merged A journeys pass (A6 both rows, A8, A10, A11, and the A12 census on
   `granted_read_succeeds`), and the A6 row fails under the lane's own
   F-ac3b. The journeys are sound as fixture journeys; the gaps above are
   about what they can and cannot show of the Runtime.

## Results by module (this machine, final branch head)

| Module | Tests | Expected failures (reproduced findings) | Plain tests |
| --- | --- | --- | --- |
| `test_m1_ac_linux.py` (Linux port, Runtime built twice) | 6 | 3: FM-A6, FM-A8, FM-A12 | 3 pass: merged journeys, F-ac3b control, rebuilt-Runtime precondition |
| `test_m1_runtime.py` (`elastos-server` handler tests) | 3 | 2: FM-A6, FM-A8 | 1 pass: 4 Runtime controls |
| `test_m1_agent_conformance.py` (static) | 9 | 5: FM-AX, FM-A10, FM-A11 (two), FM-A12 | 4 pass |
| `test_m1_confine.py` | 11 | 5: FM-C1 to FM-C5 | 6 pass (controls) |
| `test_m1_model_confine.py` | 5 | 3: FM-C5 (model), FM-C6 (two) | 2 pass |
| `test_m1_wasm.py` | 4 | 2: FM-W1, FM-W2 | 2 pass (control, #269 replay) |
| `test_m1_bus_v2.py` | 3 | 2: FM-B1 (two) | 1 pass |
| `test_m1_grant_binding.py` | 4 | 3: FM-GB1 to FM-GB3 | 1 pass (controls) |
| `test_m1_provider.py` | 3 | 0 | 3 pass (#257 citations, #251 replay) |

## Owner suites on this host (baseline, merged bytes)

| Suite | Result on Linux |
| --- | --- |
| `lab/grant-binding` | 32 passed |
| `capsules/wallet-provider` | 106 unit passed; `--test confine` 43 passed (10 are skips) |
| `capsules/did-provider` | 46 unit passed, 1 ignored; `--test confine` 15 passed (10 are skips), 1 ignored |
| `capsules/model-provider --test confine` | 24 passed (11 are skips) |
| `lab/agent-conformance --test report` | 13 passed, 6 failed: "throwaway Homes require macOS" (by design) |
| `lab/agent-conformance --test effects` (Linux port) | the six A journeys pass (see FM-A6) |
| `lab/wasm-capsule` (`--no-fail-fast`) | all targets pass; `tests/run.rs` 38 passed, 1 ignored (7 are skips) |
| `lab/bus-v2-proposal/tests` | passed |

## Not run here

- macOS `sandbox-exec` behaviour (whether nested SBPL rules apply; every
  sandbox test). The Mac remains the only place the confine profiles run.
- Real `wasmtime` and `wasmer`.
- The agent-conformance journeys on macOS. The Linux port uses three
  scratch-only shims (`test_m1_ac_linux.py`: the Linux data-dir rule, the
  Linux `lsof` path and the `linux-amd64` platform key). Linux is not the
  lane's declared host; FM-A6, FM-A8 and FM-A12 should be repeated on the Mac.
- The full M1 check text. Mappings marked "inferred" need `milestones.json`.

## How to run

```bash
python3 -I -m unittest discover -s lab/redteam-m1/py -v
```

`RT_M1_SCRATCH` (default `/tmp/redteam-m1`) holds the scratch clones and
`RT_M1_TARGET` (default `<scratch>/target`) the shared cargo targets;
`RT_M1_AC_NAME` names the agent-conformance port clone. The Runtime builds
are the slow part (`elastos-server`, about 8 minutes each here). FM-A12
refuses to start if `/tmp/elastos/storage` already exists, because it measures
whether a run creates it. An expected failure is a reproduced finding named in
this table; a plain test is a positive control or a precondition. All builds
and owner runs happen in `setUpClass`, so a setup or build error is an ERROR,
never an expected failure.
