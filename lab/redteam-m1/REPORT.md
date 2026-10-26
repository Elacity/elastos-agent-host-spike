# M1 evidence red team

Independent adversarial review of the evidence behind the M1 checks that the
merged PRs carry. Status: **first pass, in progress**. A row marked
"in progress" is not a verdict yet.

- Target: `spike/agent-host` at `b5069b992dac29d1457576efabd5700e34ea05e7`
  (merge of #277).
- Machine: Linux x86_64 (cloud VM, 4 cores), `rustc 1.91.0`, Python 3.12,
  no `sandbox-exec`, no `wasmtime`, no `wasmer`, no KVM.
- Scope: PRs #248 to #277, plus #179, #201, #213 and #219 (#265 and #275 are
  inside the range).
- Rule: every mutation happens in a scratch clone outside this repository
  (`git clone --shared` of this checkout at HEAD). No lane folder, no
  `BACKLOG.md`, no `lane.env`, no `scripts/` and no Runtime source in this
  repository changes.

## Check wording

The text of the M1 checks lives in the orchestrator's `milestones.json`, which
is not in this repository or anywhere this machine can read. The merged lanes
name some checks themselves, and this review uses those names:

- A6: "process-isolation lab half of A3, A6 and A9" (#201,
  `lab/agent-conformance/src/report.rs`).
- A8: "M1 A8, one fake host-file route" (#179, `lab/agent-conformance/GAPS.md`).
- A10: "cancel at the pending-request point, lab half of A10 (A12 census)" (#213).
- A11: "kill-worker settlement, lab half of A11 (A12 census)" (#219, #249).
- A12: "cleanup census, lab half of A10/A11/A12" (#187, carried by #213, #219,
  #249); #187's title is "Cleanup census: a run leaves no process, socket,
  temp file or grant".

No file, commit message or PR body names A1, A2 or C1 to C8. A draft note for
Sash (bot store, "M1 working session with Anders", 26 Oct) gives M1 as 15/30
and lists the open checks (A3, A4, A5, A7, B1 to B4, C9, D1). This review
therefore attacks each PR's own stated claim and records the check it most
plausibly feeds. Those mappings are marked "inferred". Correct them against
`milestones.json` before reading a verdict as a statement about a numbered
check.

## Verdict table

| PR | Check claimed | Verdict | Evidence | Suggested fix |
| --- | --- | --- | --- | --- |
| #265 confine 070 | Allow rules trace to declared rights (C-series, inferred) | **weak** | FM-C2: a root-wide read `(allow file-read* (subpath "/"))` added to `did-provider/confine.sb` and to the `storage` right in `declared-rights.json` passes `every_did_and_wallet_allow_rule_traces_to_one_declared_right` and `both_file_profiles_bind_one_storage_parameter_contract`. Control: the same rule without the declared entry fails the trace test. The declared-rights file copies the profile's own rules, so the check proves the two files agree, not that a right bounds its rules. | Pin each right id to the rule forms it may claim (for `storage`: only the two `STORAGE_*` param rules) in the check itself, not in the sibling file. |
| #275 confine 073 | Declared rights share one shape; platform baseline justified (C-series, inferred) | **weak** | FM-C3: both platform-baseline justifications replaced by `macOS did-provider executable bound as PROVIDER_EXECUTABLE: x` pass the trace test. Control: `x` without the prefix fails. The check is a prefix test. The PR also replaces "observed startup needs, not approved rights; Anders decides" with "Runtime platform baseline ... not approved rights", which drops the open decision from the label. | Keep "Anders decides" until he decides; check a justification against a fixed list per baseline id, or drop the field. |
| #253 confine 068, #259 confine 069 | Operations table cites each right and its test (C-series, inferred) | **weak** | FM-C4: with `fn outside_read_denied()` renamed and its old text left in a comment, `every_operations_table_cites_existing_tests` passes. Control: rename without the comment fails. The check is `source.contains("fn NAME(")`; the doc already says it does not check `#[test]`. | Parse the test file's `#[test] fn` items (or list tests via `cargo test -- --list`) and match the citation against that list. |
| #253, #259, #265, #267, #275 (shared contract check) | Profiles meet the contract: no `(allow default)`, no network allow, one exec allow (C-series, inferred) | **falsified** (for the source checks' stated scope) | FM-C1: appending `(if #t (allow default))`, `(begin (allow network*))`, `(begin (allow process-exec))` and `(import "bsd.sb")` to `did-provider/confine.sb` passes all four Linux-runnable checks (`both_file_profiles_bind_one_storage_parameter_contract`, the trace test, the removal test, did's `profile_denies_network`). Control: a top-level `(allow default)` fails the contract test and `profile_denies_network`. The checks read only top-level forms that start with `(allow `. Not run here: whether macOS `sandbox-exec` applies the nested rules (Apple's own profiles grant inside `(if ...)` forms); on the Mac the behavioural sandbox tests are the remaining guard. | Refuse any top-level form other than `version`, `deny`, `allow` (no `if`, `begin`, `define`, `import`, macros), or walk nested forms. |
| confine lane (did, wallet) | Sandbox tests prove the macOS profile | **weak** (documented) | FM-C5: on this Linux host 10 wallet and 10 did sandbox tests print a `SKIP ... confinement test` line and libtest reports them as passed (wallet `--test confine`: 43 passed; did: 15 passed). The lane documents the skip; a test count from a non-macOS host is not evidence. | Mark them `#[ignore]` off macOS, or fail on any host without `sandbox-exec`, so a skip never counts as a pass. |
| #263, #271, #274, #277 grant-binding | None ("counts toward no M1 check"); models A5, A7 (F-A7-*), B2 | holds as labelled; **weak** as an A5/A7 model | FM-GB1: one ceiling and one outstanding total for the whole verifier; agent-2's first reserve is refused with `OverCeiling { ceiling: 5, held: 5, asked: 1 }` after agent-1 reserves 5. FM-GB2: `use_path` returns `Ok(())` for `UsersAI/agent-1/notes/page.md` when `page.md` is a real symlink out of the root; the "symlink-shaped" refusal is a character-class check. FM-GB3: agents `agent-1` and `AGENT-1` both bind `UsersAI/<name>/notes`, one directory on a case-insensitive file system. Controls pass. Also: `child_journal` is stored and never checked; `operate` takes no path. | Ledger per grant or per principal; rename `SymlinkShaped` (it cannot see a symlink) or move the check to the provider; canonicalise principal names (case and Unicode) before comparing. |
| #179 cx-agent-conformance 017 | A8 (lab, one route) | in progress | Runtime-side test and Linux-port journey running. | |
| #201 cx-agent-conformance 023 | A6 (lab half, with A3 and A9) | in progress | Runtime-side test and Linux-port journey running. | |
| #213 cx-agent-conformance 026 | A10 (lab half) | in progress | | |
| #219, #249 cx-agent-conformance 027, 035 | A11 (lab half) | in progress | | |
| #187 (+#213, #219, #249) census | A12 | in progress | | |
| #248, #256 cx-agent-conformance 034, 032 | report grading, P7 gap row | in progress | | |
| #250, #252, #260, #266, #268 cc-model-confine | C-series (inferred); #250 and #252 say "counts toward no M1 check" | in progress | | |
| #254, #262, #269, #273 wasm-capsule-lab | memory cap, receipt (C-series, inferred) | in progress | | |
| #255, #258, #261, #264, #270, #272, #276 cu-bus-v2-proposal | None (design input for A3, A5, A7, B2) | in progress | | |
| #251, #257 provider | None ("books no M1 check") | in progress | | |

## Owner suites on this host (baseline, merged bytes)

| Suite | Result on Linux |
| --- | --- |
| `lab/grant-binding` | 32 passed |
| `capsules/wallet-provider` | 106 unit passed; `--test confine` 43 passed (10 of them print a skip line) |
| `capsules/did-provider` | 46 unit passed, 1 ignored; `--test confine` 15 passed, 1 ignored (10 print a skip line) |
| `capsules/model-provider --test confine` | 24 passed |
| `lab/agent-conformance --test report` | 13 passed, 6 failed: "throwaway Homes require macOS" (the harness refuses non-macOS hosts by design) |
| `lab/wasm-capsule` (`--no-fail-fast`) | all targets pass; `tests/run.rs` 38 passed, 1 ignored. No `wasmtime`/`wasmer` here, so the real-engine tests printed "SKIPPED" and returned (see the wasm row when done) |
| `lab/bus-v2-proposal/tests` | passed |

## How to run

```bash
python3 -I -m unittest discover -s lab/redteam-m1/py -v
```

`RT_M1_SCRATCH` (default `/tmp/redteam-m1`) holds the scratch clones and
`RT_M1_TARGET` (default `<scratch>/target`) the shared cargo targets. An
expected failure is a reproduced finding named in this table; a plain test is
a positive control or a precondition. A setup or build error is an ERROR,
never an expected failure, because all builds and owner runs happen in
`setUpClass` and the finding tests only read their results.
