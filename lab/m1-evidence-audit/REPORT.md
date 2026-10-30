# M1 honest-count audit

```text
Lane:         lab/m1-evidence-audit
Branch:       cursor/m1-evidence-audit-cc38
Base:         spike/agent-host 62e4aa697052d923bedb98a2c9a62917fc5b0c25
Develop:      Elacity develop not merged (this folder only)
Machine:      Linux x86_64 cloud VM, rustc 1.91.0, no sandbox-exec, no KVM
```

No remote `lab/m1-evidence-audit` branch existed. An earlier agent
(`bc-c11f6457`) died mid-read with no commit. This folder is new.

## Rule

A check counts only when its complete journey, refusal evidence and
required reviews all pass.

The 11 checks in the honest count are A1, A2, A8, C1, C2, C3, C4, C5,
C6, C7 and S1. That drops A6, A10, A11 and A12 from the 15 booked
"done" on 26 Oct (red-team #294 falsified A6 and A12, and weakened
A10 and A11). C8 stays out of the count (in flight).

None of the 11 hold under that rule on this read. None is falsified
against its own wording by a test run here. Every row is **weak**.

## Verdict table

| Check | Verdict | Evidence | Refusal row | Runtime or kernel | Skip counted as pass | Needs Mac |
| --- | --- | --- | --- | --- | --- | --- |
| A1 | weak | unit `rejects_extra_component_import`; lab `probe_imports_only_the_bus`; draft #301 `wasi_import_is_refused_at_admission` | yes (unit + draft Runtime) | merged path is unit/lab; real Runtime row is draft #301 | no | no for unit and #301; older probe path is Mac |
| A2 | weak | ignored e2e `the_agent_host_writes_and_reads_its_journal_through_the_real_bridge`; unit `a_stale_journal_revision_is_refused_and_the_stored_journal_is_kept`; reviews #8 #9 #20 | yes (unit stale revision) | e2e is a real bridge test, ignored | no (ignored, not ok) | no; needs guest wasm |
| A8 | weak | #179 `host_key_read_is_refused`; red-team FM-A8; draft #301 `agent_host_host_key_read_is_refused` | yes | #179 real Runtime on Mac; #301 real Runtime on Linux; FM-A8 same outcome for an ordinary undeclared file | no (`probe::skipped` panics) | yes for #179 |
| C1 | weak | `init_requires_storage_without_key` in did-provider | yes | provider unit; no Runtime | no | no |
| C2 | weak | `nickname_metadata_change_reports_storage_error`; `init_reports_nickname_read_error` | yes | identity + provider unit | no | no |
| C3 | weak | `outside_write_denied`, `outside_read_denied`; FM-C1 / FM-C5 | yes | macOS sandbox-exec; Runtime does not apply confine.sb | yes | yes |
| C4 | weak | `verify_did_recovery_under_profile` | yes | same gate as C3 | yes | yes |
| C5 | weak | `missing_storage_root_is_refused` | yes | provider unit; no Runtime | no | no |
| C6 | weak | `confined_outside_write_is_denied`; `wallet_operations_stay_under_root` | yes | profile half is sandbox-exec; stay-under-root is in-process | yes (profile half) | yes for the profile |
| C7 | weak | `model_provider_ops_under_profile`; `model_outside_write_denied` | yes | sandbox-exec; Runtime uses its own inline model policy | yes | yes |
| S1 | weak | Flint booking 26 Oct 21:10 | no | none | no | no |

## Reviews

`gh pr view` on every cited PR returned empty `reviews` and
`latestReviews`. Bodies still say "reviews PASS: …". Handoff files
exist only for #3 (verdict not recorded), #8, #9 and #20 (Codex PASS).
#88 / #112 claim Codex only. #179 claims Claude only. #294 and #301
are drafts with no review. That is why no check reaches **holds**.

## Per check

### A1

Wording asks for Runtime admission of a WASM guest that imports only
`elastos:bus`. Merged #3 is Overnight 1 (S0c, S1, S2, S3). Its review
record does not name a WASI-import row. The live allowlist test is
`rejects_extra_component_import` (synthetic bytes). The lab probe
`probe_imports_only_the_bus` checks the probe's own imports.

Draft #301 runs `elastos serve` and `elastos run` on Linux and refuses
`wasi:cli/environment@0.2.0` with the allowlist reason. F-A1a and
F-A1-runtime are recorded CAUGHT on that draft. The PR is unreviewed
and unmerged, so it does not close the check.

### A2

#20 is the named e2e journey through the real bridge. The test is
`#[ignore]` and points at `run-e2e.sh`. cargo reports ignored, not ok.
The revision refusal is a different unit test. Codex PASS is on file
for #8, #9 and #20. GitHub has no review objects.

### A8

#179's `host_key_read_is_refused` needs a macOS throwaway Home. On
Linux, `ThrowawayHome` fails and `probe::skipped` panics, so the skip
is not a pass. Red-team #294 FM-A8 (Linux port) still gets the same
outcome when the fake key is replaced by an ordinary undeclared file:
the Runtime returns `manifest_capability_denied`. Draft #301 repeats
that manifest-bound refusal with an injected agent-host on a real
Linux Runtime. Its shipped-bytes row is BLOCKED (AC-002-ARGS).

### C1, C2, C5

These are provider or identity unit rows. They have a refusal with a
reason. They do not need a Mac. They do not run a Runtime. Reviews are
PR-body strings only. Falsifiers are comments or later confine lists,
not a CAUGHT receipt read here.

### C3, C4, C6, C7

Named sandbox tests exist. On this host they print SKIP and return;
cargo reports ok (red-team FM-C5). The Mac remains the only place the
profiles run. The Runtime does not generate or apply these files (B3).
Red-team FM-C1 shows nested `(allow default)` forms pass the Linux
source checks. C7 claims one reviewer.

### S1

This is Rong's principles sign-off, not the agent-host slice
`sell-closed-admission`. Flint booked it DONE for seven running lanes
(lowest B) and named `rong-20261026-1920.md`. That file is not in this
repository. Stopped lanes were not graded. There is no refusal row.
The wording "every lane" is wider than the booking.

## Checker

```bash
python3 -I lab/m1-evidence-audit/audit.py
python3 -I lab/m1-evidence-audit/falsify.py F-M1-ROW
python3 -I -m unittest discover -s lab/m1-evidence-audit -v
```

`audit.py` reads `evidence.json` and each cited file (or `git show`
for draft #294 and #301). It fails when a required row id is missing
or a cited marker is gone.

## Falsifier

F-M1-ROW deletes `C1-init-requires-storage` from a temp catalog.
`audit.py` must exit 1 and name that row. Reverted by using a temp
copy; the committed catalog is unchanged.

## Tests run here

| Command | Result |
| --- | --- |
| `python3 -I lab/m1-evidence-audit/audit.py` | exit 0, catalog rows resolved |
| `python3 -I lab/m1-evidence-audit/falsify.py F-M1-ROW` | `F-M1-ROW: CAUGHT (removed C1-init-requires-storage)` |
| `python3 -I -m unittest discover -s lab/m1-evidence-audit -v` | 2 passed |
| `cargo test --manifest-path capsules/did-provider/Cargo.toml init_requires` | `tests::init_requires_storage_without_key` ok |
| `cargo test --manifest-path capsules/did-provider/Cargo.toml init_reports_nickname_read_error` | ok |
| `cargo test --manifest-path capsules/wallet-provider/Cargo.toml missing_storage_root` | `tests::storage_root::missing_storage_root_is_refused` ok |
| `cd elastos && cargo test -p elastos-identity nickname_metadata_change` | `store::tests::nickname_metadata_change_reports_storage_error` ok |
| `cd elastos && cargo test -p elastos-server rejects_extra_component_import` | `component::tests::rejects_extra_component_import` ok |
| `cd elastos && cargo test -p elastos-server a_stale_journal_revision_is_refused` | `resource_bridge::tests::a_stale_journal_revision_is_refused_and_the_stored_journal_is_kept` ok |
| `cd elastos && cargo test -p elastos-server the_agent_host_writes_and_reads_its_journal` | 0 passed, 1 ignored |
| `cargo test --manifest-path capsules/did-provider/Cargo.toml --test confine outside_write_denied -- --exact` | SKIP `sandbox-exec is absent`, then `ok` |
| `cargo test --manifest-path capsules/did-provider/Cargo.toml --test confine verify_did_recovery_under_profile -- --exact` | SKIP, then `ok` |
| `cargo test --manifest-path capsules/wallet-provider/Cargo.toml --test confine confined_outside_write_is_denied -- --exact` | SKIP, then `ok` |
| `cargo test --manifest-path capsules/model-provider/Cargo.toml --test confine model_outside_write_denied -- --exact` | SKIP, then `ok` |

## Not run here

- macOS `sandbox-exec` behaviour
- agent-conformance throwaway Homes
- the ignored A2 e2e (guest wasm)
- draft #301's Runtime builds
- red-team scratch Runtime rebuilds
- `milestones.json` (not in this repository)

## Next

Keep the 11 as the honest count. Do not book any of them as passed
until the missing review objects, the draft #301 merge-and-review, the
Mac profile runs, and the S1 source review are in hand. A1 and A8 wait
on #301. C3, C4, C6 and C7 wait on the Mac and on B3.
