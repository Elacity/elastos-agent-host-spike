# Review r7 of draft PR #457

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #457 (`cursor/a12-r6-survivors-c4de`). This folder only adds
`lab/review-a6-a12-457-r7/`. It does not edit #457, #343, other `lab/`
folders, or Runtime source. It does not merge or close anything.

- Target: #457 head `4564a30f1384f1b9d070762eb8e4a8e727bd2959`.
- Base of this review PR: `cursor/a12-r6-survivors-c4de`.
- Prior review: PR #441 of `5547edea` — r6 **FIX** (A12 Linux half).
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`.
- How to run: `lab/review-a6-a12-457-r7/run.sh`.
- Subject worktree: `/tmp/pr457-r7`, detached at the pin above.

Evidence is being collected. The counting settlement below is already
proven from git and plant headers. Reruns, independent replants, and
new hunts follow in this same review.

## Counting settlement (already proven)

The author's headings `Old plants 34/39 CAUGHT` and `New plants 12/14
CAUGHT` are **plants / CAUGHT-lines**, not **caught / total**.

- #343 at `cursor/a6-a12-evidence-fix-6e3b` has **34** plant files.
  Five of those name more than one test, so the runner prints **39**
  CAUGHT lines. No old plant is missing on #457.
- #457 adds **12** plant files and removes **0**. One new plant
  (`M-A12-NO-RECURSE-WATCH`) names three tests, so the runner prints
  **14** new CAUGHT lines.
- Disk total: **46** plant files, **53** `test:` lines.
- The FINDINGS table lists all 46 plants as CAUGHT. It does not omit
  a SURVIVED row. The slash in `34/39` is not a miss rate.

Old plants (34 files / 39 test lines):

| Plant | Tests |
| --- | --- |
| F-A6-NO-TOKEN-CHECK | 1 |
| M-A6-PREFIX-BIND | 1 |
| M-A6-EMPTY-TOKEN | 1 |
| M-A6-COMMENT-STEP4 | 2 |
| M-A6-CLAIM-RESIDENT | 1 |
| M-A6-STUB-OK | 1 |
| M-A6-LIVE-PIDS | 1 |
| F-A12-DROP-ROOTS | 2 |
| M-A12-HARDCODE-FAIL | 1 |
| M-A12-SYMLINK-ROOT | 1 |
| M-A12-RENAME-ROOT | 1 |
| M-A12-RENAME-UNRELATED | 1 |
| M-A12-NO-MARKER | 1 |
| M-A12-TMP-SLASH | 1 |
| M-A12-TMP-UNSET | 1 |
| M-A12-TMP-DOTDOT | 2 |
| M-A12-TMP-LIVE-SYMLINK | 1 |
| M-A12-SNAP-AFTER-WRITE | 1 |
| M-A12-SNAP-IGNORE-LIVE | 1 |
| M-A12-NO-ISOLATION | 1 |
| M-A12-INODE-REUSE | 1 |
| M-A12-NO-HANDLE | 1 |
| M-A12-HASH-MTIME | 1 |
| M-A12-TOCTOU-FOLLOW | 2 |
| M-A12-SIBLING-WATCH | 1 |
| M-A12-NO-SYSTEM-TEMPS | 1 |
| M-A12-NO-LIVE-WATCH | 1 |
| M-A12-HASH-CAP-64K | 1 |
| M-A12-SPARSE-READ | 1 |
| M-A12-NO-RECHECK | 1 |
| M-A12-HANDLE-EMPTY-OK | 1 |
| M-A6-CLAIMED-NO-RA6 | 1 |
| M-A6-PROVE-ALWAYS-OK | 2 |
| M-A6-INSPECT-ALWAYS-SOME | 1 |

New plants (12 files / 14 test lines):

| Plant | Tests |
| --- | --- |
| M-A12-NO-OPENAT2 | 1 |
| M-A12-DETACHED-AFTER-PASS | 1 |
| M-A12-NO-HANDLE-FOLLOW | 1 |
| M-A12-NO-HOME-WATCH | 1 |
| M-A12-SKIP-HOME-CACHE | 1 |
| M-A12-NO-RECURSE-WATCH | 3 |
| M-A12-IGNORE-WATCH-ADD | 1 |
| M-A12-IGNORE-OVERFLOW | 1 |
| M-A12-BIND-PASS | 1 |
| M-A12-PIDNS-PASS | 1 |
| M-A12-RUN-USER-PASS | 1 |
| M-A12-WATCH-SYSCTL-PASS | 1 |

Independent replant will mark each row CAUGHT or SURVIVED. Author
tables are not that proof.

## Verdict

Pending subject reruns and hunts.

**A6: BLOCKED (RA-6)** is the standing rule. **Mac: NOT RUN** on this
host. `manager.rs` sha256 before any run:
`cd4772f1190b67e307aa47556de63a9a10eafa41ef348dbf5ee9b76636066b2a`.
`/tmp/elastos` is absent.
