# Review r5 of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft
PR #343 (`cursor/a6-a12-evidence-fix-6e3b`). This folder only adds
`lab/review-a6-a12-343-r5/`. It does not edit #343's branch, other
`lab/` folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime source.

- Target: #343 head `9d55f8fbd670bbaef9cd329fd795b5fb5cb9c04e`.
- Base of this review: `origin/spike/agent-host`
  `a165fb8df9723ec10c1e0cf1b7d6acb67b6c17fe`.
- Prior review: PR #412 of head `19becdd7` — r4 FIX. Pass path accepted
  this process plus pid 1. FileId missed same-bytes reuse and a 65 KiB
  in-place rewrite. Isolation-under and the live `/tmp/elastos` snapshot
  half were untested. A leaf symlink swap after `check_tmp_root` wrote
  outside.
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`.
  No macOS. Mac owner commands stay on hold.
- How to run: `lab/review-a6-a12-343-r5/run.sh`.
- Subject worktree: `/tmp/pr343-r5`, detached at the pin above.

This file is the pre-testing scaffold. The command results, plant
table, and verdict will replace this paragraph after
`lab/review-a6-a12-343-r5/run.sh` finishes on this machine.

## Planned checks

1. Rerun `./lab/a6-a12-evidence-fix/run.sh` at `9d55f8fb`.
2. Independently replant all 25 author plants (not `plant.rs`).
3. Independently reapply M-R4-GUARD-NO-ISOLATION and
   M-R4-SNAP-IGNORE-LIVE.
4. New r5 plants: child pid of this process; two threads / one pid;
   pid reuse; `prove_resident_capsule_instance` stubbed Ok; inspect
   stubbed `Some(())`; `name_to_handle_at` empty on tmpfs; sparse /
   growing file; parent-directory swap above the checked root;
   `/var/tmp` and `/dev/shm`; write-then-delete between snapshots.

A6 stays **BLOCKED (RA-6)** regardless of the Linux A12 verdict.
