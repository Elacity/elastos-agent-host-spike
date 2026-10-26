# Review of draft PR #343

Independent adversarial review of the A6 / A12 evidence-fix in draft PR
#343 (`cursor/a6-a12-evidence-fix-6e3b`). This folder only adds
`lab/review-a6-a12-343/`. It does not edit #343's branch, other `lab/`
folders, `BACKLOG.md`, `lane.env`, `scripts/`, or Runtime source.

- Target: #343 head `011d01f283a3f4ed4717383ecedf55622d451b4d`
  (later heads were not present; this is the live head).
- Base of #343: `spike/agent-host` at `9bb68053feea8426f33ade652f87f5ad47d03bb8`.
- This review branch: `cursor/review-a6-a12-343-d684` from current
  `origin/spike/agent-host`.
- Machine: Linux x86_64, `rustc 1.91.0 (f8297e351 2025-10-28)`,
  Python 3.12.3. No macOS, so `ThrowawayHome` is NOT RUN.
- How to run: `lab/review-a6-a12-343/run.sh`.

Anders's rule, as given for this review: an M1 check counts only when its
complete journey, refusal evidence, and required reviews all pass. Treat
every #343 claim as unverified until a command on this machine shows it.

Results are filled after the review commands run. Until then, do not read
the tables below as executed verdicts.
