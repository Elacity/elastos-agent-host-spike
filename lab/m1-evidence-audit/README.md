# lab/m1-evidence-audit

Re-check of the 11 M1 checks that the honest count still carries: A1, A2,
A8, C1, C2, C3, C4, C5, C6, C7 and S1.

Anders's rule, as given for this audit: a check counts only when its
complete journey, refusal evidence and required reviews all pass. This
folder does not raise or lower the count. It records what the cited
files actually contain.

Sources:

- `lab/redteam-m1/REPORT.md` on draft PR #294 (`origin/cursor/redteam-m1-c3b0`)
- draft PR #301 (`origin/cursor/a1-a8-hardening-85ce`) for A1 and A8
- the merged lab PRs those documents cite
- in-tree tests and the handoff review records

## Run

```bash
git fetch origin cursor/redteam-m1-c3b0 cursor/a1-a8-hardening-85ce
python3 -I lab/m1-evidence-audit/audit.py
python3 -I lab/m1-evidence-audit/falsify.py F-M1-ROW
python3 -I -m unittest discover -s lab/m1-evidence-audit -v
```

`audit.py` reads `evidence.json`, then each cited file. It fails when a
required row is missing from the catalog or when a cited marker is gone
from a file that the catalog says is present.

`falsify.py F-M1-ROW` deletes one required evidence row in a temp copy
and requires `audit.py` to catch it.

## Limits

This machine is Linux x86_64. It has no `sandbox-exec` and no KVM. Mac
profile tests and the agent-conformance throwaway Home are not run here.
The M1 check text in `milestones.json` is not in this repository.
