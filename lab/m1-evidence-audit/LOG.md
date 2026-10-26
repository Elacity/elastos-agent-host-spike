# Log

## 26 Oct 2026: first audit (Linux x86_64)

No remote branch `lab/m1-evidence-audit*` existed. Earlier agent
bc-c11f6457 errored after reading PRs and running some tests, with no
branch, commit or files.

This session created `lab/m1-evidence-audit/` on
`cursor/m1-evidence-audit-cc38` from `origin/spike/agent-host`
`62e4aa697052d923bedb98a2c9a62917fc5b0c25`.

Sources read: draft #294 `lab/redteam-m1/REPORT.md`, draft #301
`lab/a1-a8-hardening/LOG.md` and its A1/A8 tests, merged PRs #3 #8 #9
#20 #57 #62 #63 #65 #66 #67 #69 #88 #112 #179, handoff review records,
and the in-tree tests those PRs name.

`gh pr view` showed empty GitHub review objects on every cited PR.

Verdicts: all 11 weak. None holds. None falsified here.

Commands on this machine:

- `python3 -I lab/m1-evidence-audit/audit.py` -> exit 0, catalog rows resolved
- `python3 -I lab/m1-evidence-audit/falsify.py F-M1-ROW` -> `F-M1-ROW: CAUGHT (removed C1-init-requires-storage)`
- `python3 -I -m unittest discover -s lab/m1-evidence-audit -v` -> 2 passed
