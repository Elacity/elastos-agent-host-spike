# Message to paste into Claude Code

Start it with:

```bash
cd /Users/sash/code/wt-agent-host && claude
```

Then paste:

```text
You are picking up a local spike on this Mac. Read examples/agent-host/handoff/HANDOFF.md fully before anything else, then ROADMAP.md and the checklist at the top of SLICES.md in the same folder.

Do slice S0 only (baseline, no code change). Follow the hard rules in HANDOFF.md section 3: never push, never open a PR or comment on GitHub (the repo is public), one local commit per slice with the author and trailer given there, stop after the slice.

When S0 is done, write examples/agent-host/handoff/reports/S0-baseline.md in the report format from section 5, add one line to handoff/LOG.md, commit, and stop. Tell me the commit SHA.
```

For later slices, replace "S0 only (baseline, no code change)" with the slice name, for example "S1 only (sell-closed-admission)".
