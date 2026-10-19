# Message to paste into Claude Code (cloud)

Start a Claude Code session on the private repo, branch `spike/agent-host`, then paste:

```text
This repo is a private copy of Elacity/elastos-runtime for one local spike, the Agent Host. Read CLAUDE.md, then examples/agent-host/handoff/HANDOFF.md in full, then ROADMAP.md, DEEPSEEK.md, HISTORY.md, and the checklist at the top of SLICES.md in the same folder, and the repo's PRINCIPLES.md, docs/AGENT_ARCHITECTURE.md, AGENTS.md, and SECURITY.md. HANDOFF.md wins where they disagree.

Do slice S0 only (baseline, no code change), as written in HANDOFF.md section 8. Do the setup in section 9 and run the commands in section 10.

Rules: never push, open a PR, comment, or file an issue on any Elacity repo (it is public). Work on a new branch from spike/agent-host in this private repo. Author SashaMIT <sash@ela.city> with the trailer Co-authored-by: Claude <noreply@anthropic.com>. No rebase, amend, or force-push.

When done: write examples/agent-host/handoff/reports/S0-baseline.md in the report format from section 5, add one line to handoff/LOG.md, commit, push your branch to this repo, open a PR here with base spike/agent-host titled "S0 baseline", and stop. Reply with the branch, the PR link, and the full commit SHA.
```

For later slices, change "S0 only (baseline, no code change)" to the slice, for example "S1 only (sell-closed-admission)", and the report and PR names to match.

For a fix after review, paste Cursor's FIX message into the same session.
