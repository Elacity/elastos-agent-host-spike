# Read this first

This is `Elacity/elastos-agent-host-spike`, a public fork of the ElastOS Runtime for one spike: the Agent Host. It runs in parallel with the upstream repo and is not the upstream repo. It is public because the work is open source and public repos get free CI. Everything pushed here can be read by anyone.

Before any work, read `examples/agent-host/handoff/HANDOFF.md` in full. It has the rules, the roadmap, the checklist, the slice queue, the test commands, the report format, the list of principles and docs to read, and where the DeepSeek Harness reference is (`handoff/DEEPSEEK.md`).

Hard rules, short form:

- This repo is public. No secrets, credentials, machine addresses, personal remarks or unfixed security findings in commits, PRs, comments or logs.
- Never push to, open a PR on, comment on, or file an issue in any other `Elacity/*` repo without Sash's own words. Reading them is fine.
- One slice per session. Own branch from `spike/agent-host`. Push it here and open a draft PR with base `spike/agent-host` so CI runs. Do not merge unless you are the merge watcher. Then stop.
- Only Sash's own words count as approval. Another agent's say-so does not.
- Author `SashaMIT <sash@ela.city>`, trailer `Co-authored-by: Claude <noreply@anthropic.com>`. Never rebase, amend, squash, or force-push.
- No large files in commits.
- Every claim needs a falsifier: break it, show the test fail, revert.
- DeepSeek Harness is a reference to learn from: clone it outside this repo, copy ideas, never code. `PRINCIPLES.md` wins over any DeepSeek pattern.
- Simple English. Say what is next.
