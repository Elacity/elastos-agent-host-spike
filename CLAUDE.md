# Read this first

This is a private copy of `Elacity/elastos-runtime` for one spike: the Agent Host.

Before any work, read `examples/agent-host/handoff/HANDOFF.md` in full. It has the rules, the roadmap, the checklist, the slice queue, the test commands, and the report format.

Hard rules, short form:

- Never push to, open a PR on, comment on, or file an issue in any `Elacity/*` repo. That repo is public. Reading it is fine.
- One slice per session. Own branch from `spike/agent-host`. Push it to this private repo, open a PR here with base `spike/agent-host`, do not merge. Then stop.
- Author `SashaMIT <sash@ela.city>`, trailer `Co-authored-by: Claude <noreply@anthropic.com>`. Never rebase, amend, squash, or force-push.
- No secrets and no large files in commits.
- Every claim needs a falsifier: break it, show the test fail, revert.
- Simple English. Say what is next.
