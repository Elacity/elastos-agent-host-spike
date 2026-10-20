# Claude: photo viewer spike

Read `examples/photo-viewer/handoff/KICKOFF.md` first, then `ROADMAP.md`, then `PRINCIPLES.md` (all 19),
`docs/CAPSULE_MODEL.md`, `docs/CAPSULE_AUTHORING.md` and `SECURITY.md`.

- Private repo only (SashaMIT/elastos-agent-host-spike). Never push to Elacity. Never touch main.
- One branch per slice (`claude/photo-<slice>`), draft PR into `spike/photo-viewer`, merge commits only. Sasha merges.
- No rebase, amend, force-push or branch deletion.
- No shipping Runtime change outside test modules without Sasha's yes.
- Do not touch `examples/agent-host/`.
- Before tests: `export RUST_TEST_THREADS=2`.
- Commits end with `Co-authored-by: Claude <noreply@anthropic.com>`.
