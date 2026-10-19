# DeepSeek Harness: the reference we learn from

Repo: https://github.com/deepseek-ai/deepseek-harness (public, MIT, developer preview, Node/TypeScript).

## Two pinned versions

- **Read version** `5cf7ac9c44eeb7743da5486b7bb15605d0a7db7b` (12 Oct 2026). Every DeepSeek quote and file path in `ROADMAP.md` and `SLICES.md` is from this version. Those files link to `master`; read them at this commit instead.
- **Latest checked** `687f282e8625c6b8d11ff58211a90524be2e4317` (17 Oct 2026). 556 commits and 300 files changed since the read version.

Between the two, these cited files changed: `docs/subsystems/session.md`, `packages/core/session/src/index.ts`, `docs/module-graph.md`, `docs/persistence-catalog.md`. These did not: `docs/architecture.md`, `docs/subsystems/compaction.md`, `docs/subsystems/core.md`, `docs/tool-execution-pipeline.md`, `packages/README.md`, `packages/fs/fs-observation-policy/README.md`, `packages/core/agent-loop/src/runtime-context.ts`, `SAFETY.md`, `AGENTS.md`.

## How to read it

Clone it outside this repo. Never inside it, never as a submodule, never committed.

```bash
git clone https://github.com/deepseek-ai/deepseek-harness.git /tmp/deepseek-harness
cd /tmp/deepseek-harness && git checkout 5cf7ac9c44eeb7743da5486b7bb15605d0a7db7b
```

- **Copy the idea, never the code.** No TypeScript, no file, no test, no long passage goes into this repo. Short quotes (one or two lines) with file and commit are fine in plan text. Name the DeepSeek file and commit in the report when a slice uses a lesson from it.
- **Their design is not our security model.** Their plugins are the authority and their sandbox is same-kernel (their own `SAFETY.md` says it is not a security boundary). Ours: the guest proposes, the Runtime authorizes, a provider acts. When a DeepSeek pattern conflicts with `PRINCIPLES.md`, the principle wins, and the report says so.
- **Their tests are a source of falsifiers.** When a slice copies a pattern, look at how their tests try to break it, and make sure ours refuses the same cases.
- Our 12 Oct research read their docs and package READMEs, not all their source. Reading the source behind a pattern before building it is expected.

## Which DeepSeek files go with which slice

| Our slice or row | Read at the read version |
| --- | --- |
| Loop, turn and step (row 1) | `docs/architecture.md`, `docs/subsystems/core.md`, `packages/core/agent-loop/` |
| Session log, replay (row 2), S2 journal format, S3 journal storage | `docs/subsystems/session.md`, `packages/core/session/src/index.ts`, `docs/persistence-catalog.md` |
| Prefix cache, node 0, series (row 3), S4 | `packages/core/agent-loop/src/runtime-context.ts` (`SystemPromptProjection`, `systemPromptUpdate: 'in-history'`, `startsSeries`) |
| Compaction (row 4), S5 | `docs/subsystems/compaction.md` and the compaction package |
| Tool pipeline (row 5) | `docs/tool-execution-pipeline.md` |
| Read-before-edit, versions (row 6) | `packages/fs/fs-observation-policy/README.md` and that package |
| Sandbox limits (rows 7 and 12) | `SAFETY.md` |
| Package layout | `packages/README.md`, `docs/module-graph.md` |

S1 (closed admission) has no DeepSeek pattern; they have a plugin manager and no signed admission.

## One-time job in S0

Run `git diff --stat 5cf7ac9c 687f282e -- docs packages/core/session packages/core/agent-loop packages/fs SAFETY.md` and read the session and persistence changes. In the S0 report, add a short section "DeepSeek since 12 Oct": anything that changes a pattern we copy (journal, replay, series, compaction, tool pipeline, observations), and whether a slice in `SLICES.md` should change because of it. Do not change our code in S0 because of it; list it, and Sasha decides.
