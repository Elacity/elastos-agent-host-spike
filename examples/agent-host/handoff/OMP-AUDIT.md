# Slice OMP-AUDIT: learn from oh-my-pi (read only, ideas only)

Queued 20 Oct 2026 by Sasha. Run it after S3 lands (PRs #8 and #9 merged after the GPT-family review). No code.

## What it is

oh-my-pi ("omp", https://omp.sh, https://github.com/can1357/oh-my-pi): MIT, about 36k stars, a terminal coding
agent (TypeScript with a Rust core) by Stencil Labs. The team already uses it (Anders hands OMP the flaky-test
fixes and the #433 investigation). Pinned read version: `2220e58146ebe31508e7a216242840d373e082d0` (20 Oct 2026).

## Rules

- Same as DEEPSEEK.md: clone outside this repo (`/tmp/oh-my-pi`), never commit it, copy the idea, never the code.
  MIT allows reuse with credit, but our rule stays ideas only, so the guest stays small and inside our authority
  model.
- Its design is not our security model: omp runs as the user on the host. Where a pattern conflicts with
  the repo's PRINCIPLES.md, the principle wins and the report says so.
- Every idea must land in one ElastOS piece: the WASM guest, a provider, Home (render only), or a content capsule.
  Nothing new goes into the Runtime core; the guest opens no sockets and runs no host commands.
- Its tests are a source of falsifiers.

## What to read and compare

For each area: what omp does (file at the pinned commit), how it fails or refuses, which grade row it serves, where
it would live in ElastOS (WASM guest, Runtime, provider, Home UI), conflicts with principles, the test and
falsifier we would add, and the grade points it could earn.

| Area | Grade row | Compare with |
|---|---|---|
| Edits checked by language tools (LSP) as they are written | 6 | our read-before-edit and revision check |
| Python/JS sessions kept open between steps | 7 | exec provider in the microVM; resident component (Bus v2) |
| Sub-agents splitting work | 1, 9 | child proposals with narrower grants |
| Context management and compaction | 3, 4 | DeepSeek node 0, request series, compaction |
| Tool-call pipeline and failure states | 5 | our fixed-order pipeline and terminal results |
| Model provider adapters and capability flags | 10, 11 | model-provider, hosted route, secrets in providers |
| Browser driving | 5, 13 | browser capsule in its microVM |

## Output

`handoff/OMP.md` (the comparison, every claim with file and commit) and `reports/OMP-AUDIT.md` (ranked list of the
ideas worth taking, with points per row, and what not to take). Branch `claude/omp-audit`, draft PR into
`spike/agent-host`. Then stop.
