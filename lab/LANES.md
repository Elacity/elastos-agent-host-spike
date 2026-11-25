# Lane builders and reviewers

This note lists who built each of the nine graded lanes, and who reviewed, using only `Built-by`, `Built by`, and `Co-authored-by` lines in `git log` for the paths below. No commit on these paths has a `Reviewed-by` trailer. A builder line that also says who reviewed is quoted. The rest of the record is the pull requests named in that same `git log`.

## A5 — agent identity and admission

Paths: `elastos/crates/elastos-server/src/agents.rs`, `elastos/crates/elastos-server/src/agent_admission.rs`.

Built by Claude, Codex (`gpt-6-sol`), DeepSeek, and Grok 4.7. Co-authored-by trailers also name Claude Fable 5.2, Claude Opus 5.5, and DeepSeek V4 Flash. The trailers name no reviewer. Commit subjects name #1826, #1827, #1831, and #1834.

## M1 — stand-in agent runtime

Paths: `lab/agent-conformance/standin-runtime`, `lab/agent-conformance/probe`, `lab/agent-conformance/tests/standin_contract.rs`, `lab/agent-conformance/GAPS.md`.

Built by Claude, Codex (`gpt-6-sol` and `gpt-6-astra`), DeepSeek (including `deepseek-v4-flash` and `deepseek-v4.1-flash`), and Grok 4.7. One line is `Built-by: Ultrafast/omp` and names no model family. Co-authored-by trailers also name Claude Fable 5.2, Claude Opus 5.5, Codex, Cursor, and DeepSeek-V4-Flash. One builder line says "reviewed by codex + composer". Commit subjects name the pull requests; `git log` on these paths is the list.

## Provider confinement — B3/B4

Paths: `elastos/crates/elastos-runtime/src/provider`, `capsules/did-provider`, `capsules/wallet-provider`, `capsules/model-provider`.

Built by Claude (including `claude-opus-5-5` and Claude Code), Codex (`gpt-6-sol`), DeepSeek (including `deepseek-v4.1-flash`), Grok 4.7, and GLM. One line is `Built-by: Ultrafast/omp` and names no model family. Co-authored-by trailers also name Claude Fable 5.2, Claude Opus 5.5, Codex, Cursor, and DeepSeek-V4-Flash. One builder line says "reviewed by codex + composer". Commit subjects name the pull requests; `git log` on these paths is the list.

## M2 — photo viewer and content by CID

Path: `examples/photo-viewer`.

Built by Claude, Codex (`gpt-6-sol`), DeepSeek, and Grok. One Cursor builder line names `claude-opus-5-5-high`. Co-authored-by trailers also name Claude Fable 5.2, Claude Opus 5, Claude Opus 5.5, DeepSeek V4 Flash, and Grok. The trailers name no reviewer. Commit subjects name #1668, #1688, #1691, and #1828.

## AP3 — archive viewer

Path: `examples/archive-viewer`.

Built by Claude, Codex (`gpt-6-sol`), and DeepSeek. One Cursor builder line names `claude-opus-5-5-high`. Co-authored-by trailers also name Claude Fable 5.2, Claude Opus 5.5, and DeepSeek V4 Flash. The trailers name no reviewer. Commit subjects name #1626, #1691, and #1828.

## AP4 — GBA viewer by CID

Path: `examples/gba-viewer`.

Built by Claude, DeepSeek, Codex, and Grok. Co-authored-by trailers also name Claude Fable 5.2, DeepSeek V4 Flash, and Grok. The trailers name no reviewer. The commit subject names #1670.

## S1 — principles review fixes

Paths: `lab/grant-binding`, `lab/redteam`, `lab/bus-v2-proposal`.

Built by Claude (`claude-opus-5-5`), Codex (`gpt-6-sol`), DeepSeek (`deepseek-v4-flash` and `deepseek-v4.1-flash`), and Grok 4.7. Co-authored-by trailers also name Claude Opus 5.5, Codex, Cursor, and DeepSeek-V4-Flash. One builder line says "reviewed by codex + composer". Commit subjects name the pull requests; `git log` on these paths is the list.

## A14 — installed demo acceptance

Paths: `lab/agent-conformance/src/report.rs`, `lab/agent-conformance/src/runtime.rs`, `lab/agent-conformance/demo.sh`, `lab/agent-conformance/run.sh`, `lab/agent-conformance/tests/report.rs`, `lab/agent-conformance/tests/installed-layout.sh`, `lab/agent-conformance/tests/demo-gates.sh`, `lab/agent-conformance/RUNBOOK.md`.

Built by Claude, Codex (`gpt-6-sol` and `gpt-6-astra`), DeepSeek (`deepseek-v4-flash` and `deepseek-v4.1-flash`), and Grok 4.7. Co-authored-by trailers also name Claude Fable 5.2, Claude Opus 5.5, Codex, Cursor, and DeepSeek-V4-Flash. One builder line says "reviewed by codex + composer". Commit subjects name #1576 and #1638.

## Build and CI infrastructure

Paths: `.github/workflows/ci.yml`, `scripts/core-size.py`, `scripts/ci-release-policy-test.py`, `elastos/.cargo/audit.toml`.

Built by Claude (including `claude-opus-5-5`), Codex (`gpt-6-sol`), DeepSeek, Grok 4.7, and GLM-5.3-Flash. Co-authored-by trailers also name Claude Fable 5.2, Claude Opus 5.5, DeepSeek V4 Flash, Cursor, and Sash. Two builder lines say "reviewed by codex + composer". Commit subjects name the pull requests; `git log` on these paths is the list.
