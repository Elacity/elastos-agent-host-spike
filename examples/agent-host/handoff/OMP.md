# oh-my-pi (omp): what it does, and where each idea would live in ElastOS

Written 20 Oct 2026 for slice OMP-AUDIT (`OMP-AUDIT.md`). Read only, ideas only, no code taken.

- **Read version:** `2220e58146ebe31508e7a216242840d373e082d0` (https://github.com/can1357/oh-my-pi), cloned to `/tmp/oh-my-pi`, outside this repo, never committed, never built or run.
- Every file path below is at that commit, relative to its repo root. Unless a path starts otherwise, `src/...` and `test/...` mean `packages/coding-agent/src/...` and `packages/coding-agent/test/...`.
- The reading was split across three read-only agents. I re-read eight of their citations myself (edit tag, stale-edit message, append-only context, child tool list, child approval mode, worker environment, no-UI approval, shell-command config values), and all eight match the code.

## The one difference that decides everything

omp runs **as the user, on the host**:
- tools are in-process (`packages/agent/src/agent-loop.ts`, `src/tools/eval.ts:300` makes `eval` an `exec`-tier tool);
- it writes files directly (`src/edit/index.ts:39-43`, with a "privileged fallback writer");
- it spawns interpreters, language servers and Chromium as host processes (`src/eval/py/kernel.ts:305-319`, `src/lsp/client.ts:1081`, `src/tools/browser/launch.ts:640`).

In ElastOS the agent is a WASM guest that can only propose. The Runtime checks a grant, and a provider in its own capsule or microVM acts (PRINCIPLES 3, 5, 7, 16, 18, 19).

So every idea below is moved into one of four places: the **guest**, a **provider**, **Home** (render only), or a **content capsule**. Nothing new goes into the Runtime core. Where omp's choice conflicts with a principle, the principle wins, and the section says so.

## 1. Edits checked as they are written (row 6, Edit reliability)

**What omp does**
- The edit tool is a thin TypeScript wrapper, marked `concurrency = "exclusive"`, over the Rust crate `crates/pi-edit` (`src/edit/index.ts:366-407`). It has five formats; the interesting one is **hashline**.
  - Each section starts with `[path#TAG]`. TAG is four hex digits of an xxh32 hash of the whole file, with trailing whitespace stripped (`crates/pi-edit/src/store.rs:74-94`).
  - Ops anchor on line numbers shown by `read`.
- **Read-before-edit, by line.**
  - `read`, `search` and `write` record snapshots and *seen lines* in a per-session store (`src/edit/store.ts:1-19`; `crates/pi-edit/src/store.rs:210, 264`).
  - A section with no tag is refused (`crates/pi-edit/src/modes/hashline/patcher.rs:665`).
  - An anchor on a line the model was never shown is refused. omp then reveals those lines (capped) and records them as seen, so a retry can succeed. A line that may have been cut by column truncation is refused (`patcher.rs:391-475`, `:405-409`, `:447`).
- **Stale file.**
  - `apply_with_recovery` compares the live hash with the tag (`patcher.rs:478-560`).
  - On a mismatch it first tries `try_recover`, which re-maps the line numbers through a diff (`crates/pi-edit/src/modes/hashline/recovery.rs:77`).
  - Only if that fails does it refuse: "Edit rejected…: file changed between read and edit", or "hash … is not from this session" (`mismatch.rs:76-117`).
- **Other refusals:**
  - two sections for one file in one call (`patcher.rs:699-706`);
  - a no-op payload repeated three times (`patcher.rs:776-781`, `store.rs:422`);
  - a write that "appeared successful but file content did not change on disk", checked by reading back (`src/edit/index.ts:771-819`).
- **Writes are not atomic across files.** Everything is staged and checked first, then written one file after another (`crates/pi-edit/src/session.rs:303-331`).
- **LSP.** Each write goes through language servers under a 5 s budget (`src/lsp/writethrough.ts:440-535`).
  - Diagnostics are awaited inline for only 500 ms (`src/lsp/diagnostics.ts:45`).
  - Later ones are queued into the conversation, marked stale if the file changed again (`src/lsp/deferred-diagnostics.ts:15-56`).
  - A parse regression adds a warning or an automatic repair, but the edit stays applied (`src/edit/index.ts:578-612`).
- **Their tests:**
  - `crates/pi-edit/src/modes/hashline/patcher.rs:991` `stale_shifted_replace_stays_rejected`, `:1045` `unseen_anchor_without_shift_history_stays_rejected`, `:1194` `wide_unseen_line_requires_full_read`;
  - `crates/pi-edit/tests/hashline_apply.rs:576` `recovery_rejects_a_changed_anchor`, `:706` `recovery_rejects_ambiguous_duplicate_anchor_context`;
  - `crates/pi-edit/tests/session.rs:58` `multi_file_failure_stages_nothing`;
  - `test/read-edit-seen-lines.test.ts:62`;
  - `test/lsp/issue-4910-diagnostics-bounded.test.ts:61`.

**What we have.** The guest refuses an unread or stale edit and requires the old text exactly once (`propose_edit`). A later write waits for the earlier one. The provider write needs a grant and the current version. Since S3, the Runtime gives every principal-root object a content revision and writes only by compare-and-swap.

**Where it would live**
- **Guest:** a *seen range* per observation. An edit may only touch text the journal shows was read; a windowed or cut read covers only its window. Also a no-op guard: the same edit proposal repeated with no effect is refused after a set count.
- **Provider (an edit provider or the object provider):** bind each edit to the Runtime revision the guest read. That is the content tag; S3's `if_revision` already is one. Apply all files of one change, or none.
- **Provider (a separate, swappable LSP provider capsule):** diagnostics after a granted write, returned as data the guest records. The guest never starts a language server.
- **Not taken:**
  - `try_recover`, which re-applies an edit to a file that changed. Ours refuses and makes the guest read again (11, 19).
  - Writes that are not atomic across files.

## 2. Python and JS sessions kept open (row 7, Shell and tests)

**What omp does**
- **Python:** one host child process per kernel, `python -u runner.py`, talking newline-delimited JSON over stdin/stdout (`src/eval/py/kernel.ts:1-9, 305-319`).
- **JS:** a worker subprocess, falling back to a Bun Worker, never the host thread (`src/eval/js/context-manager.ts:623-660`).
- **State:** a session registry keeps the kernel between calls, or starts fresh per call (`src/eval/kernel-session-registry.ts:162-213`; `src/eval/settings.ts:91-103`).
- **Output:** cut to a head and a tail, with the full text spilled to an artifact (`src/eval/executor-base.ts:446-451, 534-540`).
- **Cancel:**
  - SIGINT, then shutdown after 5 s (`kernel.ts:47-53`; `src/eval/kernel-base.ts:329-341`);
  - shutdown is exit, then SIGTERM, then SIGKILL of the process group (`kernel-base.ts:460-505`);
  - a crash fails pending runs and the next call respawns the kernel (`kernel-base.ts:246-252`; registry `:216-240`);
  - the model is told "kernel has been killed and will be recreated" (registry `:124-131`).
- **Idle watchdog:** pauses while host tools run (`src/eval/idle-timeout.ts:4-88`).
- **Authority:**
  - **Python:** the environment is filtered by an allowlist, and about ten model API keys are denied (`src/eval/py/runtime.ts:12-83`).
  - **JS:** the worker gets the **whole parent environment**, minus git variables, so API keys reach it (`src/subprocess/worker-client.ts:185-199`).
  - **Tool bridge:** the kernel calls host tools over 127.0.0.1 with a bearer token passed in environment variables (`src/eval/py/tool-bridge.ts:151-160`; `executor-base.ts:311-318`).
- **Their tests:**
  - `test/eval/kernel-session-registry.test.ts` ("preserves partial output without replaying side effects and recovers on the next call");
  - `test/eval/kernel-process-group.test.ts`;
  - `test/eval/context-manager-startup.test.ts` ("surfaces dual spawn failure without running synchronous cell code on the host").

**What we have.** The exec provider admits a closed set of commands. It runs them in a micro-VM with one core and 256 MiB, reads the exit code from a console mark, and cuts the log to 4000 bytes keeping the end (`exec_vm.rs`).

**Where it would live**
- **Provider, inside the micro-VM:** a resident interpreter kept for one task, under one grant. Interrupt, then kill; a "recreated" result the guest records; partial output kept and never replayed; an idle limit. All of it runs inside the VM, never on the host.
- **Guest:** records each cell as a step with its settlement word. A crash is `settlement_unknown`, as today.
- **Not taken:**
  - host processes;
  - passing the user's environment, or a bearer token in environment variables, to a child (3, 18);
  - an unfiltered environment of any kind. Secrets stay in the model provider (row 11).

## 3. Sub-agents (rows 1 and 9)

**What omp does**
- Sub-agents run **in-process on the main thread** (`src/task/executor.ts:1-5`). Isolation, when asked for, is a git worktree whose patch is merged back (`src/task/isolation-runner.ts:383, 633`).
- **A child's tools come from its agent definition and are not intersected with the parent's** (`executor.ts:4203-4238`). The default `task` agent gets the full default set; the per-spawn `tools` field adds tools, it does not narrow (`src/task/index.ts:961-972`).
- **Children run with `tools.approvalMode: "yolo"`.** The parent's approval of the task call is the only gate; user policies still apply (`executor.ts:1176-1182`).
- **Limits:**
  - recursion depth 2, and a child at the limit loses the `task` tool (`src/task/settings.ts:328-344`; `executor.ts:4203-4219`);
  - "Cannot spawn another agent at task depth…" (`src/task/structured-subagent.ts:287-294`);
  - concurrency 32 (`settings.ts:294-316`);
  - no wall-clock limit by default (`settings.ts:346-364`);
  - a soft request budget, then a forced stop (`executor.ts:1576-1583`).
- **Results:**
  - an exit code, error or abort reason (`executor.ts:2393-2398`);
  - results over 5000 characters cut to an `agent://<id>` artifact (`src/task/result-summary.ts:1-16`);
  - errors labelled with the provider and model (`src/task/error-attribution.ts:27-39`);
  - cancel stops scheduling siblings but lets started ones clean up (`src/task/parallel.ts`).
- **Their tests:**
  - `test/task/executor-wall-clock.test.ts`;
  - `test/rpc-cancel-subagent.test.ts` ("aborts a running subagent and leaves an aborted tombstone");
  - `test/task/failed-child-artifact.test.ts`;
  - `test/task/parallel.test.ts`;
  - `test/task/spawn-policy.test.ts`.

**What we have.** A child proposal must sit strictly under the parent's resource. It never inherits the parent's grant, and the parent stores one result line (`propose_child`, `narrower_resource`, `grant_child_host`, `record_child_result`; pinned in S0c and the sweep).

**Where it would live**
- **Guest:**
  - a depth limit on child proposals, so at the limit no child step can be proposed;
  - a request and time budget per child, with the abort reason recorded;
  - a child result over a cap stored as a spill pointer (we have `spill_pointer`), not inline;
  - cancel of a parent stops new children and leaves started ones to settle.
- **Runtime (existing, not new):** each child gets its own narrower grant. Child capsules as separate component instances wait for Bus v2.
- **Not taken:**
  - child tools that are not narrower than the parent's;
  - a "yolo" child that runs without its own grant (3, 7);
  - in-process children that share the parent's authority.

## 4. Context management and compaction (rows 3 and 4)

**What omp does**
- **Session file:** one JSONL file of entries forming a tree, with a movable leaf (`src/session/session-manager.ts:867-890`).
  - Written synchronously but never fsync'd, and streaming text is not saved until the message ends (`:873-877`).
  - Pruning rewrites the file through a temp file and rename (`:1714, :2830`).
  - Malformed lines are counted and skipped (`src/session/session-loader.ts:93-169`).
- **Stable prefix:** `StablePrefix` freezes the system prompt and the tool specs, with a fingerprint of each tool's wire identity. `AppendOnlyLog` only grows (`packages/agent/src/append-only-context.ts:1-15, 37-54`).
  - A rewritten message cuts the log back to the longest unchanged prefix (`:343-375`).
  - A model switch invalidates it (`:388-390`).
- **Compaction triggers:**
  - context tokens over a threshold after a turn (`packages/agent/src/compaction/compaction.ts:352-355, 388-418`; `src/session/session-maintenance.ts:3340-3356`);
  - or a provider overflow error, after first trying a larger-window model (`session-maintenance.ts:3004-3015`);
  - a 413 payload error is not treated as overflow (`:2990-3001`).
- **What is kept:**
  - The cut keeps the newest complete groups within a token budget. It **never cuts at a tool result**, and always keeps the newest group even when it is too big (`compaction.ts:509-597`).
  - The system prompt is never summarised.
  - Tool-output pruning protects the newest 40k tokens and skill results (`packages/agent/src/compaction/pruning.ts:77-81, 375-434`).
  - The summary is appended as one entry once ready (`session-manager.ts:3547-3576`).
- **Their tests:**
  - `packages/agent/test/append-only-context.test.ts` ("returns true when tool description changes");
  - `packages/agent/test/compaction-cut-point.test.ts`;
  - `test/agent-session-compaction-cancellation.test.ts:208` ("resumes the interrupted turn when compaction rejects after the entry is appended");
  - `test/session-manager-immediate-persist.test.ts:135, 201`.

**What we have**
- Node 0 is the system head. Head rewrites start a new series.
- Compaction shrinks the tail only, refuses a summary that does not shrink, and never replaces node 0.
- A crash during compaction restores the saved bytes.
- Format 1 has a hash chain, and S3 writes the journal by compare-and-swap.

Ours is stricter than omp on persistence: there is no "skip malformed lines", and decode refuses any changed byte.

**Where it would live (guest)**
- The **tool specs join the head**: a change in a tool description starts a new series, as a change in the system line does.
- The **cut point never splits a step from its result**, and always keeps the newest turn.
- A **provider overflow error is a compaction trigger**, but a payload-size error is not.
- **Not taken:**
  - skipping malformed records on load (11: we refuse);
  - writes that are not durable (our journal is a compare-and-swap object);
  - changing the model on overflow without a new grant.

## 5. Tool-call pipeline and failure states (row 5)

**What omp does**
- **Before running** (`packages/agent/src/agent-loop.ts:3075-3175`):
  - tool-call ids are made unique;
  - the tool is resolved, with "Did you mean…";
  - arguments are checked against the schema (`packages/agent/src/tool-arguments.ts:21-41`);
  - a hook may block the call or revise it, and revised arguments are checked again.
- **Malformed JSON** becomes a parse-error marker that is never passed to a tool (`packages/ai/src/utils.ts:572-592`; `tool-arguments.ts:35`).
- **Running** (`agent-loop.ts:3518-3707`):
  - a validation error becomes an error result, and the tool does not run;
  - a throwing tool becomes an error result;
  - terminal states are ok, error, blocked, aborted and skipped (`packages/agent/src/run-collector.ts:619`; `agent-loop.ts:3712-3735, 3961`).
- **Approval:**
  - modes are always-ask, always-ask-cached, write and yolo, with read, write and exec tiers (`src/tools/approval.ts:44, 150-155`);
  - **with no UI it fails closed**, and anything but an explicit approval is a deny (`src/extensibility/extensions/wrapper.ts:420-464`; `approval.ts:699-735`).
- **Timeouts:** per tool, clamped (`src/tools/tool-timeouts.ts:10-38`).
- **Their tests:**
  - `packages/agent/test/agent-loop.test.ts:754, 816` (malformed JSON never runs a lenient tool), `:3119` ("keeps a completed error result instead of clobbering it into skipped"), `:2540` (incomplete tool calls dropped on abort);
  - `test/cfg-approval-timeout.test.ts:156, 199` (a pending approval is denied when the mode stops or the turn aborts).

**What we have**
- Step states: prepared, not started, denied, cancelled, dispatched, settlement unknown.
- Dispatch only with a grant; cancel before dispatch; a crash after dispatch is unknown.
- The approval card is drawn by Home, and the decision is the Runtime's (16).

**Where it would live**
- **Guest:**
  - a model tool call that does not parse, or fails its schema, creates no step and records a model-visible error;
  - a step that already has a result is never moved to another state (pinned in part by `a_crash_after_the_result_does_not_erase_it`);
  - a step proposed inside a turn that is cancelled before dispatch is cancelled, not left prepared.
- **Runtime (existing pending store):** a pending capability request is denied when the asking capsule stops.
- **Home:** draws the card only.
- **Not taken:**
  - approval modes that allow without asking ("yolo", "write");
  - approval cached in the agent (3, 16).

## 6. Model provider adapters and capability flags (rows 10 and 11)

**What omp does**
- **Catalog:** a bundled model list (`packages/catalog/src/models.json`) plus per-provider rules (`packages/catalog/src/compat/rules/providers/*.kdl`).
- **Capability flags per model:** reasoning, tokenizer, input kinds, tool support, prompt cache, context window, max tokens, and a larger-window promotion target (`packages/catalog/src/types.ts:1505-1761`).
- **Vision guard:** images sent to a model without vision become "[image omitted: model does not support vision]" (`packages/ai/src/providers/vision-guard.ts:1-17`).
- **Errors:** an unknown API is a `ConfigurationError` (`packages/ai/src/stream.ts:996`); a missing key is `MissingApiKeyError` (`:873`).
- **Keys:**
  - stored in SQLite with a 0700 folder and a 0600 file (`packages/ai/src/auth/sqlite-credential-store.ts:580-596`);
  - also read from environment variables and `.env` files (`packages/ai/src/env-api-key.ts:13-55`);
  - **config values starting with `!` are run as shell commands** (`src/config/resolve-config-value.ts:23, 124`);
  - on auth failure omp rotates accounts, up to 64 tries (`packages/ai/src/auth-retry.ts:1-30, 135`).
- **Local:** Ollama, lm-studio, llama.cpp and vllm rules; Ollama retries at 2, 5 and 10 s (`packages/ai/src/providers/ollama.ts:458, 612`).
- **Fallback:** chains by role (`src/session/retry-fallback-chains.ts:7-50`; walked in `src/session/turn-recovery.ts:1907-1985`).
- **Their tests:**
  - `packages/ai/test/api-key-validation.test.ts` ("propagates network failures without relabeling them as credential failures");
  - `packages/ai/test/issue-967-vision-guard.test.ts`;
  - `packages/ai/test/api-registry.test.ts` (a custom API may not shadow a built-in);
  - `test/agent-session-retry-fallback.test.ts`.

**What we have**
- The model provider owns local runs and admission.
- The hosted route keeps secrets in the provider.
- A hosted proposal in the guest names a model resource and has no secret field.

**Where it would live**
- **Model provider capsule:** typed capability flags on each offer (context window, max tokens, tools, vision, cache). Errors that keep their kind: a network failure is never reported as a bad key. A vision guard. All of it is data the guest reads through `offers_list`.
- **Guest:** chooses a model only among offers the Runtime granted. A fallback is a new proposal under its own grant.
- **Not taken:**
  - config values that run shell commands (3, 5);
  - keys in environment variables or `.env` files read by the agent;
  - rotating across accounts;
  - a 12 MB catalog in the guest.

## 7. Browser driving (rows 5 and 13)

**What omp does**
- **Driver:** Puppeteer over CDP (`src/tools/browser/launch.ts:27, 161, 228, 640`), exposed as an `exec`-tier `browser` helper inside eval (`src/tools/browser.ts:244-252`).
- **Backends:** a spawned Chromium, a CDP URL, or a **relay to the user's own Chrome tabs** (`browser.ts:158-235`; relay on 127.0.0.1 that rejects an `Origin` header, `src/tools/browser/relay/server.ts:83-109`).
- **Chromium settings:** launched with **`--no-sandbox`** and stealth patches (`launch.ts:55-75, 582`), with a fresh temp profile per launch (`:634`) and one worker per tab (`src/tools/browser/tab-supervisor.ts:2329`).
- **Domains:** `allowed_domains` is enforced by request interception (`src/tools/browser/network.ts:179-180, 423-439`).
- **Time limits:**
  - 20 s for reads, 8 s for actions, 2 s fail-fast when nothing matches (`src/tools/browser/op-timeouts.ts:20-29`);
  - a timed-out run names the stalled step (`src/tools/browser/tab-worker.ts:2001-2011`);
  - closing is bounded, then the process tree is killed (`test/tools/browser-dispose-timeout.test.ts:42`).
- **Their tests:** `test/tools/browser-network.test.ts:198` ("enforces allowed_domains and logs blocked cross-host fetches"), `browser-relay-tab-isolation.test.ts`, `browser-tab-timeouts.test.ts`.

**What we have.** A browser capsule in its own micro-VM (the Browser VM), and the `net` provider for fetches.

**Where it would live**
- **Provider (browser capsule in its micro-VM):** allowed domains as part of the grant's resource, enforced in the provider; per-operation time limits, with the stalled step named in the result; a bounded close.
- **Guest:** proposes browser steps, with the domains named in the resource.
- **Not taken:**
  - driving the user's real browser through a relay;
  - `--no-sandbox` on the host;
  - stealth patches (18, and Home's own browsing policy).

## What this audit did not do

- No omp code was built or run, so its tests are cited as ideas, not results.
- The rows were read in the code paths named above. Docs and extensions outside them were not read.
- No grade changes because of this audit. A grade moves only with our own test and falsifier.
