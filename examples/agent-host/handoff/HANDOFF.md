# Agent Host spike: handover to Claude

Written 19 Oct 2026 by Cursor for Claude Code. Read this whole file first. When this file and `SLICES.md` disagree, this file wins.

## 1. What this is

ElastOS Runtime is a private computer. Its Assistant today is chat only: no tools, no authority. On 12 Oct we compared it with DeepSeek Harness, a full coding agent. DeepSeek is 5/5 as a coding agent, we are about 1.5. We are ahead as a private local computer (4 vs 2), because we have no tools and keep authority in the Runtime.

The plan is to grow an **Agent Host**: Rust compiled to a WebAssembly component, running inside the Runtime's Wasmtime with no files, no network, no shell. It copies DeepSeek's ideas (append-only journal, stable prompt head, compaction, guarded tool pipeline, read-before-edit). Every effect is a request on the Bus that the Runtime grants or refuses. We copy patterns, never DeepSeek's code.

- `ROADMAP.md` is the audit: grades, what to copy, what not to copy, phases A to F, where WASM sits.
- `SLICES.md` is the working plan and the checklist (the `todos` at the top). It has one section per grade row, the DeepSeek source for each pattern, and the target Rust. From now on `SLICES.md` in this folder is the live checklist. Update a todo's `status` in the same commit as the slice that finishes it.
- Principles that bind every line: `PRINCIPLES.md` 3, 5, 7, 10, 11, 16, 18, 19. Architecture contract: `docs/AGENT_ARCHITECTURE.md`. Team rules: `AGENTS.md`.

## 2. Where things are

- Worktree: `/Users/sash/code/wt-agent-host`. Branch: `spike/agent-host`. No upstream on purpose.
- Merged with `origin/develop` `3beb81643` (= 0.8.0-alpha.24 plus one CI commit) as `d465df3bc`. 0 commits behind on 19 Oct.
- Spike code: `examples/agent-host/src/lib.rs` (about 10,000 lines, 72 host tests), `examples/vm-smoke/`, `elastos/crates/elastos-compute/src/exec_vm.rs`, the ignored Wasmtime tests in `elastos/crates/elastos-compute/src/providers/component.rs`, Home screens `capsules/home-gui/browser/shell-version-list.js`, `shell-approval.js`, `shell-demo-app.js`, `version-list.html`, `file-versions.json`, prompt packing in `capsules/assistant/browser/agent-context.js`, admission counting in `capsules/model-provider/src/local_memory.rs` and `adapters.rs`.
- Guest hash on 19 Oct: `fe9bcaa48669b10c9e7633f9ba7f34db1fcc65fa0dcc41ea1517c2dfc10f60c5`.
- Backup of the pre-merge work: `/Users/sash/code/agent-host-backup-20261019/`. Do not delete it.
- Installed ElastOS on this Mac: 0.8.0-alpha.24 (`~/.local/bin/elastos`, data in `~/Library/Application Support/elastos`). That is Sasha's real Home. Do not touch its data or start it unless Sasha asks.
- Checklist: 55 of 62 done.

## 3. Hard rules

1. **Never push.** No `git push`, no `gh pr ...`, no GitHub comments, no issues. The repo `Elacity/elastos-runtime` is **public**. Pushing this branch would publish the spike. Sasha decides if and when it is shown to Anders.
2. **Commit locally, one commit per slice.** Author `SashaMIT <sash@ela.city>`. Last line of the message: `Co-authored-by: Claude <noreply@anthropic.com>`. Never rebase, amend, squash, or force anything. A fix after review is a new commit.
3. **Before a slice:** `export HOME=/Users/sash RUST_TEST_THREADS=2`, `git fetch origin`, `git merge origin/develop`. If the merge is not clean, stop and report. Do not rewrite history.
4. **One slice, then stop and write the report.** Do not start the next slice.
5. **Do not touch:** `main`, `develop`, other worktrees under `/Users/sash/code`, Sasha's real Home data, the board QMF1, `~/.ssh`. Do not delete branches, worktrees, or the backup.
6. **No secrets in any file or output.** If you meet a token, key, ticket, or password, report the path and type only.
7. **No long-lived Runtime from `/tmp`.** A test Home goes under `/Users/sash/code/agent-host-desktop/` (already used for this). Stop anything you start before you finish the slice, and say so.
8. **Large files stay out of the repo and out of Home folders.** No model weights, VM images, or build output in commits.
9. **Simple English** in reports and docs: short sentences, exact commands, say what is next.

## 4. Coding rules (from the plan; they still hold)

- Copy invariants, not code. No Node port, no host `bash`, no host `rg`, no `run_code` in the guest, no session upload.
- The guest records proposals. The Runtime authorizes. A provider performs the effect. Home only shows state; a Home screen is never a grant.
- Fail closed: no grant, an empty grant, or an unknown settlement stops the effect and says why.
- About nine tenths of a slice is the invariant, the refusals, and the test names. Write those first (in `SLICES.md` if missing), then the code.
- `cargo fmt`, then `./examples/agent-host/verify.sh`, then `./examples/agent-host/run-local.sh`. A wasm32 warning is a failed slice.
- Every claim in a report needs a **falsifier**: break the code on purpose, show which test fails, then revert. No falsifier, no claim.
- The ignored Wasmtime test checks the guest's import list. Today it is only `elastos:bus/identity`, `runtime`, `types`. Changing that list is a security change: say so in the report and expect an adversarial review.
- Do not edit the shipping Assistant prompt `DEFAULT_LIVE_SYSTEM_PROMPT`. It must keep saying there are no tools.

## 5. How we work together

1. Sasha starts you here and names the slice.
2. You do that one slice, commit locally, write `handoff/reports/S<n>-<slug>.md` (format below), add one line to `handoff/LOG.md`, and stop.
3. Sasha tells Cursor. Cursor reviews that exact commit: reads the diff, reruns the tests, runs its own tamper tests, and checks the principles. Because you wrote the code, the independent review is done by a GPT-family reviewer, not Claude. The result goes in `handoff/reviews/S<n>-review.md` with `VERDICT: PASS` or `VERDICT: FIX`, plus a short message for you.
4. On FIX, Sasha pastes that message back to you. You fix it in a new commit and update the same report with a "Fix" section.
5. On PASS, Sasha names the next slice.

### Report format (`handoff/reports/S<n>-<slug>.md`)

```text
Slice:        S<n> <checklist id>
Commit:       <full sha>   parent <full sha>
Develop:      origin/develop <sha>, behind 0
Changed:      <file> - <one line why>   (one line per file)
Invariant:    <the rule this slice makes true, in one or two sentences>
Refusals:     <each input that must be refused, and what the code returns>
Tests run:    <exact command> -> <result line>   (one line per command)
Falsifiers:   <what I broke> -> <test that failed> -> reverted
Guest hash:   <sha256 of agent-host.component.wasm>
Import list:  unchanged | changed to <list> because <reason>
Not proven:   <limits, honestly>
Checklist:    <n> of 62   (<ids> moved to completed)
Stopped:      <anything started and stopped, or "nothing started">
Questions:    <for Sasha, or "none">
```

## 6. Corrections to `SLICES.md` (it was written 12-14 Oct)

- "No commit" everywhere: replaced by rule 2 above. Local commits are now required so review is bound to an exact commit.
- "#116 and #277": both are finished. Ignore those lines.
- "Desktop Home at `localhost:61180` stays the 2 Oct runtime": that Home is not running any more. Sasha's Mac now runs installed alpha.24 on `localhost:8090`.
- "Prefix packing waits until after 0.8.0": alpha.24 is the 0.8.0 candidate. Phase A packing is already in the spike. The measured cache hit (S4 below) may now start.
- Todo `run-tests-in-vm` still says "Home still has to show that list". Sasha saw the Versions list on a running Home on 13 Oct (19:42). The open part is that `cargo` is not in the VM image. S0 below settles this.

## 7. Slice queue

Do them in this order. Each is one session. Stop after each.

### S0 - baseline, no code change

- Merge `origin/develop`. Run every command in section 8. Confirm the guest hash is still `fe9bcaa4...`.
- Update `SLICES.md`: mark `run-tests-in-vm` done for the Home list, and add a new pending todo `exec-cargo-in-image` for "cargo is not in the VM image" under section 7.
- Report the baseline. This proves your setup matches ours before you change anything.

### S1 - `sell-closed-admission` (small, test only)

- Invariant: while issue #217 is open (it is, on 19 Oct), a capsule signed by a key that is not trusted on this Home is refused at install and at launch. Assistant tests show no store.
- First find the existing admission path (search `trusted`, `verify`, `signature`, `install` under `elastos/crates`). If a test already proves the refusal, cite it by name and add only what is missing. Do not change production code in this slice.
- Falsifiers: remove the check locally and show the test fails; sign the same capsule with a trusted test key and show it is accepted, so the test is not refusing everything.
- Signing is security code. Expect the GPT review.

### S2 - UsersAI journal format, guest only, no I/O

- `docs/AGENT_ARCHITECTURE.md` (around lines 330-350) says agent state lives under `UsersAI/...` and that the path layout needs a versioned object contract first. Write that contract as `handoff/USERSAI-JOURNAL.md`: resource name, object versions, append as compare-and-swap on the previous version, a hash link from each record to the last, a size cap, and what is model-visible. Check how the object provider names resources and versions today before you choose.
- In the guest: `encode` and `decode` for the journal with a format version. Tests: decode(encode(j)) is j; replay bytes are unchanged; one flipped byte is refused; a wrong format version is refused; a truncated journal is refused; node 0 and the epoch survive the round trip.
- No file, no Bus call, no import change.

### S3 - `hold-usersai`: the Runtime stores the journal. Ask Sasha before starting.

- The guest proposes a journal append. The Runtime checks the grant and writes it through the object provider as compare-and-swap under the S2 resource name. The guest still never sees a host path.
- This is the first time the guest calls `providers.invoke`. The import list changes. That is intended, and the report must say so.
- Tests: no grant is denied before the provider; a stale version is refused; a crash between append and result is `settlement_unknown` and is not retried; resume reads back the same bytes; another principal's journal is refused.
- Needs an adversarial review with `VERDICT: PASS` on the exact commit. Still no push.

### S4 - `prefix-aplus-hit`: a measured cache hit with honest admission

- Use a test Home under `/Users/sash/code/agent-host-desktop/`, never Sasha's real Home. Use the smallest model (SmolLM2-135M). If the memory gate refuses, report the numbers. Do not lower the gate in shipping code.
- Measure the reused prefix tokens that llama.cpp reports, for the same head across two turns. Admission must count the cached prefix (`counted_input_tokens`) in the same change that allows `--cache-ram` above 0. If both do not land together, `--cache-ram` stays `0`.

### S5 - `compact-aplus-model`: Home's model writes the summary

- A model run with purpose `compaction`. Large tool results are cut first (already proven). The model sees the head plus the range being replaced. Node 0 and replay stay as they are. A skill text that will be injected again is not summarised.
- Same memory-gate rule as S4.

### Later, not now

Phase C real writes through the object provider; `exec-cargo-in-image`; phase E create-in-Home; a full adversarial review before anything is ever pushed. Phase F (selling, second Home, `sell-second-home`) is Anders' scope: do not start it.

## 8. Test commands (all green on 19 Oct at `d465df3bc`)

```bash
export HOME=/Users/sash RUST_TEST_THREADS=2
cd /Users/sash/code/wt-agent-host
./examples/agent-host/verify.sh                       # fmt, 72 host tests, clippy, component build
./examples/agent-host/run-local.sh                    # guest inside the Runtime's Wasmtime
shasum -a 256 examples/agent-host/agent-host.component.wasm
(cd elastos && cargo test -p elastos-compute --lib -- --include-ignored)            # 16 tests
cargo test --manifest-path capsules/model-provider/Cargo.toml local_memory          # 7 tests
node --test scripts/home-agent-prefix.test.mjs                                       # 2 tests
ELASTOS_PLAYWRIGHT_MODULE=/Users/sash/code/wt-phone/elastos/tools/browser-playwright-engine/node_modules/playwright/index.js \
  node scripts/home-version-list-smoke.mjs                                           # Versions screen
```

This worktree has no Playwright install; the variable borrows the copy in `wt-phone`. Do not install packages into the repo.

## 9. If you are stuck

Stop and write the report with `Questions:` filled in. A clear "blocked because X" is a good result. Guessing past a security question is not.
