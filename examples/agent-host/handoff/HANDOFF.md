# Agent Host spike: handover to Claude (cloud)

Written 19 Oct 2026 by Cursor for Claude Code on the web. Read this whole file first. When this file and `SLICES.md` or `ROADMAP.md` disagree, this file wins.

## 1. What this is

ElastOS Runtime is a private computer. Its Assistant today is chat only: no tools, no authority. On 12 Oct we compared it with DeepSeek Harness, a full coding agent. DeepSeek is 5/5 as a coding agent, we are about 1.5. We are ahead as a private local computer (4 vs 2), because we have no tools and keep authority in the Runtime.

The plan is to grow an **Agent Host**: Rust compiled to a WebAssembly component, running inside the Runtime's Wasmtime with no files, no network, no shell. It copies DeepSeek's ideas (append-only journal, stable prompt head, compaction, guarded tool pipeline, read-before-edit). Every effect is a request on the Bus that the Runtime grants or refuses. We copy patterns, never DeepSeek's code.

Files in this folder:

- `ROADMAP.md`: the audit. Grades, what to copy, what not to copy, phases A to F, where WASM sits.
- `SLICES.md`: the working plan and the checklist (the `todos` at the top). One section per grade row, the DeepSeek source for each pattern, and the target Rust. It is now the live checklist. Update a todo's `status` in the same commit as the slice that finishes it.
- `DEEPSEEK.md`: how to read DeepSeek Harness (pinned commits, which file goes with which slice, what changed since we read it, and the copy-ideas-not-code rule).
- `HISTORY.md`: every proven step from 12 to 14 Oct, oldest first. Read it before changing a behaviour, so you do not undo a proof.
- `LOG.md`, `reports/`, `reviews/`: the running record.

`ROADMAP.md`, `SLICES.md`, and `HISTORY.md` were written on Sasha's Mac. A path that starts with `/Users/sash/code/wt-agent-host/` means the repo root here. Other `/Users/sash/...` paths (Cursor plans, the task log, a canvas) do not exist in the cloud; this folder already holds what you need from them.

### Read before coding (in the repo, not in this folder)

- `PRINCIPLES.md`, all 19 and the decision rule at the end. These bind every slice: 3 No ambient authority; 5 Small trusted core; 7 Humans and agents share one authority model; 10 One canonical path per operation; 11 Fail closed, then explain; 12 Docs, code, tests, and operations must agree; 15 Trust and access must travel with signed content (S1, S3); 16 UI surfaces must not be authority; 18 Executable capsules are isolated execution environments; 19 Consequences govern effects, not transports. A report names the principles its slice touches.
- `docs/AGENT_ARCHITECTURE.md`: the Agent Host contract (Agent Host owns the loop, Runtime authorizes, model output is a proposal, UI is not a grant). S2 and S3 start from its `UsersAI` section.
- `docs/ARCHITECTURE.md`: the component path and web projections.
- `AGENTS.md`: the team's rules. Its review rules apply here too: one concern per change, its own tests, and an independent adversarial review from another model family for grants, gateway, provider launch, confinement, or signing.
- `SECURITY.md`: how security findings are written. Even in this private repo, a report or PR text gives a safe summary. A real weakness in shipping ElastOS code goes in the report under `Questions:` as "security finding, details for Sasha", with no exploit steps.

### Grades (from the 12 Oct canvas, which lives on Sasha's Mac)

Scale: 0 absent, 1 sketched or prompt-only, 3 real but incomplete, 5 production for that job. A+ is 5 on every row (70 of 70).

| Row | DeepSeek | ElastOS Assistant 12 Oct | Path target |
| --- | --- | --- | --- |
| 1 Agent loop | 5 | 1 | 5 |
| 2 Session log | 5 | 2 | 5 |
| 3 Prefix cache | 5 | 1 | 4 |
| 4 Compaction | 4 | 2 | 4 |
| 5 Tool system | 5 | 0 | 5 |
| 6 Edit reliability | 4 | 0 | 5 |
| 7 Shell and tests | 4 | 0 | 4 |
| 8 Git and undo | 2 | 0 | 3 |
| 9 Skills | 4 | 0 | 4 |
| 10 Local model ops | 1 | 5 | 5 |
| 11 Hosted and secrets | 2 | 4 | 5 |
| 12 Capability model | 2 | 4 | 5 |
| 13 Create an app | 3 | 1 | 4 |
| 14 Package and sell | 0 | 2 | 4 |

The task log called the spike "about 43 of 70" on 13 Oct. That was a rough total with no per-row breakdown. A path grade is a name, not a proof: a row only counts when a test proves it.

## 2. Where things are

- This repo is a **private** copy for the spike only. The real project is `Elacity/elastos-runtime`, which is **public**.
- Main line here: branch `spike/agent-host`. It already contains `origin/develop` of Elacity at `3beb81643` (= 0.8.0-alpha.24 plus one CI commit), merged as `d465df3bc`.
- Spike code: `examples/agent-host/src/lib.rs` (about 10,000 lines, 72 host tests), `examples/vm-smoke/`, `elastos/crates/elastos-compute/src/exec_vm.rs`, the ignored Wasmtime test in `elastos/crates/elastos-compute/src/providers/component.rs`, Home screens `capsules/home-gui/browser/shell-version-list.js`, `shell-approval.js`, `shell-demo-app.js`, `version-list.html`, `file-versions.json`, prompt packing in `capsules/assistant/browser/agent-context.js`, admission counting in `capsules/model-provider/src/local_memory.rs` and `adapters.rs`.
- Guest hash is per machine type (S0 review). Cargo's symbol hashes depend on the build machine, and they change both the `name` section and the code bytes. Reference hashes for the 19 Oct source: Mac aarch64 `fe9bcaa48669b10c9e7633f9ba7f34db1fcc65fa0dcc41ea1517c2dfc10f60c5`, Linux x86_64 `e34772d1a03a24327eea7626ba4928e19dfb13d214d14c2b70a42d698bc489a1`. In a report, give the Linux hash from two builds and the output of `python3 examples/agent-host/handoff/tools/wasm_sections.py examples/agent-host/agent-host.component.wasm`. Cursor rebuilds on the Mac. Do not change the build to make hashes match.
- Checklist: 55 of 63 done (after S0, and after the S0b review reopened `prefix-phase-a-pack`).
- Spike grade: 37 of 70, proven row by row in `reports/S0b-catch-up.md`. That is the baseline. A row goes up only with a named test and a falsifier.

## 3. Hard rules

1. **Never push to, open a PR on, comment on, or file an issue in `Elacity/elastos-runtime`** or any other Elacity repo. Reading it (fetching `develop`) is fine. Sasha decides if and when the work is shown to the team.
2. **Work only in this private repo.** One slice per session, on its own branch from the latest `spike/agent-host`. Push that branch here and open a PR **in this repo** with base `spike/agent-host`, titled `S<n> <checklist id>`. Do not merge it. Sasha merges after review.
3. **Commits:** author `SashaMIT <sash@ela.city>`. Last line of every message: `Co-authored-by: Claude <noreply@anthropic.com>`. Never rebase, amend, squash, or force-push. A fix after review is a new commit on the same branch.
4. **Before a slice:** `export RUST_TEST_THREADS=2`, then bring in the team's latest code:
   `git fetch https://github.com/Elacity/elastos-runtime.git develop && git merge FETCH_HEAD`.
   If the merge is not clean, stop and report. Do not rewrite history.
5. **One slice, then stop and write the report.** Do not start the next slice. The only exception is a written run plan such as `OVERNIGHT-1.md`, which lists the items allowed in a row and when to stop.
6. **No secrets** in any file, commit, PR text, or output. If you meet a token, key, ticket, or password, report the path and type only.
7. **No large files:** no model weights, VM images, `*.component.wasm`, or build output in commits.
8. **Do not delete branches** you did not create in this session.
9. **Simple English** in reports and PR text: short sentences, exact commands, say what is next. PR description = the report.

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

1. Sasha starts a cloud session on this repo and names the slice.
2. You do that one slice, commit, write `examples/agent-host/handoff/reports/S<n>-<slug>.md`, add one line to `handoff/LOG.md`, push the branch, open the PR in this repo, and stop. Your last message gives the branch, the PR link, and the full commit SHA.
3. Cursor reviews that exact commit: reads the diff, reruns the tests, runs its own tamper tests, and checks the principles. Because you wrote the code, the independent review is done by a GPT-family reviewer, not Claude. The verdict is `VERDICT: PASS` or `VERDICT: FIX`, with a short message for you.
4. On FIX, Sasha pastes that message into the same session. You fix it in a new commit on the same branch, push, and add a "Fix" section to the report.
5. On PASS, Sasha merges the PR into `spike/agent-host` and starts the next slice.

### Report format (`examples/agent-host/handoff/reports/S<n>-<slug>.md`)

```text
Slice:        S<n> <checklist id>
Branch / PR:  <branch>  <PR link in this repo>
Commit:       <full sha>   parent <full sha>
Develop:      Elacity develop <sha>, merged, behind 0
Machine:      <OS, arch, rustc version>
Changed:      <file> - <one line why>   (one line per file)
Invariant:    <the rule this slice makes true, in one or two sentences>
Refusals:     <each input that must be refused, and what the code returns>
Tests run:    <exact command> -> <result line>   (one line per command)
Not run here: <tests that need Sasha's Mac, and why>
Falsifiers:   <what I broke> -> <test that failed> -> reverted
Guest hash:   <Linux sha256 of agent-host.component.wasm, same on two builds; plus wasm_sections.py output>
Import list:  unchanged | changed to <list> because <reason>
Principles:   <numbers this slice touches, one line each on how it keeps them>
DeepSeek:     <file and commit of any pattern used, or "none">
Not proven:   <limits, honestly>
Checklist:    <n> of 62   (<ids> moved to completed)
Questions:    <for Sasha, or "none">
```

## 6. Corrections to `SLICES.md` (it was written 12-14 Oct)

- "No commit, no push" everywhere: replaced by rules 2 and 3 above (commit, push to this private repo only, PR here).
- "#116 and #277": both are finished. Ignore those lines.
- "Desktop Home at `localhost:61180`": not running and not reachable from the cloud. Ignore.
- "Prefix packing waits until after 0.8.0": alpha.24 is the 0.8.0 candidate. The packer function exists, but the live Assistant does not use it yet (found in S0b). Slice SA wires it in.
- Todo `run-tests-in-vm` still says "Home still has to show that list". Sasha saw the Versions list on a running Home on 13 Oct. The open part is that `cargo` is not in the VM image. S0 settles this.

## 7. What the cloud can and cannot run

- Can: the agent-host host tests, clippy, the WebAssembly build, the Wasmtime load test, `elastos-compute` tests, model-provider unit tests, Node tests.
- Cannot: the exec micro-VM (Apple Virtualization on Mac, crosvm needs KVM), `elastos-vz` tests, a running Home, model downloads, real model runs. Any slice that needs these is marked **Mac** below and is not for the cloud. If a test fails only because the machine lacks these, list it under "Not run here". Do not change the test to pass.

## 8. Slice queue

Do them in this order. Each is one session. Stop after each.

### S0 - baseline, no code change (cloud)

- Set up (section 9). Merge Elacity `develop`. Run every command in section 10. Report the guest hash and whether it matches `fe9bcaa4...`.
- Update `SLICES.md`: mark `run-tests-in-vm` done for the Home list, and add a pending todo `exec-cargo-in-image` (section 7 of SLICES.md) for "cargo is not in the VM image".
- Do the one-time DeepSeek catch-up in `DEEPSEEK.md` and add the "DeepSeek since 12 Oct" section to the report.
- Read `HISTORY.md` and say in the report if any proof there no longer matches the code.
- Add a section "Spike grade today": for each of the 14 rows, the grade the spike has actually proven, with the test name that proves it. Unproven means it does not count. Cursor checks this.
- This proves the cloud setup matches the Mac before anything changes.

### S0b - catch-up reading, no code change (cloud)

S0 started before these were added, so they are their own slice. One report: `reports/S0b-catch-up.md`.

- The one-time DeepSeek catch-up in `DEEPSEEK.md`, as a section "DeepSeek since 12 Oct".
- Read `HISTORY.md`. Section "History check": any proof there that no longer matches the code, or "none".
- Section "Spike grade today": for each of the 14 rows in section 1, the grade the spike has proven, with the test name that proves it. Unproven does not count.
- Section "Guest hash": run `handoff/tools/wasm_sections.py` on your build and paste the output. Then find the line in Cargo's source (rust-lang/cargo, the version that ships with Rust 1.91.0) that puts the compiler's verbose version, or the host, into the metadata hash. Cite file and line. If it is not there, say so.
- Only `handoff/` files change. If the catch-up suggests a slice should change, write the suggestion; Sasha decides.

### S0c - pin the three untested guest rules (cloud, tests only)

S0b found three rules in `examples/agent-host/src/lib.rs` that are right today but not pinned. S3 builds on them, so they get direct tests first.

- G1: `dispatch` refuses a step with no grant. Add a short direct test; today only one long test catches its removal.
- G2: `narrower_resource`. A child must be strictly under the parent: refuse `.../demo2` under `.../demo`, refuse the parent itself, refuse `.../demo/` with nothing after it, accept `.../demo/x`. This is the child-grant boundary.
- G3: `propose_hosted` refuses a resource that does not start with `localhost://` (for example `https://...` and a bare model name) and leaves the journal unchanged.
- Falsifiers: remove each check in turn (both halves of the G2 check separately) and show the new test fails. Revert each.
- Tests only. No production change, no import change. Report the Linux guest hash: it must not change, because tests are not in the wasm32 build.

### S1 - `sell-closed-admission` (cloud, small, test only)

- Invariant: while issue #217 is open (it is, on 19 Oct), a capsule signed by a key that is not trusted on this Home is refused at install and at launch. Assistant tests show no store.
- First find the existing admission path (search `trusted`, `verify`, `signature`, `install` under `elastos/crates`). If a test already proves the refusal, cite it by name and add only what is missing. Do not change production code in this slice.
- Falsifiers: remove the check locally and show the test fails; sign the same capsule with a trusted test key and show it is accepted, so the test is not refusing everything.
- Signing is security code. Expect the GPT review.

### S2 - UsersAI journal format, guest only, no I/O (cloud)

- `docs/AGENT_ARCHITECTURE.md` (around lines 330-350) says agent state lives under `UsersAI/...` and that the path layout needs a versioned object contract first. Write that contract as `examples/agent-host/handoff/USERSAI-JOURNAL.md`: resource name, object versions, append as compare-and-swap on the previous version, a hash link from each record to the last, a size cap, and what is model-visible. Check how the object provider names resources and versions today before you choose.
- In the guest: `encode` and `decode` for the journal with a format version. Tests: decode(encode(j)) is without_grants(j), because grant strings are never stored (confirmed in the PR #3 review); replay bytes are unchanged; one flipped byte is refused; a wrong format version is refused; a truncated journal is refused; node 0 and the epoch survive the round trip.
- No file, no Bus call, no import change.

### S3 - `hold-usersai`: the Runtime stores the journal (cloud). Ask Sasha before starting.

- The guest proposes a journal append. The Runtime checks the grant and writes it through the object provider as compare-and-swap under the S2 resource name. The guest still never sees a host path.
- This is the first time the guest calls `providers.invoke`. The import list changes. That is intended, and the report must say so.
- Tests: no grant is denied before the provider; a stale version is refused; a crash between append and result is `settlement_unknown` and is not retried; resume reads back the same bytes; another principal's journal is refused.
- Needs an adversarial review with `VERDICT: PASS` on the exact commit.

### SA - `prefix-phase-a-pack`: the live Assistant uses the packer (cloud). Only after Sasha says yes.

- `compileLiveContext` in `capsules/assistant/browser/agent-live.js` builds the prompt through `packStablePrefix`: system line first, then notes, then excerpts.
- New Node tests on `compileLiveContext` itself: the head bytes are the same across two turns; a changed note does not change the head; the existing Assistant contract tests stay green; the live prompt still says there are no tools.
- `--cache-ram` stays `0` in this slice. Do not change `DEFAULT_LIVE_SYSTEM_PROMPT`.
- This edits the shipping Assistant's code inside the spike. It still goes nowhere outside this private repo.

### S4 - `prefix-aplus-hit` (Mac, not cloud)

A measured llama.cpp prefix-cache hit on a test Home, with admission counting the cached prefix in the same change that allows `--cache-ram` above 0. Needs a real model and a running Home. Cursor does this on Sasha's Mac.

### S5 - `compact-aplus-model` (Mac, not cloud)

Home's own model writes the compaction summary. Same reason. Cursor does this on Sasha's Mac.

### Later, not now

Phase C real writes through the object provider; `exec-cargo-in-image` (Mac); phase E create-in-Home; a full adversarial review before anything goes to Elacity. Phase F (selling, second Home, `sell-second-home`) is Anders' scope: do not start it.

## 9. Cloud setup

The repo pins Rust `1.91.0` in `rust-toolchain.toml`. Also needed:

```bash
rustup target add wasm32-unknown-unknown --toolchain 1.91.0
python3 --version   # 3.10 or newer
node --version      # 20 or newer
```

Hosts the work needs: `static.rust-lang.org` (target), `crates.io` and `index.crates.io` (crates), `registry.npmjs.org` (optional Playwright), `github.com` (Elacity `develop` and DeepSeek Harness, read only). If a download is blocked by the network setting, say exactly which host was blocked and stop. Do not work around it.

## 10. Test commands (all green on 19 Oct on the Mac at `d465df3bc`)

```bash
export RUST_TEST_THREADS=2
./examples/agent-host/verify.sh                       # fmt, 72 host tests, clippy, component build
./examples/agent-host/run-local.sh                    # guest inside the Runtime's Wasmtime
sha256sum examples/agent-host/agent-host.component.wasm
(cd elastos && cargo test -p elastos-compute --lib -- --include-ignored)            # 16 on Mac
cargo test --manifest-path capsules/model-provider/Cargo.toml local_memory          # 7 tests
node --test scripts/home-agent-prefix.test.mjs                                       # 2 tests
(cd elastos && cargo test -p elastos-server launch_refuses_untrusted)              # 1 test (S1); first build is long
node --test scripts/home-agent-no-store.test.mjs                                     # 2 tests (S1)
```

Counts since then: 86 host tests after S2 (overnight 1); the guest hash changed in S2.

Optional, only if Playwright and Chromium install cleanly (do not commit `node_modules`):

```bash
(cd elastos/tools/browser-playwright-engine && npm ci && npx playwright install chromium)
node scripts/home-version-list-smoke.mjs                                             # Versions screen
```

## 11. If you are stuck

Stop and write the report with `Questions:` filled in. A clear "blocked because X" is a good result. Guessing past a security question is not.

## 12. Before this ever goes to Elacity

Not your job, recorded so it is not forgotten: the `handoff/` folder and the root `CLAUDE.md` exist only in this private repo. They are removed before any branch is offered to the team, and the work is split into one-concern PRs on Elacity `develop` after Sasha and Anders agree.
