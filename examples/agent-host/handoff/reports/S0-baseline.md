# S0 baseline

```text
Slice:        S0 baseline (no code change)
Branch / PR:  claude/festive-wozniak-rf6shm  https://github.com/SashaMIT/elastos-agent-host-spike/pull/1
Commit:       3fd4168066775a7cdebabdfa402704285ccecbf4   parent 189a34ff6f8ba8095baeb1ec450a3a30b8262ee8
              (the SLICES.md change; this report and the LOG line are the next commit on the same branch)
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, already merged (d465df3bc), behind 0. No new merge commit.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0 (f8297e351 2025-10-28), cargo 1.91.0,
              target wasm32-unknown-unknown added, Python 3.13.16, Node 22.22.0. No /dev/kvm.
Changed:      examples/agent-host/handoff/SLICES.md - run-tests-in-vm marked completed for the Home list; new pending todo exec-cargo-in-image; one paragraph in section 7
              examples/agent-host/handoff/reports/S0-baseline.md - this report
              examples/agent-host/handoff/LOG.md - one line for S0
Invariant:    The cloud setup runs every section 10 command green at the spike head, with no code change.
              The guest still imports only elastos:bus identity, runtime, and types.
Refusals:     None new. S0 adds no code. The falsifiers below show that three existing refusals still bite.
Tests run:    export RUST_TEST_THREADS=2
              ./examples/agent-host/verify.sh -> "test result: ok. 72 passed; 0 failed", clippy clean, 0 warnings, "agent-host capsule verification: OK"
              ./examples/agent-host/run-local.sh -> "agent_host_example_keeps_the_head_across_a_compaction ... ok", "test result: ok. 1 passed"
              sha256sum examples/agent-host/agent-host.component.wasm -> e34772d1a03a24327eea7626ba4928e19dfb13d214d14c2b70a42d698bc489a1
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> "test result: ok. 16 passed; 0 failed; 0 ignored"
              cargo test --manifest-path capsules/model-provider/Cargo.toml local_memory -> "test result: ok. 7 passed; 0 failed"
              node --test scripts/home-agent-prefix.test.mjs -> "# tests 2 # pass 2 # fail 0"
Not run here: node scripts/home-version-list-smoke.mjs (optional). npm ci worked, but Playwright 1.59.1 wants
              chromium_headless_shell-1217 and this machine has build 1194. This environment says not to run
              "playwright install", so I stopped. Error: "Executable doesn't exist at
              /opt/pw-browsers/chromium_headless_shell-1217/...".
              Exec micro-VM boots (Apple VZ, crosvm needs /dev/kvm, which is absent), elastos-vz tests, a running
              Home, model runs. Mac only, per HANDOFF section 7.
Falsifiers:   1. lib.rs admit_skill: changed "text.len() > SKILL_BUDGET" to ">=" ->
                 tests::an_over_budget_skill_leaves_the_journal_unchanged FAILED (71 passed, 1 failed) -> reverted, 72 pass.
              2. component.rs: added "elastos:bus/providers@1.0.0" to the expected import list ->
                 agent_host_example_keeps_the_head_across_a_compaction FAILED with "agent-host may import only the Bus
                 calls it uses", left = [identity, runtime, types] -> reverted, test passes.
              3. exec_vm.rs admit_exec_argv: let "cargo test" return Ok(TestPass) instead of Err("program missing") ->
                 exec_vm::tests::cargo_is_not_in_the_image_and_an_unknown_command_does_not_launch FAILED -> reverted, 10 pass.
                 This is the test the new todo exec-cargo-in-image cites.
Guest hash:   e34772d1a03a24327eea7626ba4928e19dfb13d214d14c2b70a42d698bc489a1
              DOES NOT MATCH the Mac hash fe9bcaa48669b10c9e7633f9ba7f34db1fcc65fa0dcc41ea1517c2dfc10f60c5. Not "fixed".
              What I checked: the hash is the same on three builds here (verify.sh, run-local.sh, and a fresh
              worktree at a different path), so the build is repeatable on this machine and the repo path remap works.
              The wasm has no unremapped host path (the build script checks this, and strings shows only /rustc/... and /rust/...).
              Likely cause, not proven: something tied to the host toolchain (x86_64 Linux here, aarch64 macOS on
              the Mac) or to HOME / cargo layout reaches the output, for example symbol hashes or the producers section.
Import list:  unchanged (elastos:bus/identity@1.0.0, runtime@1.0.0, types@1.0.0)
Not proven:   Why the hash differs from the Mac. To find out, diff the two files, for example with
              "wasm-tools print" or "wasm-tools objdump" on both, and compare the custom sections and symbol names.
              The cloud tests prove the source behaves the same. They do not prove the bytes match.
Checklist:    56 of 63   (run-tests-in-vm moved to completed; exec-cargo-in-image added as pending, so the total went from 62 to 63)
Questions:    1. Can you send the Mac agent-host.component.wasm (or its "wasm-tools print" output) so the hash
                 difference can be explained? Until then, should reviews treat the guest hash as per-machine?
              2. Is it OK that the checklist total is now 63, not 62, because S0 adds exec-cargo-in-image?
```

## What is next

S1 `sell-closed-admission` (cloud, test only), in a new session, after Sasha merges this PR.
