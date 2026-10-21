# S0c pin guards

```text
Slice:        S0c pin the three untested guest rules (G1, G2, G3 from S0b). Overnight 1, item 1.
Branch / PR:  claude/overnight-1  (draft PR in this repo, link in LOG.md and the PR)
Commit:       21f87260f26991c635d85828c02854ae504730a0 (tests) and 194b533e9e3503cafeda09f45b3efaee054ccb47 (demo-old case)
              parent 04ec1910b01a3d4e415ae58430b33ad31528e60b (merge of PR #2, which contains PR #1)
Base:         origin/spike/agent-host 6883dda (overnight plan). PRs #1 and #2 were still open, so this branch
              merges claude/s0b-catch-up first (04ec191), then spike/agent-host (2475b09). Merge commits only.
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, already merged (d465df3bc), behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0 (f8297e351 2025-10-28), cargo 1.91.0 (ea2d97820).
Changed:      examples/agent-host/src/lib.rs - three new tests inside `mod tests`; no production line changed
              examples/agent-host/handoff/reports/S0c-pin-guards.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    G1: dispatch refuses a Prepared step that has no grant, even when authorize was never called.
              G2: a child resource must sit strictly under its parent: a prefix sibling, the parent itself,
                  and the parent plus a bare slash are refused; parent/x is accepted.
              G3: a hosted proposal must name a localhost:// resource; anything else leaves the journal unchanged.
Refusals:     dispatch(no grant)                         -> false, state Denied, grant None, model bytes unchanged
              propose_child(.../demo2)                   -> Err("not a subset"), no step
              propose_child(.../demo-old)                -> Err("not a subset"), no step
              propose_child(.../demo)                    -> Err("not a subset"), no step
              propose_child(.../demo/)                   -> Err("not a subset"), no step
              open_child_host(any of the four above)     -> Err
              propose_hosted("https://api.example.com/v1/model") -> Err("host path"), journal unchanged
              propose_hosted("qwen2.5-1.5b")             -> Err("host path"), journal unchanged
              Controls (so the tests do not refuse everything): a granted read dispatches; .../demo/x is a
              Child step; localhost://Models/hosted is a Prepared step.
Tests run:    export RUST_TEST_THREADS=2
              ./examples/agent-host/verify.sh -> "test result: ok. 75 passed; 0 failed", 0 warnings, "agent-host capsule verification: OK"
              ./examples/agent-host/run-local.sh -> "agent_host_example_keeps_the_head_across_a_compaction ... ok"
              (cd elastos && cargo test -p elastos-compute --lib -- --include-ignored) -> "test result: ok. 16 passed; 0 failed"
              cargo test --manifest-path capsules/model-provider/Cargo.toml local_memory -> "test result: ok. 7 passed; 0 failed"
              node --test scripts/home-agent-prefix.test.mjs -> "# pass 2 # fail 0"
Not run here: home-version-list-smoke.mjs (Chromium build mismatch, as in S0); Mac-only VM tests.
Falsifiers:   Each mutation alone, on the committed tests, undone with git checkout; tree clean after.
              G1  dispatch: `|| step.grant.is_none()` removed
                  -> dispatch_without_a_grant_is_denied_even_without_authorize FAILED (+ the long test) -> reverted
              G2a narrower_resource: `rest.starts_with('/') &&` removed
                  -> a_child_must_sit_strictly_under_its_parent FAILED -> reverted
              G2b narrower_resource: `rest.len() > 1 &&` removed
                  -> a_child_must_sit_strictly_under_its_parent FAILED -> reverted
              G2  both halves removed -> a_child_must_sit_strictly_under_its_parent FAILED -> reverted
              G3  propose_hosted: `!resource.starts_with("localhost://")` replaced by `resource.is_empty()`
                  -> a_hosted_proposal_must_name_a_localhost_resource FAILED -> reverted
              Before any of these, each of G2a, G2b, G3 failed no test at all (S0b).
Guest hash:   e34772d1a03a24327eea7626ba4928e19dfb13d214d14c2b70a42d698bc489a1 on two builds (verify.sh, run-local.sh).
              Unchanged, as expected: tests are not in the wasm32 build.
              wasm_sections.py: file 259928 bytes; /1/10 201840 7de05070202bdf50 (same as S0b).
Import list:  unchanged (elastos:bus/identity@1.0.0, runtime@1.0.0, types@1.0.0)
Principles:   3 No ambient authority and 11 Fail closed: a step with no grant cannot be dispatched, and a child
                cannot widen its parent's resource. Now both are pinned by direct tests.
              10 One canonical path: a hosted proposal names a localhost:// resource, never a raw endpoint.
              12 Docs, code, tests agree: three rules the docs state are now held by tests.
DeepSeek:     none
Not proven:   These are guest rules with the test token fixture-grant. The Runtime grant check for a real
              guest proposal is still S3.
Checklist:    55 of 63 (no todo for S0c; nothing moved)
Questions:    none
```

## What I found while writing the tests

The first G2 test used only `…/demo2`, as HANDOFF names it. The falsifier for the slash half (G2a) still passed: after the parent, `demo2` leaves one byte (`"2"`), so the length half refused it anyway. I added `…/demo-old` (four bytes left), so each half now fails the test on its own. That is commit `194b533`.

## Grade

No row moves. G1 to G3 were listed under "Not proven" for rows 5, 9 and 11 in S0b. They are now pinned, but each of those rows still needs the Runtime path (S3) to go up. Total stays 37 of 70.

## What is next

Overnight item 2: S1 `sell-closed-admission`.
