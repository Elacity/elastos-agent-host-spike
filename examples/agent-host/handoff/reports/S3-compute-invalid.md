# S3: map bridge refusals made before storage to Invalid

```text
Slice:        S3, the elastos-compute error mapping (asked for as its own small PR, after the PR #9 review answers).
Branch / PR:  claude/compute-invalid-mapping  (draft PR in this repo, base spike/agent-host)
Commit:       0bd4655 (mapping and test); parent 92a16fa (spike/agent-host). This branch starts from spike/agent-host,
              which does not yet hold the earlier unmerged PRs, so reports/ starts here with this file.
Develop:      Elacity develop 3beb816438fd567145a8d725e22465bd83277cf0, merged, behind 0.
Machine:      Linux 6.18.44 x86_64 (cloud container), rustc 1.91.0.
Changed:      elastos/crates/elastos-compute/src/providers/component.rs - SHIPPING CODE: bus_error maps four bridge
                refusal codes to Invalid; one test
              examples/agent-host/handoff/reports/S3-compute-invalid.md - this report
              examples/agent-host/handoff/LOG.md - one line
Invariant:    A bridge refusal that is made before storage reaches the component as Invalid, so the Agent Host guest
              closes the step as refused instead of settlement_unknown. A failure that may come after storage stays
              Internal (unknown), and a token refusal stays Denied.
Refusals:     error envelope code revision_required                    -> BusError::Invalid (was Internal)
              error envelope code principal_root_protection_required   -> Invalid (was Internal)
              error envelope code invalid_localhost_path (non-canonical or misspelled Agents path) -> Invalid (was Internal)
              error envelope code revision_conflict                    -> Invalid (was Internal)
              write_failed, read_failed, provider_error, unknown codes -> Internal (unchanged)
              capability_denied, missing_token, invalid_token, denied  -> Denied (unchanged)
Tests run:    export RUST_TEST_THREADS=2
              (cd elastos && cargo test -p elastos-compute --lib) -> "16 passed; 1 ignored" (15 before, 1 new)
              (cd elastos && cargo clippy -p elastos-compute --lib --tests -- -D warnings) -> clean; fmt -> ok
New test:     bridge_refusals_made_before_storage_are_invalid
Not run here: the ignored Wasmtime test on this branch (it loads the guest built on another branch; no guest
              change here).
Falsifiers:   one at a time on 0bd4655, undone with git checkout; tree clean after.
              revision_required stays Internal                   -> bridge_refusals_made_before_storage_are_invalid FAILED
              revision_conflict stays Internal                   -> same FAILED
              principal_root_protection_required stays Internal  -> same FAILED
              invalid_localhost_path stays Internal              -> same FAILED
              write_failed becomes Invalid                       -> same FAILED (a failure after storage must stay unknown)
Guest hash:   no guest change on this branch.
Import list:  unchanged.
Principles:   11 Fail closed, then explain: a refusal is reported as a refusal; anything that may have changed storage
                stays unknown.
              19 Consequences govern effects: the guest's settlement word follows what the Runtime knows happened.
DeepSeek:     none
Not proven:   - The in-Runtime bridge sends revision_conflict as a resource result (status error), not as an error
                envelope, so this mapping does not change that path; the guest already reads that result as a
                conflict. The mapping covers the error-envelope form only.
              - append_not_allowed, operation_not_allowed and invalid_content are also refused before storage. They
                were not in the requested list, so they still map to Internal.
Checklist:    no item moves
Questions:    Map append_not_allowed, operation_not_allowed and invalid_content to Invalid too?
```

## What is next

The end-to-end Wasmtime test through the real bridge. It needs PR #8, PR #9 and this PR together, so it goes on a branch that merges all three.

## Update: three more codes (20 Oct)

Review answer to this PR's question: yes. `append_not_allowed`, `operation_not_allowed` and `invalid_content` are refused by the bridge before storage, so they now map to `Invalid` too.

```text
Commit:       the commit after 3ceac3e ("also map append_not_allowed, operation_not_allowed, invalid_content")
Tests run:    (cd elastos && cargo test -p elastos-compute --lib) -> "16 passed; 1 ignored"; clippy clean
Test:         bridge_refusals_made_before_storage_are_invalid now covers seven codes
Falsifiers:   append_not_allowed stays Internal    -> bridge_refusals_made_before_storage_are_invalid FAILED
              operation_not_allowed stays Internal -> same FAILED
              invalid_content stays Internal       -> same FAILED
```
