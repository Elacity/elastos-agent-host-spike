# plan-approval lane log

> A proposal carries no authority.

- 001: `preview` returns the plan bytes and `agent_conformance::identity::sha256` of those bytes and calls no `StandIn` method; the exact-name test reads the stand-in only through `get_capability_list` and `get_capsules`; two hand-run plants caught and restored; 1 test, 2 plants.
- 002: `submit_shown_plan` calls only `seed_request` with the preview hash as `reason`, `grant_shown_plan` calls only `post_capability_grant` for duration `once`, and `perform_shown_plan` ignores `approved` and calls `authorise` only when the recomputed hash matches that `reason`; `preview` unchanged; `approval_binds_to_the_previewed_plan_hash` added; eight hand-run plants caught and restored; 2 tests, 8 plants.

## 001

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 5:

> A proposal carries no authority.

Plant command, one plant at a time, each restored before the next:

```bash
cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib preview_makes_no_effect -- --exact
```

### F-preview-writes-grant

- old bytes, 17: `let _ = stand_in;`
- new bytes, 164: `stand_in.seed_grant("req-plant", "component-1", "localhost://Public/plan-approval/a.txt", "read", "once", 1, agent_conformance::standin_runtime::Life::Live, false);`
- planted crate compiled; `preview_makes_no_effect` failed at `src/lib.rs:56:5` on the first unchanged-grants assertion: `assertion left == right failed: the preview returned the plan bytes, the hash is sha256 of those bytes, and the live grants and the capsule list are unchanged on a fresh stand-in`; left held the seeded `req-plant` entry, right was empty.
- restored, the test passes.

### F-preview-fixed-hash

- old bytes, 41: `agent_conformance::identity::sha256(plan)`
- new bytes, 77: `"0000000000000000000000000000000000000000000000000000000000000000".to_owned()` (the literal is 64 zeroes; `.to_owned()` makes it an owned `String` so the planted crate compiles, per the spec check).
- planted crate compiled; `preview_makes_no_effect` failed at `src/lib.rs:74:5` on the `previews[0].sha256` assertion: left `0000000000000000000000000000000000000000000000000000000000000000`, right `156e544f8e98e81c5e504dfd7ed21d2adb703b8f9dafa8701b064255b69f85ae`.
- restored, the test passes.

After both restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant. The restored proof command took 0.56 s real. This lane has no `falsifiers.json`; the runner has no `plan-approval` command (BACKLOG item 3).

## 002

Design text followed, [docs/AGENT_ARCHITECTURE.md](../../docs/AGENT_ARCHITECTURE.md) Request flow step 8:

> If additional consent is required, Runtime records a pending request and
> Home or Inbox presents it. The UI does not mint the grant itself.

Delegation and mandates:

> **Allow once** authorizes one exact operation.

Non-negotiable boundaries:

> A visible approval card is not the grant authority.

Plant command, one plant at a time, each restored before the next:

```bash
RUST_TEST_THREADS=2 CARGO_INCREMENTAL=0 cargo test --locked --manifest-path lab/plan-approval/Cargo.toml --lib approval_binds_to_the_previewed_plan_hash -- --exact
```

Every plant compiled. Assertion lines below are in the planted file.

### F-approval-changed-plan

- old bytes, 122: the three lines
  `if reason != shown.as_str() {`, `return Err((400, "plan bytes differ from the approved hash".to_owned()));`
  and `}` inside `perform_shown_plan`.
- new bytes, 0: the block deleted, so a differing plan reaches `authorise`.
- planted file failed at `src/lib.rs:434:5` on the `assert_eq!` whose text is
  `the shell grant bound the shown hash and the flag granted nothing`; left `Ok(())`,
  right `Err((400, "plan bytes differ from the approved hash"))`.
- restored, the test passes.

### F-approval-flag-grants

- old bytes, 22: `    let _ = approved;`
- new bytes, 35: `    if approved { return Ok(()); }`
- planted file failed at `src/lib.rs:286:81` with
  `called Result::unwrap_err() on an Ok value: ()` on the first perform with `approved` true.
- restored, the test passes.

### F-approval-step-not-in-plan

- old bytes, 277: the UTF-8 refusal and the `contains` refusal inside
  `submit_shown_plan`, from `let Ok(text) = std::str::from_utf8(&preview.plan) else {`
  through the closing `}` of `if !(text.contains(resource) && text.contains(action)) {`.
- new bytes, 0: both refusals deleted, so an absent resource reaches `seed_request`.
- planted file failed at `src/lib.rs:289:5` on the assertion
  `a step the shown bytes do not contain is refused`; left `Ok(())`,
  right `Err((400, "step is not in the shown plan"))`.
- restored, the test passes.

### F-approval-submit-hash

- old bytes, 161: the three lines
  `if agent_conformance::identity::sha256(&preview.plan) != preview.sha256 {`,
  `return Err((400, "plan hash does not name these bytes".to_owned()));` and `}`
  inside `submit_shown_plan`.
- new bytes, 0: the hash refusal deleted.
- planted file failed at `src/lib.rs:314:5` on the assertion
  `a hash that does not name the bytes is refused`; left `Ok(())`,
  right `Err((400, "plan hash does not name these bytes"))`.
- restored, the test passes.

### F-approval-perform-hash

- old bytes, 116: the three lines `if shown != preview.sha256 {`,
  `return Err((400, "plan hash does not name these bytes".to_owned()));` and `}`
  inside `perform_shown_plan`.
- new bytes, 0: the hash refusal deleted.
- planted file failed at `src/lib.rs:333:5` on the assertion
  `perform refuses a hash that does not name the bytes`; left
  `(400, "unknown grant: req-plan")`, right `(400, "plan hash does not name these bytes")`.
- restored, the test passes.

### F-approval-unknown-request

- old bytes, 74: `        .ok_or_else(|| (400, format!("unknown request: {request_id}")))?;`
- new bytes, 175: the missing-reason refusal replaced with
  `let Some(reason) = reason else { return stand_in.authorise(Caller::Client { session_id }, request_id); };`
  after the reason chain.
- planted file failed at `src/lib.rs:388:5` on the assertion
  `perform refuses a request no listing holds`; left
  `(400, "unknown grant: req-unknown")`, right `(400, "unknown request: req-unknown")`.
- restored, the test passes.

### F-approval-invalid-utf8

- old bytes, 139: the three lines
  `let Ok(text) = std::str::from_utf8(&preview.plan) else {`,
  `return Err((400, "step is not in the shown plan".to_owned()));` and `};`
  inside `submit_shown_plan`.
- new bytes, 55: `    let text = String::from_utf8_lossy(&preview.plan);`
- planted file failed at `src/lib.rs:348:5` on the assertion
  `bytes that are not UTF-8 carry no step`; left `Ok(())`,
  right `Err((400, "step is not in the shown plan"))`.
- restored, the test passes.

### F-approval-absent-action

- old bytes, 61: `    if !(text.contains(resource) && text.contains(action)) {`
- new bytes, 34: `    if !text.contains(resource) {`
- planted file failed at `src/lib.rs:368:5` on the assertion
  `an action the shown bytes do not contain is refused`; left `Ok(())`,
  right `Err((400, "step is not in the shown plan"))`.
- restored, the test passes.

After all restores, `git diff -- lab/plan-approval/src/lib.rs` shows no plant.
`cargo fmt --manifest-path lab/plan-approval/Cargo.toml -- --check` passed. The
restored proof command took 0.38 s real; `preview_makes_no_effect` passed in the
same run. This lane has no `falsifiers.json`; the runner's `plan-approval`
command is a crate-table row, not a recovery target (BACKLOG item 3).
