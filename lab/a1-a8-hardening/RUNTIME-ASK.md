# Runtime ask: bind A8 receipts to this launch

Lab-only. This file is the ask. Do not treat a lab workaround as the fix.

A8 can lock write-then-read isolation on a fresh Home. It cannot book
"this guest, this session, this Runtime call" until the Runtime writes
those bindings itself.

## What the Runtime writes today

`record_capability_request` in `elastos/crates/elastos-server/src/resource_bridge.rs`
appends one JSON line to `<data dir>/runtime/capability-requests.jsonl`:

```json
{
  "action": "write",
  "capsule_id": "component-<uuid>",
  "code": "manifest_capability_denied",
  "principal_id": null,
  "resource": "localhost://Public/../../../../.ssh/id_ed25519"
}
```

`capsule_id` is `component-<uuid>` from load in
`elastos-compute` `ComponentProvider::load`. `principal_id` is null on
`elastos run`. There is no session field and no guest module hash field.

`elastos run` prints `[run] Component capsule attached` and
`[run] Component capsule '<name>' exited`. It does not print the assigned
id. The attached-run Home also has no signed audit chain for this path.

The test process and the Runtime share one uid, so the test can write the
same file. chmod on the file or its directory also blocks the Runtime.

## What A8 needs the Runtime to record

Each receipt line, for the launch that just ran:

1. **Component id** the Runtime assigned at load, also printed on a `[run]`
   line or returned by an operator API the test can read without opening
   the jsonl.
2. **Session id** for this `elastos run` (today the pending store reuses
   the capsule id, and the jsonl has no session field).
3. **Guest module hash** of the exact component bytes that were loaded,
   written by the Runtime, not by the test.
4. **A writer the test process cannot satisfy**: a Runtime signature or
   a monotonic sequence over those fields, or a file the test user cannot
   append to.

Optional, and useful: the bus reason and the guest function that asked
(`request_journal_grants`), so write-then-read without that function
cannot look like the honest sequence.

## What the lab will do until then

- Fresh Home via `mktemp`.
- Fail if `capability-requests.jsonl` exists before the guest starts.
- Record size and inode at launch; read only lines appended after.
- Reject a record whose capsule id is not the id from `[run]` / API when
  that id is present.
- Catch a test that writes the two expected lines and launches a no-bus
  guest (`F-A8-test-writes-lines`).
- Require the honest follow-up sentence after `request_journal_grants`
  (`F-A8-skip-journal-grants`).

Until items 1 to 3 land in the Runtime, the A8 pass row stays
**NEEDS RUNTIME**. Do not count it as closed authorship.
