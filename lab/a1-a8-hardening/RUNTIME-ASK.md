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
`elastos run`. There is no session field, no guest module hash field, and
no guest function field.

`elastos run` prints `[run] Component capsule attached` and
`[run] Component capsule '<name>' exited`. It does not print the assigned
id or a session id. The attached-run Home also has no signed audit chain
for this path.

The test process and the Runtime share one uid, so the test can write the
same file. chmod on the file or its directory also blocks the Runtime.

## Required asserts (the cargo test refuses PASS without them)

Each receipt line, for the launch that just ran, must carry every field
below. The cargo test itself asserts them. `run.sh` remaps that failure
to NEEDS RUNTIME. A cargo `ok` while any field is missing is a FAIL.

1. **Component id** the Runtime assigned at load, also printed on a `[run]`
   line or returned by an operator API the test can read without opening
   the jsonl. A missing assigned id is **not** a match for any
   `capsule_id`. It is NEEDS RUNTIME at best, never PASS. A record whose
   `capsule_id` is not that id is a FAIL.
2. **Session id** for this `elastos run`, printed on a `[run]` line or
   returned by the same API. Mint a 128-bit hex from a host CSPRNG at
   launch and record it in a host-held used set. Do not write
   `identity::context().session` (today `self.capsule_id` in
   `elastos-compute` `component.rs`) and do not alias `capsule_id`.
   `session-1`, a 32-hex value below `2^64` (clock, pid, or zeros), and
   a session reused across runs are not a bind. The receipt
   `session_id` must **equal this launch's id**. Any other non-empty
   string is a FAIL. Presence alone is not a bind.
3. **Guest module hash** of the exact component bytes that were loaded,
   written by the Runtime in the field named `module_hash` only, hashed
   from the same opened fd that `load` reads (or re-checked after load).
   A rename-swap between hash and load is a FAIL. Aliases (`guest_hash`,
   `wasm_hash`) are not a match. A missing hash is NEEDS RUNTIME. A hash
   that is not these executed bytes is a FAIL.
4. **Guest function** the Runtime recorded for the ask. Required. The
   honest sequence is `request_journal_grants`, then write refused, then
   read refused. Judge that sequence only from host-side evidence: the
   jsonl lines appended after launch, and the Runtime / bus host log.
   Guest-controlled stderr is not evidence, including
   `Invalid("the journal append did not follow its grants")`. A guest
   that skips `request_journal_grants` and prints that sentence is a
   FAIL (`F-A8-guest-follow-sentence`).
5. **A writer the test process cannot satisfy**: a Runtime signature or
   a monotonic sequence over those fields, or a file the test user cannot
   append to.
6. **Strictly increasing `seq`** on each receipt line, using checked
   add. Gaps, repeats, reordering, or wrap at `u64::MAX` are a FAIL. A
   missing `seq` is NEEDS RUNTIME.
7. **Same-inode shrink or rewrite** of the jsonl is a FAIL. Record the
   real size at lock. Bind receipts to a host-held snapshot taken at
   run end (`F-A8-shrink-dead`, `F-A8-rewrite-after-run`). A dangling
   symlink journal, a UTF-8 BOM, or a truncated final line is a FAIL.
   One complete line is not a bind.
8. **Duplicate JSON keys FAIL.** Bind fields are byte-exact. A
   `capsule_id` with whitespace is a FAIL (`F-A8-dup-keys`,
   `F-A8-capsule-trim`).

Receipts written after the inode snapshot, or at any point in the launch
window before `elastos run` starts, are a FAIL (`F-A8-race-after-snapshot`,
`F-A8-test-writes-lines`). The pre-exist check covers the whole run
window: absent at snapshot, still absent at spawn, then only the inode
that appears during that run is read. A rewrite after `run_until` is a
FAIL against the sealed copy.

## What the lab will do until then

- Fresh Home via `mktemp`.
- Fail if `capability-requests.jsonl` exists before spawn, including after
  the inode snapshot or as a dangling symlink.
- Record size and inode at launch; lock the first inode seen during the
  run; read only that file.
- Treat a missing assigned id as no match (NEEDS RUNTIME). Refuse a
  record whose capsule id is not the id from `[run]` / API when that id
  is present.
- Require `session_id` to equal this launch, to be a CSPRNG 128-bit hex
  (`>= 2^64`), unused across runs, and to differ from `capsule_id`.
  `module_hash` must equal the staged bytes hashed from the same opened
  fd that `load` will execute. `guest_function` must be
  `request_journal_grants`. `seq` must be strictly increasing without
  wrap. A BOM or a truncated final line is refused.
- Catch a test that writes the two expected lines before launch
  (`F-A8-test-writes-lines`) or after the snapshot
  (`F-A8-race-after-snapshot`).
- Catch a guest that skips `request_journal_grants` and prints the
  Invalid sentence (`F-A8-guest-follow-sentence`,
  `F-A8-skip-journal-grants`).

Until items 1 to 4 land in the Runtime, the A8 pass row stays
**NEEDS RUNTIME**. Do not count it as closed authorship.
