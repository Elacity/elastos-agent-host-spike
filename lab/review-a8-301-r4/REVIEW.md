# Adversarial review r4 of #301 A1/A8 at `b0cc24c2`

Draft. Do not merge.

Independent review of [PR #301](https://github.com/Elacity/elastos-agent-host-spike/pull/301) at
`b0cc24c2a6ba5088e15146990c89cbbc1435769f` (code `460746b2`, parent `10316585`).
Prior reviews:
[PR #356](https://github.com/Elacity/elastos-agent-host-spike/pull/356) (r1) on `1a82d25b`,
[PR #388](https://github.com/Elacity/elastos-agent-host-spike/pull/388) (r2) on `a2398b5d`,
[PR #408](https://github.com/Elacity/elastos-agent-host-spike/pull/408) (r3) on `10316585`.

Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28), uid 1000.
No KVM. Detached worktree `/tmp/pr-301-a8-r4` at the reviewed commit. That
branch was left untouched. This folder is the only write surface. This
private repo only; `Elacity/elastos-runtime` was not touched.

Anders's rule used here: a check counts when its complete journey, its
refusal evidence, and its required reviews all pass.

**Plain English.** The author's suite counts match this rerun: **1 PASS**,
**2 NEEDS RUNTIME**, **1 BLOCKED**. The host-key cargo test is **FAILED**.
`run.sh` remaps that to NEEDS RUNTIME and exits 0. All **14** named plants
are **CAUGHT** by real assertions. All **7** binding mutants are **KILLED**.
Timeouts are **not** counted as caught. `F-A8a` and `F-A8-runtime` stop on
a `pending` host record with `exit:signaled`.

A1 is a real admission refusal from this checkout's `elastos` binary, not
a lab shim. That row can count on Linux.

A8 stays **NEEDS RUNTIME** / **BLOCKED**. The r3 hunts that reached cargo
`ok` are dead. New hunts in this round also fail to reach cargo `ok`.
Ten of them still **SURVIVED** as later PASS holes: the guest can read
this launch's id as `identity.session`; the lab will bind `session-1` or
`session == capsule_id`; `module_hash` is of in-memory bytes, not the
file `load` reads; sequence numbers are ignored; a same-inode rewrite of
the jsonl is accepted as the host receipt; duplicate JSON keys last-win;
`capsule_id` is trimmed.

**Lab half: `VERDICT: FIX`.** The author's r3 claims hold. The lab is
still not a closed authorship lock for the day the Runtime prints an id.
Keep A8 out of the counted column.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| Suite: 1 PASS, 2 NEEDS RUNTIME, 1 BLOCKED; cargo host-key FAILED; `run.sh` exit 0 | HOLDS | `lab/a1-a8-hardening/run.sh` |
| Falsifiers 14/14 CAUGHT by real assertions | HOLDS | `python3 lab/a1-a8-hardening/falsify.py` |
| Binding mutants 7/7 KILLED | HOLDS | `python3 lab/a1-a8-hardening/mutants/binding.py` |
| Timeouts counted as CAUGHT | HOLDS that they are not | `F-A8a` / `F-A8-runtime` are `exit:signaled` + `pending` |
| Sequence judged only from host receipts and the Runtime / bus host log | HOLDS against r3 hunts | `host_sequence_function` ignores guest stderr; `F-A8-guest-follow-sentence` CAUGHT |
| Missing assigned is not a match | HOLDS | `bound_denied_actions(..., None)` is empty; cargo FAILED |
| Receipts after snapshot or with foreign `capsule_id` fail | HOLDS against the named plants | `F-A8-race-after-snapshot`, `F-A8-test-writes-lines` CAUGHT |
| Cargo test FAILS while component id, session id, module hash, or guest function is missing; `session_id` must equal this launch | HOLDS | honest row FAILED; `M-session-presence` KILLED |
| RUNTIME-ASK.md states those as required asserts | HOLDS | ask items 1–4 match the cargo panic |
| A1 PASS is genuine | HOLDS | this checkout's `elastos`, `validate_component_capsule` before load |
| A8 host-key row stays NEEDS RUNTIME | HOLDS | `run.sh` remap; `assigned:None`, `session_id None`, `module_hash None`, `guest_function None` |
| A8 WasmBus sentence stays NEEDS RUNTIME | HOLDS | ignore + `--ignored` panic |
| A8 shipped-bytes row stays BLOCKED | HOLDS | ignore + `--ignored` panic AC-002-ARGS |

## Suite

Command, after `cargo fetch --locked` of the lane, wasi-guest, agent-host,
`elastos/tools/componentize`, and `elastos` manifests (the suite itself stays
`--offline`):

```sh
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
```

fmt exit 0. `run.sh` cargo exit 0. Lib unit tests: 8 passed. Raw row
output: `evidence/run.sh.txt`.

```text
a1 runtime: elastos sha256 de9f9b9ff6faed144f35791dbdf9087cc23b1caad4eb46d1e19888612e1929df
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; …")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 de9f9b9ff6faed144f35791dbdf9087cc23b1caad4eb46d1e19888612e1929df
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports [five elastos:bus]
a8 injected agent-host: sha256 f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 imports [the same five]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 receipt cursor: size:0 inode:None path:/tmp/a8-home.jimwjq/home/.local/share/elastos/runtime/capability-requests.jsonl
a8 host key read: exit:Some(1) assigned:None session:None guest_hash:f3d89ab4… host_records:[write then read, both manifest_capability_denied, capsule_id component-49151c47-…, session_id None, module_hash None, guest_function None] marker_absent:true unchanged:true
a8 authorship: needs runtime: capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | NEEDS RUNTIME (capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function)
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Guest component hashes match the PR log. The debug `elastos` hash on this
machine is `de9f9b9f…`. The PR log's `e027209c…` is a different native
debug binary of the same source.

Source SHA-256 matches the PR log:

- `tests/a1_wasi_import.rs`: `ccf9fc61…`
- `tests/a8_agent_host_host_key.rs`: `a6822318…`
- `src/lib.rs`: `f18dfdb6…`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5…`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `d52efcf8…`

Forced ignored rows both panic with their ignore reason (exit 101):
`shipped_wasm_bus_prints_internal_sentence` and
`shipped_agent_host_bytes_read_host_key`. Cargo exit 0 on the suite is
those ignores plus the remapped host-key FAILED. They are honest, not
hidden passes.

## A1 is a real Runtime refusal

`Home::spawn` launches `runtime().path`. That path is
`lab/a1-a8-hardening/target/runtime/debug/elastos`, built by
`cargo build --locked --offline --manifest-path elastos/Cargo.toml -p
elastos-server --bin elastos`. SHA-256 `de9f9b9f…` matches the printed
`a1 runtime` line. The file is an ELF 64-bit pie executable, 193 MiB,
not stripped. The allowlist sentence and `elastos:bus/…@1.0.0` names
are in this binary's strings. The lab crate has no copy of that check.

`F-A1-runtime` rebuilt this binary. The WASI guest was still refused,
now by the core-module check
(`component core module import "wasi:cli/environment@0.2.0::get-environment" is forbidden`).
The exact-reason assert failed. That is the allowlist in this
checkout's Runtime, with the core-module check behind it.

The control guest is admitted and prints `[run] Component capsule
'a1-wasi-guest' exited`. The refused guest does not print `exited`.
One WASI interface on the `elastos run` path. Other WASI interfaces and
Home launch stay out.

## Falsifiers

`python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.
14 of 14 CAUGHT. Each failed at a listed `fail_needle` with exit 101.
No timeout. Source restored to the baseline SHA-256 after each entry
(`evidence/post-falsify-sha256.txt`). `git status` in the worktree
stayed clean after the last restore.

| ID | Runner | What ran |
| --- | --- | --- |
| F-A1a | CAUGHT | Control bytes in the refused slot: `exit:Some(0) refusal_line:None` |
| F-A1-runtime | CAUGHT | Allowlist off. Core-module reason. Exact-reason assert failed. |
| F-A8a | CAUGHT | Manifest declared the fake key. Host record is `pending` for write. `exit:signaled`. |
| F-A8-runtime | CAUGHT | Manifest refusal off. elastos `7e8a2c8a…`. Same `pending` write and `exit:signaled`. |
| F-A8-forge | CAUGHT | `guest_has_refusal_sentence:true`, injected `45e4b8fb…`. Failed before `serve`. |
| F-A8-early | CAUGHT | Old early-return guest `9cff3664…`. `guest_has_early_injection:true`. Failed before `serve`. |
| F-A8-skip-guards | CAUGHT | Injected `c0745cec…`. `host_records:[]`. |
| F-A8-piece-forge | CAUGHT | Injected `92d42c03…`. `host_records:[]`. |
| F-A8-wasm-bus-only | CAUGHT | Honest guest `f3d89ab4…` has write then read. Internal sentence on stderr failed. |
| F-A8-direct-request | CAUGHT | Injected `8441f14e…`. One `read` only. |
| F-A8-test-writes-lines | CAUGHT | Test wrote the two lines; no-bus guest `92d42c03…`. File existed before launch. |
| F-A8-skip-journal-grants | CAUGHT | Injected `9363b143…`. Write then read present. Cargo FAILED on host-side sequence / guest function. |
| F-A8-guest-follow-sentence | CAUGHT | Injected `d661f4d6…`. Write then read present. Invalid sentence printed. Cargo FAILED. |
| F-A8-race-after-snapshot | CAUGHT | Injected `7d81d0cb…`. Foreign id after snapshot. File existed at spawn. |

The skip-journal-grants and guest-follow-sentence hashes on this
machine (`9363b143…`, `d661f4d6…`) match r3's independent replants.
The PR log's `47c2355d…` / `66790ec5…` are different compiles of the
same fixtures.

## Binding mutants

`python3 lab/a1-a8-hardening/mutants/binding.py`: 7 of 7 KILLED.

| ID | Mutant | Result |
| --- | --- | --- |
| M-sequence-stderr | Follow sentence on guest stderr is the lock | KILLED |
| M-assigned-none-match | Missing assigned matches any `capsule_id` | KILLED |
| M-after-snapshot-window | Inode-none cursor accepts a post-snapshot file | KILLED |
| M-println-not-assert | Missing Runtime-ask fields still cargo `ok` | KILLED |
| M-session-presence | Any non-empty `session_id` binds | KILLED |
| M-guest-function-optional | `guest_function` is not required | KILLED |
| M-hash-alias | `wasm_hash` / `guest_hash` count as `module_hash` | KILLED |

## New attacks

Each plant is an exact edit of the detached worktree, or a predicate
copy of `src/lib.rs`. Live plants restore SHA-256. None reached cargo
`ok`. Ten SURVIVED as later PASS holes.

### 1. Guest writes the host log or receipts file (preopen / symlink)

**H-guest-write-preopen: CAUGHT.**
`ComponentProvider` says it exposes no WASI, environment, filesystem
preopen, FIFO, raw socket, or gateway. `instantiate_component` links
only `ProductCapsuleV1` (elastos:bus). There is no `DirPerms` and no
`wasi:filesystem`.

Patch (read-only, `elastos/crates/elastos-compute/src/providers/component.rs`):

```text
/// This runner exposes no WASI, environment, filesystem preopen, FIFO, raw
/// socket, or gateway authority. Every guest effect goes through the Bus
/// hostcall configured by Runtime.
…
ProductCapsuleV1::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
```

**H-guest-write-receipts: CAUGHT.**
Live plant: symlink `<data>/Public/capability-requests.jsonl` → the
receipts path, then a guest that `capabilities::request` write and
`providers::invoke` write on `localhost://Public/capability-requests.jsonl`,
then the honest fake-key write/read.

Exact patch: `attacks/guest-write-receipts.txt` plus

```rust
    let home = Home::new();
    {
        let receipts = home.receipts_path();
        let public = home.data().join("Public");
        std::fs::create_dir_all(&public).unwrap();
        let alias = public.join("capability-requests.jsonl");
        let _ = std::os::unix::fs::symlink(&receipts, &alias);
    }
```

Injected `60245514…`. The Public write is `manifest_capability_denied`.
The jsonl is not guest-written. The extra denied resource fails
"the injection must fail only the fake key". Cargo FAILED. The guest
cannot open the host log or the receipts file.

### 2. Forged receipt whose session_id is copied from env / argv the guest can read

**H-session-from-env-argv: CAUGHT.**
`Home::spawn` clears the environment and sets only `HOME`, `TMPDIR`,
`PATH`, and `ELASTOS_CARRIER_MDNS=0`. `elastos run` is invoked as
`run <capsule dir>` with no capsule argv. `elastos:bus@v1` has no
launch-argument channel (AC-002-ARGS). WASI environ is refused at
admission (A1).

**H-session-from-identity: SURVIVED.**
The guest can read this launch's id:

```rust
// elastos/crates/elastos-compute/src/providers/component.rs
fn context(&mut self) -> elastos::bus::types::IdentityContext {
    elastos::bus::types::IdentityContext {
        principal: self.principal_id.clone(),
        capsule: self.capsule_id.clone(),
        session: self.capsule_id.clone(),
        device: None,
    }
}
```

`identity::context().session` is the assigned `component-<uuid>`. The
guest cannot write the jsonl. The lab never reads this field. The
value is still a bind source the guest already has.

**H-forged-session-from-identity: CAUGHT.**
Live plant: guest asks write then read, then returns
`Invalid(format!("[run] session_id={}", context.session))`.

Exact patch: `attacks/session-from-identity.txt`.

Injected `cc26d1e5…`. Printed `session:None`.
`assigned_session_id` only reads lines that start with `[run] `. The
Runtime wraps the error, so the guest cannot mint a `[run]` session.
Cargo FAILED.

### 3. Session id predictable or reused across launches

**H-session-predictable: SURVIVED.**
`is_session_id` accepts any `session-<alnum-_>` token. A complete bind
with `session-1` is PASS. UUID v4 per `load` is not reused across
Homes. Fresh `mktemp` plus `assert_receipts_absent` catches a leftover
file. The lab will still bind a short printed id.

**H-session-equals-capsule: SURVIVED.**
A complete bind with `session_id == capsule_id` is PASS.
`identity.session` is already that alias. The lab does not refuse it.

Patch (missing check in `authorship_gaps`):

```rust
// not present: refuse session_id == capsule_id, and refuse session-1
// is_session_id("session-1") == true
```

### 4. module_hash over a different file than the one executed (TOCTOU)

**H-toctou-hash-vs-load: SURVIVED.**
The test hashes in-memory `injected.bytes`. `ComponentProvider::load`
later does `Component::from_file` on `path.join(entrypoint)`. There is
no re-hash of the staged file and no Runtime `module_hash` today.

```rust
let guest_hash = sha256(&injected.bytes);           // tests/a8_agent_host_host_key.rs
let component = Component::from_file(&engine, &component_path)  // load()
```

**H-toctou-swap-staged: CAUGHT** for this swap.
Exact patch, after `home.stage`:

```rust
    let capsule = home.stage("agent-host", &injected.bytes, &manifest);
    {
        let entry = /* capsule.json entrypoint */;
        std::fs::write(capsule.join(entry), &shipped.bytes).unwrap();
    }
```

`guest_hash` stays `f3d89ab4…`. The executed file is the shipped
guest. `exit:Some(0)`, `host_records:[]`. Isolation fails. Cargo
FAILED. A swap to another write-then-read binary of different bytes
is still untested; the hash is not of the loaded file.

### 5. Duplicate or out-of-order sequence numbers

**H-seq-out-of-order-actions: CAUGHT.**
`isolation_denied_actions` keeps file order. `[read, write]` is not
`[write, read]`.

**H-seq-duplicate-pairs: CAUGHT.**
`[write, read, write, read]` fails the exact list.

**H-seq-numbers-ignored: SURVIVED.**
`parse_capability_record` has no `seq` / `sequence` field. A complete
bind with `seq: 2` then `seq: 1` is PASS.

```rust
// parse_capability_record reads action/resource/code/capsule_id/…
// unknown keys including "seq" are dropped
```

### 6. Host log rotated or truncated mid-run

**H-log-rotate-new-inode: CAUGHT.**
`read_capability_requests_since` panics when the inode changes after
a known file.

**H-log-truncate-same-inode: SURVIVED.**
**H-log-shrink-dead: SURVIVED.**
`lock_launch_receipts` always stores `size: 0`:

```rust
        if guard.is_none() {
            *guard = Some(ReceiptCursor {
                path,
                inode: Some(meta.ino()),
                size: 0,
            });
        }
```

The shrink check (`meta.len() < cursor.size`) never fires for that
cursor. A same-inode truncate+rewrite is read from offset 0.

**H-log-rewrite-same-inode: SURVIVED.**
Live patch, after `run_until` and before `receipts_since_launch`:

```rust
    {
        let path = home.receipts_path();
        std::fs::write(&path, /* write+read, capsule_id FOREIGN, session-1,
            module_hash = sha256(&injected.bytes),
            guest_function = request_journal_grants */).unwrap();
    }
    let records = home.receipts_since_launch();
```

Printed `host_records` carry
`capsule_id component-00000000-…`, `session_id Some("session-1")`,
`module_hash Some("f3d89ab4…")`, `guest_function Some("request_journal_grants")`.
Cargo still FAILED (`assigned:None`, bind session missing). The
forged lines replaced the Runtime's honest pair on the same inode.
The day `[run]` prints an id, rewrite those lines with that id and
the row can flip to PASS.

### 7. JSON with duplicate keys (first vs last wins)

**H-json-duplicate-keys: SURVIVED.**

```json
{"action":"write","capsule_id":"component-00000000-…","capsule_id":"component-341af27a-…",…}
```

`parse_capability_record` uses `serde_json::Value::get`. Last key
wins. The foreign first id is dropped. A complete bind is PASS.
There is no reject of duplicate keys.

### 8. capsule_id case or whitespace variants

**H-capsule-whitespace: SURVIVED.**
`optional_string` does `str::trim`. `"  component-341af27a-…  "`
matches the assigned id. A complete bind is PASS.

```rust
        .map(str::trim)
        .filter(|text| !text.is_empty())
```

**H-capsule-case: CAUGHT.**
`COMPONENT-341AF27A-…` (uppercase) is `FAIL foreign capsule_id`.
Comparison is `==` after trim. No case fold.

## RUNTIME-ASK

The ask is still accurate on what the Runtime writes today:
`capsule_id` = `component-<uuid>`, `principal_id` null, no session,
no module hash, no guest function, no `[run]` id. The raw records in
this rerun match that shape.

Item 5 (a writer the test process cannot satisfy) is still open.
`H-log-rewrite-same-inode` is that writer on the same inode.

Add to the minimum, or the lab will book a later PASS with these
hunts live:

1. Refuse a same-inode rewrite: lock size at first sight, or a
   Runtime signature / monotonic sequence the test cannot append.
2. Reject duplicate JSON keys. Do not trim bind fields.
3. Session must be this launch **and** must not be the capsule id
   (identity already aliases them). `session-1` is not a bind.
4. `module_hash` must be of the bytes `load` executed, hashed by the
   Runtime after the file is opened, not of the test's in-memory copy.
5. If sequence numbers exist, require them strictly increasing on
   `request_journal_grants` then write then read.

## Counted or not

| Row | Counted? | Why |
| --- | --- | --- |
| A1 `wasi_import_is_refused_at_admission` | **Counted on Linux** | Allowlist sentence from this checkout's `elastos`, control admitted, F-A1a and F-A1-runtime caught. Other WASI interfaces and Home launch stay out. |
| A8 `agent_host_host_key_read_is_refused` | **Not counted. Stays NEEDS RUNTIME.** | Linux run of this checkout's Runtime does refuse write then read on the fake key when the honest injection calls the bus. Authorship fields are still missing. Same-inode rewrite, last-wins keys, trimmed ids, and session aliases stay live. |
| A8 `shipped_wasm_bus_prints_internal_sentence` | **Not counted. Stays NEEDS RUNTIME.** | Honest ignore. Forced run panics with that reason. |
| A8 `shipped_agent_host_bytes_read_host_key` | **Not counted. Stays BLOCKED.** | Honest ignore AC-002-ARGS. Forced run panics with that reason. |

## What must run on macOS

This host did not run macOS, aarch64, or Jetson. The data-dir rule is
written (`~/Library/Application Support/elastos`). Sash's Mac still
needs:

1. `lab/a1-a8-hardening/run.sh` — the four rows, and the printed jsonl
   records under the Mac data dir.
2. The fourteen plants and `mutants/binding.py`.
3. The four live hunts here (`H-guest-write-receipts`,
   `H-forged-session-from-identity`, `H-toctou-swap-staged`,
   `H-log-rewrite-same-inode`).
4. A dump of the raw jsonl, to see `capsule_id` / `session_id` /
   `module_hash` / `guest_function` on Darwin.
5. Timeouts stay NOT CAUGHT.

macOS NOT RUN.

## Bookability

A1 on this lane is one WASI import (`wasi:cli/environment@0.2.0`)
refused at admission on `elastos run`, Linux x86_64, plus a control
that is admitted. That journey is complete enough to count on Linux.

A8 is still one Bus read of one fake file, from a mutated agent-host
copy, on Linux x86_64. The fourteen plants hold. The cargo test
refuses PASS while the Runtime-ask fields are missing. The row stays
NEEDS RUNTIME until the Runtime writes the bind **and** the test
refuses the surviving hunts above.

Keep the WasmBus Internal sentence in NEEDS RUNTIME. Keep the shipped
bytes BLOCKED on AC-002-ARGS.

The agent-conformance probe proof (PR #179 / F-ac8a) was NOT RUN here.
This lane does not replace it.

## Principles

- 3, 7, 18: Runtime still owns admission and the manifest bound on the
  committed guest. The fake file stays a fixture. The guest has no
  filesystem preopen.
- 5: the receipt writer lives in the trusted core. It is small. The
  test process can still replace the same inode.
- 10: the signed audit chain is still absent on this `elastos run`
  Home. The jsonl is a second path added for the test.
- 11: empty grants fail closed. Duplicate keys and trimmed ids do not.
- 12: README says sequence is host receipts and the Runtime / bus host
  log. That holds against guest stderr. It does not hold against a
  same-inode rewrite of those receipts.

DeepSeek: none.

## Not run

- macOS A8 (needs Sash's Mac).
- aarch64, Jetson, a real host key, Home launch, other WASI interfaces.
- Provider `Path traversal not allowed` (the request stays on this side
  of the operator).
- Agent-conformance `host_key_read_is_refused` / F-ac8a on this head.
