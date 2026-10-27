# Log

## 26 Oct 2026: first runs (Linux x86_64)

Machine: Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), no KVM.
Base: `spike/agent-host` at `b5069b992dac29d1457576efabd5700e34ea05e7`.
Elacity `develop` was not merged: this task may change only this folder.

### Rows

Command: `lab/a1-a8-hardening/run.sh` (after the falsifiers below, with the
Runtime source restored). Result: cargo exit 0, 1m57s.

```text
a1 runtime: elastos sha256 97c4cc2e31d6fe3b72413022cfc640829bd4f6d57ac6efd4cc40304eddfb7931
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 97c4cc2e31d6fe3b72413022cfc640829bd4f6d57ac6efd4cc40304eddfb7931
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 injected agent-host: sha256 9cff3664618f2ad65cd2ff4e0b3349568ee1f5b8ab159e78f8548e112eed8a96 imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 host key read: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Compute error: Component capsule denied: BusError::Internal(\"capsule manifest does not declare authority for localhost://Public/../../../../.ssh/id_ed25519\")") marker_absent:true unchanged:true

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | PASS
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

The same component hashes came out of every build in this session (the two
guest builds also match a manual trial build), so the builds were stable on
this machine. The `localhost-provider` hash is not printed; it is pinned in
each Home's `components.json` and verified by the Runtime at `serve`.

The first separate runs of each test file (before any falsifier) gave the same
lines: A1 passed in 189 s (including the provider and guest builds), A8 passed
in 39 s.

### Falsifiers

Command: `python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.

| ID | Observed | Verdict |
| --- | --- | --- |
| F-A1a | The control build in the refused slot was admitted: `exit:Some(0) refusal_line:None`. The test failed at the refusal assertion (exit 101). | CAUGHT |
| F-A1-runtime | Runtime rebuilt with the allowlist check off (elastos sha256 `15f2aa61…`). The WASI build was still refused, now by the core-module check: `Error: Component capsule failed: Invalid manifest: component core module import "wasi:cli/environment@0.2.0::get-environment" is forbidden`. The exact-reason assertion failed (exit 101). | CAUGHT |
| F-A8a | The staged manifest declared the fake key. The request went on to the operator and stayed pending: `Component capsule denied: BusError::Internal("capability request still pending after 30s")`. Marker absent, key unchanged. The refusal assertion failed (exit 101). | CAUGHT |
| F-A8-runtime | Runtime rebuilt with the manifest refusal off (elastos sha256 `02099ce8…`). Same pending-request result as F-A8a. Marker absent, key unchanged. The refusal assertion failed (exit 101). | CAUGHT |

After each entry `falsify.py` restored the edited file and checked its SHA-256:

- `tests/a1_wasi_import.rs`: `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`
- `tests/a8_agent_host_host_key.rs`: `c20d3ba1dd15b3cb37ee587e27e6a68dfeed8290dd833f9e4105297476d27e2d`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5f1bcb725c08f8e54e347a23caa9856992007a2306b8289896a0da992`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `b8edb86cf709a23c1634e420691cf9916e07014f648009e19878285a3da076be`

`sha256sum -c` on both Runtime files matched the hashes taken before the first
Runtime falsifier, `git status` showed no Runtime change, and the final run's
rebuilt `elastos` has the original hash `97c4cc2e…`.

What the falsifiers show beyond "caught":

- A1: behind the allowlist, the Runtime's core-module import check refuses the
  same WASI import. The A1 row pins the allowlist reason, so it fails if the
  allowlist alone is removed.
- A8: behind the manifest bound, the next step is an operator decision. This
  operator (`dev_mode = true`, no shell attached) left the request pending, and
  the client gave up after 30 s. No grant reached the guest, so the provider's
  own `..` check was not reached in these runs.

### Cleanup

Passing runs removed their Homes. The four falsifier Homes (each holding only
its staged capsules and captures) were checked and removed by hand. No
`elastos` or `localhost-provider` process was left. `/tmp/elastos/storage`
exists as an empty directory from `elastos run` (AC-006-STORAGE); it was left
in place.

## 26 Oct 2026: #316 A8 findings

Machine: Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), no KVM.
Head after the grant-path fix: `bf52805734d14ec98190fea44d29597a9e723bd3`.
Elacity `develop` was not merged. Only this folder changed.

#316 on `32abea67` found two A8 holes. Both were reproduced here, then
closed in this folder.

1. A guest that returns `capsule manifest does not declare authority for …`
   and mentions the bus only under `core::hint::black_box(0) == 1` kept all
   five imports. On the old test that run would pass. After the origin
   assert, `F-A8-forge` is CAUGHT
   (`guest_has_refusal_sentence:true`, injected sha256 `45e4b8fb…`).
2. The old injection returned at the start of `run()`. Compaction,
   `host_path`, and `request_journal_grants` never ran. The copy now fails
   `host_path` only for the fake key, drops the `JOURNAL_ROOT` early return,
   points `journal_resource` at the key, asks through `WasmBus`, and `?`s
   the same `capabilities::request`. `F-A8-early` restores the old
   injection. CAUGHT (`guest_has_early_injection:true`). That planted
   guest is byte-identical to the old row
   (`9cff3664618f2ad65cd2ff4e0b3349568ee1f5b8ab159e78f8548e112eed8a96`).

A first grant-path attempt set `host_path` to always false. `run()` then
failed at `compaction did not shrink the journal` before any grant. The
next commit fails `host_path` only for the fake key. Other `..` and `/`
checks stay.

### Rows

Command: `lab/a1-a8-hardening/run.sh` after the falsifiers, with Runtime
source restored. cargo exit 0.

```text
a1 runtime: elastos sha256 97c4cc2e31d6fe3b72413022cfc640829bd4f6d57ac6efd4cc40304eddfb7931
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 97c4cc2e31d6fe3b72413022cfc640829bd4f6d57ac6efd4cc40304eddfb7931
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 injected agent-host: sha256 f7a41ffdbe7cf6bd041108599079a64ec4f6bc2aa635a97d7455c7b423f9b8e5 imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 host key read: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Compute error: Component capsule denied: BusError::Internal(\"capsule manifest does not declare authority for localhost://Public/../../../../.ssh/id_ed25519\")") marker_absent:true unchanged:true

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | PASS
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

### Falsifiers

Command: `python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.

| ID | Observed | Verdict |
| --- | --- | --- |
| F-A1a | Control bytes in the refused slot were admitted: `exit:Some(0) refusal_line:None`. | CAUGHT |
| F-A1-runtime | Allowlist off (elastos sha256 `15f2aa61…`). Core-module check refused the WASI build. Exact-reason assertion failed. | CAUGHT |
| F-A8a | Manifest declared the fake key. Client waited out the 60s bound: `exit:None refusal_line:None`. Marker absent, key unchanged. Origin asserts still held. | CAUGHT |
| F-A8-runtime | Manifest refusal off (elastos sha256 `02099ce8…`). Same timeout as F-A8a. | CAUGHT |
| F-A8-forge | Forged guest: `guest_has_refusal_sentence:true`, five bus imports kept. Failed at the origin assert before `serve`. | CAUGHT |
| F-A8-early | Old early-return guest, hash `9cff3664…`. `guest_has_early_injection:true`. Failed at that origin assert before `serve`. | CAUGHT |

Restored SHA-256 after each entry:

- `tests/a1_wasi_import.rs`: `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`
- `tests/a8_agent_host_host_key.rs`: `3c03fdc79e8ac2d4f2f7bbeda81f77dae265d60f1f8e0c6f1e50577520722859`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5f1bcb725c08f8e54e347a23caa9856992007a2306b8289896a0da992`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `b8edb86cf709a23c1634e420691cf9916e07014f648009e19878285a3da076be`

`git status` showed no Runtime change. The final `run.sh` rebuilt `elastos`
to the original hash `97c4cc2e…`.

macOS was not run.

## 26 Oct 2026: #356 host-receipt A8

Machine: Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), no KVM.
Head of the evidence: `032df8eef4dddfcd87dce29f9745c91cefb8044b` (this log
is the next commit). Elacity `develop` was not merged.

#356 on `1a82d25b` kept four plants alive. This run closes them on the
host-side receipt, not on stderr text.

1. B-piece-forge (`F-A8-piece-forge`): the guest builds the Internal
   sentence from split strings. Origin still prints
   `guest_has_refusal_sentence:false`. Host records stay empty. The write
   then read `manifest_capability_denied` assert fails.
2. A-skip-guards (`F-A8-skip-guards`): the `host_path` special-case and
   the `JOURNAL_ROOT` delete are dropped. `request_journal_grants` never
   calls the bus. Host records stay empty.
3. D-direct-request (`F-A8-direct-request`): the guest asks
   `capabilities::request` once after identity. Host records one `read`.
   The test requires write then read from `request_journal_grants`.
4. C-wasm-bus-only (`F-A8-wasm-bus-only`): the honest guest already uses
   shipped `WasmBus` only. Requiring the Internal sentence on stderr
   fails. That claim stays the NEEDS RUNTIME row.

`F-A8a` and `F-A8-runtime` now stop on the first non-denied host record
(`pending`). Both fail the receipt assert with `exit:signaled`. A
timeout (`exit:timeout` / `exit:None`) is NOT CAUGHT.

### Rows

Command: `lab/a1-a8-hardening/run.sh` after the falsifiers, with Runtime
source restored. cargo exit 0.

```text
a1 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 injected agent-host: sha256 f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 host key read: exit:Some(1) host_records:[CapabilityRequestRecord { action: "write", resource: "localhost://Public/../../../../.ssh/id_ed25519", code: "manifest_capability_denied" }, CapabilityRequestRecord { action: "read", resource: "localhost://Public/../../../../.ssh/id_ed25519", code: "manifest_capability_denied" }] marker_absent:true unchanged:true

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | PASS
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Forced ignored rows both panic with their ignore reason (exit 101):
`shipped_wasm_bus_prints_internal_sentence` and
`shipped_agent_host_bytes_read_host_key`.

### Falsifiers

Command: `python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.
10 of 10 CAUGHT. Each failed at a listed `fail_needle` with exit 101.
No timeout.

| ID | Observed | Verdict |
| --- | --- | --- |
| F-A1a | Control bytes in the refused slot: `exit:Some(0) refusal_line:None`. | CAUGHT |
| F-A1-runtime | Allowlist off (elastos sha256 `9d4a0c09…`). Core-module check refused the WASI build. Exact-reason assertion failed. | CAUGHT |
| F-A8a | Manifest declared the fake key. Host record is `pending` for write. Client stopped early: `exit:signaled`. Receipt assert failed. | CAUGHT |
| F-A8-runtime | Manifest refusal off (elastos sha256 `72fe1fa5…`). Same `pending` write and `exit:signaled`. | CAUGHT |
| F-A8-forge | Forged guest: `guest_has_refusal_sentence:true`, injected sha256 `45e4b8fb…`. Failed at the origin assert before `serve`. | CAUGHT |
| F-A8-early | Old early-return guest, hash `9cff3664…`. `guest_has_early_injection:true`. Failed at that origin assert before `serve`. | CAUGHT |
| F-A8-skip-guards | A-skip-guards: injected sha256 `c0745cec…`. `host_records:[]`. Failed the write-then-read receipt. | CAUGHT |
| F-A8-piece-forge | B-piece-forge: injected sha256 `92d42c03…` (same bytes as the #356 plant). `host_records:[]`. Failed the receipt. | CAUGHT |
| F-A8-wasm-bus-only | C-wasm-bus-only: honest guest `f3d89ab4…` has write then read receipts. Requiring the Internal sentence on stderr failed. | CAUGHT |
| F-A8-direct-request | D-direct-request: injected sha256 `8441f14e…` (same bytes as the #356 plant). One `read` receipt only. Failed write-then-read. | CAUGHT |

Restored SHA-256 after each entry:

- `tests/a1_wasi_import.rs`: `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`
- `tests/a8_agent_host_host_key.rs`: `ebad194d6d99143bf717a081645c2b7370e90a0d20bb774a6b83a5edb4a77ff0`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5f1bcb725c08f8e54e347a23caa9856992007a2306b8289896a0da992`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `d52efcf8754427be26b2c276ae66bb11e8ce521eb84da47fd7128cf2833cf92a`

`git status` showed no Runtime change after restore. The final `run.sh`
`elastos` hash is `e027209c…`.

macOS A8, aarch64, Jetson: NOT RUN.
Shipped agent-host bytes: BLOCKED (AC-002-ARGS).

## 26 Oct 2026: #388 r2 authorship binding

Machine: Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), no KVM.
Head: `68de7051de9f96a73f98d807e430e2a9293eeafc` (parent `ee99fecdd5f5f91128ff92cabbde306c43abacc6`,
which sits on `a2398b5d`). Elacity `develop` was not merged. Lab only.
No Runtime source change. Ask: `RUNTIME-ASK.md`.

#388 on `a2398b5d` found that the test process could write the two
expected jsonl lines, that the file was not bound to this guest or
session, and that write-then-read without `request_journal_grants`
also passed. This run closes those holes on the lab side and keeps
the pass row out of PASS.

1. Each Home is `mktemp -d` (`/tmp/a8-home.*`). The test fails if
   `capability-requests.jsonl` exists before launch. Size and inode
   at launch were `0` / `None`. Only appended lines are read.
2. The pass row wants the component id from a `[run]` line or API,
   plus session id and guest module hash. Runtime writes
   `capsule_id` as `component-<uuid>` and leaves `principal_id`,
   `session_id`, and `module_hash` empty. `[run]` does not print the
   id. The row is NEEDS RUNTIME.
3. `F-A8-test-writes-lines` writes the two expected lines and launches
   the no-bus piece-forge guest (`92d42c03…`). CAUGHT: the file
   already existed.
4. `F-A8-skip-journal-grants` asks write then read after identity,
   ignores the refusal, and skips `request_journal_grants`. Host
   records are write then read. CAUGHT on the honest follow-up
   sentence. First plant build failed (`return` made `run()`
   unreachable under `-Dwarnings`); `black_box` fixed that so the
   catch is a real assertion.

The test process and the Runtime share one uid, so the file cannot
be made unwritable without also blocking the Runtime. That stays in
`RUNTIME-ASK.md`.

### Rows

Command: `lab/a1-a8-hardening/run.sh` after the falsifiers, with Runtime
source restored. cargo exit 0.

```text
a1 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 injected agent-host: sha256 f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 receipt cursor: size:0 inode:None path:/tmp/a8-home.cwtQgL/home/.local/share/elastos/runtime/capability-requests.jsonl
a8 host key read: exit:Some(1) assigned:None guest_hash:f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 host_records:[write then read, both manifest_capability_denied, capsule_id component-341af27a-…, session_id None, module_hash None] marker_absent:true unchanged:true
a8 authorship: needs runtime: capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | NEEDS RUNTIME (capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash)
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Forced ignored rows both panic with their ignore reason (exit 101):
`shipped_wasm_bus_prints_internal_sentence` and
`shipped_agent_host_bytes_read_host_key`.

### Falsifiers

Command: `python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.
12 of 12 CAUGHT. Each failed at a listed `fail_needle` with exit 101.
No timeout.

| ID | Observed | Verdict |
| --- | --- | --- |
| F-A1a | Control bytes in the refused slot: `exit:Some(0) refusal_line:None`. | CAUGHT |
| F-A1-runtime | Allowlist off (elastos sha256 `9d4a0c09…`). Core-module check refused the WASI build. Exact-reason assertion failed. | CAUGHT |
| F-A8a | Manifest declared the fake key. Host record is `pending` for write. Client stopped early: `exit:signaled`. Receipt assert failed. | CAUGHT |
| F-A8-runtime | Manifest refusal off (elastos sha256 `72fe1fa5…`). Same `pending` write and `exit:signaled`. | CAUGHT |
| F-A8-forge | Forged guest: `guest_has_refusal_sentence:true`, injected sha256 `45e4b8fb…`. Failed at the origin assert before `serve`. | CAUGHT |
| F-A8-early | Old early-return guest, hash `9cff3664…`. `guest_has_early_injection:true`. Failed at that origin assert before `serve`. | CAUGHT |
| F-A8-skip-guards | A-skip-guards: injected sha256 `c0745cec…`. `host_records:[]`. Failed the write-then-read receipt. | CAUGHT |
| F-A8-piece-forge | B-piece-forge: injected sha256 `92d42c03…`. `host_records:[]`. Failed the receipt. | CAUGHT |
| F-A8-wasm-bus-only | C-wasm-bus-only: honest guest `f3d89ab4…` has write then read receipts. Requiring the Internal sentence on stderr failed. | CAUGHT |
| F-A8-direct-request | D-direct-request: injected sha256 `8441f14e…`. One `read` receipt only. Failed write-then-read. | CAUGHT |
| F-A8-test-writes-lines | Test wrote the two expected lines; no-bus guest `92d42c03…`. Failed because the jsonl existed before launch. | CAUGHT |
| F-A8-skip-journal-grants | Injected sha256 `47c2355d…`. Write then read receipts present. Failed the honest follow-up sentence. | CAUGHT |

Restored SHA-256 after each entry:

- `tests/a1_wasi_import.rs`: `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`
- `tests/a8_agent_host_host_key.rs`: `1d5e7818c05c665c975839c7c831cf67f6667270ecb1a4ce235e8d6fe0d9c627`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5f1bcb725c08f8e54e347a23caa9856992007a2306b8289896a0da992`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `d52efcf8754427be26b2c276ae66bb11e8ce521eb84da47fd7128cf2833cf92a`

`git status` showed no Runtime change after restore. The rebuilt
`elastos` hash is `e027209c…` again.

### macOS (NOT RUN)

Sash's Mac still needs these, with the data dir
`~/Library/Application Support/elastos`:

```sh
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
python3 lab/a1-a8-hardening/falsify.py F-A8-test-writes-lines
python3 lab/a1-a8-hardening/falsify.py F-A8-skip-journal-grants
python3 lab/a1-a8-hardening/falsify.py F-A8-piece-forge
python3 lab/a1-a8-hardening/falsify.py F-A8-skip-guards
python3 lab/a1-a8-hardening/falsify.py F-A8-direct-request
python3 lab/a1-a8-hardening/falsify.py F-A8-wasm-bus-only
python3 lab/a1-a8-hardening/falsify.py F-A8a
python3 lab/a1-a8-hardening/falsify.py F-A8-runtime
```

Dump the raw jsonl from that Home and check `capsule_id` / `session_id`
/ `module_hash` on Darwin. Timeouts stay NOT CAUGHT.

macOS A8, aarch64, Jetson: NOT RUN.
Shipped agent-host bytes: BLOCKED (AC-002-ARGS).
A8 authorship: NEEDS RUNTIME.

## 27 Oct 2026: #408 r3 host-side sequence and launch window

Machine: Linux x86_64 cloud VM, rustc 1.91.0 (f8297e351 2025-10-28), no KVM.
Head: `460746b2124aefbf47683a467fe40a6407ea3f97` (parent `10316585`).
Elacity `develop` was not merged. Lab only. No Runtime source change.
Ask: `RUNTIME-ASK.md`. Mutants: `mutants/binding.py`.

#408 on `10316585` found two hunts that still reached cargo `ok`:
a guest that skips `request_journal_grants` and prints the Invalid
follow sentence, and a jsonl written after the inode snapshot with a
foreign `capsule_id`. The cargo test was `ok` while every Runtime-ask
field was missing. This run closes those holes on the lab side.

1. Sequence is judged from host receipts and the Runtime / bus host
   log. Guest stderr is ignored. `F-A8-guest-follow-sentence` is
   CAUGHT (`66790ec5…`). Write then read present. Cargo FAILED.
2. The pre-exist check covers snapshot through spawn. The first inode
   seen during `elastos run` is the lock. Missing assigned is not a
   match. `F-A8-race-after-snapshot` is CAUGHT (`7d81d0cb…`): the file
   existed at spawn.
3. The cargo test itself refuses PASS (`test ... FAILED`) while
   component id, session id, module hash, or guest function is
   missing. `session_id` must equal this launch. `module_hash` has no
   aliases. `run.sh` remaps that failure to NEEDS RUNTIME. cargo `ok`
   while authorship is unmet is a FAIL.
4. Seven mutants of those asserts are KILLED (`mutants/binding.py`).

The Runtime still writes only `capsule_id` and leaves session, hash,
and guest function empty. `[run]` does not print the id. The pass row
stays NEEDS RUNTIME.

### Rows

Command: `lab/a1-a8-hardening/run.sh` after the falsifiers, with Runtime
source restored. cargo exit 0. The host-key cargo test is FAILED
(refuses PASS); `run.sh` remaps it.

```text
a1 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 injected agent-host: sha256 f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 imports ["elastos:bus/types@1.0.0", "elastos:bus/runtime@1.0.0", "elastos:bus/identity@1.0.0", "elastos:bus/capabilities@1.0.0", "elastos:bus/providers@1.0.0"]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 receipt cursor: size:0 inode:None path:/tmp/a8-home.ppyc0u/home/.local/share/elastos/runtime/capability-requests.jsonl
a8 host key read: exit:Some(1) assigned:None session:None guest_hash:f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 host_records:[write then read, both manifest_capability_denied, capsule_id component-7f8982d4-…, session_id None, module_hash None, guest_function None] marker_absent:true unchanged:true
a8 authorship: needs runtime: capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | NEEDS RUNTIME (capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function)
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Forced ignored rows both panic with their ignore reason (exit 101):
`shipped_wasm_bus_prints_internal_sentence` and
`shipped_agent_host_bytes_read_host_key`.

Lib unit tests: 8 passed (`cargo test --lib`).

### Falsifiers

Command: `python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.
14 of 14 CAUGHT. Each failed at a listed `fail_needle` with exit 101.
No timeout. Zero SURVIVED.

| ID | Observed | Verdict |
| --- | --- | --- |
| F-A1a | Control bytes in the refused slot: `exit:Some(0) refusal_line:None`. | CAUGHT |
| F-A1-runtime | Allowlist off (elastos sha256 `9d4a0c09…`). Core-module check refused the WASI build. Exact-reason assertion failed. | CAUGHT |
| F-A8a | Manifest declared the fake key. Host record is `pending` for write. `exit:signaled`. Receipt assert failed. | CAUGHT |
| F-A8-runtime | Manifest refusal off (elastos sha256 `72fe1fa5…`). Same `pending` write and `exit:signaled`. | CAUGHT |
| F-A8-forge | Forged guest: `guest_has_refusal_sentence:true`, injected sha256 `45e4b8fb…`. Failed at the origin assert before `serve`. | CAUGHT |
| F-A8-early | Old early-return guest, hash `9cff3664…`. `guest_has_early_injection:true`. Failed at that origin assert before `serve`. | CAUGHT |
| F-A8-skip-guards | A-skip-guards: injected sha256 `c0745cec…`. `host_records:[]`. Failed the write-then-read receipt. | CAUGHT |
| F-A8-piece-forge | B-piece-forge: injected sha256 `92d42c03…`. `host_records:[]`. Failed the receipt. | CAUGHT |
| F-A8-wasm-bus-only | C-wasm-bus-only: honest guest `f3d89ab4…` has write then read receipts. Requiring the Internal sentence on stderr failed. | CAUGHT |
| F-A8-direct-request | D-direct-request: injected sha256 `8441f14e…`. One `read` receipt only. Failed write-then-read. | CAUGHT |
| F-A8-test-writes-lines | Test wrote the two expected lines; no-bus guest `92d42c03…`. Failed because the jsonl existed before launch. | CAUGHT |
| F-A8-skip-journal-grants | Injected sha256 `47c2355d…`. Write then read present. Failed the host-side sequence (`request_journal_grants`). | CAUGHT |
| F-A8-guest-follow-sentence | Injected sha256 `66790ec5…`. Write then read present. Printed the Invalid sentence. Cargo FAILED. | CAUGHT |
| F-A8-race-after-snapshot | Injected sha256 `7d81d0cb…`. Foreign id written after the snapshot. Failed because the jsonl existed at spawn. | CAUGHT |

### Mutants

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

Restored SHA-256 after each entry:

- `tests/a1_wasi_import.rs`: `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`
- `tests/a8_agent_host_host_key.rs`: `a68223187680161cf2021f8e4e0a3f48469c0de580f6fc02d1252cba8a8b2a1b`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5f1bcb725c08f8e54e347a23caa9856992007a2306b8289896a0da992`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `d52efcf8754427be26b2c276ae66bb11e8ce521eb84da47fd7128cf2833cf92a`

`git status` showed no Runtime change after restore. The rebuilt
`elastos` hash is `e027209c…` again.

### macOS (NOT RUN)

Sash's Mac still needs these, with the data dir
`~/Library/Application Support/elastos`:

```sh
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
python3 lab/a1-a8-hardening/falsify.py F-A8-guest-follow-sentence
python3 lab/a1-a8-hardening/falsify.py F-A8-race-after-snapshot
python3 lab/a1-a8-hardening/falsify.py F-A8-test-writes-lines
python3 lab/a1-a8-hardening/falsify.py F-A8-skip-journal-grants
python3 lab/a1-a8-hardening/falsify.py F-A8-piece-forge
python3 lab/a1-a8-hardening/falsify.py F-A8-skip-guards
python3 lab/a1-a8-hardening/falsify.py F-A8-direct-request
python3 lab/a1-a8-hardening/falsify.py F-A8-wasm-bus-only
python3 lab/a1-a8-hardening/falsify.py F-A8a
python3 lab/a1-a8-hardening/falsify.py F-A8-runtime
python3 lab/a1-a8-hardening/mutants/binding.py
```

Dump the raw jsonl from that Home and check `capsule_id` / `session_id`
/ `module_hash` / `guest_function` on Darwin. Timeouts stay NOT CAUGHT.

macOS A8, aarch64, Jetson: NOT RUN.
Shipped agent-host bytes: BLOCKED (AC-002-ARGS).
A8 authorship: NEEDS RUNTIME.

## 27 Oct 2026: #437 r4 authorship lock

Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28), no KVM.
Head: `f062eb8c8c3c93a99e7946ee3b0f578726c418d6` on
`cursor/a8-authorship-lock-0a84`, parent `b0cc24c2` (#301). Lab/test only.
No Runtime source change.

### Rows

Command: `lab/a1-a8-hardening/run.sh`. cargo exit 0.

```text
a1 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; …")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports [five elastos:bus]
a8 injected agent-host: sha256 f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 imports [the same five]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 receipt cursor: size:0 inode:None path:/tmp/a8-home.BoWx3g/home/.local/share/elastos/runtime/capability-requests.jsonl
a8 host key read: exit:Some(1) assigned:None session:None guest_hash:f3d89ab4… host_records:[write then read, both manifest_capability_denied, capsule_id component-f4801332-…, session_id None, module_hash None, guest_function None, seq None] marker_absent:true unchanged:true
a8 authorship: needs runtime: capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function, receipt seq

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | NEEDS RUNTIME (capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function, receipt seq)
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Lib unit tests: 8 passed. Authorship-lock tests: 8 passed.

### Falsifiers

`python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.
14 of 14 original plants CAUGHT. 8 of 8 new plants CAUGHT. Each failed
at a listed `fail_needle` with exit 101. No timeout.

| ID | Observed | Verdict |
| --- | --- | --- |
| F-A1a | Control bytes in the refused slot: `exit:Some(0) refusal_line:None`. | CAUGHT |
| F-A1-runtime | Allowlist off (elastos sha256 `9d4a0c09…`). Core-module check refused the WASI build. Exact-reason assertion failed. | CAUGHT |
| F-A8a | Manifest declared the fake key. Host record is `pending` for write. `exit:signaled`. | CAUGHT |
| F-A8-runtime | Manifest refusal off (elastos sha256 `72fe1fa5…`). Same `pending` write and `exit:signaled`. | CAUGHT |
| F-A8-forge | Forged guest `45e4b8fb…`. `guest_has_refusal_sentence:true`. | CAUGHT |
| F-A8-early | Old early-return guest `9cff3664…`. `guest_has_early_injection:true`. | CAUGHT |
| F-A8-skip-guards | Injected `c0745cec…`. `host_records:[]`. | CAUGHT |
| F-A8-piece-forge | Injected `92d42c03…`. `host_records:[]`. | CAUGHT |
| F-A8-wasm-bus-only | Honest guest `f3d89ab4…` has write then read. Internal sentence on stderr failed. | CAUGHT |
| F-A8-direct-request | Injected `8441f14e…`. One `read` only. | CAUGHT |
| F-A8-test-writes-lines | Test wrote the two lines; no-bus guest `92d42c03…`. File existed before launch. | CAUGHT |
| F-A8-skip-journal-grants | Injected `47c2355d…`. Write then read present. Cargo FAILED on host-side sequence. | CAUGHT |
| F-A8-guest-follow-sentence | Injected `66790ec5…`. Write then read present. Invalid sentence printed. Cargo FAILED. | CAUGHT |
| F-A8-race-after-snapshot | Injected `7d81d0cb…`. Foreign id after snapshot. File existed at spawn. | CAUGHT |
| F-A8-session-alias | Accept `session_id == capsule_id`. Unit test failed the alias refuse. | CAUGHT |
| F-A8-session-1 | Accept `session-1`. Unit test failed the unguessable-id refuse. | CAUGHT |
| F-A8-toctou-hash | Hash the in-memory copy only. Unit test failed the staged-byte check. | CAUGHT |
| F-A8-seq-ignored | Ignore `seq`. Unit test failed the strictly-increasing refuse. | CAUGHT |
| F-A8-shrink-dead | Lock size 0. Same-inode shrink no longer panicked. | CAUGHT |
| F-A8-rewrite-after-run | Skip the seal hash. Rewrite after run was accepted. | CAUGHT |
| F-A8-dup-keys | Last-wins parse. Duplicate `capsule_id` was accepted. | CAUGHT |
| F-A8-capsule-trim | Trim `capsule_id`. Whitespace still bound. | CAUGHT |

### Mutants

`python3 lab/a1-a8-hardening/mutants/binding.py`: 7 of 7 original KILLED.
3 new also KILLED. 10 of 10 total.

| ID | Mutant | Result |
| --- | --- | --- |
| M-sequence-stderr | Follow sentence on guest stderr is the lock | KILLED |
| M-assigned-none-match | Missing assigned matches any `capsule_id` | KILLED |
| M-after-snapshot-window | Inode-none cursor accepts a post-snapshot file | KILLED |
| M-println-not-assert | Missing Runtime-ask fields still cargo `ok` | KILLED |
| M-session-presence | Any non-empty `session_id` binds | KILLED |
| M-guest-function-optional | `guest_function` is not required | KILLED |
| M-hash-alias | `wasm_hash` / `guest_hash` count as `module_hash` | KILLED |
| M-session-alias | `session_id == capsule_id` binds | KILLED |
| M-session-1 | `session-1` binds | KILLED |
| M-seq-ignored | `seq` 1 then 3 binds | KILLED |

Restored SHA-256 after each entry:

- `tests/a1_wasi_import.rs`: `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`
- `tests/a8_agent_host_host_key.rs`: `8d0c842b74ef02c8cf1e892aeed195205992075412ab7aded2d14090e07f91ca`
- `src/lib.rs`: `c868d26909a315cb25cb6f40e2e0f2a74e1058f260a8c2907218eeac3ca47568`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5f1bcb725c08f8e54e347a23caa9856992007a2306b8289896a0da992`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `d52efcf8754427be26b2c276ae66bb11e8ce521eb84da47fd7128cf2833cf92a`

`git status` showed no Runtime change after restore. The rebuilt
`elastos` hash is `e027209c…` again.

### macOS (NOT RUN)

Sash's Mac still needs `run.sh`, the twenty-two plants, and
`mutants/binding.py`. Dump the raw jsonl under
`~/Library/Application Support/elastos` and check `capsule_id` /
`session_id` / `module_hash` / `guest_function` / `seq`. Timeouts stay
NOT CAUGHT.

macOS A8, aarch64, Jetson: NOT RUN.
A8 authorship: NEEDS RUNTIME.

## 27 Oct 2026: #475 r5 later-PASS holes

Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28), no KVM.
Code: `96f8baae406806ebebdda0dba791b4bda861b323` on
`cursor/a8-authorship-lock-0a84`, parent `75bb4d85`. Lab/test only.
No Runtime source change. Closes the eight later-PASS holes from
`lab/review-a8-455-r5/REVIEW.md`.

### Rows

Command: `lab/a1-a8-hardening/run.sh`. cargo exit 0.

```text
a1 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; …")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports [five elastos:bus]
a8 injected agent-host: sha256 f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 imports [the same five]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 receipt cursor: size:0 inode:None path:/tmp/a8-home.sCDbUm/home/.local/share/elastos/runtime/capability-requests.jsonl
a8 host key read: exit:Some(1) assigned:None session:None guest_hash:f3d89ab4… host_records:[write then read, both manifest_capability_denied, capsule_id component-f23c18f3-…, session_id None, module_hash None, guest_function None, seq None] marker_absent:true unchanged:true
a8 authorship: needs runtime: capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function, receipt seq

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | NEEDS RUNTIME (capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function, receipt seq)
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Lib unit tests: 8 passed. Authorship-lock tests: 16 passed.

### Falsifiers

`python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.
22 of 22 original plants CAUGHT. 8 of 8 r5 plants CAUGHT. 30 of 30
total. Each failed at a listed `fail_needle` with exit 101. No timeout.

| ID | Observed | Verdict |
| --- | --- | --- |
| F-A1a | Control bytes in the refused slot: `exit:Some(0) refusal_line:None`. | CAUGHT |
| F-A1-runtime | Allowlist off (elastos sha256 `9d4a0c09…`). Core-module check refused the WASI build. Exact-reason assertion failed. | CAUGHT |
| F-A8a | Manifest declared the fake key. Host record is `pending` for write. `exit:signaled`. | CAUGHT |
| F-A8-runtime | Manifest refusal off (elastos sha256 `72fe1fa5…`). Same `pending` write and `exit:signaled`. | CAUGHT |
| F-A8-forge | Forged guest `45e4b8fb…`. `guest_has_refusal_sentence:true`. | CAUGHT |
| F-A8-early | Old early-return guest `9cff3664…`. `guest_has_early_injection:true`. | CAUGHT |
| F-A8-skip-guards | Injected `c0745cec…`. `host_records:[]`. | CAUGHT |
| F-A8-piece-forge | Injected `92d42c03…`. `host_records:[]`. | CAUGHT |
| F-A8-wasm-bus-only | Honest guest `f3d89ab4…` has write then read. Internal sentence on stderr failed. | CAUGHT |
| F-A8-direct-request | Injected `8441f14e…`. One `read` only. | CAUGHT |
| F-A8-test-writes-lines | Test wrote the two lines; no-bus guest `92d42c03…`. File existed before launch. | CAUGHT |
| F-A8-skip-journal-grants | Injected `47c2355d…`. Write then read present. Cargo FAILED on host-side sequence. | CAUGHT |
| F-A8-guest-follow-sentence | Injected `66790ec5…`. Write then read present. Invalid sentence printed. Cargo FAILED. | CAUGHT |
| F-A8-race-after-snapshot | Injected `7d81d0cb…`. Foreign id after snapshot. File existed at spawn. | CAUGHT |
| F-A8-session-alias | Accept `session_id == capsule_id`. Unit test failed the alias refuse. | CAUGHT |
| F-A8-session-1 | Accept `session-1`. Unit test failed the unguessable-id refuse. | CAUGHT |
| F-A8-toctou-hash | Hash the in-memory copy only. Unit test failed the staged-byte check. | CAUGHT |
| F-A8-seq-ignored | Ignore `seq`. Unit test failed the strictly-increasing refuse. | CAUGHT |
| F-A8-shrink-dead | Lock size 0. Same-inode shrink no longer panicked. | CAUGHT |
| F-A8-rewrite-after-run | Skip the seal hash. Rewrite after run was accepted. | CAUGHT |
| F-A8-dup-keys | Last-wins parse. Duplicate `capsule_id` was accepted. | CAUGHT |
| F-A8-capsule-trim | Trim `capsule_id`. Whitespace still bound. | CAUGHT |
| F-A8-session-from-time | Accept 32 hex from the clock. Pin test failed the unguessable-id refuse. | CAUGHT |
| F-A8-session-from-pid | Accept 32 hex from the pid. Pin test failed the unguessable-id refuse. | CAUGHT |
| F-A8-session-zeros | Accept the all-zero session. Pin test failed the unguessable-id refuse. | CAUGHT |
| F-A8-session-reused | Skip the used-set insert. Pin test failed the reuse refuse. | CAUGHT |
| F-A8-seq-wrap | Wrap `u64::MAX` to `0`. Pin test failed the wrap refuse. | CAUGHT |
| F-A8-toctou-rename | Skip the post-load inode and hash recheck. Pin test failed the staged-byte check. | CAUGHT |
| F-A8-symlink-journal | Use `exists()` so a dangling symlink looks absent. Pin test failed the pre-exist refuse. | CAUGHT |
| F-A8-bom-truncated | Drop a BOM or truncated line and bind the rest. Pin test failed the journal refuse. | CAUGHT |

### Mutants

`python3 lab/a1-a8-hardening/mutants/binding.py`: 10 of 10 KILLED.

| ID | Mutant | Result |
| --- | --- | --- |
| M-sequence-stderr | Follow sentence on guest stderr is the lock | KILLED |
| M-assigned-none-match | Missing assigned matches any `capsule_id` | KILLED |
| M-after-snapshot-window | Inode-none cursor accepts a post-snapshot file | KILLED |
| M-println-not-assert | Missing Runtime-ask fields still cargo `ok` | KILLED |
| M-session-presence | Any non-empty `session_id` binds | KILLED |
| M-guest-function-optional | `guest_function` is not required | KILLED |
| M-hash-alias | `wasm_hash` / `guest_hash` count as `module_hash` | KILLED |
| M-session-alias | `session_id == capsule_id` binds | KILLED |
| M-session-1 | `session-1` binds | KILLED |
| M-seq-ignored | `seq` 1 then 3 binds | KILLED |

Restored SHA-256 after each entry:

- `tests/a1_wasi_import.rs`: `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`
- `tests/a8_agent_host_host_key.rs`: `83849410ea319a911c7cb71c2080c3d5209d08a0cdc49ef26c921fee9e4d8035`
- `src/lib.rs`: `0180f31a8a7e8d29bfe5194b7749dc4f2a20ea20948db370fce3db475b2884be`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5f1bcb725c08f8e54e347a23caa9856992007a2306b8289896a0da992`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `d52efcf8754427be26b2c276ae66bb11e8ce521eb84da47fd7128cf2833cf92a`

`git status` showed no Runtime change after restore. The rebuilt
`elastos` hash is `e027209c…` again.

### macOS (NOT RUN)

Sash's Mac still needs `run.sh`, the thirty plants, and
`mutants/binding.py`. Dump the raw jsonl under
`~/Library/Application Support/elastos` and check `capsule_id` /
`session_id` / `module_hash` / `guest_function` / `seq`. Timeouts stay
NOT CAUGHT.

macOS A8, aarch64, Jetson: NOT RUN.
A8 authorship: NEEDS RUNTIME.

## 27 Oct 2026: #475 r5 later-PASS holes

Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28), no KVM.
Code: `96f8baae406806ebebdda0dba791b4bda861b323` on
`cursor/a8-authorship-lock-0a84`, parent `75bb4d85`. Lab/test only.
No Runtime source change. Closes the eight later-PASS holes from
`lab/review-a8-455-r5/REVIEW.md`.

### Rows

Command: `lab/a1-a8-hardening/run.sh`. cargo exit 0.

```text
a1 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; …")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 e027209ca94cdaf39e6758219f7737c99f5b3cc4f8e6ded9d5d1cb12f4f0d0d3
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports [five elastos:bus]
a8 injected agent-host: sha256 f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 imports [the same five]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 receipt cursor: size:0 inode:None path:/tmp/a8-home.sCDbUm/home/.local/share/elastos/runtime/capability-requests.jsonl
a8 host key read: exit:Some(1) assigned:None session:None guest_hash:f3d89ab4… host_records:[write then read, both manifest_capability_denied, capsule_id component-f23c18f3-…, session_id None, module_hash None, guest_function None, seq None] marker_absent:true unchanged:true
a8 authorship: needs runtime: capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function, receipt seq

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | NEEDS RUNTIME (capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function, receipt seq)
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Lib unit tests: 8 passed. Authorship-lock tests: 16 passed.

### Falsifiers

`python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.
22 of 22 original plants CAUGHT. 8 of 8 r5 plants CAUGHT. 30 of 30
total. Each failed at a listed `fail_needle` with exit 101. No timeout.

| ID | Observed | Verdict |
| --- | --- | --- |
| F-A1a | Control bytes in the refused slot: `exit:Some(0) refusal_line:None`. | CAUGHT |
| F-A1-runtime | Allowlist off (elastos sha256 `9d4a0c09…`). Core-module check refused the WASI build. Exact-reason assertion failed. | CAUGHT |
| F-A8a | Manifest declared the fake key. Host record is `pending` for write. `exit:signaled`. | CAUGHT |
| F-A8-runtime | Manifest refusal off (elastos sha256 `72fe1fa5…`). Same `pending` write and `exit:signaled`. | CAUGHT |
| F-A8-forge | Forged guest `45e4b8fb…`. `guest_has_refusal_sentence:true`. | CAUGHT |
| F-A8-early | Old early-return guest `9cff3664…`. `guest_has_early_injection:true`. | CAUGHT |
| F-A8-skip-guards | Injected `c0745cec…`. `host_records:[]`. | CAUGHT |
| F-A8-piece-forge | Injected `92d42c03…`. `host_records:[]`. | CAUGHT |
| F-A8-wasm-bus-only | Honest guest `f3d89ab4…` has write then read. Internal sentence on stderr failed. | CAUGHT |
| F-A8-direct-request | Injected `8441f14e…`. One `read` only. | CAUGHT |
| F-A8-test-writes-lines | Test wrote the two lines; no-bus guest `92d42c03…`. File existed before launch. | CAUGHT |
| F-A8-skip-journal-grants | Injected `47c2355d…`. Write then read present. Cargo FAILED on host-side sequence. | CAUGHT |
| F-A8-guest-follow-sentence | Injected `66790ec5…`. Write then read present. Invalid sentence printed. Cargo FAILED. | CAUGHT |
| F-A8-race-after-snapshot | Injected `7d81d0cb…`. Foreign id after snapshot. File existed at spawn. | CAUGHT |
| F-A8-session-alias | Accept `session_id == capsule_id`. Unit test failed the alias refuse. | CAUGHT |
| F-A8-session-1 | Accept `session-1`. Unit test failed the unguessable-id refuse. | CAUGHT |
| F-A8-toctou-hash | Hash the in-memory copy only. Unit test failed the staged-byte check. | CAUGHT |
| F-A8-seq-ignored | Ignore `seq`. Unit test failed the strictly-increasing refuse. | CAUGHT |
| F-A8-shrink-dead | Lock size 0. Same-inode shrink no longer panicked. | CAUGHT |
| F-A8-rewrite-after-run | Skip the seal hash. Rewrite after run was accepted. | CAUGHT |
| F-A8-dup-keys | Last-wins parse. Duplicate `capsule_id` was accepted. | CAUGHT |
| F-A8-capsule-trim | Trim `capsule_id`. Whitespace still bound. | CAUGHT |
| F-A8-session-from-time | Accept 32 hex from the clock. Pin test failed the unguessable-id refuse. | CAUGHT |
| F-A8-session-from-pid | Accept 32 hex from the pid. Pin test failed the unguessable-id refuse. | CAUGHT |
| F-A8-session-zeros | Accept the all-zero session. Pin test failed the unguessable-id refuse. | CAUGHT |
| F-A8-session-reused | Skip the used-set insert. Pin test failed the reuse refuse. | CAUGHT |
| F-A8-seq-wrap | Wrap `u64::MAX` to `0`. Pin test failed the wrap refuse. | CAUGHT |
| F-A8-toctou-rename | Skip the post-load inode and hash recheck. Pin test failed the staged-byte check. | CAUGHT |
| F-A8-symlink-journal | Use `exists()` so a dangling symlink looks absent. Pin test failed the pre-exist refuse. | CAUGHT |
| F-A8-bom-truncated | Drop a BOM or truncated line and bind the rest. Pin test failed the journal refuse. | CAUGHT |

### Mutants

`python3 lab/a1-a8-hardening/mutants/binding.py`: 10 of 10 KILLED.

| ID | Mutant | Result |
| --- | --- | --- |
| M-sequence-stderr | Follow sentence on guest stderr is the lock | KILLED |
| M-assigned-none-match | Missing assigned matches any `capsule_id` | KILLED |
| M-after-snapshot-window | Inode-none cursor accepts a post-snapshot file | KILLED |
| M-println-not-assert | Missing Runtime-ask fields still cargo `ok` | KILLED |
| M-session-presence | Any non-empty `session_id` binds | KILLED |
| M-guest-function-optional | `guest_function` is not required | KILLED |
| M-hash-alias | `wasm_hash` / `guest_hash` count as `module_hash` | KILLED |
| M-session-alias | `session_id == capsule_id` binds | KILLED |
| M-session-1 | `session-1` binds | KILLED |
| M-seq-ignored | `seq` 1 then 3 binds | KILLED |

Restored SHA-256 after each entry:

- `tests/a1_wasi_import.rs`: `ccf9fc61b70f4c0e6a9b7c44de03ecfbac9a76595bdf07ddb55e55a84d34f17a`
- `tests/a8_agent_host_host_key.rs`: `83849410ea319a911c7cb71c2080c3d5209d08a0cdc49ef26c921fee9e4d8035`
- `src/lib.rs`: `0180f31a8a7e8d29bfe5194b7749dc4f2a20ea20948db370fce3db475b2884be`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5f1bcb725c08f8e54e347a23caa9856992007a2306b8289896a0da992`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `d52efcf8754427be26b2c276ae66bb11e8ce521eb84da47fd7128cf2833cf92a`

`git status` showed no Runtime change after restore. The rebuilt
`elastos` hash is `e027209c…` again.

### macOS (NOT RUN)

Sash's Mac still needs `run.sh`, the thirty plants, and
`mutants/binding.py`. Dump the raw jsonl under
`~/Library/Application Support/elastos` and check `capsule_id` /
`session_id` / `module_hash` / `guest_function` / `seq`. Timeouts stay
NOT CAUGHT.

macOS A8, aarch64, Jetson: NOT RUN.
A8 authorship: NEEDS RUNTIME.
