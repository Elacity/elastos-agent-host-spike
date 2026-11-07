# Adversarial review r2 of #301 A8 at `a2398b5d`

Draft. Do not merge.

Independent review of [PR #301](https://github.com/Elacity/elastos-agent-host-spike/pull/301) at
`a2398b5d6c59c2794077b3b3fd38880dd7bbc4b1`. Prior review:
[PR #356](https://github.com/Elacity/elastos-agent-host-spike/pull/356) on `1a82d25b`.

Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28), uid 1000.
No KVM. Detached worktree `/tmp/pr-301-a8-r2` at the reviewed commit. That
branch was left untouched. This folder is the only write surface.

Anders's rule used here: a check counts when its complete journey, its refusal
evidence, and its required reviews all pass.

**Plain English.** The four #356 plants are dead. A guest that only prints the
Internal sentence, or that never calls the bus, no longer gets a pass. The
author's suite counts match this rerun: **2 PASS**, **1 NEEDS RUNTIME**,
**1 BLOCKED**. All **10** named falsifiers are **CAUGHT** by real assertions.
Timeouts are **not** counted as caught. `F-A8a` and `F-A8-runtime` stop on a
`pending` host record with `exit:signaled`.

The receipt file is real Runtime code in this checkout's `elastos` binary, not
a lab shim. The guest cannot name a Home path that maps to that file. The test
process can write the same two lines, and the test does not notice. The file
is not bound to the guest module hash or to a session id. A guest that asks
write, ignores the refusal, then asks read — without `request_journal_grants`
— also passes.

**A8 verdict: the #356 closures hold. Authorship binding is still open.
`VERDICT: FIX` on that binding.** The pass row is not bookable as "this guest,
this session, this Runtime call" until the receipt is bound and the test
refuses a file it did not just see the Runtime write.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| Suite: 2 PASS, 1 NEEDS RUNTIME, 1 BLOCKED, cargo exit 0 | HOLDS | `lab/a1-a8-hardening/run.sh` |
| Falsifiers 10/10 CAUGHT by real assertions | HOLDS | `python3 lab/a1-a8-hardening/falsify.py` |
| Timeouts counted as CAUGHT | HOLDS that they are not | `F-A8a` / `F-A8-runtime` are `exit:signaled` + `pending`; runner rejects `exit:timeout` / `exit:None` |
| #356 B-piece-forge is dead | HOLDS | independent plant, injected `92d42c03…`, `host_records:[]` |
| #356 A-skip-guards is dead | HOLDS | independent plant, injected `c0745cec…`, `host_records:[]` |
| #356 D-direct-request is dead | HOLDS | independent plant, injected `8441f14e…`, one `read` only |
| #356 C-wasm-bus-only stays out of the pass column | HOLDS | honest guest `f3d89ab4…` has the receipts; Internal sentence on stderr fails |
| Guest has no filesystem and cannot write the jsonl | HOLDS | no WASI preopen; `runtime` is not a localhost root; `..` does not resolve |
| Pass row requires write then read, both `manifest_capability_denied` | HOLDS against the four #356 plants | A/B empty; D one `read` |
| Those two lines prove `request_journal_grants` called the bus | **FALSIFIED** | hunt `K-write-then-read-continue` |
| Those two lines prove the Runtime wrote them for this guest and session | **FALSIFIED** | hunt `J-preseed-jsonl`; raw jsonl ignores `capsule_id` |
| Record written by shipped Runtime code, not a lab shim | HOLDS | `elastos-server` `record_capability_request`; this checkout's `elastos` binary |
| A8 shipped-bytes row is a pass | HOLDS that it is BLOCKED | ignore + `--ignored` panic AC-002-ARGS |
| A8 WasmBus Internal sentence is a pass | HOLDS that it is NEEDS RUNTIME | ignore + `--ignored` panic; C stderr is `Invalid("the journal append did not follow its grants")` |

## Suite

Command, after `cargo fetch --locked` of the lane, wasi-guest, agent-host,
`elastos/tools/componentize`, and `elastos` manifests (the suite itself stays
`--offline`):

```sh
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
```

fmt exit 0. `run.sh` cargo exit 0, 433s (22:42:24Z to 22:49:37Z). Raw output:
`evidence/run.sh.txt`.

```text
a1 runtime: elastos sha256 16993259a77cd1300101036e922841436c5ca66d54dff0d3cfa6982429a8e275
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 16993259a77cd1300101036e922841436c5ca66d54dff0d3cfa6982429a8e275
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports [five elastos:bus]
a8 injected agent-host: sha256 f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 imports [the same five]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 host key read: exit:Some(1) host_records:[write then read, both manifest_capability_denied] marker_absent:true unchanged:true

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | PASS
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Guest component hashes match the PR log. The debug `elastos` hash on this
machine is `16993259…`. The PR log's `e027209c…` is a different native debug
binary.

Source SHA-256 matches the PR log:

- `tests/a1_wasi_import.rs`: `ccf9fc61…`
- `tests/a8_agent_host_host_key.rs`: `ebad194d…`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5…`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `d52efcf8…`

Forced ignored rows both panic with their ignore reason (exit 101):
`shipped_wasm_bus_prints_internal_sentence` and
`shipped_agent_host_bytes_read_host_key`. Cargo exit 0 on the suite is those
ignores. They are honest, not hidden passes.

## Falsifiers

`python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time. Source restored
to the baseline SHA-256 after each entry (`evidence/post-falsify-sha256.txt`).
`git status` in the worktree stayed clean.

| ID | Runner | What ran |
| --- | --- | --- |
| F-A1a | CAUGHT | Control bytes in the refused slot: `exit:Some(0) refusal_line:None` |
| F-A1-runtime | CAUGHT | Allowlist off. Core-module reason. Exact-reason assert failed. elastos `bedf1484…` |
| F-A8a | CAUGHT | Manifest declared the fake key. Host record is `pending` for write. `exit:signaled`. Receipt assert failed. |
| F-A8-runtime | CAUGHT | Manifest refusal off. elastos `a7c1734b…`. Same `pending` write and `exit:signaled`. |
| F-A8-forge | CAUGHT | `guest_has_refusal_sentence:true`, injected `45e4b8fb…`. Failed before `serve`. |
| F-A8-early | CAUGHT | Old early-return guest `9cff3664…`. `guest_has_early_injection:true`. Failed before `serve`. |
| F-A8-skip-guards | CAUGHT | Injected `c0745cec…`. `host_records:[]`. |
| F-A8-piece-forge | CAUGHT | Injected `92d42c03…`. `host_records:[]`. |
| F-A8-wasm-bus-only | CAUGHT | Honest guest `f3d89ab4…` has write then read. Internal sentence on stderr failed. |
| F-A8-direct-request | CAUGHT | Injected `8441f14e…`. One `read` only. |

`falsifiers.json` says a timeout does not count as caught. None of these ten
were a timeout. After the runtime entries, a rebuild of this checkout's
`elastos` returned hash `16993259…` again.

## Re-planted #356 attacks

Scratch edits in the worktree only. Each run restored
`tests/a8_agent_host_host_key.rs` to
`ebad194d6d99143bf717a081645c2b7370e90a0d20bb774a6b83a5edb4a77ff0`.
Scripts: `attacks/run_attacks.py`. Outputs: `evidence/attacks/`.

| Plant | Injected guest | Result |
| --- | --- | --- |
| A-skip-guards | `c0745cec…` | CAUGHT. `host_records:[]`. Guest printed a refusal. Runtime wrote nothing. |
| B-piece-forge | `92d42c03…` (same bytes as #356) | CAUGHT. `host_records:[]`. Origin still `guest_has_refusal_sentence:false`. |
| C-wasm-bus-only | honest `f3d89ab4…` | CAUGHT as a sentence claim. Receipts are present. stderr is `BusError::Invalid("the journal append did not follow its grants")`. |
| D-direct-request | `8441f14e…` (same bytes as #356) | CAUGHT. One `read` only. |

Those four plants no longer pass the A8 row.

## New hunts

### Can the guest reach the jsonl?

No path that this guest can name maps to
`<data dir>/runtime/capability-requests.jsonl`.

- The component runner gives no WASI, no filesystem preopen, no env, no raw
  socket. Every effect is a Bus hostcall.
- The staged manifest grants only
  `localhost://Users/self/.AppData/Agents/agent-host/*`.
- File-backed localhost roots are AppCapsules, ElastOS, Local, MyWebSite,
  Public, Users, UsersAI. There is no `runtime` root.
- `rooted_localhost_fs_path` returns no path when a segment is `..`.
- A wildcard match also refuses a `..` suffix.

Hunt `I-jsonl-path` asked for a `..` path under the granted prefix. The guest
did not name the fake key, so the origin lock failed before `serve`. The
source already answers the hunt: the guest cannot write that file through a
granted capability, a preopen, a bus call, or a Home path it can name.

### Can the harness write the record?

Yes. `Home::capability_requests` only reads the file. `Home::new` does not
create it. The file is append-only (`create` + `append`). It is not truncated
per run and not created exclusive.

The honest test uses a fresh throwaway Home, so a leftover file from an
earlier run is not in that Home. The test does not prove that. It never
checks that the file was empty when the guest started.

Hunt `J-preseed-jsonl`: the test process wrote the two expected lines, then
ran the #356 piece-forge guest (`92d42c03…`, no bus call). The test passed.
`host_records` showed write then read, both `manifest_capability_denied`.

So: the guest cannot mint the file. The test process can, and the pass row
accepts that.

### Is the record bound to this guest and session?

No.

A dump of the honest run's raw file (`evidence/hunts/dump-jsonl.txt`):

```text
{"action":"write","capsule_id":"component-23921c05-6b9c-4892-a618-808f0b687a9d","code":"manifest_capability_denied","principal_id":null,"resource":"localhost://Public/../../../../.ssh/id_ed25519"}
{"action":"read","capsule_id":"component-23921c05-6b9c-4892-a618-808f0b687a9d","code":"manifest_capability_denied","principal_id":null,"resource":"localhost://Public/../../../../.ssh/id_ed25519"}
```

Runtime writes `capsule_id` and `principal_id`. `capsule_id` is
`component-<uuid>` from load, not the guest module hash. `principal_id` is
null on this `elastos run` path. There is no session id field and no guest
hash field. The test's `denied_actions` keeps only `action` / `resource` /
`code`. Any matching pair satisfies the pass.

Hunt `K-write-then-read-continue`: a guest asked write, ignored the refusal,
then asked read, after `identity::context()`, without `request_journal_grants`.
Injected `fd30e4d8…`. The test passed. The pass row locks "write then read
were denied on that path". It does not lock the journal grant function.

### Lab code or shipped Runtime?

The write is in shipping crate code:
`elastos/crates/elastos-server/src/resource_bridge.rs`, function
`record_capability_request`. This PR adds it. `spike/agent-host` does not
have it yet. The A8 harness builds `elastos-server --bin elastos` from this
checkout and launches that binary with `elastos serve` and `elastos run`.
That is a real debug Runtime build of this branch, not a lab fake.

`elastos run` uses `handle_remote_request_with_audit_dir` and writes the
jsonl under `default_data_dir()` (`~/.local/share/elastos` on this Linux
Home). The harness reads the same path. The signed audit chain the author
first tried is still absent on a fresh attached-run Home. The jsonl is the
fallback they added.

A write failure is logged and swallowed. It does not change the bus refusal.

## Counted or not

| Row | Counted? | Why |
| --- | --- | --- |
| A1 `wasi_import_is_refused_at_admission` | **Counted on Linux** | Allowlist sentence, control admitted, F-A1a and F-A1-runtime caught. Other WASI interfaces and Home launch stay out. |
| A8 `agent_host_host_key_read_is_refused` | **Not counted as closed authorship** | Linux run of this checkout's Runtime does refuse write then read on the fake key when the honest injection calls the bus. The test cannot tell that apart from harness-written lines or any two bus asks. #356 plants are dead. Binding is open. |
| A8 `shipped_wasm_bus_prints_internal_sentence` | **Not counted** | Honest NEEDS RUNTIME. stderr is the guest's Invalid follow-up. |
| A8 `shipped_agent_host_bytes_read_host_key` | **Not counted** | Honest BLOCKED (AC-002-ARGS). |

## What must run on macOS

This host did not run macOS, aarch64, or Jetson. The data-dir rule is written
(`~/Library/Application Support/elastos`). That path is the A8 receipt path
on a Mac. Sash's Mac still needs:

1. `lab/a1-a8-hardening/run.sh` — the four rows, and the printed jsonl
   records under the Mac data dir.
2. The four #356 plants (A/B/C/D) against that Mac run.
3. `F-A8a` and `F-A8-runtime`, to show `pending` + `exit:signaled` there, and
   that a timeout is still not a catch.
4. A dump of the raw jsonl, to see `capsule_id` / `principal_id` on Darwin.

The binding hunts (pre-seed, write-then-read without `request_journal_grants`)
are source facts. They will behave the same on a Mac until the test binds the
record.

## Bookability

A8 on this lane is still one Bus read of one fake file, from a mutated
agent-host copy, on Linux x86_64. The #356 sentence-forge and skip-bus plants
are closed **if** the file is only written by this Runtime for this run.

That "if" is still a hole:

1. Bind the receipt to this guest module hash and this run or session. Read
   those fields in the pass row.
2. Treat a file that already had the expected lines, or a line the Runtime
   did not just append, as a fail.
3. Keep the WasmBus Internal sentence in NEEDS RUNTIME, out of the pass
   column.
4. macOS on Sash's Mac.
5. The shipped agent-host bytes, still BLOCKED on AC-002-ARGS.

The agent-conformance probe proof (PR #179 / F-ac8a) was NOT RUN here. This
lane does not replace it.

## Principles

- 3, 7, 18: Runtime still owns admission and the manifest bound on the
  committed guest. The fake file stays a fixture.
- 5: the new writer lives in the trusted core. It is small. It is also the
  only A8 authorship proof.
- 10: the signed audit chain is still absent on this `elastos run` Home. The
  jsonl is a second path added for the test.
- 11: empty grants fail closed, but as
  `Invalid("the journal append did not follow its grants")`, which hides the
  manifest bound on stderr.
- 12: README says write then read proves `request_journal_grants` called the
  bus. Hunt K shows any two asks in that order also pass.

DeepSeek: none.

## Not run

- macOS A8 (needs Sash's Mac).
- aarch64, Jetson, a real host key, Home launch, other WASI interfaces.
- Provider `Path traversal not allowed` (the request stays on this side of the
  operator).
- Agent-conformance `host_key_read_is_refused` / F-ac8a on this head.
