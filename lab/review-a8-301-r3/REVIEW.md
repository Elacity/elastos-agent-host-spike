# Adversarial review r3 of #301 A8 at `10316585`

Draft. Do not merge.

Independent review of [PR #301](https://github.com/Elacity/elastos-agent-host-spike/pull/301) at
`10316585addf30c0f1e6446793cce302c0035acf`. Prior reviews:
[PR #356](https://github.com/Elacity/elastos-agent-host-spike/pull/356) (r1) on `1a82d25b`,
[PR #388](https://github.com/Elacity/elastos-agent-host-spike/pull/388) (r2) on `a2398b5d`.

Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28), uid 1000.
No KVM. Detached worktree `/tmp/pr-301-a8-r3` at the reviewed commit. That
branch was left untouched. This folder is the only write surface. This
private repo only; `Elacity/elastos-runtime` was not touched.

Anders's rule used here: a check counts when its complete journey, its
refusal evidence, and its required reviews all pass.

**Plain English.** The author's suite counts match this rerun: **1 PASS**,
**2 NEEDS RUNTIME**, **1 BLOCKED**. All **12** named plants are **CAUGHT**
by real assertions. Timeouts are **not** counted as caught. `F-A8a` and
`F-A8-runtime` stop on a `pending` host record with `exit:signaled`.

A1 is a real admission refusal from this checkout's `elastos` binary, not
a lab shim. That row can count on Linux.

A8 stays **NEEDS RUNTIME** / **BLOCKED**. The r2 plants that skip the bus
or skip `request_journal_grants` and return a different error are dead.
Two new hunts still reach cargo `ok`:

1. A guest that asks write then read, skips `request_journal_grants`, and
   returns `Invalid("the journal append did not follow its grants")`.
2. A no-bus guest plus the same sentence, with the two jsonl lines written
   by the test process **after** the inode snapshot, using a foreign
   `capsule_id`. `assigned` is `None`, so those planted lines match.

The cargo test still reaches `ok` while component id, session id, and
guest hash are all missing. `run.sh` remaps that to NEEDS RUNTIME. There
is no env-var skip. Empty session and empty hash stay unmet. They are
not treated as a match.

**A8 verdict: the twelve plants hold. The new sequence lock and the
inode snapshot do not. `VERDICT: FIX`.** Keep A8 out of the counted
column. Do not book it when the Runtime later prints an id.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| Suite: 1 PASS, 2 NEEDS RUNTIME, 1 BLOCKED, cargo exit 0 | HOLDS | `lab/a1-a8-hardening/run.sh` |
| Falsifiers 12/12 CAUGHT by real assertions | HOLDS | `python3 lab/a1-a8-hardening/falsify.py` |
| Timeouts counted as CAUGHT | HOLDS that they are not | `F-A8a` / `F-A8-runtime` are `exit:signaled` + `pending`; runner rejects `exit:timeout` / `exit:None` |
| Fresh `mktemp` Home; fail if jsonl pre-exists | HOLDS against `F-A8-test-writes-lines` | file written before `assert_receipts_absent` |
| Size/inode; only appended lines read | **FALSIFIED** as a race close | hunt `H-race-after-snapshot` |
| Receipts must match component id + session id + guest hash | **WEAK** | missing assigned matches any `capsule_id`; session is presence-only; authorship is `println`, not `assert` |
| Honest sequence required | **FALSIFIED** | hunt `H-guest-follow-sentence` |
| A1 PASS is genuine | HOLDS | this checkout's `elastos`, `validate_component_capsule` before load |
| A8 host-key row stays NEEDS RUNTIME | HOLDS | `run.sh` remap; `assigned:None`, `session_id None`, `module_hash None` |
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

fmt exit 0. `run.sh` cargo exit 0, 460s (23:34:51Z to 23:42:31Z). Raw
row output: `evidence/run.sh.txt`.

```text
a1 runtime: elastos sha256 d185ab44586171595d639dd1bdb0aea0cf4bf1abc7dca2c4986f6f0d7fca2be9
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 d185ab44586171595d639dd1bdb0aea0cf4bf1abc7dca2c4986f6f0d7fca2be9
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports [five elastos:bus]
a8 injected agent-host: sha256 f3d89ab4d9276261372979ebdd67f65327af1b098c5d1f0c59e4417170380737 imports [the same five]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 receipt cursor: size:0 inode:None path:/tmp/a8-home.Nb8kqI/home/.local/share/elastos/runtime/capability-requests.jsonl
a8 host key read: exit:Some(1) assigned:None guest_hash:f3d89ab4… host_records:[write then read, both manifest_capability_denied, capsule_id component-8af42c6b-…, session_id None, module_hash None] marker_absent:true unchanged:true
a8 authorship: needs runtime: capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | NEEDS RUNTIME (capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash)
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Guest component hashes match the PR log. The debug `elastos` hash on this
machine is `d185ab44…`. The PR log's `e027209c…` is a different native
debug binary of the same source.

Source SHA-256 matches the PR log:

- `tests/a1_wasi_import.rs`: `ccf9fc61…`
- `tests/a8_agent_host_host_key.rs`: `1d5e7818…`
- `elastos/crates/elastos-server/src/component.rs`: `7ef1dea5…`
- `elastos/crates/elastos-server/src/resource_bridge.rs`: `d52efcf8…`

Forced ignored rows both panic with their ignore reason (exit 101):
`shipped_wasm_bus_prints_internal_sentence` and
`shipped_agent_host_bytes_read_host_key`. Cargo exit 0 on the suite is
those ignores. They are honest, not hidden passes.

## A1 is a real Runtime refusal

`Home::spawn` launches `runtime().path`. That path is
`lab/a1-a8-hardening/target/runtime/debug/elastos`, built by
`cargo build --locked --offline --manifest-path elastos/Cargo.toml -p
elastos-server --bin elastos`. SHA-256 `d185ab44…` matches the printed
`a1 runtime` line. The file is an ELF 64-bit pie executable, 193 MiB,
not stripped.

`elastos-server` `runtime.rs` calls `validate_component_capsule` before
the compute provider loads the component. The allowlist sentence and
`elastos:bus/…@1.0.0` names are in this binary's strings. The lab crate
has no copy of that check.

`F-A1-runtime` rebuilt this binary (`13d770db…`). The WASI guest was
still refused, now by the core-module check. The exact-reason assert
failed. That is the allowlist in this checkout's Runtime, with the
core-module check behind it.

The control guest is admitted and prints `[run] Component capsule
'a1-wasi-guest' exited`. The refused guest does not print `exited`.
One WASI interface on the `elastos run` path. Other WASI interfaces and
Home launch stay out.

## Falsifiers

`python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time, 23:44:39Z
to 23:54:44Z. Source restored to the baseline SHA-256 after each entry
(`evidence/post-falsify-sha256.txt`). `git status` in the worktree
stayed clean after the last restore.

| ID | Runner | What ran |
| --- | --- | --- |
| F-A1a | CAUGHT | Control bytes in the refused slot: `exit:Some(0) refusal_line:None` |
| F-A1-runtime | CAUGHT | Allowlist off. Core-module reason. Exact-reason assert failed. elastos `13d770db…` |
| F-A8a | CAUGHT | Manifest declared the fake key. Host record is `pending` for write. `exit:signaled`. Receipt assert failed. |
| F-A8-runtime | CAUGHT | Manifest refusal off. elastos `8da37993…`. Same `pending` write and `exit:signaled`. |
| F-A8-forge | CAUGHT | `guest_has_refusal_sentence:true`, injected `45e4b8fb…`. Failed before `serve`. |
| F-A8-early | CAUGHT | Old early-return guest `9cff3664…`. `guest_has_early_injection:true`. Failed before `serve`. |
| F-A8-skip-guards | CAUGHT | Injected `c0745cec…`. `host_records:[]`. |
| F-A8-piece-forge | CAUGHT | Injected `92d42c03…`. `host_records:[]`. |
| F-A8-wasm-bus-only | CAUGHT | Honest guest `f3d89ab4…` has write then read. Internal sentence on stderr failed. |
| F-A8-direct-request | CAUGHT | Injected `8441f14e…`. One `read` only. |
| F-A8-test-writes-lines | CAUGHT | Test wrote the two lines; no-bus guest `92d42c03…`. Failed because the jsonl existed before launch. |
| F-A8-skip-journal-grants | CAUGHT | Injected `9363b143…`. Write then read present. Failed the follow-up sentence. |

`falsifiers.json` says a timeout does not count as caught. None of these
twelve were a timeout. After the runtime entries, later plants printed
elastos `d185ab44…` again.

The skip-journal-grants guest hash on this machine is `9363b143…`. The
PR log's `47c2355d…` is a different compile of that plant. The
independent replant below reproduced `9363b143…`.

## Re-planted r1/r2 attacks

Scratch edits in the worktree only. Each run restored
`tests/a8_agent_host_host_key.rs` to
`1d5e7818c05c665c975839c7c831cf67f6667270ecb1a4ce235e8d6fe0d9c627`.
Scripts: `attacks/run_hunts.py`. Outputs: `evidence/hunts/`.

| Plant | Injected guest | Result |
| --- | --- | --- |
| r2 skip-journal-grants | `9363b143…` | CAUGHT. Write then read present. Follow sentence missing. |
| r1/r2 B-piece-forge | `92d42c03…` | CAUGHT. `host_records:[]`. |
| r1/r2 A-skip-guards | `c0745cec…` | CAUGHT as `F-A8-skip-guards`. |
| r1/r2 D-direct-request | `8441f14e…` | CAUGHT as `F-A8-direct-request`. One `read`. |
| r1/r2 C-wasm-bus-only | honest `f3d89ab4…` | CAUGHT as `F-A8-wasm-bus-only`. Receipts present. Internal sentence missing. |

Those plants stay dead when they keep their original error text.

## New hunts

### Can a row reach PASS with NEEDS RUNTIME conditions unmet?

At cargo level, **yes**. The honest A8 test is `ok` while `assigned` is
`None` and every receipt has `session_id None` and `module_hash None`.
The missing-field list is a `println`. `run.sh` remaps `ok` plus that
line to NEEDS RUNTIME. There is no environment variable that skips the
check. `Home::spawn` clears the environment and sets only `HOME`,
`TMPDIR`, `PATH`, and `ELASTOS_CARRIER_MDNS=0`.

Empty session and empty hash become `None` in `optional_string`. They
stay in the missing list. They are not treated as a match of empty to
empty.

Missing **assigned** is treated as a match. `denied_actions` uses
`.unwrap_or(true)`. The capsule-id equality assert is skipped when
`assigned` is `None`. Today's Runtime never prints a `component-<uuid>`
on a `[run]` line (`run_cmd.rs` prints the API URL and the manifest
name). So every honest Linux run matches any `capsule_id`.

`run.sh` itself prints PASS only when the test is `ok` and the
"needs runtime" line is absent. That needs a `[run]` id plus a
non-empty session plus a hash that equals the test's guest hash. See
mutants M5 and M6. This rerun did not reach that PASS path.

### Is the inode/size check racy?

**Yes.** `assert_receipts_absent` then `snapshot_receipts` run before
`elastos run`. When the file is absent, the cursor is `size:0
inode:None`. `capability_requests_since` skips the inode check when
inode is `None` and reads from offset 0. A file created in that window
is accepted as the whole receipt.

Hunt `H-race-after-snapshot`: after the snapshot, the test process wrote
the two expected lines with `capsule_id`
`component-00000000-0000-0000-0000-000000000000`, then launched a
no-bus guest that returns the follow sentence. The test passed. The
printed records carry that planted id. `F-A8-test-writes-lines` still
catches a file that exists **before** the assert. The race is the
window after it.

The test process and the Runtime share one uid. That is already in
RUNTIME-ASK. The snapshot does not close it.

### Does the sequence check rely on text the guest controls?

**Yes.** The lock is `run.stderr.contains("the journal append did not
follow its grants")`. That string is the guest's `BusError::Invalid`
after empty grants. A guest that never calls `request_journal_grants`
can return the same error.

Hunt `H-guest-follow-sentence`: write then read through
`capabilities::request`, then `return Err(BusError::Invalid("the
journal append did not follow its grants"))`. Injected `d661f4d6…`.
The test passed. Receipts are write then read, both
`manifest_capability_denied`. Authorship still prints needs runtime.

`F-A8-skip-journal-grants` is CAUGHT only because that fixture returns
`Denied("skipped request_journal_grants")`.

Guest stdout cannot mint a `[run]` id today: the guest has no WASI, and
`assigned_component_id` only reads lines that start with `[run] `.
`elastos run` does not print the assigned id on those lines. That hole
stays closed until someone prints a `component-<uuid>` on a `[run]`
line.

### Timeouts counted as catches?

No. The test fails on `run.status.is_none()`. `falsify.py` rejects
`exit:timeout`, `exit:None`, and the bound message. `F-A8a` and
`F-A8-runtime` are `exit:signaled` plus a `pending` record.

## Binding mutants

`mutants/binding.py` copies the predicates from `src/lib.rs` and
`tests/a8_agent_host_host_key.rs`. Output: `evidence/mutants-binding.txt`.

| ID | Mutant | Result |
| --- | --- | --- |
| M1 | `assigned=None` matches any `capsule_id` | Honest and foreign-id rows both `cargo_ok`. Confirmed live by `H-race-after-snapshot`. |
| M2 | Authorship missing is `println`, not `assert` | Honest row `cargo_ok` with all three fields missing. |
| M3 | Empty session == empty session | Empty strings become `None`. They stay unmet. Not a match. |
| M4 | Vacuous `any()` on empty records | Session and hash look present if there are no rows. Write-then-read still fails, so cargo is not `ok`. |
| M5 | `wasm_hash` / `guest_hash` aliases count as `module_hash` | A planted `wasm_hash` plus a printed component id and any session makes `run.sh` PASS. |
| M6 | Session check is presence, not equality | Any non-empty `session_id` clears the field. There is no expected session from the Runtime. |
| M7 | Stronger check: require assigned before matching rows | Today's honest Runtime run would FAIL, not NEEDS RUNTIME. |
| M8 | Follow sentence is a stderr substring | `cargo_ok` does not need a receipt field. Confirmed live by `H-guest-follow-sentence`. |

M3 is the one place the new binding is conservative. M1, M2, M5, M6, and
M8 are the holes that will matter the day the Runtime prints an id.

## RUNTIME-ASK

The ask is **accurate** on what the Runtime writes today:
`capsule_id` = `component-<uuid>`, `principal_id` null, no session
field, no module hash, no `[run]` id. The raw records in this rerun
match that shape.

It is **almost minimal**. Items 1 to 3 (print the component id; record
session id; record the guest module hash) are the right bind. Item 4 (a
writer the test process cannot satisfy) is the authorship close. The
optional "guest function" line should not be optional. The sequence
lock is guest stderr today. A Runtime-authored field for
`request_journal_grants` (or a signed write-then-read pair) is part of
the minimum, not a later nice-to-have.

Two gaps in the ask:

1. Session must be the id of **this** launch, compared to a value the
   test reads from `[run]` or an API. Presence of any non-empty string
   is not a bind (M6).
2. Hash aliases (`guest_hash`, `wasm_hash`) should be one Runtime field
   name, written by the Runtime, not accepted from a planted synonym (M5).

A lab workaround that treats missing assigned as match, or that keeps
the cargo test `ok` while the fields are absent, is not the fix. The
ask already says that.

## Counted or not

| Row | Counted? | Why |
| --- | --- | --- |
| A1 `wasi_import_is_refused_at_admission` | **Counted on Linux** | Allowlist sentence from this checkout's `elastos`, control admitted, F-A1a and F-A1-runtime caught. Other WASI interfaces and Home launch stay out. |
| A8 `agent_host_host_key_read_is_refused` | **Not counted. Stays NEEDS RUNTIME.** | Linux run of this checkout's Runtime does refuse write then read on the fake key when the honest injection calls the bus. The test also accepts a guest that returns the follow sentence, and a file the test writes after snapshot. Binding is still a print. |
| A8 `shipped_wasm_bus_prints_internal_sentence` | **Not counted. Stays NEEDS RUNTIME.** | Honest ignore. Forced run panics with that reason. |
| A8 `shipped_agent_host_bytes_read_host_key` | **Not counted. Stays BLOCKED.** | Honest ignore AC-002-ARGS. Forced run panics with that reason. |

## What must run on macOS

This host did not run macOS, aarch64, or Jetson. The data-dir rule is
written (`~/Library/Application Support/elastos`). Sash's Mac still
needs:

1. `lab/a1-a8-hardening/run.sh` — the four rows, and the printed jsonl
   records under the Mac data dir.
2. `F-A8-test-writes-lines`, `F-A8-skip-journal-grants`, the four #356
   plants, `F-A8a`, and `F-A8-runtime`.
3. The two live hunts here (`H-guest-follow-sentence`,
   `H-race-after-snapshot`), to show the same cargo `ok`.
4. A dump of the raw jsonl, to see `capsule_id` / `session_id` /
   `module_hash` on Darwin.
5. Timeouts stay NOT CAUGHT.

## Bookability

A1 on this lane is one WASI import (`wasi:cli/environment@0.2.0`)
refused at admission on `elastos run`, Linux x86_64, plus a control
that is admitted. That journey is complete enough to count on Linux.

A8 is still one Bus read of one fake file, from a mutated agent-host
copy, on Linux x86_64. The twelve plants hold. The row stays NEEDS
RUNTIME until the Runtime writes the bind **and** the test refuses:

1. A `[run]` / API id that is missing, or a record whose `capsule_id`
   is not that id.
2. A session id that is missing or that is not this launch.
3. A module hash that is missing or that is not the staged bytes.
4. A file the test process created, including after the snapshot.
5. A follow sentence the guest returned without
   `request_journal_grants`.

Until those are asserts, a later Runtime change that prints the id will
flip `run.sh` to PASS with the hunts above still live.

Keep the WasmBus Internal sentence in NEEDS RUNTIME. Keep the shipped
bytes BLOCKED on AC-002-ARGS.

The agent-conformance probe proof (PR #179 / F-ac8a) was NOT RUN here.
This lane does not replace it.

## Principles

- 3, 7, 18: Runtime still owns admission and the manifest bound on the
  committed guest. The fake file stays a fixture.
- 5: the receipt writer lives in the trusted core. It is small. It is
  also the only A8 authorship proof, and the test process can write the
  same file.
- 10: the signed audit chain is still absent on this `elastos run`
  Home. The jsonl is a second path added for the test.
- 11: empty grants fail closed. The visible sentence is
  `Invalid("the journal append did not follow its grants")`, which the
  guest can return on its own.
- 12: README says the follow sentence proves `request_journal_grants`.
  Hunt `H-guest-follow-sentence` shows any guest that returns that
  string also passes.

DeepSeek: none.

## Not run

- macOS A8 (needs Sash's Mac).
- aarch64, Jetson, a real host key, Home launch, other WASI interfaces.
- Provider `Path traversal not allowed` (the request stays on this side
  of the operator).
- Agent-conformance `host_key_read_is_refused` / F-ac8a on this head.
