# Adversarial review r5 of #455 A8 at `75bb4d85`

Draft. Do not merge.

Independent review of [PR #455](https://github.com/Elacity/elastos-agent-host-spike/pull/455)
at `75bb4d85c157c6191246a8dd5042a08c7b6eacb2` (code `f062eb8c`, parent
`b0cc24c2`). Prior reviews: [PR #437](https://github.com/Elacity/elastos-agent-host-spike/pull/437)
(r4) on `b0cc24c2`. Writes only under `lab/review-a8-455-r5/`. Does not
push to #455 or #301. `Elacity/elastos-runtime` was not touched.

Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28), uid
1000. No KVM. Branch `cursor/review-a8-455-r5-f00e` from the reviewed
commit. This folder is the only write surface.

Anders's rule used here: a check counts when its complete journey, its
refusal evidence, and its required reviews all pass.

**Plain English.** The author's suite counts match this rerun: **1
PASS**, **2 NEEDS RUNTIME**, **1 BLOCKED**. The host-key cargo test is
**FAILED**. `run.sh` remaps that to NEEDS RUNTIME and exits 0. All
**22** named plants are **CAUGHT** by real assertions. All **10**
binding mutants are **KILLED**. Timeouts are **not** counted as caught.
`F-A8a` and `F-A8-runtime` stop on a `pending` host record with
`exit:signaled`.

A1 is a real admission refusal from this checkout's `elastos` binary,
not a lab shim. That row can count on Linux.

A8 stays **NEEDS RUNTIME** / **BLOCKED**. No row claims PASS for A8.
The r4 holes the author named are closed on the lab side. New hunts in
this round also fail to reach cargo `ok`. Eight of them still
**SURVIVED** as later PASS holes: a 32-hex session minted from the
clock, the pid, or zeros binds; the same session binds on two runs;
`u64::MAX` then `0` panics in debug and would wrap in release; a
rename-swap between hash and `load` keeps both hashes honest; a
dangling symlink is treated as an absent journal; a UTF-8 BOM or a
truncated final line drops one receipt and the remaining complete line
later-PASSes `authorship_gaps`.

**Lab half: `VERDICT: FIX`.** The author's r4 claims hold. The lab is
still not a closed authorship lock for the day the Runtime prints an
id. Keep A8 out of the counted column.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| Suite: 1 PASS, 2 NEEDS RUNTIME, 1 BLOCKED; cargo host-key FAILED; `run.sh` exit 0 | HOLDS | `lab/a1-a8-hardening/run.sh` |
| Falsifiers 22/22 CAUGHT by real assertions | HOLDS | `python3 lab/a1-a8-hardening/falsify.py` |
| Binding mutants 10/10 KILLED | HOLDS | `python3 lab/a1-a8-hardening/mutants/binding.py` |
| Timeouts counted as CAUGHT | HOLDS that they are not | `F-A8a` / `F-A8-runtime` are `exit:signaled` + `pending` |
| Session is host-minted 128-bit hex, not `capsule_id` or `context.session` | HOLDS against the named plants | `F-A8-session-alias` CAUGHT |
| `session-1` is refused | HOLDS against the named plant | `F-A8-session-1` CAUGHT |
| `module_hash` is over the staged bytes that load executes | HOLDS against the named plant; SURVIVED against rename TOCTOU | `F-A8-toctou-hash` CAUGHT; `H-toctou-rename` SURVIVED |
| `seq` is strictly increasing | HOLDS against gaps/repeats/reorder; SURVIVED against wrap | `F-A8-seq-ignored` CAUGHT; `H-seq-overflow-wrap` SURVIVED |
| Same-inode shrink records the real size | HOLDS | `F-A8-shrink-dead` CAUGHT |
| Post-run rewrite is judged against a host-held seal | HOLDS | `F-A8-rewrite-after-run` CAUGHT; seal is process memory |
| Duplicate JSON keys and `capsule_id` whitespace fail | HOLDS | `F-A8-dup-keys`, `F-A8-capsule-trim` CAUGHT |
| A1 PASS is genuine | HOLDS | this checkout's `elastos`, allowlist sentence in the binary |
| A8 host-key row stays NEEDS RUNTIME | HOLDS | `run.sh` remap; `assigned:None`, `session:None`, `module_hash None`, `guest_function None`, `seq None` |
| A8 WasmBus sentence stays NEEDS RUNTIME | HOLDS | ignore + `--ignored` panic |
| A8 shipped-bytes row stays BLOCKED | HOLDS | ignore + `--ignored` panic AC-002-ARGS |
| No PASS claimed for A8 | HOLDS | three A8 rows are NEEDS RUNTIME or BLOCKED |

## Suite

```sh
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
```

fmt exit 0. `run.sh` cargo exit 0. Lib unit tests: 8 passed.
Authorship-lock tests: 8 passed. Raw row output:
`evidence/run.sh.full.txt`.

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
a8 receipt cursor: size:0 inode:None path:/tmp/a8-home.I4fO9Q/home/.local/share/elastos/runtime/capability-requests.jsonl
a8 host key read: exit:Some(1) assigned:None session:None guest_hash:f3d89ab4… host_records:[write then read, both manifest_capability_denied, capsule_id component-22014035-…, session_id None, module_hash None, guest_function None, seq None] marker_absent:true unchanged:true
a8 authorship: needs runtime: capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function, receipt seq

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | NEEDS RUNTIME (capability-requests.jsonl omits component id from Runtime [run] output or API, session id, guest module hash, guest function, receipt seq)
A8 | shipped_wasm_bus_prints_internal_sentence | NEEDS RUNTIME (WasmBus maps BusError::Internal to BusFailure::Other, so the path-specific Internal sentence is not visible)
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Guest component hashes match the PR log. The debug `elastos` hash on
this machine is `e027209c…`, the same native debug binary the PR log
printed.

Source SHA-256 matches the PR log:

- `tests/a1_wasi_import.rs`: `ccf9fc61…`
- `tests/a8_agent_host_host_key.rs`: `8d0c842b…`
- `src/lib.rs`: `c868d269…`
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
elastos-server --bin elastos`. SHA-256 `e027209c…` matches the printed
`a1 runtime` line. The file is an ELF 64-bit pie executable, 185 MiB,
not stripped. The allowlist sentence and `elastos:bus/…@1.0.0` names
are in this binary's strings. The lab crate has no copy of that check.

The control guest is admitted and prints `[run] Component capsule
'a1-wasi-guest' exited`. The refused guest does not print `exited`.
One WASI interface on the `elastos run` path. Other WASI interfaces and
Home launch stay out.

## Falsifiers

`python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time.
22 of 22 CAUGHT. Each failed at a listed `fail_needle` with exit 101.
No timeout. Source restored to the baseline SHA-256 after each entry
(`evidence/post-falsify-sha256.txt`). `git status` on Runtime and lane
source stayed clean after the last restore.

| ID | Result | What ran |
| --- | --- | --- |
| F-A1a | CAUGHT | Control bytes in the refused slot: `exit:Some(0) refusal_line:None` |
| F-A1-runtime | CAUGHT | Allowlist off (elastos `9d4a0c09…`). Core-module reason. Exact-reason assert failed. |
| F-A8a | CAUGHT | Manifest declared the fake key. Host record is `pending` for write. `exit:signaled`. |
| F-A8-runtime | CAUGHT | Manifest refusal off (elastos `72fe1fa5…`). Same `pending` write and `exit:signaled`. |
| F-A8-forge | CAUGHT | Injected `45e4b8fb…`. `guest_has_refusal_sentence:true`. Failed before `serve`. |
| F-A8-early | CAUGHT | Old early-return guest `9cff3664…`. `guest_has_early_injection:true`. Failed before `serve`. |
| F-A8-skip-guards | CAUGHT | Injected `c0745cec…`. `host_records:[]`. |
| F-A8-piece-forge | CAUGHT | Injected `92d42c03…`. `host_records:[]`. |
| F-A8-wasm-bus-only | CAUGHT | Honest guest `f3d89ab4…` has write then read. Internal sentence on stderr failed. |
| F-A8-direct-request | CAUGHT | Injected `8441f14e…`. One `read` only. |
| F-A8-test-writes-lines | CAUGHT | Test wrote the two lines; no-bus guest `92d42c03…`. File existed before launch. |
| F-A8-skip-journal-grants | CAUGHT | Injected `47c2355d…`. Write then read present. Cargo FAILED on host-side sequence. |
| F-A8-guest-follow-sentence | CAUGHT | Injected `66790ec5…`. Write then read present. Invalid sentence printed. Cargo FAILED. |
| F-A8-race-after-snapshot | CAUGHT | Injected `7d81d0cb…`. Foreign id after snapshot. File existed at spawn. |
| F-A8-session-alias | CAUGHT | `session_id == capsule_id` / identity.session. |
| F-A8-session-1 | CAUGHT | Predictable `session-1`. |
| F-A8-toctou-hash | CAUGHT | Hash of the in-memory copy, not staged bytes. |
| F-A8-seq-ignored | CAUGHT | `seq` gaps/repeats/reorder. |
| F-A8-shrink-dead | CAUGHT | Lock size 0. Same-inode shrink no longer panicked. |
| F-A8-rewrite-after-run | CAUGHT | Same-inode rewrite after `run_until`. |
| F-A8-dup-keys | CAUGHT | Last-wins duplicate JSON keys. |
| F-A8-capsule-trim | CAUGHT | Trimmed `capsule_id`. |

Per-id output: `evidence/falsifiers/`. Guest hashes match the PR log.

## Binding mutants

`python3 lab/a1-a8-hardening/mutants/binding.py`: 10 of 10 KILLED.

```text
M-sequence-stderr: mutant=PASS real=NEEDS RUNTIME hunt=H-guest-follow-sentence KILLED
M-assigned-none-match: mutant=PASS real=NEEDS RUNTIME hunt=foreign capsule_id KILLED
M-after-snapshot-window: mutant=PASS real=FAIL hunt=H-race-after-snapshot KILLED
M-println-not-assert: mutant=PASS real=NEEDS RUNTIME hunt=honest missing fields KILLED
M-session-presence: mutant=PASS real=FAIL hunt=other-session KILLED
M-guest-function-optional: mutant=PASS real=NEEDS RUNTIME hunt=missing guest function KILLED
M-hash-alias: mutant=PASS real=NEEDS RUNTIME hunt=wasm_hash alias KILLED
M-session-alias: mutant=PASS real=FAIL hunt=session == capsule_id KILLED
M-session-1: mutant=PASS real=FAIL hunt=session-1 KILLED
M-seq-ignored: mutant=PASS real=FAIL hunt=seq 1 then 3 KILLED

10 of 10 mutants KILLED
```

## New hunts

Each hunt calls the subject's public API
(`tests/r5_hunts.rs`). None reached cargo `ok` on the live A8 row.
Eight SURVIVED as later PASS holes. Minimal patches:
`attacks/patches.md`.

| ID | Hunt | Result |
| --- | --- | --- |
| H-session-from-time | 32 hex from `unix_nanos` | SURVIVED |
| H-session-from-pid | 32 hex from pid | SURVIVED |
| H-session-all-zeros | `0000…0` | SURVIVED |
| H-session-reused | same session on two binds | SURVIVED |
| H-seal-guest-writable | seal written where the guest can write | CAUGHT (process memory; no sibling file; guest has no WASI preopen) |
| H-seal-before-flush | seal, then append | CAUGHT (`rewritten after run`) |
| H-seq-overflow-wrap | `u64::MAX` then `0` | SURVIVED (debug overflow panic; release wrap would bind) |
| H-seq-gaps | `1` then `3` | CAUGHT |
| H-toctou-rename | rename-swap between hash and load | SURVIVED |
| H-mmap-swap | hash a live mmap that changes | CAUGHT (hash is a `Vec` snapshot) |
| H-unicode-lookalike-keys | Cyrillic `сapsule_id` | CAUGHT (`capsule_id` absent; no later PASS) |
| H-nan-large-numbers | `NaN`, `u64::MAX+1`, `-1`, `1.5` | CAUGHT |
| H-bom | UTF-8 BOM on the first line | SURVIVED (write dropped; remaining complete read later-PASSes authorship) |
| H-crlf | CRLF jsonl | CAUGHT / HONEST (two lines parse; not a hole) |
| H-truncated-final-line | no final newline | SURVIVED (read dropped; remaining complete write later-PASSes authorship) |
| H-symlink-journal | dangling symlink at the jsonl path | SURVIVED (`exists()` is false; target later-PASSes) |
| H-hardlink-journal | hardlink of a pre-written file | CAUGHT (pre-exist) |
| H-tmpfs-remount | remount the journal tmpfs | NOT RUN (`mount` needs CAP_SYS_ADMIN; not a PASS) |

`ComponentProvider` still says it exposes no WASI, environment,
filesystem preopen, FIFO, raw socket, or gateway. The guest cannot
write the seal or the journal. Shared uid with the test process stays
in `RUNTIME-ASK.md`.

### Survivors, in short

1. **Predictable 32-hex session.** `is_session_id` is a format check.
   Clock, pid, and zeros later-PASS. Patch: refuse values `< 2^64`.
2. **Session reuse.** No host-held used set. Patch: `Home` inserts the
   session once.
3. **seq wrap.** `pair[0] + 1` overflows. Patch: `checked_add`.
4. **Rename TOCTOU.** Hash is of slices, not a sealed inode. Patch:
   seal the staged path; re-check inode and hash at load.
5. **Dangling symlink.** `exists()` misses it. Patch:
   `symlink_metadata`.
6. **BOM / truncated line.** One remaining complete line later-PASSes
   `authorship_gaps`. Today's A8 row still fails write-then-read. Patch:
   refuse a BOM; require the write-then-read pair inside
   `authorship_gaps`.

## A8 BLOCKED / NEEDS RUNTIME are honest

`--ignored` on
`shipped_wasm_bus_prints_internal_sentence` panics with the WasmBus
`BusError::Internal` → `BusFailure::Other` sentence. `--ignored` on
`shipped_agent_host_bytes_read_host_key` panics with AC-002-ARGS. The
host-key cargo test panics
`needs runtime: capability-requests.jsonl omits component id from
Runtime [run] output or API, session id, guest module hash, guest
function, receipt seq`. `run.sh` remaps that FAILED to NEEDS RUNTIME
and would print FAIL if cargo were `ok` while the ask is missing. No
A8 row is PASS.

## macOS

NOT RUN. Sash's Mac still needs `run.sh`, the twenty-two plants, the
ten mutants, and the r5 hunts. Dump the raw jsonl under that Home's
`~/Library/Application Support/elastos` and check `capsule_id` /
`session_id` / `module_hash` / `guest_function` / `seq`. Timeouts stay
NOT CAUGHT.

## Next

Close the eight later-PASS holes with the patches in
`attacks/patches.md`. Keep A8 out of the counted column until the
Runtime prints a host-minted session, the staged-byte hash, the guest
function, and a wrapping-safe `seq`, and the lab refuses time/pid/zero
sessions, reuse, rename TOCTOU, dangling symlinks, and a BOM.
