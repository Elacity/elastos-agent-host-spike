# Adversarial review of #301 A8 at `1a82d25b`

Draft. Do not merge.

Independent review of [PR #301](https://github.com/Elacity/elastos-agent-host-spike/pull/301) at
`1a82d25bdd00d3a383433de84e97c39a4184d107`. Prior review:
[PR #316](https://github.com/Elacity/elastos-agent-host-spike/pull/316) on `32abea67`.

Machine: Linux 6.12.94+ x86_64, rustc 1.91.0 (f8297e351 2025-10-28), uid 1000,
Landlock ABI 6. No KVM. Detached worktree `/tmp/pr-301-a8` at the reviewed
commit. That branch was left untouched. This folder is the only write surface.

Anders's rule used here: a check counts when its complete journey, its refusal
evidence, and its required reviews all pass.

**A8 verdict: NOT BOOKABLE.** `VERDICT: FIX` on the two #316 closures.

## Verdicts

| Claim | Verdict | Evidence |
| --- | --- | --- |
| A1: `wasi:cli/environment@0.2.0` is refused at admission with the allowlist sentence; the bus-only build is admitted | HOLDS | `lab/a1-a8-hardening/run.sh` |
| A1: the row is not "every component is refused" | HOLDS | `python3 lab/a1-a8-hardening/falsify.py F-A1a` admitted the control bytes |
| A8: the committed injection's stderr sentence is the Runtime manifest-bound line; fake key unchanged | HOLDS for that guest | same `run.sh`; origin `guest_has_refusal_sentence:false`; key `unchanged:true` |
| A8: `agent_host_host_key_read_is_refused` proves the Runtime wrote that sentence | **FALSIFIED** | attack `B-piece-forge` |
| A8: the injection fails only the fake key and goes through `request_journal_grants` | **FALSIFIED** | attacks `A-skip-guards` and `D-direct-request`; `F-A8-early` only locks a marker |
| A8: the shipped `WasmBus` prints `BusError::Internal` | HOLDS that it does not (author: NEEDS RUNTIME) | attack `C-wasm-bus-only` |
| A8 shipped-bytes row is a pass | HOLDS that it is BLOCKED | `run.sh` maps the ignore; `--ignored` panics with AC-002-ARGS |
| Falsifiers 6/6 CAUGHT | HOLDS as runner output. WEAK as a catch for `F-A8a` / `F-A8-runtime` | both ended `exit:None` after the 60s client bound |
| Suite: 2 passed, 1 BLOCKED, cargo exit 0 | HOLDS | `run.sh`, 425s |
| Cited tests exist | HOLDS | `wasi_import_is_refused_at_admission`, `agent_host_host_key_read_is_refused`, `shipped_agent_host_bytes_read_host_key` |

## Suite

Command, after `cargo fetch --locked` of the lane, wasi-guest, agent-host,
`elastos/tools/componentize`, and `elastos` manifests (the suite itself stays
`--offline`):

```sh
cargo fmt --manifest-path lab/a1-a8-hardening/Cargo.toml -- --check
cargo fmt --manifest-path lab/a1-a8-hardening/wasi-guest/Cargo.toml -- --check
lab/a1-a8-hardening/run.sh
```

fmt exit 0. `run.sh` cargo exit 0, 425s. Raw output:
`evidence/run.sh.txt`, `evidence/run-raw.txt`.

```text
a1 runtime: elastos sha256 d10015590bba0ed5224ad9c94b003c0d2ba9afda3d33f45587a3257c5367a540
a1 wasi build: sha256 a6aa5328127a6c08cd2aee4aae4ef58cf5bb0ca0047e9e3089dedd0b4a33d884 imports ["wasi:cli/environment@0.2.0", "elastos:bus/types@1.0.0"]
a1 control build: sha256 b2eaaf6f054837ca0880218909766100214706fbaa9a098aba4fca72e06f6c4f imports ["elastos:bus/types@1.0.0"]
a1 refused run: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Invalid manifest: component import \"wasi:cli/environment@0.2.0\" is not allowed; allowed imports: elastos:bus/types@1.0.0, elastos:bus/runtime@1.0.0, elastos:bus/identity@1.0.0, elastos:bus/capabilities@1.0.0, elastos:bus/providers@1.0.0")
a1 control run: exit:Some(0) admitted_line:Some("[run] Component capsule 'a1-wasi-guest' exited")
a8 runtime: elastos sha256 d10015590bba0ed5224ad9c94b003c0d2ba9afda3d33f45587a3257c5367a540
a8 shipped agent-host: sha256 c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d imports [five elastos:bus]
a8 injected agent-host: sha256 f7a41ffdbe7cf6bd041108599079a64ec4f6bc2aa635a97d7455c7b423f9b8e5 imports [the same five]
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 host key read: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Compute error: Component capsule denied: BusError::Internal(\"capsule manifest does not declare authority for localhost://Public/../../../../.ssh/id_ed25519\")") marker_absent:true unchanged:true

row | test | result
A1 | wasi_import_is_refused_at_admission | PASS
A8 | agent_host_host_key_read_is_refused | PASS
A8 | shipped_agent_host_bytes_read_host_key | BLOCKED (AC-002-ARGS; the shipped agent-host names only its own journal)
```

Guest hashes match the PR log. The debug `elastos` hash on this machine is
`d1001559…`. The PR log's `97c4cc2e…` is a different native debug binary.

Forced BLOCKED row:

```sh
cargo test --locked --manifest-path lab/a1-a8-hardening/Cargo.toml \
  --test a8_agent_host_host_key shipped_agent_host_bytes_read_host_key \
  -- --exact --ignored --nocapture
```

Exit 101. Panic text is the AC-002-ARGS ignore reason. Cargo exit 0 on the
suite is the ignored test. The BLOCKED row is an honest ignore, not a hidden
pass.

## Falsifiers

`python3 lab/a1-a8-hardening/falsify.py <ID>`, one at a time. Source restored
to the baseline SHA-256 after each entry (`evidence/post-falsify-sha256.txt`).
`git status` in the worktree stayed clean.

| ID | Runner | What ran |
| --- | --- | --- |
| F-A1a | CAUGHT | Control bytes in the refused slot: `exit:Some(0) refusal_line:None` |
| F-A1-runtime | CAUGHT | Allowlist off. Core-module reason. Exact-reason assert failed. elastos `0575e924…` |
| F-A8-forge | CAUGHT | `guest_has_refusal_sentence:true`, injected `45e4b8fb…`, failed before `serve` |
| F-A8-early | CAUGHT | `guest_has_early_injection:true`, injected `9cff3664…` (old row), failed before `serve` |
| F-A8a | CAUGHT | Origin still held. `exit:None refusal_line:None`. 60s client bound |
| F-A8-runtime | CAUGHT | Same timeout. elastos `1437b908…` |

`falsifiers.json` says a timeout does not count as caught. `F-A8a` and
`F-A8-runtime` are that case: the client hits `BOUND` with no status. The
exact-reason assert then fails, so the runner prints CAUGHT. The next layer
(operator pending, or provider `..`) was not observed.

`F-A8-forge` and `F-A8-early` catch the two plants they name. They leave the
holes below open.

## Break attempts

Scratch edits in the worktree only. Each run restored
`tests/a8_agent_host_host_key.rs` to
`3c03fdc79e8ac2d4f2f7bbeda81f77dae265d60f1f8e0c6f1e50577520722859`.
Scripts: `attacks/run_attacks.py`. Outputs: `evidence/attacks/`.

### B-piece-forge — origin lock

The guest returns `BusError::Internal` with the manifest sentence built at
runtime from `"capsule manifest does "` and `"not declare authority"`, under
`black_box`. Bus imports stay referenced the same way as the #316 forge.
`contains_bytes` looks for the contiguous prefix. Origin printed
`guest_has_refusal_sentence:false`. The test passed:

```text
a8 injected agent-host: sha256 92d42c030a295c221c98c8e13fb0f5fa774a6da7beb43e6dcc9b87d4c4ccb274
a8 origin: guest_has_refusal_sentence:false guest_has_early_injection:false guest_has_host_key:true
a8 host key read: exit:Some(1) refusal_line:Some(the Internal sentence) marker_absent:true unchanged:true
test agent_host_host_key_read_is_refused ... ok
```

The stderr line is the guest's own `Internal` string, wrapped by `elastos run`.
The test treats that wrap as Runtime authorship.

### A-skip-guards and D-direct-request — grant path

The committed injection still needs `journal_resource` to name the key, plus a
second `capabilities::request?` after `request_journal_grants`. Dropping the
`host_path` special-case and the `JOURNAL_ROOT` early-return delete left the
test passing (`A-skip-guards`, injected `d982e887…`).
`request_journal_grants` still sees `..` and returns empty grants with no bus
call. The extra `?` produces the sentence.

A still smaller guest (`D-direct-request`, injected `8441f14e…`) inserts only
`capabilities::request?` after `identity::context()`. Compaction,
`host_path`, `journal_cursor`, and `request_journal_grants` stay unreached.
Origin printed `guest_has_early_injection:false` because the old marker
`agent-host read the host key` is absent. The test passed with the same
Internal line.

`F-A8-early` restores that old marker. It does not require the journal grant
path to run.

### C-wasm-bus-only — shipped adapter

Keep the `host_path` / `JOURNAL_ROOT` / `journal_resource` edits. Drop the extra
`?`. `request_journal_grants` goes through `WasmBus`. The test failed:

```text
a8 host key read: exit:Some(1) refusal_line:Some("Error: Component capsule failed: Compute error: Component capsule denied: BusError::Invalid(\"the journal append did not follow its grants\")")
```

`WasmBus::request_grant` maps `BusError::Internal` to `BusFailure::Other`.
Empty grants then fail the guest's own append follow-up. The path-specific
Internal sentence is the test-only `?`, as the README already says.

## Bookability

A8 on this lane is one Bus read of one fake file, from a mutated agent-host
copy, on Linux x86_64. The complete journey Anders's rule asks for still
needs:

1. A lock that the sentence is absent from the guest in every encoding the
   guest can emit, or a Runtime-owned receipt that the guest cannot mint.
2. A lock that `request_journal_grants` actually called the bus, rather than a
   second `capabilities::request?` or an early request.
3. The shipped `WasmBus` surface, or an honest remaining NEEDS RUNTIME row
   that stays out of the pass column.
4. macOS on Sash's Mac (data-dir rule is written; this host did not run it).
5. The shipped agent-host bytes, still BLOCKED on AC-002-ARGS.

The agent-conformance probe proof (PR #179 / F-ac8a) was NOT RUN here. This
lane does not replace it.

## Principles

- 3, 7, 18: Runtime still owns admission and the manifest bound on the
  committed guest. The fake file stays a fixture.
- 10: the visible Internal sentence is a second `capabilities::request?` beside
  `WasmBus`. Two asks, one reported reason.
- 11: empty grants fail closed, but as `Invalid("the journal append did not
  follow its grants")`, which hides the manifest bound.
- 12: README claims the grant-path guards failed. `F-A8-early` only names the
  old marker.

DeepSeek: none.

## Not run

- macOS A8 (needs Sash's Mac).
- aarch64, Jetson, a real host key, Home launch, other WASI interfaces.
- Provider `Path traversal not allowed` (the request stays on this side of the
  operator).
- Agent-conformance `host_key_read_is_refused` / F-ac8a on this head.
