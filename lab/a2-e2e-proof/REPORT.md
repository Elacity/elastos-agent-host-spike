# A2 e2e proof

```text
Lane:         lab/a2-e2e-proof
Branch / PR:  cursor/a2-e2e-proof-55ab  https://github.com/Elacity/elastos-agent-host-spike/pull/331
Commit:       (this folder only; see evidence.txt)
Base:         spike/agent-host 042cb132371f77ce1b469af059e054bb7ef78295
Develop:      not merged (this folder only)
Machine:      Linux x86_64, rustc 1.91.0 (f8297e351 2025-10-28)
```

## Why the e2e is ignored

The named A2 journey is
`runtime::tests::the_agent_host_writes_and_reads_its_journal_through_the_real_bridge`
in `elastos/crates/elastos-server/src/runtime.rs`. The attribute is:

```text
#[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-e2e.sh"]
```

It needs a built guest WASM that is not in git. CI does not run
`examples/agent-host/build.sh`. A default `cargo test` reports
`ignored`, not `ok`. The test is not flaky and is not marked broken.
Two sibling tests share the same ignore:
`the_agent_host_stores_nothing_when_its_journal_grants_are_denied` and
`the_agent_host_refuses_a_format_1_journal_with_its_reason`.

This runner built the guest, then ran those tests with `--ignored`.
Without `--ignored` the write test stayed ignored. That skip is not a
pass.

## Journey

A2 wording: session journal written through the real Runtime bridge,
revision-checked, resumable by head hash.

| Step | Result | Evidence |
| --- | --- | --- |
| Write through the bridge | PASS | ignored e2e, `--ignored --exact`, `... ok` in 0.48s |
| Stale-revision write refused with its reason | PASS | `a_stale_journal_revision_is_refused_and_the_stored_journal_is_kept` `... ok`; reason `revision_conflict` |
| Resume after restart reads back the latest revision | FAIL | ignored e2e reads back in the same process; shipped `run()` uses `create_only` and does not load a stored format-2 journal after a new launch |

Sibling ignored tests also `ok` with `--ignored` (denied grants; format 1 refusal). They are not the resume row.

## Runtime start

The runner built `elastos` and `localhost-provider` from this checkout
and started `elastos serve` on a throwaway Linux Home. Health was 200
(`runtime_serve_ready: True` in `evidence.txt`). The journal write
still goes through the in-process real bridge, because that is the
named A2 e2e path. Guest hash
`sha256:c93e461d0d5b0cb2ca7866ad399441e59dd2b95cba8b12f4711bd18e9d349e9d`.
Runtime `sha256:43db61137d3f07276626ccc72594fa67337df1f040ddc0a1002a621c52e8e680`.

## Falsifier

`F-A2-REVISION` makes a stale `if_revision` write return ok. The stale
test failed. Result: **CAUGHT**. `resource_bridge.rs` was restored
byte-identical (`git status` clean).

## A2 count

**A2 does not stay counted.** Write and stale pass. Resume after
restart does not. Under Anders's rule the whole journey must pass.
A2 is at risk.

## Proposed fix

`PROPOSED-CHANGE.md` adds one always-on bridge test: write, stale
`revision_conflict`, new bridge on the same data dir, read back the
latest revision. No WASM. Not applied here.

## Principles

3 No ambient authority: the guest writes only after the two grants.
7 One authority model: the same pending request and bridge as any app.
11 Fail closed: a stale revision is `revision_conflict`.
12 Docs, code, tests agree: an ignored test is not a pass.

## Next

Apply `PROPOSED-CHANGE.md` in a Runtime slice. Keep `run-e2e.sh` for
the guest WASM row. Do not treat `#[ignore]` as ok.
