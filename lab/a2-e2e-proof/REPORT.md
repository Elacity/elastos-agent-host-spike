# A2 e2e proof

```text
Lane:         lab/a2-e2e-proof
Branch:       cursor/a2-e2e-proof-55ab
Base:         spike/agent-host
Develop:      not merged (this folder only)
```

## Why the e2e is ignored

The named A2 journey is
`runtime::tests::the_agent_host_writes_and_reads_its_journal_through_the_real_bridge`
in `elastos/crates/elastos-server/src/runtime.rs`. The attribute is:

```text
#[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-e2e.sh"]
```

Reason: the test loads a built guest WASM that is not in git. CI does
not run `examples/agent-host/build.sh`, so the default `cargo test`
reports `ignored`, not `ok`. The test is not marked flaky or broken.
Two sibling tests share the same ignore:
`the_agent_host_stores_nothing_when_its_journal_grants_are_denied` and
`the_agent_host_refuses_a_format_1_journal_with_its_reason`.

A skip is not a pass.

## Journey as worded

A2: session journal written through the real Runtime bridge,
revision-checked, resumable by head hash.

| Step | Result | Evidence |
| --- | --- | --- |
| Write through the bridge | pending run | ignored e2e with `--ignored` |
| Stale-revision write refused with its reason | pending run | `a_stale_journal_revision_is_refused_and_the_stored_journal_is_kept` (`revision_conflict`) |
| Resume after restart reads back the latest revision | FAIL until proven | ignored e2e does not restart; shipped `run()` uses `create_only` and does not load a stored format-2 journal |

## Falsifier

`F-A2-REVISION`: accept a stale `if_revision` write as ok. The stale
test must fail. Restore must be byte-identical.

## A2 count

Pending the run in `evidence.txt`. Under Anders's rule the check counts
only when the whole journey passes. Resume after restart is not in the
ignored e2e, so A2 is at risk unless that step passes.

## Next

If resume stays FAIL, apply `PROPOSED-CHANGE.md` in a later Runtime
slice. Do not apply it from this folder.
