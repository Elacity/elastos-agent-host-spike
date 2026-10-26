# Proposed change (not applied)

The ignored guest e2e writes and reads in one process. The stale-revision
row is a different unit test. Neither restarts the Runtime. Do not un-ignore
the guest tests in CI: they need a built `agent-host.component.wasm`.

Smallest fix: add one always-on test next to the existing bridge journal
tests in `elastos/crates/elastos-server/src/resource_bridge.rs`. It uses the
same `journal_context` / `handle_request` helpers. No WASM. No new public
API. CI would run it.

```rust
/// Write through the real bridge, refuse a stale if_revision with its
/// reason, then start a new bridge on the same data dir and read back
/// the latest revision.
#[tokio::test]
async fn a_journal_survives_bridge_restart_and_a_stale_write_is_refused() {
    let (temp, ctx, object_uri) = journal_context("person:local:journal-owner");
    let write = |ctx: BridgeContext, id: u64, content: &[u8], precondition: serde_json::Value| {
        let token = bridge_token(&ctx, &object_uri, Action::Write);
        let line = journal_write_line(id, JOURNAL_SELF_URI, Some(token), content, precondition);
        let ctx = Some(ctx);
        async move { handle_request(&line, &ctx).await.unwrap() }
    };
    let first = write(
        ctx.clone(),
        81,
        b"journal v1",
        serde_json::json!({ "create_only": true }),
    )
    .await;
    assert_eq!(first["response"]["result"]["status"], "ok");
    let v1 = first["response"]["result"]["data"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let second = write(ctx.clone(), 82, b"journal v2", serde_json::json!({ "if_revision": v1 })).await;
    assert_eq!(second["response"]["result"]["status"], "ok");
    let v2 = second["response"]["result"]["data"]["revision"]
        .as_str()
        .unwrap()
        .to_string();
    let stale = write(
        ctx.clone(),
        83,
        b"journal v1 replayed",
        serde_json::json!({ "if_revision": v1 }),
    )
    .await;
    assert_eq!(stale["response"]["result"]["code"], "revision_conflict");
    assert!(
        stale["response"]["result"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("precondition failed")
            || stale["response"]["result"]["code"] == "revision_conflict"
    );

    drop(ctx);
    let principal_id = "person:local:journal-owner";
    let mut ctx = bridge_context();
    ctx.principal_id = Some(principal_id.to_string());
    ctx.data_dir = Some(temp.path().to_path_buf());
    ctx.manifest_capabilities = vec![format!(
        "{}/.AppData/Agents/demo-agent/*",
        crate::auth::principal_localhost_root(principal_id)
    )];
    let read_token = bridge_token(&ctx, &object_uri, Action::Read);
    let read_line = journal_read_line(84, JOURNAL_SELF_URI, read_token);
    let read = handle_request(&read_line, &Some(ctx)).await.unwrap();
    assert_eq!(read["response"]["result"]["status"], "ok");
    let content: Vec<u8> =
        serde_json::from_value(read["response"]["result"]["data"]["content"].clone()).unwrap();
    assert_eq!(content, b"journal v2");
    assert_eq!(
        read["response"]["result"]["data"]["revision"].as_str().unwrap(),
        v2
    );
}
```

Keep `run-e2e.sh` for the guest WASM row. Do not treat its `#[ignore]` as
ok. After this test lands, A2 still needs the guest e2e run with
`--ignored` (or CI building the guest) before the whole wording holds.

Falsifier for the new test: the same plant as `F-A2-REVISION` in this
folder, or skip the second `bridge_context()` and read from the first
process only. The latter must fail the restart assertion.
