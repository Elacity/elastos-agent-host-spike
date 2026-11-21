# Third-party stand-in

This lab is a stand-in for one third-party provider and one app. It is mechanism proof for the P2-10 hooks. It does not close the check. The real subject is Neptune Swap.

The check says a third-party capsule and its provider install and run with no Runtime patch: their scheme and needs come from signed manifests and user approval. This crate gives each later hook a fixture that is red today and goes green without a Runtime source edit that names the app.

What this lab holds:

- Two signed manifests, `fixtures/provider` and `fixtures/app`. Both pass `CapsuleManifest::validate` unchanged. The signature admits those bytes. It grants nothing.
- The fingerprint in each `identity.json` is the content sha256 that the Runtime signature covers. This crate does not compute a UnixFS CID.
- The signer is the public test key of 32 bytes of value 7, already used by tests in this repo. The signer DID is recorded beside each manifest.
- One today-row for each hook. Each row asserts the behaviour this tree has now, so the lab is green. A later slice reviews and flips its row when it builds the hook.
- One sites row for H1. It lists production registration calls under `elastos/crates` and `.provides` field accesses on any receiver. This includes accesses on other types with the same field name.
- One ignored test, `p2_10_matrix_wanted`, that names the wanted behaviour. Where no API can express it yet, the row says so and is red. It does not pass on a weaker stand-in.
- One no-name tripwire. A search of `elastos/crates/` for the stand-in name returns nothing.
- One open row, declared limits are descriptive today. The log range and the topic message limit live in interface `input_schema`. The Runtime treats interface descriptors as discoverability metadata. No manifest field enforces those numbers. The owner is the P2-10 hook slices.

The provider network right (named hosts, loopback) is a WAITING row. It waits for Sash's ruling and Rong's answer. This lab builds nothing for it.

This crate does not depend on `elastos-server`. The wallet, chain, Carrier, approval, and install doors live there, so those rows read the server source.

The lab's provider calls use `ProviderRegistry::route` on a test double. This route runs no capability check. The lab therefore proves nothing about the server's capability gate.

## What these rows cannot see

The inventory rows watch the named files and call shapes below. A hook built in another file or a helper can leave a row green. A limit enforced when an operation is invoked, rather than during manifest validation, can also leave the declared-limits row green. The ignored `p2_10_matrix_wanted` test states the acceptance behaviour. The slice that builds a hook must flip its row by hand and prove the wanted behaviour through the new API.

| Row | Watched production files and shapes |
| --- | --- |
| H1 | Production Rust under `elastos/crates/`: registration calls, `.provides` field accesses on any receiver; `elastos-runtime/src/provider/registry.rs`: the current registry signature and route result. |
| H2 | `elastos-server/src/api/gateway_browser_wallet.rs` and `api/gateway_provider_proxy.rs`: uses of `BROWSER_CAPSULE_ID`. |
| H3 | `elastos-server/src/api/gateway_browser_wallet_reads.rs`: internet gate call argument and `.asks` or `.input_schema` field access. |
| H4 | `elastos-server/src/carrier.rs`: wire maximum expression and uses, plus `topic_pattern` references. |
| H5 | `elastos-server/src/provider_resource.rs`: operation action map and approval reads; `api/handlers/provider.rs`: approval reads; production Rust under `elastos/crates/`: calls to the action map. |
| H6 | `elastos-server/src/stage_cmd.rs`, `run_cmd.rs`, `main.rs`, and `runtime.rs`: stage and run calls, plus named calls for registration, routing, bundle admission, and start in the launch functions specified in `tests/matrix.rs`. |
| Declared-limits | `fixtures/app/capsule.json`, `fixtures/rows.json`, and `elastos-common/src/manifest.rs`: fixture limit keys, manifest fields, and validation reads. |

The H1 field scan also counts unrelated types with a `.provides` field. Review a changed site before treating the count as a hook.

Gate, from the repository root:

```sh
cd lab/third-party-standin && cargo test --locked
```

The ignored wanted test:

```sh
cd lab/third-party-standin && cargo test --locked -- --ignored p2_10_matrix_wanted
```

`tokio` and `async-trait` are dev-dependencies. They are already in the `elastos-runtime` tree. The tests need them to call the async registry and to implement a test provider.
