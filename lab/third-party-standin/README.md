# Third-party stand-in

This lab is a stand-in for one third-party provider and one app. It is mechanism proof for the P2-10 hooks. It does not close the check. The real subject is Neptune Swap.

The check says a third-party capsule and its provider install and run with no Runtime patch: their scheme and needs come from signed manifests and user approval. This crate gives each later hook a fixture that is red today and goes green without a Runtime source edit that names the app.

What this lab holds:

- Two signed manifests, `fixtures/provider` and `fixtures/app`. Both pass `CapsuleManifest::validate` unchanged. The signature admits those bytes. It grants nothing.
- The fingerprint in each `identity.json` is the content sha256 that the Runtime signature covers. This crate does not compute a UnixFS CID.
- The signer is the public test key of 32 bytes of value 7, already used by tests in this repo. The signer DID is recorded beside each manifest.
- One today-row for each hook. Each row asserts the behaviour this tree has now, so the lab is green. A later slice that builds the hook makes that row fail, and the row is then flipped.
- One sites row for H1. It lists every production call of `ProviderRegistry` registration under `elastos/crates`, and every production reader of the manifest `provides` field. A new site turns that row red. That is when H1 is flipped.
- One ignored test, `p2_10_matrix_wanted`, that names the wanted behaviour. Where no API can express it yet, the row says so and is red. It does not pass on a weaker stand-in.
- One no-name tripwire. A search of `elastos/crates/` for the stand-in name returns nothing.
- One open row, declared limits are descriptive today. The log range and the topic message limit live in interface `input_schema`. The Runtime treats interface descriptors as discoverability metadata. No manifest field enforces those numbers. The owner is the P2-10 hook slices.

The provider network right (named hosts, loopback) is a WAITING row. It waits for Sash's ruling and Rong's answer. This lab builds nothing for it.

This crate does not depend on `elastos-server`. The wallet, chain, Carrier, approval, and install doors live there, so those rows read the server source.

The lab's provider calls use `ProviderRegistry::route` on a test double. This route runs no capability check. The lab therefore proves nothing about the server's capability gate.

## Rows that must be flipped by hand

None. H2, H3, H4, H5, and H6 are counted production inventories. A new production use turns the row red. The H1 sites row does the same for registration and for readers of `provides`. The wanted test stays red until a later slice can assert each behaviour through an API, and it says which behaviour is missing.

Gate, from the repository root:

```sh
cd lab/third-party-standin && cargo test --locked
```

The ignored wanted test:

```sh
cd lab/third-party-standin && cargo test --locked -- --ignored p2_10_matrix_wanted
```

`tokio` and `async-trait` are dev-dependencies. They are already in the `elastos-runtime` tree. The tests need them to call the async registry and to implement a test provider.
