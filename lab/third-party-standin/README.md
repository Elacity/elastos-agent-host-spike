# Third-party stand-in

This lab is a stand-in for one third-party provider and one app. It is mechanism proof for the P2-10 hooks. It does not close the check. The real subject is Neptune Swap.

The check says a third-party capsule and its provider install and run with no Runtime patch: their scheme and needs come from signed manifests and user approval. This crate gives each later hook a fixture that is red today and goes green without a Runtime source edit that names the app.

What this lab holds:

- Two signed manifests, `fixtures/provider` and `fixtures/app`. Both pass `CapsuleManifest::validate` unchanged. The signature admits those bytes. It grants nothing.
- The fingerprint in each `identity.json` is the content sha256 that the Runtime signature covers. This crate does not compute a UnixFS CID.
- The signer is the public test key of 32 bytes of value 7, already used by tests in this repo. The signer DID is recorded beside each manifest.
- One today-row for each hook. Each row asserts the behaviour this tree has now, so the lab is green. A later slice that builds the hook makes that row fail, and the row is then flipped.
- One ignored test, `p2_10_matrix_wanted`, that asserts the wanted behaviour. It is red today.
- One no-name tripwire. A search of `elastos/crates/` for the stand-in name returns nothing.

The provider network right (named hosts, loopback) is a WAITING row. It waits for Sash's ruling and Rong's answer. This lab builds nothing for it.

This crate does not depend on `elastos-server`. The wallet, chain, Carrier, approval, and install doors live there, so those rows read the server source. Provider calls in this crate go through `ProviderRegistry::route`.

Gate, from the repository root:

```sh
cd lab/third-party-standin && cargo test --locked
```

The ignored wanted test:

```sh
cd lab/third-party-standin && cargo test --locked -- --ignored p2_10_matrix_wanted
```

`tokio` and `async-trait` are dev-dependencies. They are already in the `elastos-runtime` tree. The tests need them to call the async registry and to implement a test provider.
